package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TaskSnapshot is a value copy; callers never retain mutable task-store entries.
type TaskSnapshot struct {
	TaskID                  string
	Status                  TaskStatus
	Output, Error, Logs     string
	CreatedAt, UpdatedAt    time.Time
	CompletedAt, ExpiresAt  *time.Time
	Cached, ResultAvailable bool
}

type TaskError struct{ Code, Message string }

func (e *TaskError) Error() string { return e.Message }

type taskMetadata struct {
	createdAt, updatedAt   time.Time
	completedAt, expiresAt *time.Time
	ttl                    time.Duration
	cached                 bool
	cancelRequested        bool
	requestID, fingerprint string
	artifactDir            string
	artifact               []byte // Fallback if temporary storage is unavailable.
	resultAvailable        bool
}

type taskCompletion struct {
	Status              TaskStatus
	Output, Error, Logs string
	Cached              bool
	CacheKey            string
}

var (
	requestIDs        = make(map[string]string) // Guarded by taskMutex.
	activeDirectories = make(map[string]bool)
	taskWorkers       sync.WaitGroup
	stopping          bool // Guarded by requestMutex.
)

func taskDurations() (time.Duration, time.Duration, error) {
	values := []time.Duration{30 * time.Minute, 24 * time.Hour}
	for i, name := range []string{"GVS_SCAN_TIMEOUT", "GVS_TASK_TTL"} {
		if raw := os.Getenv(name); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d <= 0 {
				return 0, 0, fmt.Errorf("%s must be a positive Go duration", name)
			}
			values[i] = d
		}
	}
	return values[0], values[1], nil
}

func ValidateTaskConfiguration() error {
	_, _, err := taskDurations()
	if err != nil {
		return err
	}
	if raw := os.Getenv("GVS_PUBLIC_URL"); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("GVS_PUBLIC_URL must be an absolute HTTP(S) base URL without credentials, query, or fragment")
		}
	}
	return nil
}

func PublicBaseURL(r *http.Request) string {
	if value := os.Getenv("GVS_PUBLIC_URL"); value != "" {
		return strings.TrimRight(value, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if value := r.Header.Get("X-Forwarded-Proto"); value == "http" || value == "https" {
		scheme = value
	}
	return scheme + "://" + r.Host
}

func startTask(requestID, fingerprint string, work func(context.Context, string) taskCompletion) (TaskSnapshot, error) {
	timeout, ttl, err := taskDurations()
	if err != nil {
		return TaskSnapshot{}, err
	}
	requestMutex.Lock()
	defer requestMutex.Unlock()
	taskMutex.Lock()
	defer taskMutex.Unlock()
	expireTasksLocked(time.Now())
	if requestID != "" {
		if id, ok := requestIDs[requestID]; ok {
			task := taskStore[id]
			if task.meta.fingerprint != fingerprint {
				return TaskSnapshot{}, &TaskError{"request_id_conflict", "requestId was already used with different scan arguments"}
			}
			log.Printf("[Task %s] Reusing submission status=%s", id, task.Status)
			return snapshotLocked(id, task), nil
		}
	}
	if stopping {
		return TaskSnapshot{}, &TaskError{"server_stopping", "Server is shutting down"}
	}
	if inProgress {
		return TaskSnapshot{}, &TaskError{"scan_busy", "Another scan is in progress. Retry after 5 seconds."}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return TaskSnapshot{}, err
	}
	id := hex.EncodeToString(random[:])
	now := time.Now().UTC()
	task := &TaskResult{Status: StatusPending, meta: taskMetadata{createdAt: now, updatedAt: now, ttl: ttl, requestID: requestID, fingerprint: fingerprint}}
	taskStore[id] = task
	if requestID != "" {
		requestIDs[requestID] = id
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	taskCancelMutex.Lock()
	taskCancels[id] = cancel
	taskCancelMutex.Unlock()
	progressMutex.Lock()
	progressStreams[id] = make(chan string, 100)
	progressMutex.Unlock()
	inProgress = true
	log.Printf("[Task %s] Accepted status=%s", id, task.Status)
	taskWorkers.Add(1)
	go func() {
		defer taskWorkers.Done()
		defer cancel()
		defer func() {
			progressMutex.Lock()
			close(progressStreams[id])
			delete(progressStreams, id)
			progressMutex.Unlock()
			taskCancelMutex.Lock()
			delete(taskCancels, id)
			taskCancelMutex.Unlock()
			requestMutex.Lock()
			inProgress = false
			requestMutex.Unlock()
		}()
		taskMutex.Lock()
		task.Status = StatusRunning
		task.meta.updatedAt = time.Now().UTC()
		log.Printf("[Task %s] Running", id)
		taskMutex.Unlock()
		completion := work(ctx, id)
		if finishTask(ctx, id, completion) && completion.CacheKey != "" && !completion.Cached {
			if err := SaveCacheToDisk(completion.CacheKey, []byte(completion.Output)); err != nil {
				log.Printf("[Task %s] Cache write: %v", id, err)
			}
			if err := SaveCacheLogsToDisk(completion.CacheKey, []byte(completion.Logs)); err != nil {
				log.Printf("[Task %s] Cache log write: %v", id, err)
			}
		}
	}()
	return snapshotLocked(id, task), nil
}

func finishTask(ctx context.Context, id string, result taskCompletion) bool {
	taskMutex.Lock()
	defer taskMutex.Unlock()
	task := taskStore[id]
	if task == nil || isTerminal(task.Status) {
		return false
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Status, result.Error = StatusFailed, "Scan exceeded the configured GVS_SCAN_TIMEOUT"
	} else if task.meta.cancelRequested || ctx.Err() != nil {
		result.Status, result.Error = StatusCancelled, "Scan cancelled"
	}
	if !isTerminal(result.Status) {
		result.Status, result.Error = StatusFailed, "Scan worker returned without a terminal result"
	}
	task.Status, task.Output, task.Error, task.Logs = result.Status, result.Output, result.Error, result.Logs
	now := time.Now().UTC()
	expires := now.Add(task.meta.ttl)
	task.meta.updatedAt, task.meta.completedAt, task.meta.expiresAt, task.meta.cached = now, &now, &expires, result.Cached
	artifact, err := json.Marshal(taskResultFields(task))
	if err != nil { // Fields contain only strings and validated JSON.
		log.Printf("[Task %s] Serialize result: %v", id, err)
		return false
	}
	dir, err := os.MkdirTemp("", "gvs-task-"+id+"-")
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "expires"), []byte(expires.Format(time.RFC3339Nano)), 0600)
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "result.json"), artifact, 0600)
		}
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}
	if err != nil {
		log.Printf("[Task %s] Result storage unavailable, retaining in memory: %v", id, err)
		task.meta.artifact = artifact
	} else {
		task.meta.artifactDir = dir
	}
	task.meta.resultAvailable = true
	log.Printf("[Task %s] Finished status=%s cached=%t duration=%s", id, task.Status, task.meta.cached, time.Since(task.meta.createdAt))
	return result.Status == StatusCompleted
}

func taskResultFields(task *TaskResult) map[string]any {
	fields := make(map[string]any)
	if task.Output != "" {
		if json.Valid([]byte(task.Output)) {
			fields["output"] = json.RawMessage(task.Output)
		} else {
			fields["output"] = task.Output
		}
	}
	if task.Error != "" {
		fields["error"] = task.Error
	}
	if task.Logs != "" {
		fields["logs"] = task.Logs
	}
	return fields
}

func snapshotLocked(id string, task *TaskResult) TaskSnapshot {
	s := TaskSnapshot{TaskID: id, Status: task.Status, Output: task.Output, Error: task.Error, Logs: task.Logs,
		CreatedAt: task.meta.createdAt, UpdatedAt: task.meta.updatedAt, Cached: task.meta.cached, ResultAvailable: task.meta.resultAvailable}
	if task.meta.completedAt != nil {
		t := *task.meta.completedAt
		s.CompletedAt = &t
	}
	if task.meta.expiresAt != nil {
		t := *task.meta.expiresAt
		s.ExpiresAt = &t
	}
	return s
}

func isTerminal(status TaskStatus) bool {
	return status == StatusCompleted || status == StatusFailed || status == StatusCancelled
}

func GetTask(id string) (TaskSnapshot, error) {
	taskMutex.Lock()
	defer taskMutex.Unlock()
	expireTasksLocked(time.Now())
	task := taskStore[id]
	if task == nil {
		return TaskSnapshot{}, &TaskError{"task_not_found", "Task not found or expired"}
	}
	return snapshotLocked(id, task), nil
}

func CancelTask(id string) (TaskSnapshot, error) {
	taskMutex.Lock()
	defer taskMutex.Unlock()
	expireTasksLocked(time.Now())
	task := taskStore[id]
	if task == nil {
		return TaskSnapshot{}, &TaskError{"task_not_found", "Task not found or expired"}
	}
	if task.Status == StatusCancelled {
		return snapshotLocked(id, task), nil
	}
	if isTerminal(task.Status) {
		return TaskSnapshot{}, &TaskError{"task_not_running", "Task is not running"}
	}
	taskCancelMutex.Lock()
	cancel := taskCancels[id]
	taskCancelMutex.Unlock()
	if cancel == nil {
		return TaskSnapshot{}, &TaskError{"task_not_running", "Task cannot be cancelled"}
	}
	if !task.meta.cancelRequested {
		log.Printf("[Task %s] Cancellation requested", id)
	}
	task.meta.cancelRequested = true
	task.meta.updatedAt = time.Now().UTC()
	cancel()
	return snapshotLocked(id, task), nil
}

func ReadTaskResult(id string) ([]byte, error) {
	taskMutex.Lock()
	defer taskMutex.Unlock()
	expireTasksLocked(time.Now())
	task := taskStore[id]
	if task == nil {
		return nil, &TaskError{"task_not_found", "Task not found or expired"}
	}
	if !task.meta.resultAvailable {
		return nil, &TaskError{"task_not_ready", "Result is not ready; poll gvs_status"}
	}
	if task.meta.artifact != nil {
		return append([]byte(nil), task.meta.artifact...), nil
	}
	data, err := os.ReadFile(filepath.Join(task.meta.artifactDir, "result.json"))
	if err != nil {
		return nil, &TaskError{"result_unavailable", "Stored task result is unavailable"}
	}
	return data, nil
}

func expireTasksLocked(now time.Time) {
	for id, task := range taskStore {
		if !isTerminal(task.Status) || task.meta.expiresAt == nil || now.Before(*task.meta.expiresAt) {
			continue
		}
		if task.meta.artifactDir != "" {
			if err := os.RemoveAll(task.meta.artifactDir); err != nil {
				log.Printf("Expire task %s: %v", id, err)
			}
		}
		delete(requestIDs, task.meta.requestID)
		delete(taskStore, id)
	}
}

func MaintainTasks(ctx context.Context) {
	cleanupOrphanResults(os.TempDir(), time.Now())
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			taskMutex.Lock()
			expireTasksLocked(now)
			taskMutex.Unlock()
			cleanupOrphanResults(os.TempDir(), now)
		}
	}
}

// Expiry is stored beside artifacts so crashes do not leave permanent files.
// Other server instances may share TMPDIR; never remove unexpired artifacts.
func cleanupOrphanResults(root string, now time.Time) {
	taskMutex.Lock()
	defer taskMutex.Unlock()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	owned := make(map[string]bool)
	for _, task := range taskStore {
		owned[task.meta.artifactDir] = true
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "gvs-task-") {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		if owned[dir] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "expires"))
		if err != nil {
			continue
		}
		expires, err := time.Parse(time.RFC3339Nano, string(data))
		if err != nil || now.Before(expires) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("Expire result artifact: %v", err)
		}
	}
}

func ShutdownTasks(ctx context.Context) error {
	requestMutex.Lock()
	stopping = true
	requestMutex.Unlock()
	taskCancelMutex.Lock()
	for _, cancel := range taskCancels {
		cancel()
	}
	taskCancelMutex.Unlock()
	done := make(chan struct{})
	go func() { taskWorkers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func IsActiveDirectory(dir string) bool {
	taskMutex.Lock()
	defer taskMutex.Unlock()
	return activeDirectories[dir]
}

func registerDirectory(dir string) func() {
	taskMutex.Lock()
	activeDirectories[dir] = true
	taskMutex.Unlock()
	return func() { taskMutex.Lock(); delete(activeDirectories, dir); taskMutex.Unlock() }
}

func sendTaskProgress(id, message string) {
	progressMutex.Lock()
	defer progressMutex.Unlock()
	if ch := progressStreams[id]; ch != nil {
		select {
		case ch <- message:
		default:
		}
	}
}

// DefaultTaskBackend exposes the shared task lifecycle to protocol adapters.
type DefaultTaskBackend struct{}

func (DefaultTaskBackend) StartCallgraph(r CallgraphRequest, base string) (TaskSnapshot, error) {
	return StartCallgraph(r, base)
}
func (DefaultTaskBackend) GetTask(id string) (TaskSnapshot, error)    { return GetTask(id) }
func (DefaultTaskBackend) CancelTask(id string) (TaskSnapshot, error) { return CancelTask(id) }
func (DefaultTaskBackend) ReadTaskResult(id string) ([]byte, error)   { return ReadTaskResult(id) }
