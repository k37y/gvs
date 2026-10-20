package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func prepareTaskTest(t *testing.T) {
	t.Helper()
	t.Setenv("GVS_SCAN_TIMEOUT", "10s")
	t.Setenv("GVS_TASK_TTL", "24h")
	waitTaskWorkers(t)
	requestMutex.Lock()
	wasStopping := stopping
	stopping = false
	requestMutex.Unlock()
	taskMutex.Lock()
	previous := make(map[string]bool, len(taskStore))
	for id := range taskStore {
		previous[id] = true
	}
	taskMutex.Unlock()
	t.Cleanup(func() {
		taskMutex.Lock()
		var ids []string
		for id := range taskStore {
			if !previous[id] {
				ids = append(ids, id)
			}
		}
		taskMutex.Unlock()
		taskCancelMutex.Lock()
		for _, id := range ids {
			if cancel := taskCancels[id]; cancel != nil {
				cancel()
			}
		}
		taskCancelMutex.Unlock()
		waitTaskWorkers(t)
		taskMutex.Lock()
		for _, id := range ids {
			if task := taskStore[id]; task != nil {
				if task.meta.artifactDir != "" {
					if err := os.RemoveAll(task.meta.artifactDir); err != nil {
						t.Errorf("remove task artifact: %v", err)
					}
				}
				if requestIDs[task.meta.requestID] == id {
					delete(requestIDs, task.meta.requestID)
				}
				delete(taskStore, id)
			}
		}
		taskMutex.Unlock()
		requestMutex.Lock()
		stopping = wasStopping
		requestMutex.Unlock()
	})
}

func waitTaskWorkers(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { taskWorkers.Wait(); close(done) }()
	awaitTaskSignal(t, done)
}

func awaitTaskSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for task worker")
	}
}

func taskRelease(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	return release, unblock
}

func requireTaskError(t *testing.T, err error, code string) {
	t.Helper()
	var taskErr *TaskError
	if !errors.As(err, &taskErr) || taskErr.Code != code {
		t.Fatalf("error = %v, want TaskError %q", err, code)
	}
}

func TestTaskIdempotentSubmission(t *testing.T) {
	prepareTaskTest(t)
	release, unblock := taskRelease(t)
	started := make(chan struct{})
	var calls atomic.Int32
	work := func(ctx context.Context, _ string) taskCompletion {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return taskCompletion{Status: StatusCompleted, Output: `{"IsVulnerable":"false"}`}
	}
	first, err := startTask("retry-key", "arguments", work)
	if err != nil {
		t.Fatal(err)
	}
	awaitTaskSignal(t, started)
	type submission struct {
		task TaskSnapshot
		err  error
	}
	const concurrentRetries = 24
	results := make(chan submission, concurrentRetries)
	for i := 0; i < concurrentRetries; i++ {
		go func() {
			task, err := startTask("retry-key", "arguments", work)
			results <- submission{task, err}
		}()
	}
	for i := 0; i < concurrentRetries; i++ {
		result := <-results
		if result.err != nil || result.task.TaskID != first.TaskID {
			t.Fatalf("retry returned task %q, error %v; want %q", result.task.TaskID, result.err, first.TaskID)
		}
	}
	_, err = startTask("retry-key", "different arguments", work)
	requireTaskError(t, err, "request_id_conflict")
	_, err = startTask("busy-key", "arguments", work)
	requireTaskError(t, err, "scan_busy")
	taskMutex.Lock()
	_, reserved := requestIDs["busy-key"]
	taskMutex.Unlock()
	if reserved {
		t.Error("busy rejection reserved requestId")
	}
	unblock()
	waitTaskWorkers(t)
	retry, err := startTask("retry-key", "arguments", work)
	if err != nil || retry.TaskID != first.TaskID || retry.Status != StatusCompleted {
		t.Fatalf("completed retry = %+v, error %v", retry, err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("worker executions = %d, want 1", got)
	}
	next, err := startTask("busy-key", "new arguments", work)
	if err != nil || next.TaskID == first.TaskID {
		t.Fatalf("retry after busy = %+v, error %v", next, err)
	}
	waitTaskWorkers(t)
}

func TestTaskTimeoutPreservesPartialResult(t *testing.T) {
	prepareTaskTest(t)
	t.Setenv("GVS_SCAN_TIMEOUT", "20ms")
	task, err := startTask("", "", func(ctx context.Context, _ string) taskCompletion {
		<-ctx.Done()
		return taskCompletion{Status: StatusCompleted, Output: "partial output", Logs: "final logs"}
	})
	if err != nil {
		t.Fatal(err)
	}
	waitTaskWorkers(t)
	result, err := GetTask(task.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFailed || !strings.Contains(result.Error, "GVS_SCAN_TIMEOUT") {
		t.Errorf("timeout result = %+v", result)
	}
	if result.Output != "partial output" || result.Logs != "final logs" || !result.ResultAvailable {
		t.Errorf("timeout discarded output or logs: %+v", result)
	}
}

func TestTaskCancellationWaitsForWorker(t *testing.T) {
	prepareTaskTest(t)
	release, unblock := taskRelease(t)
	started, cancelled := make(chan struct{}), make(chan struct{})
	task, err := startTask("", "", func(ctx context.Context, _ string) taskCompletion {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		return taskCompletion{Status: StatusCompleted, Output: `{"partial":true}`, Logs: "logs collected on exit"}
	})
	if err != nil {
		t.Fatal(err)
	}
	awaitTaskSignal(t, started)
	for i := 0; i < 2; i++ {
		ack, err := CancelTask(task.TaskID)
		if err != nil || ack.Status != StatusRunning || ack.ResultAvailable {
			t.Fatalf("cancellation acknowledgement = %+v, error %v", ack, err)
		}
	}
	awaitTaskSignal(t, cancelled)
	_, err = startTask("", "", func(context.Context, string) taskCompletion {
		t.Error("busy worker should not have started")
		return taskCompletion{Status: StatusCompleted}
	})
	requireTaskError(t, err, "scan_busy")
	_, err = ReadTaskResult(task.TaskID)
	requireTaskError(t, err, "task_not_ready")
	unblock()
	waitTaskWorkers(t)
	result, err := GetTask(task.TaskID)
	if err != nil || result.Status != StatusCancelled || result.Output != `{"partial":true}` || result.Logs != "logs collected on exit" {
		t.Fatalf("cancelled result = %+v, error %v", result, err)
	}
	ack, err := CancelTask(task.TaskID)
	if err != nil || ack.Status != StatusCancelled {
		t.Fatalf("repeated terminal cancellation = %+v, error %v", ack, err)
	}
	artifact, err := ReadTaskResult(task.TaskID)
	if err != nil || !bytes.Contains(artifact, []byte("logs collected on exit")) || !bytes.Contains(artifact, []byte("Scan cancelled")) {
		t.Fatalf("cancellation artifact = %s, error %v", artifact, err)
	}
}

func TestTaskCancellationCompletionRace(t *testing.T) {
	prepareTaskTest(t)
	for i := 0; i < 20; i++ {
		release, unblock := taskRelease(t)
		task, err := startTask("", "", func(context.Context, string) taskCompletion {
			<-release
			return taskCompletion{Status: StatusCompleted, Output: `{"finished":true}`}
		})
		if err != nil {
			t.Fatal(err)
		}
		gate := make(chan struct{})
		cancelResult := make(chan error, 1)
		go func() { <-gate; _, err := CancelTask(task.TaskID); cancelResult <- err }()
		go func() { <-gate; unblock() }()
		close(gate)
		cancelErr := <-cancelResult
		waitTaskWorkers(t)
		result, err := GetTask(task.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		if cancelErr == nil {
			if result.Status != StatusCancelled {
				t.Fatalf("accepted cancellation overwritten: %+v", result)
			}
		} else {
			requireTaskError(t, cancelErr, "task_not_running")
			if result.Status != StatusCompleted {
				t.Fatalf("rejected cancellation changed completion: %+v", result)
			}
		}
		if finishTask(context.Background(), task.TaskID, taskCompletion{Status: StatusFailed, Error: "late result"}) {
			t.Error("a second completion was accepted")
		}
		after, err := GetTask(task.TaskID)
		if err != nil || after.Status != result.Status || after.Error != result.Error || after.Output != result.Output {
			t.Fatalf("terminal result changed: before=%+v, after=%+v, error=%v", result, after, err)
		}
	}
}

func TestTaskExpiryAndActiveDirectory(t *testing.T) {
	prepareTaskTest(t)
	directory := t.TempDir()
	release, unblock := taskRelease(t)
	registered := make(chan struct{})
	task, err := startTask("expiry-key", "arguments", func(context.Context, string) taskCompletion {
		defer registerDirectory(directory)()
		close(registered)
		<-release
		return taskCompletion{Status: StatusCompleted, Output: `{}`}
	})
	if err != nil {
		t.Fatal(err)
	}
	awaitTaskSignal(t, registered)
	if !IsActiveDirectory(directory) {
		t.Fatal("worker directory is not marked active")
	}
	past := time.Now().Add(-time.Hour)
	taskMutex.Lock()
	taskStore[task.TaskID].meta.expiresAt = &past
	taskMutex.Unlock()
	if _, err := GetTask(task.TaskID); err != nil {
		t.Fatalf("active task expired: %v", err)
	}
	unblock()
	waitTaskWorkers(t)
	if IsActiveDirectory(directory) {
		t.Error("finished worker directory is still active")
	}
	result, err := GetTask(task.TaskID)
	if err != nil || result.CompletedAt == nil || result.ExpiresAt == nil {
		t.Fatalf("missing completion timestamps: %+v, error %v", result, err)
	}
	if got := result.ExpiresAt.Sub(*result.CompletedAt); got != 24*time.Hour {
		t.Errorf("retention = %v, want 24h", got)
	}
	taskMutex.Lock()
	artifactDir := taskStore[task.TaskID].meta.artifactDir
	taskStore[task.TaskID].meta.expiresAt = &past
	taskMutex.Unlock()
	_, err = GetTask(task.TaskID)
	requireTaskError(t, err, "task_not_found")
	if _, err := os.Stat(artifactDir); !os.IsNotExist(err) {
		t.Errorf("expired artifact directory remains: %v", err)
	}
	_, err = ReadTaskResult(task.TaskID)
	requireTaskError(t, err, "task_not_found")
	_, err = startTask("expiry-key", "new arguments", func(context.Context, string) taskCompletion {
		return taskCompletion{Status: StatusCompleted}
	})
	if err != nil {
		t.Fatalf("expired retry key was retained: %v", err)
	}
	waitTaskWorkers(t)
}

func TestTaskResultImmutableAndExactJSON(t *testing.T) {
	prepareTaskTest(t)
	const output = `{"IsVulnerable":"unknown","huge":9007199254740993123456789,"future":{"nested":[null,"雪",true]}}`
	task, err := startTask("", "", func(context.Context, string) taskCompletion {
		return taskCompletion{Status: StatusCompleted, Output: output, Logs: "retained logs", Cached: true}
	})
	if err != nil {
		t.Fatal(err)
	}
	waitTaskWorkers(t)
	result, err := GetTask(task.TaskID)
	if err != nil || !result.Cached || !result.ResultAvailable || result.CreatedAt.IsZero() || result.CompletedAt == nil || result.ExpiresAt == nil {
		t.Fatalf("snapshot = %+v, error %v", result, err)
	}
	completed := *result.CompletedAt
	*result.CompletedAt = time.Time{}
	*result.ExpiresAt = time.Time{}
	again, err := GetTask(task.TaskID)
	if err != nil || !again.CompletedAt.Equal(completed) {
		t.Fatalf("snapshot shared timestamp pointers: %+v, error %v", again, err)
	}
	artifact, err := ReadTaskResult(task.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(artifact, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["output"]) != output || string(fields["logs"]) != `"retained logs"` {
		t.Fatalf("artifact lost exact output: %s", artifact)
	}
	original := string(artifact)
	artifact[0] = '!'
	againArtifact, err := ReadTaskResult(task.TaskID)
	if err != nil || string(againArtifact) != original {
		t.Fatalf("read mutated stored artifact: %s, error %v", againArtifact, err)
	}
}

func TestShutdownTasksWaitsAndRejectsSubmissions(t *testing.T) {
	prepareTaskTest(t)
	release, unblock := taskRelease(t)
	cancelled := make(chan struct{})
	task, err := startTask("", "", func(ctx context.Context, _ string) taskCompletion {
		<-ctx.Done()
		close(cancelled)
		<-release
		return taskCompletion{Status: StatusCompleted, Logs: "shutdown logs"}
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ShutdownTasks(ctx) }()
	awaitTaskSignal(t, cancelled)
	_, err = startTask("new-during-shutdown", "", func(context.Context, string) taskCompletion {
		t.Error("shutdown accepted a new worker")
		return taskCompletion{Status: StatusCompleted}
	})
	requireTaskError(t, err, "server_stopping")
	select {
	case err := <-done:
		t.Fatalf("shutdown returned before worker exit: %v", err)
	default:
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	result, err := GetTask(task.TaskID)
	if err != nil || result.Status != StatusCancelled || result.Logs != "shutdown logs" {
		t.Fatalf("shutdown result = %+v, error %v", result, err)
	}
}

func TestTaskConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, timeout, ttl, publicURL string
		invalid                       bool
	}{
		{name: "defaults"},
		{name: "custom", timeout: "2m", ttl: "3h", publicURL: "https://gvs.example.com/gvs"},
		{name: "invalid timeout", timeout: "later", invalid: true},
		{name: "zero timeout", timeout: "0s", invalid: true},
		{name: "negative ttl", ttl: "-1h", invalid: true},
		{name: "invalid ttl", ttl: "tomorrow", invalid: true},
		{name: "relative URL", publicURL: "/gvs", invalid: true},
		{name: "unsupported URL", publicURL: "ftp://example.com", invalid: true},
		{name: "credentials", publicURL: "https://user:password@example.com", invalid: true},
		{name: "query", publicURL: "https://example.com?secret=1", invalid: true},
		{name: "fragment", publicURL: "https://example.com/#fragment", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GVS_SCAN_TIMEOUT", tc.timeout)
			t.Setenv("GVS_TASK_TTL", tc.ttl)
			t.Setenv("GVS_PUBLIC_URL", tc.publicURL)
			if err := ValidateTaskConfiguration(); (err != nil) != tc.invalid {
				t.Errorf("configuration error = %v, invalid = %v", err, tc.invalid)
			}
			if tc.name == "defaults" {
				timeout, ttl, err := taskDurations()
				if err != nil || timeout != 30*time.Minute || ttl != 24*time.Hour {
					t.Errorf("defaults = %v, %v, %v", timeout, ttl, err)
				}
			}
		})
	}
}

func TestPublicBaseURL(t *testing.T) {
	for _, tc := range []struct{ target, forwarded, configured, want string }{
		{"http://internal:8082/status", "", "", "http://internal:8082"},
		{"https://internal:8082/status", "", "", "https://internal:8082"},
		{"http://internal:8082/status", "https", "", "https://internal:8082"},
		{"http://internal:8082/status", "untrusted", "", "http://internal:8082"},
		{"http://internal:8082/status", "http", "https://gvs.example.com/base/", "https://gvs.example.com/base"},
	} {
		t.Run(fmt.Sprintf("%s_%s_%s", tc.target, tc.forwarded, tc.configured), func(t *testing.T) {
			t.Setenv("GVS_PUBLIC_URL", tc.configured)
			req := httptest.NewRequest("POST", tc.target, nil)
			req.Header.Set("X-Forwarded-Proto", tc.forwarded)
			if got := PublicBaseURL(req); got != tc.want {
				t.Errorf("PublicBaseURL = %q, want %q", got, tc.want)
			}
		})
	}
}
