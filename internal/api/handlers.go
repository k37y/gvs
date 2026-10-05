package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/k37y/gvs/pkg/cmd/gvc"
)

var (
	requestMutex    sync.Mutex
	inProgress      bool
	taskStore       = make(map[string]*TaskResult)
	taskMutex       sync.Mutex
	progressStreams = make(map[string]chan string)
	progressMutex   sync.Mutex
	taskCancels     = make(map[string]context.CancelFunc)
	taskCancelMutex sync.Mutex
	counterURL      = os.Getenv("GVS_COUNTER_URL")
)

// getGraphCacheDir returns the graph cache directory from environment or default
func getGraphCacheDir() string {
	if dir := os.Getenv("GVS_GRAPH_CACHE"); dir != "" {
		return dir
	}
	// Fallback for container/legacy deployments
	return "/tmp/gvs-cache/graph"
}

func trackAPICall() {
	if counterURL != "" {
		go func() {
			if resp, err := http.Get(counterURL); err == nil {
				resp.Body.Close()
			}
		}()
	}
}

type TaskStatus string

const (
	StatusPending   TaskStatus = "pending"
	StatusRunning   TaskStatus = "running"
	StatusCompleted TaskStatus = "completed"
	StatusFailed    TaskStatus = "failed"
	StatusCancelled TaskStatus = "cancelled"
)

type TaskResult struct {
	Status TaskStatus `json:"status"`
	Output string     `json:"output,omitempty"`
	Error  string     `json:"error,omitempty"`
	Logs   string     `json:"logs,omitempty"`
	meta   taskMetadata
}

// LogRequests leaves the response writer intact so progress streaming still works.
func LogRequests(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		defer func() {
			log.Printf("[API] remote_ip=%.128q method=%.16q path=%.256q duration=%s", RemoteIP(r), r.Method, r.URL.Path, time.Since(started))
		}()
		next(w, r)
	}
}

// RemoteIP identifies the connected peer; forwarded headers are not trusted.
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	trackAPICall()
	var req gvc.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	clientIP := r.RemoteAddr
	task, err := startTask("", "", func(ctx context.Context, id string) taskCompletion {
		return runRepositoryScan(ctx, id, req, clientIP)
	})
	if err != nil {
		writeTaskError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"taskId": task.TaskID}); err != nil {
		log.Printf("[API] write task response: %v", err)
	}
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("[API] failed to write response: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		log.Printf("[API] failed to write JSON response: %v", err)
	}
}

func CallgraphHandler(w http.ResponseWriter, r *http.Request) {
	trackAPICall()
	var req CallgraphRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	task, err := StartCallgraph(req, PublicBaseURL(r))
	if err != nil {
		writeTaskError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"taskId": task.TaskID}); err != nil {
		log.Printf("[API] write task response: %v", err)
	}
}

func writeTaskError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if taskErr, ok := err.(*TaskError); ok {
		switch taskErr.Code {
		case "invalid_argument", "task_not_running":
			status = http.StatusBadRequest
		case "task_not_found":
			status = http.StatusNotFound
		case "scan_busy":
			status = http.StatusTooManyRequests
		case "request_id_conflict":
			status = http.StatusConflict
		case "server_stopping":
			status = http.StatusServiceUnavailable
		}
	}
	writeJSONError(w, status, err.Error())
}

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskID string `json:"taskId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == "" {
		writeJSONError(w, http.StatusBadRequest, "Invalid or missing taskId")
		return
	}

	result, err := GetTask(req.TaskID)
	if err != nil {
		writeTaskError(w, err)
		return
	}
	resp := taskResultFields(&TaskResult{Output: result.Output, Error: result.Error, Logs: result.Logs})
	resp["status"] = result.Status

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[API] failed to write status response: %v", err)
	}
}

func ProgressHandler(w http.ResponseWriter, r *http.Request) {
	// Extract taskId from URL path
	taskId := strings.TrimPrefix(r.URL.Path, "/progress/")
	if taskId == "" {
		http.Error(w, "Missing task ID", http.StatusBadRequest)
		return
	}

	// Check if progress stream exists
	progressMutex.Lock()
	progressChan, exists := progressStreams[taskId]
	progressMutex.Unlock()

	if !exists {
		http.Error(w, "Progress stream not found", http.StatusNotFound)
		return
	}

	// Set headers for Server-Sent Events
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create a flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Stream progress messages
	for {
		select {
		case message, ok := <-progressChan:
			if !ok {
				// Channel closed, end stream silently
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", message)
			flusher.Flush()
		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

// Paths are expected to be like: {graphCacheDir}/CVE-XXXX/repo/branch/algo/library-symbol.svg
// Converts to: http://host:port/graph/CVE-XXXX/repo/branch/algo/library-symbol.svg
func convertGraphPathsToURLs(jsonOutput []byte, baseURL string) []byte {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(jsonOutput, &result); err != nil {
		log.Printf("Failed to parse JSON for graph path conversion: %v", err)
		return jsonOutput
	}

	// Check if GraphPaths field exists
	var graphPaths []string
	if err := json.Unmarshal(result["GraphPaths"], &graphPaths); err != nil || len(graphPaths) == 0 {
		return jsonOutput
	}

	// Convert file paths to full URLs
	// Extract the path relative to graph cache dir and prefix with baseURL/graph/
	webPaths := make([]string, 0, len(graphPaths))
	cacheDir := getGraphCacheDir() + "/"
	for _, pathStr := range graphPaths {
		var relativePath string
		if strings.HasPrefix(pathStr, cacheDir) {
			relativePath = strings.TrimPrefix(pathStr, cacheDir)
		} else if parsed, err := url.Parse(pathStr); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			_, suffix, found := strings.Cut(parsed.EscapedPath(), "/graph/")
			if found {
				relativePath = suffix
			}
		} else {
			relativePath = filepath.Base(pathStr)
		}
		if relativePath == "" {
			webPaths = append(webPaths, pathStr)
		} else {
			webPaths = append(webPaths, strings.TrimRight(baseURL, "/")+"/graph/"+relativePath)
		}
	}
	result["GraphPaths"], _ = json.Marshal(webPaths)

	// Re-encode to JSON
	modifiedJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("Failed to re-encode JSON after graph path conversion: %v", err)
		return jsonOutput
	}

	return modifiedJSON
}

func CancelHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskID string `json:"taskId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == "" {
		writeJSONError(w, http.StatusBadRequest, "Invalid or missing taskId")
		return
	}

	if _, err := CancelTask(req.TaskID); err != nil {
		writeTaskError(w, err)
		return
	}
	// Keep the REST acknowledgement shape; the worker publishes terminal status after exit.

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"}); err != nil {
		log.Printf("[API] failed to write cancel response: %v", err)
	}
}
