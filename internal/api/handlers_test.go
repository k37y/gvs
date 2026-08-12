package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConvertGraphPathsToURLs(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]interface{}
		baseURL string
		check   func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "converts graph paths to URLs",
			input: map[string]interface{}{
				"IsVulnerable": "true",
				"GraphPaths":   []interface{}{"/tmp/gvs-cache/graph/CVE-2024-1234/repo/main/rta/lib-sym.svg"},
			},
			baseURL: "http://localhost:8082",
			check: func(t *testing.T, result map[string]interface{}) {
				paths, ok := result["GraphPaths"].([]interface{})
				if !ok {
					t.Fatal("GraphPaths not found or wrong type")
				}
				if len(paths) != 1 {
					t.Fatalf("expected 1 path, got %d", len(paths))
				}
				got := paths[0].(string)
				want := "http://localhost:8082/graph/CVE-2024-1234/repo/main/rta/lib-sym.svg"
				if got != want {
					t.Errorf("got %q, want %q", got, want)
				}
			},
		},
		{
			name: "no graph paths, returns unchanged",
			input: map[string]interface{}{
				"IsVulnerable": "false",
			},
			baseURL: "http://localhost:8082",
			check: func(t *testing.T, result map[string]interface{}) {
				if _, ok := result["GraphPaths"]; ok {
					t.Error("GraphPaths should not exist")
				}
			},
		},
		{
			name: "empty graph paths array",
			input: map[string]interface{}{
				"IsVulnerable": "false",
				"GraphPaths":   []interface{}{},
			},
			baseURL: "http://localhost:8082",
			check: func(t *testing.T, result map[string]interface{}) {
				// Should return unchanged since empty
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJSON, _ := json.Marshal(tt.input)
			output := convertGraphPathsToURLs(inputJSON, tt.baseURL)

			var result map[string]interface{}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("failed to unmarshal output: %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestConvertGraphPathsToURLs_InvalidJSON(t *testing.T) {
	input := []byte("not json")
	output := convertGraphPathsToURLs(input, "http://localhost:8082")
	if string(output) != "not json" {
		t.Errorf("expected unchanged input for invalid JSON")
	}
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	HealthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "OK" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "OK")
	}
}

func TestWriteJSONError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONError(rec, http.StatusBadRequest, "bad input")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if body["error"] != "bad input" {
		t.Errorf("error = %q, want %q", body["error"], "bad input")
	}
}

func TestStatusHandler_MissingTaskID(t *testing.T) {
	req := httptest.NewRequest("POST", "/status", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	StatusHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestStatusHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/status", strings.NewReader("not json"))
	rec := httptest.NewRecorder()

	StatusHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestStatusHandler_UnknownTask(t *testing.T) {
	req := httptest.NewRequest("POST", "/status", strings.NewReader(`{"taskId":"unknown-123"}`))
	rec := httptest.NewRecorder()

	StatusHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestStatusHandler_KnownTask(t *testing.T) {
	taskMutex.Lock()
	taskStore["test-task-1"] = &TaskResult{
		Status: StatusCompleted,
		Output: `{"IsVulnerable":"true"}`,
	}
	taskMutex.Unlock()
	defer func() {
		taskMutex.Lock()
		delete(taskStore, "test-task-1")
		taskMutex.Unlock()
	}()

	req := httptest.NewRequest("POST", "/status", strings.NewReader(`{"taskId":"test-task-1"}`))
	rec := httptest.NewRecorder()

	StatusHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if body["status"] != string(StatusCompleted) {
		t.Errorf("status = %v, want %v", body["status"], StatusCompleted)
	}
	if body["output"] == nil {
		t.Error("expected output in response")
	}
}

func TestScanHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/scan", strings.NewReader("not json"))
	rec := httptest.NewRecorder()

	ScanHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCallgraphHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/callgraph", strings.NewReader("not json"))
	rec := httptest.NewRecorder()

	CallgraphHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestProgressHandler_MissingTaskID(t *testing.T) {
	req := httptest.NewRequest("GET", "/progress/", nil)
	rec := httptest.NewRecorder()

	ProgressHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestProgressHandler_NotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "/progress/nonexistent-task", nil)
	rec := httptest.NewRecorder()

	ProgressHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetGraphCacheDir_Env(t *testing.T) {
	t.Setenv("GVS_GRAPH_CACHE", "/custom/graph")
	got := getGraphCacheDir()
	if got != "/custom/graph" {
		t.Errorf("getGraphCacheDir() = %q, want /custom/graph", got)
	}
}

func TestGetGraphCacheDir_Default(t *testing.T) {
	t.Setenv("GVS_GRAPH_CACHE", "")
	got := getGraphCacheDir()
	if got != "/tmp/gvs-cache/graph" {
		t.Errorf("getGraphCacheDir() = %q, want /tmp/gvs-cache/graph", got)
	}
}

func TestProgressHandler_Stream(t *testing.T) {
	taskID := "test-progress-stream"
	ch := make(chan string, 2)
	ch <- "step 1"
	ch <- "step 2"
	close(ch)

	progressMutex.Lock()
	progressStreams[taskID] = ch
	progressMutex.Unlock()
	defer func() {
		progressMutex.Lock()
		delete(progressStreams, taskID)
		progressMutex.Unlock()
	}()

	req := httptest.NewRequest("GET", "/progress/"+taskID, nil)
	rec := httptest.NewRecorder()

	ProgressHandler(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "data: step 1") {
		t.Errorf("expected 'data: step 1' in body, got: %s", body)
	}
	if !strings.Contains(body, "data: step 2") {
		t.Errorf("expected 'data: step 2' in body, got: %s", body)
	}
}
