package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/k37y/gvs/internal/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestTaskStatesAndToolErrors(t *testing.T) {
	for _, status := range []api.TaskStatus{api.StatusPending, api.StatusRunning, api.StatusCompleted, api.StatusFailed, api.StatusCancelled} {
		t.Run(string(status), func(t *testing.T) {
			now := time.Now().UTC()
			b := &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: status, CreatedAt: now, UpdatedAt: now}}
			if !active(status) {
				b.task.ResultAvailable = true
				b.task.Output = "not JSON\n"
				b.task.Logs = "complete logs"
				b.task.Error = "execution error"
				b.task.CompletedAt = &now
				b.task.ExpiresAt = &now
				b.artifact = []byte(`{"output":"not JSON\n","logs":"complete logs","error":"execution error"}`)
			}
			s, _ := connectClient(t, b)
			result := callTool(t, s, "gvs_status", taskInput{TaskID: "task-1"})
			if result.IsError {
				t.Fatalf("known task returned tool error: %+v", result.Content)
			}
			out := decodedResult(t, result)
			_, polls := out["pollAfterSeconds"]
			if polls != active(status) {
				t.Errorf("polling guidance for %s = %t", status, polls)
			}
			if _, ok := out["summary"]; ok {
				t.Fatal("summary generated without a result object")
			}
			if !active(status) && string(out["output"]) != `"not JSON\n"` {
				t.Fatalf("non-JSON output = %s", out["output"])
			}
			validateSchema(t, outputSchema("status"), result)
			cancelled := callTool(t, s, "gvs_cancel", taskInput{TaskID: "task-1"})
			validateSchema(t, outputSchema("submission"), cancelled)
		})
	}
	for _, code := range []string{"scan_busy", "task_not_found", "task_not_ready", "task_not_running", "request_id_conflict", "server_stopping", "result_unavailable"} {
		t.Run(code, func(t *testing.T) {
			b := &fakeBackend{err: &api.TaskError{Code: code, Message: "test error"}}
			s, _ := connectClient(t, b)
			result := callTool(t, s, "gvs_status", taskInput{TaskID: "task-1"})
			if !result.IsError {
				t.Fatal("backend error was not a tool error")
			}
			var out struct {
				Error struct {
					Code      string
					Retryable bool
				}
			}
			json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &out)
			if out.Error.Code != code {
				t.Fatalf("error = %+v", out)
			}
			if out.Error.Retryable != (code == "scan_busy" || code == "task_not_ready" || code == "server_stopping") {
				t.Fatalf("retryability = %+v", out)
			}
			validateSchema(t, outputSchema("status"), result)
		})
	}
}

func validateSchema(t *testing.T, schema any, result *sdk.CallToolResult) {
	t.Helper()
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	var parsed jsonschema.Schema
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	resolved, err := parsed.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	var content any
	if err := json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &content); err != nil {
		t.Fatal(err)
	}
	if err := resolved.Validate(content); err != nil {
		t.Fatalf("result does not match output schema: %v", err)
	}
}

func TestExpiredAndChangedResultCursors(t *testing.T) {
	b := &fakeBackend{artifact: []byte(strings.Repeat("x", maxChunkBytes+100))}
	a := &adapter{backend: b, cursorKey: [32]byte{1}}
	first, err := a.readResult("task-1", "")
	if err != nil {
		t.Fatal(err)
	}
	var chunk ResultChunk
	json.Unmarshal([]byte(first.Content[0].(*sdk.TextContent).Text), &chunk)
	if chunk.NextCursor == nil {
		t.Fatal("expected cursor")
	}
	cursor := *chunk.NextCursor
	b.artifact = append(b.artifact, 'x')
	if _, err := a.readResult("task-1", cursor); err == nil {
		t.Fatal("accepted changed artifact")
	}
	b.err = &api.TaskError{Code: "task_not_found", Message: "Task not found"}
	if _, err := a.readResult("task-1", cursor); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired error = %v", err)
	}
	b.err = nil
	b.artifact = []byte(strings.Repeat("x", maxChunkBytes+100))
	other := &adapter{backend: b, cursorKey: [32]byte{2}}
	if _, err := other.readResult("task-1", cursor); err == nil {
		t.Fatal("cursor survived server restart")
	}
}

func TestResultLimitCountsBothRepresentations(t *testing.T) {
	for _, characters := range []string{"x", "界", "\x00", "\\\"<&"} {
		b := &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: api.StatusCompleted, ResultAvailable: true}}
		a := &adapter{backend: b}
		for _, n := range []int{0, 100, 4000, 12000, 32768, 65536} {
			b.task.Output = string(mustJSON(t, map[string]any{"IsVulnerable": "true", "evidence": strings.Repeat(characters, n)}))
			b.artifact = mustJSON(t, map[string]any{"output": json.RawMessage(b.task.Output)})
			result, err := a.statusResult(b.task)
			if err != nil {
				t.Fatal(err)
			}
			if !fitsResult(result) {
				t.Fatalf("status exceeds limit for %q * %d", characters, n)
			}
			var out StatusResult
			json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &out)
			if out.Result.Inline && len(out.Output) == 0 {
				t.Fatal("inlined result omitted output")
			}
			if !out.Result.Inline && len(out.Output) != 0 {
				t.Fatal("external result retained output")
			}
			validateSchema(t, outputSchema("status"), result)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestClientReconnectsToSameTask(t *testing.T) {
	b := &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: api.StatusRunning}}
	first, url := connectClient(t, b)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "reconnected", Version: "1"}, nil)
	second, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: url, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	result := callTool(t, second, "gvs_status", taskInput{TaskID: "task-1"})
	out := decodedResult(t, result)
	if string(out["taskId"]) != `"task-1"` || string(out["status"]) != `"running"` {
		t.Fatalf("reconnected result = %v", out)
	}
}

func TestOversizedToolErrorsOverHTTP(t *testing.T) {
	large := strings.Repeat("x", maxResultBytes+100)
	for _, tc := range []struct {
		name       string
		args       map[string]any
		backendErr error
	}{
		{name: "invalid field value", args: map[string]any{"repo": "https://example.com/repo", "branch": "main", "cve": "CVE-2026-33186", "algo": large}},
		{name: "unknown field name", args: map[string]any{"repo": "https://example.com/repo", "branch": "main", "cve": "CVE-2026-33186", "algo": "rta", large: "value"}},
		{name: "backend error", args: map[string]any{"repo": "https://example.com/repo", "branch": "main", "cve": "CVE-2026-33186", "algo": "rta"}, backendErr: &api.TaskError{Code: "test_error", Message: large}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBackend{err: tc.backendErr}
			s, _ := connectClient(t, b)
			result := callTool(t, s, "gvs_scan", tc.args)
			if !result.IsError || !fitsResult(result) {
				t.Fatalf("unbounded/non-error result: isError=%v", result.IsError)
			}
			data := decodedResult(t, result)
			var diagnostic struct {
				Code, Message string
				Retryable     bool
			}
			if err := json.Unmarshal(data["error"], &diagnostic); err != nil {
				t.Fatal(err)
			}
			if diagnostic.Code != "error_too_large" || diagnostic.Retryable || !strings.Contains(diagnostic.Message, "original diagnostic was not included") {
				t.Fatalf("diagnostic = %+v", diagnostic)
			}
			if strings.Contains(result.Content[0].(*sdk.TextContent).Text, large) {
				t.Fatal("oversized original diagnostic was echoed")
			}
			validateSchema(t, outputSchema("submission"), result)
			if tc.backendErr == nil && b.starts != 0 {
				t.Fatal("invalid schema reached backend")
			}
		})
	}
	if result := errorResult(&api.TaskError{Code: "test_error", Message: large}); !fitsResult(result) {
		t.Fatal("direct backend error exceeded response limit")
	}
}
