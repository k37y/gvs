package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/k37y/gvs/internal/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeBackend struct {
	mu       sync.Mutex
	task     api.TaskSnapshot
	request  api.CallgraphRequest
	baseURL  string
	artifact []byte
	err      error
	starts   int
}

func (b *fakeBackend) StartCallgraph(req api.CallgraphRequest, baseURL string) (api.TaskSnapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.request, b.baseURL = req, baseURL
	b.starts++
	return b.task, b.err
}
func (b *fakeBackend) GetTask(string) (api.TaskSnapshot, error)    { return b.task, b.err }
func (b *fakeBackend) CancelTask(string) (api.TaskSnapshot, error) { return b.task, b.err }
func (b *fakeBackend) ReadTaskResult(string) ([]byte, error)       { return b.artifact, b.err }

func connectClient(t *testing.T, backend *fakeBackend) (*sdk.ClientSession, string) {
	t.Helper()
	h, err := NewHandler("test", backend, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: s.URL, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session, s.URL
}

func callTool(t *testing.T, session *sdk.ClientSession, name string, args any) *sdk.CallToolResult {
	t.Helper()
	result, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodedResult(t *testing.T, result *sdk.CallToolResult) map[string]json.RawMessage {
	t.Helper()
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("content count = %d", len(result.Content))
	}
	text, ok := result.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("content = %T", result.Content[0])
	}
	var got, want any
	if err := json.Unmarshal([]byte(text.Text), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("text and structured content differ")
	}
	return out
}

func TestHTTPToolsAndSubmission(t *testing.T) {
	b := &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: api.StatusPending}}
	s, base := connectClient(t, b)
	listed, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"gvs_scan": {"repo", "branch", "cve", "algo"}, "gvs_manual_scan": {"repo", "branch", "library", "symbol", "fixedVersion", "algo"}, "gvs_status": {"taskId"}, "gvs_cancel": {"taskId"}, "gvs_read_result": {"taskId"}}
	if len(listed.Tools) != len(want) {
		t.Fatalf("tools = %d", len(listed.Tools))
	}
	for _, tool := range listed.Tools {
		required, ok := want[tool.Name]
		if !ok {
			t.Fatalf("unexpected tool %s", tool.Name)
		}
		data, _ := json.Marshal(tool.InputSchema)
		var schema struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(schema.Required, required) {
			t.Fatalf("%s required = %v", tool.Name, schema.Required)
		}
		if tool.OutputSchema == nil || tool.Annotations == nil {
			t.Fatalf("%s missing schema/annotations", tool.Name)
		}
	}
	for _, algo := range []string{"rta", "vta", "cha", "static"} {
		for _, manual := range []bool{false, true} {
			name := "gvs_scan"
			args := map[string]any{"repo": "https://github.com/openshift/cloud-network-config-controller", "branch": "release-4.20", "algo": algo, "requestId": "retry-key"}
			if manual {
				name = "gvs_manual_scan"
				args["library"] = "google.golang.org/grpc"
				args["symbol"] = "Server.Serve,Server.ServeHTTP"
				args["fixedVersion"] = "v1.79.3"
			} else {
				args["cve"] = "GO-2026-4762"
			}
			result := callTool(t, s, name, args)
			if result.IsError {
				t.Fatalf("submission: %+v", result.Content)
			}
			out := decodedResult(t, result)
			if string(out["pollAfterSeconds"]) != "5" || string(out["taskId"]) != `"task-1"` {
				t.Fatalf("result: %v", out)
			}
			b.mu.Lock()
			got, url := b.request, b.baseURL
			b.mu.Unlock()
			if got.Algo != algo || got.BranchOrCommit != "release-4.20" || got.RequestID != "retry-key" || url != base {
				t.Fatalf("forwarded = %+v, %s", got, url)
			}
			if manual && (got.FixVersion != "v1.79.3" || got.Symbol != "Server.Serve,Server.ServeHTTP" || got.CVE != "") {
				t.Fatalf("manual = %+v", got)
			}
		}
	}
}

func TestInvalidToolArguments(t *testing.T) {
	b := &fakeBackend{}
	s, _ := connectClient(t, b)
	for _, tc := range []struct {
		name    string
		changes map[string]any
		remove  string
	}{
		{"missing algo", nil, "algo"}, {"empty branch", map[string]any{"branch": "  "}, ""}, {"local repo", map[string]any{"repo": "/tmp/repo"}, ""}, {"file repo", map[string]any{"repo": "file:///tmp/repo"}, ""}, {"bad algorithm", map[string]any{"algo": "bogus"}, ""}, {"bad vulnerability", map[string]any{"cve": "CVE-no"}, ""}, {"long retry key", map[string]any{"requestId": strings.Repeat("x", 129)}, ""}, {"extra field", map[string]any{"unexpected": true}, ""}, {"wrong type", map[string]any{"branch": true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{"repo": "https://example.com/repo", "branch": "main", "cve": "CVE-2026-33186", "algo": "rta"}
			for k, v := range tc.changes {
				args[k] = v
			}
			delete(args, tc.remove)
			if result := callTool(t, s, "gvs_scan", args); !result.IsError {
				t.Fatalf("accepted %v", args)
			}
		})
	}
	if b.starts != 0 {
		t.Fatalf("invalid input started %d tasks", b.starts)
	}
}

func TestStatusSummaryAndPreservation(t *testing.T) {
	data, err := os.ReadFile("testdata/status-output.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture := strings.TrimSuffix(strings.TrimSpace(string(data)), "}") + `,"future":{"integer":9007199254740993},"reflection_risks":[{"association":"unresolved"}]}`
	artifact := []byte(`{"output":` + fixture + `,"logs":"complete logs"}`)
	now := time.Now().UTC()
	b := &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: api.StatusCompleted, Output: fixture, Logs: "complete logs", CreatedAt: now, UpdatedAt: now, CompletedAt: &now, ExpiresAt: &now, Cached: true, ResultAvailable: true}, artifact: artifact}
	s, _ := connectClient(t, b)
	result := callTool(t, s, "gvs_status", map[string]any{"taskId": "task-1"})
	if result.IsError {
		t.Fatalf("status failed: %+v", result)
	}
	// The SDK client's StructuredContent uses floating point numbers, so inspect
	// the JSON text fallback to verify exact large integer delivery over HTTP.
	text := result.Content[0].(*sdk.TextContent).Text
	if !strings.Contains(text, "9007199254740993") {
		t.Fatal("large integer changed")
	}
	var out struct {
		Summary          Summary
		Output           json.RawMessage
		Cached           bool
		PollAfterSeconds *int
		Result           ResultDelivery
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	want := `{"scannerVerdict":"true","aiVerdict":"false","aiConfidence":"high","verdictsDisagree":true}`
	got, _ := json.Marshal(out.Summary)
	if string(got) != want {
		t.Fatalf("summary = %s", got)
	}
	canonical, err := json.Marshal(json.RawMessage(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Output, canonical) || !out.Cached || out.PollAfterSeconds != nil || !out.Result.Inline {
		t.Fatalf("status = %s", text)
	}
}

func TestSummaryVariants(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`{"IsVulnerable":"true"}`, `{"scannerVerdict":"true","aiVerdict":null,"aiConfidence":null,"verdictsDisagree":null}`},
		{`{"IsVulnerable":"unknown","AIVerification":{"IsVulnerable":"false","confidence":"low"}}`, `{"scannerVerdict":"unknown","aiVerdict":"false","aiConfidence":"low","verdictsDisagree":null}`},
		{`{"IsVulnerable":"false","AIVerification":{"IsVulnerable":"false","confidence":"medium"}}`, `{"scannerVerdict":"false","aiVerdict":"false","aiConfidence":"medium","verdictsDisagree":false}`},
		{`{"IsVulnerable":"false","AIVerification":{"IsVulnerable":"true","confidence":"high"}}`, `{"scannerVerdict":"false","aiVerdict":"true","aiConfidence":"high","verdictsDisagree":true}`},
		{`{"IsVulnerable":true,"AIVerification":{"IsVulnerable":"n/a","confidence":"certain"}}`, `{"scannerVerdict":null,"aiVerdict":null,"aiConfidence":null,"verdictsDisagree":null}`},
		{`not json`, `null`}, {`null`, `null`}, {`[]`, `null`}, {`{}`, `null`}, {`{"runs":[]}`, `null`},
	} {
		got, _ := json.Marshal(summarize(tc.input))
		if string(got) != tc.want {
			t.Errorf("summarize(%s) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestLargeResultChunks(t *testing.T) {
	output := `{"IsVulnerable":"true","evidence":"` + strings.Repeat("界<&\\\"", 18000) + `"}`
	artifact, err := json.Marshal(map[string]string{"output": output, "logs": strings.Repeat("log\n", 2000)})
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: api.StatusCompleted, Output: output, Logs: "logs", ResultAvailable: true}, artifact: artifact}
	s, _ := connectClient(t, b)
	status := decodedResult(t, callTool(t, s, "gvs_status", map[string]any{"taskId": "task-1"}))
	if _, ok := status["output"]; ok {
		t.Fatal("large output was inlined")
	}
	var delivery ResultDelivery
	json.Unmarshal(status["result"], &delivery)
	if delivery.Inline || !delivery.Available || len(delivery.ExternalFields) == 0 {
		t.Fatalf("delivery = %+v", delivery)
	}
	var reconstructed strings.Builder
	cursor, firstCursor := "", ""
	for n := 0; n < 1000; n++ {
		result := callTool(t, s, "gvs_read_result", map[string]any{"taskId": "task-1", "cursor": cursor})
		if result.IsError {
			t.Fatalf("read failed: %+v", result.Content)
		}
		data, _ := json.Marshal(result)
		if len(data) > maxResultBytes {
			t.Fatalf("response = %d bytes", len(data))
		}
		var chunk ResultChunk
		json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &chunk)
		if !utf8.ValidString(chunk.Content) || len(chunk.Content) > maxChunkBytes {
			t.Fatal("invalid UTF-8 chunk or chunk size")
		}
		reconstructed.WriteString(chunk.Content)
		if chunk.EOF {
			break
		}
		if chunk.NextCursor == nil || *chunk.NextCursor == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = *chunk.NextCursor
		if firstCursor == "" {
			firstCursor = cursor
		}
	}
	if reconstructed.String() != string(artifact) {
		t.Fatal("artifact reconstruction differs")
	}
	first := callTool(t, s, "gvs_read_result", map[string]any{"taskId": "task-1", "cursor": firstCursor})
	second := callTool(t, s, "gvs_read_result", map[string]any{"taskId": "task-1", "cursor": firstCursor})
	if !reflect.DeepEqual(first, second) {
		t.Fatal("cursor replay differs")
	}
	for _, args := range []map[string]any{{"taskId": "other", "cursor": firstCursor}, {"taskId": "task-1", "cursor": firstCursor + "x"}, {"taskId": "task-1", "cursor": "bogus"}} {
		if !callTool(t, s, "gvs_read_result", args).IsError {
			t.Fatalf("accepted invalid cursor %v", args)
		}
	}
}

func TestOrigins(t *testing.T) {
	for _, origin := range []string{"*", "https://*.example.com", "null", "https://example.com/path", "https://user@example.com", "https://example.com?x=y", "https://example.com:bad"} {
		if _, err := NewHandler("test", &fakeBackend{}, []string{origin}, ""); err == nil {
			t.Errorf("accepted configured origin %q", origin)
		}
	}
	h, err := NewHandler("test", &fakeBackend{}, []string{"https://client.example"}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		origin, method string
		want           int
	}{{"https://client.example", "OPTIONS", 204}, {"https://other.example", "OPTIONS", 403}, {"null", "POST", 403}, {"https://client.example/path", "POST", 403}, {"", "OPTIONS", 204}} {
		t.Run(fmt.Sprintf("%s_%s", tc.method, tc.origin), func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://localhost/mcp", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			r.Header.Set("Access-Control-Request-Method", "POST")
			r.Header.Set("Access-Control-Request-Headers", "content-type,mcp-protocol-version,mcp-session-id")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, body = %s", w.Code, w.Body)
			}
			if tc.want == 204 && tc.origin != "" && w.Header().Get("Access-Control-Allow-Origin") != tc.origin {
				t.Fatal("missing CORS allow origin")
			}
		})
	}
}

func TestProtocolAndPublicURL(t *testing.T) {
	b := &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: api.StatusPending}}
	h, err := NewHandler("test", b, []string{"https://client.example"}, "https://public.example/gvs/")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, body string
		want               int
	}{
		{"initialize", "POST", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, 200},
		{"unknown tool", "POST", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"missing","arguments":{}}}`, 200},
		{"scan", "POST", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gvs_scan","arguments":{"repo":"https://example.com/repo","branch":"main","cve":"CVE-2026-33186","algo":"cha"}}}`, 200},
		{"get", "GET", "", 405}, {"delete", "DELETE", "", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "https://internal.example/mcp", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
			r.Header.Set("Origin", "https://client.example")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, body = %s", w.Code, w.Body)
			}
			if w.Header().Get("Mcp-Session-Id") != "" {
				t.Fatal("stateless endpoint issued a session")
			}
			if tc.want == http.StatusOK && !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("response type = %s", w.Header().Get("Content-Type"))
			}
			if tc.name == "unknown tool" && !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatal("unknown tool did not produce a protocol error")
			}
			if tc.name == "scan" && b.baseURL != "https://public.example/gvs" {
				t.Fatalf("public URL = %s", b.baseURL)
			}
		})
	}
	for _, origin := range []string{"", "https://client.example,https://other.example"} {
		r := httptest.NewRequest("POST", "http://localhost/mcp", nil)
		r.Header["Origin"] = []string{origin}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("accepted malformed Origin %q", origin)
		}
	}
}

func TestToolLogUsesConnectionIP(t *testing.T) {
	h, err := NewHandler("test", &fakeBackend{task: api.TaskSnapshot{TaskID: "task-1", Status: api.StatusRunning}}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ remote, ip string }{
		{"192.0.2.10:54321", "192.0.2.10"},
		{"[2001:db8::10]:54321", "2001:db8::10"},
	} {
		t.Run(tc.remote, func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(previous)
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gvs_status","arguments":{"taskId":"task-1"}}}`))
			req.RemoteAddr = tc.remote
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
			req.Header.Set("X-Forwarded-For", "203.0.113.99")
			req.Header.Set("X-Real-IP", "203.0.113.99")
			req.Header.Set("Forwarded", "for=203.0.113.99")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"structuredContent"`) {
				t.Fatalf("tool response: %d %s", rec.Code, rec.Body)
			}
			if !strings.Contains(logs.String(), `[MCP] remote_ip="`+tc.ip+`" tool="gvs_status" failed=false`) {
				t.Fatalf("missing connection IP: %s", &logs)
			}
			for _, excluded := range []string{"203.0.113.99", ":54321"} {
				if strings.Contains(logs.String(), excluded) {
					t.Fatalf("unexpected %q in request log: %s", excluded, &logs)
				}
			}
		})
	}
}

func TestHTTPRequestBodyLimit(t *testing.T) {
	b := &fakeBackend{}
	h, err := NewHandler("test", b, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gvs_scan","arguments":{"repo":"https://example.com/repo","branch":"` + strings.Repeat("x", maxRequestBytes) + `","cve":"CVE-2026-33186","algo":"rta"}}}`
	for _, unknownLength := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(body))
		if unknownLength {
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("unknownLength=%v: status=%d body=%s", unknownLength, w.Code, w.Body.String())
		}
	}
	if b.starts != 0 {
		t.Fatal("oversized request reached backend")
	}
}
