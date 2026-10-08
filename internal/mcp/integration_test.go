//go:build integration

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/k37y/gvs/internal/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exercise real task storage, cache, worker cancellation, graph URL conversion,
// and both transports without live AI or external repository/advisory requests.
func TestMCPTasksIntegration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_AI", "0")
	t.Setenv("GVS_SCAN_TIMEOUT", "20s")
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("GVS_PUBLIC_URL", "")
	h, err := NewHandler("integration", api.DefaultTaskBackend{}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	mux.HandleFunc("/callgraph", api.CallgraphHandler)
	mux.HandleFunc("/status", api.StatusHandler)
	mux.HandleFunc("/cancel", api.CancelHandler)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := sdk.NewClient(&sdk.Implementation{Name: "integration", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: server.URL + "/mcp", DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	for _, algo := range []string{"rta", "vta", "cha", "static"} {
		for _, manual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/manual=%t", algo, manual), func(t *testing.T) {
				repo := fmt.Sprintf("https://fixture.invalid/gvs-%d", time.Now().UnixNano())
				request := api.CallgraphRequest{Repo: repo, BranchOrCommit: "fixture", Algo: algo}
				name := "gvs_scan"
				args := map[string]any{"repo": repo, "branch": "fixture", "algo": algo, "requestId": repo}
				if manual {
					name = "gvs_manual_scan"
					request.Library, request.Symbol, request.FixVersion = "example.com/lib", "Call,Other", "v1.2.3"
					args["library"], args["symbol"], args["fixedVersion"] = request.Library, request.Symbol, request.FixVersion
				} else {
					request.CVE = "GO-2026-4762"
					args["cve"] = request.CVE
				}
				fixture := map[string]any{"IsVulnerable": "true", "AIVerification": map[string]any{"IsVulnerable": "false", "confidence": "high", "evidence": []string{"pkg/signals/signals.go:32: cancel()"}, "usage": map[string]any{"input_tokens": 115001}}, "Errors": nil, "algo": algo, "GraphPaths": []string{"https://old.example/graph/fixture.svg"}}
				cacheFixture(t, request, mustJSON(t, fixture), "cached complete logs")
				started := submitIntegration(t, session, name, args)
				completed := pollIntegration(t, session, started.TaskID)
				if completed.Status != api.StatusCompleted || !completed.Cached || completed.Summary == nil || completed.Summary.VerdictsDisagree == nil || !*completed.Summary.VerdictsDisagree {
					t.Fatalf("completed = %+v", completed)
				}
				var output map[string]json.RawMessage
				if err := json.Unmarshal(completed.Output, &output); err != nil {
					t.Fatal(err)
				}
				if string(output["algo"]) != fmt.Sprintf("%q", algo) || !strings.Contains(string(output["GraphPaths"]), server.URL+"/graph/fixture.svg") {
					t.Fatalf("output = %s", completed.Output)
				}
				rest := postIntegration(t, server.URL+"/status", map[string]string{"taskId": started.TaskID}, http.StatusOK)
				var restResult struct {
					Status api.TaskStatus
					Output json.RawMessage
					Logs   string
				}
				json.Unmarshal(rest, &restResult)
				if restResult.Status != completed.Status || !bytes.Equal(restResult.Output, completed.Output) || restResult.Logs != completed.Logs {
					t.Fatalf("REST/MCP result mismatch: %s", rest)
				}
				retry := submitIntegration(t, session, name, args)
				if retry.TaskID != started.TaskID {
					t.Fatal("retry started a new task")
				}
				args["branch"] = "different"
				conflict := callTool(t, session, name, args)
				if !conflict.IsError || !strings.Contains(conflict.Content[0].(*sdk.TextContent).Text, "request_id_conflict") {
					t.Fatal("conflicting retry key accepted")
				}
				// A REST submission uses the same backend/cache and can be polled over MCP.
				var restStart struct {
					TaskID string `json:"taskId"`
				}
				deadline := time.Now().Add(5 * time.Second)
				for {
					body := mustJSON(t, request)
					resp, err := http.Post(server.URL+"/callgraph", "application/json", bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					data, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						if err := json.Unmarshal(data, &restStart); err != nil {
							t.Fatal(err)
						}
						break
					}
					if resp.StatusCode != http.StatusTooManyRequests || time.Now().After(deadline) {
						t.Fatalf("REST start: %d %s", resp.StatusCode, data)
					}
					time.Sleep(10 * time.Millisecond)
				}
				if done := pollIntegration(t, session, restStart.TaskID); !done.Cached || done.Status != api.StatusCompleted {
					t.Fatalf("REST scan through MCP: %+v", done)
				}
			})
		}
	}

	t.Run("shared_busy_and_cancel", func(t *testing.T) {
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer gitServer.Close()
		defer close(release)
		args := map[string]any{"repo": gitServer.URL + "/repo.git", "branch": "main", "cve": "CVE-2026-33186", "algo": "rta"}
		started := submitIntegration(t, session, "gvs_scan", args)
		defer api.CancelTask(started.TaskID)
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("git clone did not reach fixture server")
		}
		busy := callTool(t, session, "gvs_scan", args)
		if !busy.IsError || !strings.Contains(busy.Content[0].(*sdk.TextContent).Text, "scan_busy") {
			t.Fatalf("busy = %+v", busy.Content)
		}
		postIntegration(t, server.URL+"/callgraph", api.CallgraphRequest{Repo: gitServer.URL + "/other.git", BranchOrCommit: "main", CVE: "CVE-2026-33186", Algo: "rta"}, http.StatusTooManyRequests)
		postIntegration(t, server.URL+"/cancel", map[string]string{"taskId": started.TaskID}, http.StatusOK)
		cancelled := pollIntegration(t, session, started.TaskID)
		if cancelled.Status != api.StatusCancelled || !cancelled.Result.Available {
			t.Fatalf("cancelled = %+v", cancelled)
		}
		if result := callTool(t, session, "gvs_cancel", taskInput{TaskID: started.TaskID}); result.IsError {
			t.Fatal("repeated cancellation failed")
		}
	})
}

func cacheFixture(t *testing.T, request api.CallgraphRequest, output []byte, logs string) {
	t.Helper()
	key := fmt.Sprintf("%s@%s:%s:lib=%s:sym=%s:fixver=%s:algo=%s", request.Repo, request.BranchOrCommit, request.CVE, request.Library, request.Symbol, request.FixVersion, request.Algo)
	if err := api.SaveCacheToDisk(key, output); err != nil {
		t.Fatal(err)
	}
	if err := api.SaveCacheLogsToDisk(key, []byte(logs)); err != nil {
		t.Fatal(err)
	}
	stem := strings.ReplaceAll(strings.ReplaceAll(key, "/", "_"), ":", "_")
	t.Cleanup(func() {
		for _, ext := range []string{".json", ".log"} {
			_ = os.Remove(filepath.Join("/tmp/gvs-cache", stem+ext))
		}
	})
}

func submitIntegration(t *testing.T, session *sdk.ClientSession, name string, args any) Submission {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		result := callTool(t, session, name, args)
		text := result.Content[0].(*sdk.TextContent).Text
		if !result.IsError {
			var out Submission
			if err := json.Unmarshal([]byte(text), &out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		if !strings.Contains(text, "scan_busy") || time.Now().After(deadline) {
			t.Fatalf("submit failed: %s", text)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func pollIntegration(t *testing.T, session *sdk.ClientSession, id string) StatusResult {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		result := callTool(t, session, "gvs_status", taskInput{TaskID: id})
		if result.IsError {
			t.Fatalf("poll failed: %+v", result.Content)
		}
		var out StatusResult
		if err := json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &out); err != nil {
			t.Fatal(err)
		}
		if !active(out.Status) {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("task did not finish")
	return StatusResult{}
}

func postIntegration(t *testing.T, url string, body any, wantStatus int) []byte {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s = %d, want %d: %s", url, resp.StatusCode, wantStatus, data)
	}
	return data
}
