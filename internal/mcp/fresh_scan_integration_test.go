//go:build integration

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/k37y/gvs/internal/api"
	"github.com/k37y/gvs/internal/testutil/openapitest"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPFreshScanIntegration(t *testing.T) {
	for _, tool := range []string{"go", "git", "sfdp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("fresh MCP scan requires %s: %v", tool, err)
		}
	}
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelBuild()
	binDir := t.TempDir()
	build := exec.CommandContext(buildCtx, "go", "build", "-race", "-o", filepath.Join(binDir, "cg"), "./cmd/cg")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cg: %v\n%s", err, output)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GVS_AI", "0")
	t.Setenv("GVS_SCAN_TIMEOUT", "2m")
	t.Setenv("GVS_TASK_TTL", "1h")
	t.Setenv("GVS_PUBLIC_URL", "")
	t.Setenv("GVS_DATA_DIR", t.TempDir())
	t.Setenv("GVS_GRAPH_CACHE", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GORACE", "halt_on_error=1")

	repoDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoDir, "dep"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"go.mod":            "module example.com/app\n\ngo 1.22.0\n\nrequire example.com/vulnerable v1.0.0\nreplace example.com/vulnerable => ./dep\n",
		"main.go":           "package main\nimport \"example.com/vulnerable\"\nfunc main() { println(vulnerable.Danger()) }\n",
		"dep/go.mod":        "module example.com/vulnerable\n\ngo 1.22.0\n",
		"dep/vulnerable.go": "package vulnerable\nfunc Danger() int { return 42 }\n",
	} {
		if err := os.WriteFile(filepath.Join(repoDir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoDir}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	// MCP requires HTTP(S), but Git rewrites this unique URL to a real local
	// repository before cloning. No network repository or advisory is needed.
	repoURL := fmt.Sprintf("https://fixture.invalid/mcp-%d.git", time.Now().UnixNano())
	config := filepath.Join(t.TempDir(), "gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", config)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	localURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(repoDir)}).String()
	git("config", "--file", config, "url."+localURL+".insteadOf", repoURL)
	git("config", "--file", config, "protocol.file.allow", "always")
	git("init", "-b", "main")
	git("add", ".")
	git("-c", "user.name=GVS Tests", "-c", "user.email=tests@example.com", "-c", "commit.gpgsign=false", "commit", "-m", "MCP integration fixture")

	handler, err := NewHandler("integration", api.DefaultTaskBackend{}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.HandleFunc("/status", api.StatusHandler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "fresh-integration", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + "/mcp", DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	started := submitIntegration(t, session, "gvs_manual_scan", manualInput{
		Repo: repoURL, Branch: "main", Library: "example.com/vulnerable", Symbol: "Danger", FixedVersion: "v1.1.0", Algo: "rta",
	})
	cacheKey := fmt.Sprintf("%s@main::lib=example.com/vulnerable:sym=Danger:fixver=v1.1.0:algo=rta", repoURL)
	t.Cleanup(func() {
		_, _ = api.CancelTask(started.TaskID)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			task, err := api.GetTask(started.TaskID)
			if err != nil {
				t.Error(err)
				return
			}
			if !active(task.Status) {
				// Completion is published before the worker writes its cache. Wait
				// for that last write before restoring the isolated environment.
				if task.Status != api.StatusCompleted || task.Cached {
					return
				}
				if _, err := api.RetrieveCacheLogFromDisk(cacheKey); err == nil {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("fresh scan worker did not finish cleanup")
	})

	var completed StatusResult
	for {
		result := callTool(t, session, "gvs_status", taskInput{TaskID: started.TaskID})
		if result.IsError {
			t.Fatalf("status failed: %+v", result.Content)
		}
		if err := json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &completed); err != nil {
			t.Fatal(err)
		}
		if !active(completed.Status) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fresh MCP scan did not finish:", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	if completed.Status != api.StatusCompleted || completed.Cached || completed.Error != "" {
		t.Fatalf("fresh scan = %+v", completed)
	}
	if !completed.Result.Available || !completed.Result.Inline || completed.Summary == nil || completed.Summary.ScannerVerdict == nil || *completed.Summary.ScannerVerdict != "true" {
		t.Fatalf("missing positive inline scan result: %+v", completed)
	}
	openapitest.Validate(t, "CGResult", completed.Output)
	var scan struct {
		IsVulnerable string
		Errors       []string
	}
	if err := json.Unmarshal(completed.Output, &scan); err != nil {
		t.Fatal(err)
	}
	if scan.IsVulnerable != "true" || len(scan.Errors) != 0 {
		t.Fatalf("scanner result = %s", completed.Output)
	}

	var artifact strings.Builder
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			t.Fatal("result chunks did not finish:", err)
		}
		result := callTool(t, session, "gvs_read_result", readInput{TaskID: started.TaskID, Cursor: cursor})
		if result.IsError {
			t.Fatalf("read result failed: %+v", result.Content)
		}
		var chunk ResultChunk
		if err := json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &chunk); err != nil {
			t.Fatal(err)
		}
		if chunk.TaskID != started.TaskID {
			t.Fatalf("chunk belongs to %q", chunk.TaskID)
		}
		artifact.WriteString(chunk.Content)
		if chunk.EOF {
			if chunk.NextCursor != nil {
				t.Fatal("terminal chunk has a continuation cursor")
			}
			break
		}
		if chunk.NextCursor == nil || *chunk.NextCursor == cursor {
			t.Fatal("result cursor did not advance")
		}
		cursor = *chunk.NextCursor
	}
	if completed.Result.TotalBytes == nil || artifact.Len() != *completed.Result.TotalBytes {
		t.Fatal("chunked artifact size differs from status")
	}
	var stored struct {
		Output json.RawMessage
		Logs   string
		Error  string
	}
	if err := json.Unmarshal([]byte(artifact.String()), &stored); err != nil {
		t.Fatal(err)
	}
	openapitest.Validate(t, "CGResult", stored.Output)
	if !bytes.Equal(stored.Output, completed.Output) || stored.Logs != completed.Logs || stored.Error != completed.Error {
		t.Fatalf("chunked artifact differs from MCP status: %s", artifact.String())
	}

	rest := postIntegration(t, server.URL+"/status", map[string]string{"taskId": started.TaskID}, http.StatusOK)
	openapitest.Validate(t, "TaskStatusResponse", json.RawMessage(rest))
	var restResult struct {
		Status api.TaskStatus
		Output json.RawMessage
		Logs   string
		Error  string
	}
	if err := json.Unmarshal(rest, &restResult); err != nil {
		t.Fatal(err)
	}
	openapitest.Validate(t, "CGResult", restResult.Output)
	if restResult.Status != completed.Status || !bytes.Equal(restResult.Output, completed.Output) || restResult.Logs != completed.Logs || restResult.Error != completed.Error {
		t.Fatalf("REST/MCP fresh result mismatch: %s", rest)
	}
}
