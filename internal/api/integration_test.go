//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/k37y/gvs/pkg/cmd/cg"
)

// GVS_TESTDATA_REPO allows validating fixture branches in a local checkout
// before publishing them. CI and normal runs use the GitHub repository.
var testDataRepo = func() string {
	if repo := os.Getenv("GVS_TESTDATA_REPO"); repo != "" {
		return repo
	}
	return "https://github.com/k37y/gvs-testdata"
}()

var testServerURL string
var integrationClient = &http.Client{Timeout: 15 * time.Second}

type cgUsedImport struct {
	Symbols        []string `json:"Symbols"`
	CurrentVersion string   `json:"CurrentVersion"`
	ReplaceModule  string   `json:"ReplaceModule,omitempty"`
	ReplaceVersion string   `json:"ReplaceVersion,omitempty"`
	FixCommands    []string `json:"FixCommands"`
}

type cgAffectedImport struct {
	Symbols      []string `json:"Symbols"`
	Type         string   `json:"Type"`
	FixedVersion []string `json:"FixedVersion"`
}

type cgOutput struct {
	GraphPaths      []string                           `json:"GraphPaths"`
	ReflectionRisks []cg.ReflectionRisk                `json:"reflection_risks"`
	CVE             string                             `json:"CVE"`
	IsVulnerable    string                             `json:"IsVulnerable"`
	GoCVE           string                             `json:"GoCVE"`
	Repository      string                             `json:"Repository"`
	Branch          string                             `json:"Branch"`
	Errors          []string                           `json:"Errors"`
	Unsafe          bool                               `json:"unsafe"`
	Reflect         bool                               `json:"reflect"`
	Files           map[string][][]string              `json:"Files"`
	UsedImports     map[string]map[string]cgUsedImport `json:"UsedImports"`
	AffectedImports map[string]cgAffectedImport        `json:"AffectedImports"`
}

func buildIntegrationCG(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cg")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-race", "-o", binary, "./cmd/cg")
	cmd.Dir = "../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cg: %v\n%s", err, out)
	}
	return binary
}

func startTestServer(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"go", "git", "sfdp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("integration tests require %s: %v", tool, err)
		}
	}
	binary := buildIntegrationCG(t)
	t.Setenv("PATH", filepath.Dir(binary)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GVS_AI", "0")
	t.Setenv("WORKER_COUNT", "2")
	t.Setenv("GORACE", "halt_on_error=1")
	t.Setenv("GVS_GRAPH_CACHE", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	oldCache, oldURL := cacheDir, testServerURL
	cacheDir = t.TempDir()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", HealthHandler)
	mux.HandleFunc("/callgraph", CallgraphHandler)
	mux.HandleFunc("/status", StatusHandler)
	mux.HandleFunc("/cancel", CancelHandler)
	mux.HandleFunc("/progress/", ProgressHandler)
	mux.Handle("/graph/", http.StripPrefix("/graph/", http.FileServer(http.Dir(getGraphCacheDir()))))
	server := httptest.NewServer(mux)
	testServerURL = server.URL
	t.Cleanup(func() {
		taskCancelMutex.Lock()
		for _, cancel := range taskCancels {
			cancel()
		}
		taskCancelMutex.Unlock()
		waitIntegrationIdle(t)
		server.Close()
		cacheDir, testServerURL = oldCache, oldURL
	})
}

func waitIntegrationIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		requestMutex.Lock()
		busy := inProgress
		requestMutex.Unlock()
		if !busy {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan worker did not release the request slot")
}

func pollCallgraphManualResult(t *testing.T, repo, branchOrCommit, library, symbol, fixversion, algo string) cgOutput {
	t.Helper()

	requestBody := map[string]interface{}{
		"repo":           repo,
		"branchOrCommit": branchOrCommit,
		"library":        library,
		"symbol":         symbol,
		"fixversion":     fixversion,
		"algo":           algo,
	}

	return pollCallgraphRequest(t, requestBody)
}

func pollCallgraphResult(t *testing.T, repo, branchOrCommit, cve, algo string) cgOutput {
	t.Helper()

	requestBody := map[string]interface{}{
		"repo":           repo,
		"branchOrCommit": branchOrCommit,
		"cve":            cve,
		"algo":           algo,
	}

	return pollCallgraphRequest(t, requestBody)
}

func pollCallgraphRequest(t *testing.T, requestBody map[string]interface{}) cgOutput {
	t.Helper()
	waitIntegrationIdle(t)

	reqJSON, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := integrationClient.Post(
		testServerURL+"/callgraph",
		"application/json",
		bytes.NewBuffer(reqJSON),
	)
	if err != nil {
		t.Fatalf("Failed to send callgraph request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Callgraph request failed with status %d: %s", resp.StatusCode, body)
	}

	var callgraphResp struct {
		TaskID string `json:"taskId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&callgraphResp); err != nil {
		t.Fatalf("Failed to decode callgraph response: %v", err)
	}

	taskID := callgraphResp.TaskID
	if taskID == "" {
		t.Fatal("No taskId returned from callgraph request")
	}
	t.Logf("Received taskId: %s", taskID)

	maxAttempts := 2700
	for i := 0; i < maxAttempts; i++ {
		statusReq := map[string]string{"taskId": taskID}
		statusJSON, err := json.Marshal(statusReq)
		if err != nil {
			t.Fatalf("Failed to marshal status request: %v", err)
		}

		statusResp, err := integrationClient.Post(
			testServerURL+"/status",
			"application/json",
			bytes.NewBuffer(statusJSON),
		)
		if err != nil {
			t.Fatalf("Failed to send status request: %v", err)
		}

		var statusResult struct {
			Status string          `json:"status"`
			Output json.RawMessage `json:"output"`
			Error  string          `json:"error"`
		}

		body, err := io.ReadAll(statusResp.Body)
		statusResp.Body.Close()

		if err != nil {
			t.Fatalf("Failed to read status response: %v", err)
		}

		if err := json.Unmarshal(body, &statusResult); err != nil {
			t.Fatalf("Failed to decode status response: %v", err)
		}

		if i%30 == 0 {
			t.Logf("Attempt %d: Status = %s", i+1, statusResult.Status)
		}

		if statusResult.Status == "completed" {
			var output cgOutput
			if err := json.Unmarshal(statusResult.Output, &output); err != nil {
				t.Fatalf("Failed to parse output: %v", err)
			}
			t.Logf("Task completed! IsVulnerable: %s", output.IsVulnerable)
			assertResponseContract(t, output, requestBody)
			waitIntegrationIdle(t)
			return output
		} else if statusResult.Status == "failed" {
			t.Fatalf("Task failed with error: %s", statusResult.Error)
		}

		time.Sleep(200 * time.Millisecond)
	}

	t.Fatal("Task did not complete within timeout")
	return cgOutput{}
}

func runCallgraphTest(t *testing.T, repo, branchOrCommit, cve, algo, expectedResult string, expectErrors bool) {
	t.Helper()
	output := pollCallgraphResult(t, repo, branchOrCommit, cve, algo)
	if output.IsVulnerable != expectedResult {
		t.Errorf("Expected IsVulnerable: %s, got: %s", expectedResult, output.IsVulnerable)
	}
	if !expectErrors && len(output.Errors) > 0 {
		t.Errorf("Errors = %v, want nil", output.Errors)
	}
}

func assertUsedImport(t *testing.T, output cgOutput, dir, pkg, currentVersion string, fixCommands, symbols []string, replaceModule, replaceVersion string) {
	t.Helper()
	pkgs, ok := output.UsedImports[dir]
	if !ok {
		t.Errorf("UsedImports missing dir %q", dir)
		return
	}
	wantPackages := 1
	if output.GoCVE == "GO-2023-2153" {
		wantPackages = 2
	}
	if len(pkgs) != wantPackages {
		t.Errorf("UsedImports[%q] packages = %v, want %d packages", dir, pkgs, wantPackages)
	}
	ui, ok := pkgs[pkg]
	if !ok {
		t.Errorf("UsedImports[%q] missing package %q", dir, pkg)
		return
	}
	if ui.CurrentVersion != currentVersion {
		t.Errorf("UsedImports[%q][%q].CurrentVersion = %q, want %q", dir, pkg, ui.CurrentVersion, currentVersion)
	}
	if len(fixCommands) == 0 {
		if len(ui.FixCommands) > 0 {
			t.Errorf("UsedImports[%q][%q].FixCommands = %v, want nil", dir, pkg, ui.FixCommands)
		}
	} else {
		if !slices.Equal(ui.FixCommands, fixCommands) {
			t.Errorf("UsedImports[%q][%q].FixCommands = %v, want %v", dir, pkg, ui.FixCommands, fixCommands)
		}
	}
	if symbols != nil {
		if !slices.Equal(ui.Symbols, symbols) {
			t.Errorf("UsedImports[%q][%q].Symbols = %v, want %v", dir, pkg, ui.Symbols, symbols)
		}
	} else if len(ui.Symbols) == 0 {
		t.Errorf("UsedImports[%q][%q].Symbols is empty", dir, pkg)
	}
	if ui.ReplaceModule != replaceModule {
		t.Errorf("UsedImports[%q][%q].ReplaceModule = %q, want %q", dir, pkg, ui.ReplaceModule, replaceModule)
	}
	if ui.ReplaceVersion != replaceVersion {
		t.Errorf("UsedImports[%q][%q].ReplaceVersion = %q, want %q", dir, pkg, ui.ReplaceVersion, replaceVersion)
	}
}

func assertAffectedImport(t *testing.T, output cgOutput, pkg, typ string, fixedVersions []string) {
	t.Helper()
	ai, ok := output.AffectedImports[pkg]
	if !ok {
		t.Errorf("AffectedImports missing package %q", pkg)
		return
	}
	if ai.Type != typ {
		t.Errorf("AffectedImports[%q].Type = %q, want %q", pkg, ai.Type, typ)
	}
	if !slices.Equal(ai.FixedVersion, fixedVersions) {
		t.Errorf("AffectedImports[%q].FixedVersion = %v, want %v", pkg, ai.FixedVersion, fixedVersions)
	}
	if len(ai.Symbols) == 0 {
		t.Errorf("AffectedImports[%q].Symbols is empty", pkg)
	}
}

func assertCommon(t *testing.T, output cgOutput, isVuln, goCVE, branch string, wantUnsafe, wantReflect bool, files map[string][][]string, usedImportDirs []string) {
	t.Helper()
	if output.IsVulnerable != isVuln {
		t.Errorf("IsVulnerable = %q, want %q", output.IsVulnerable, isVuln)
	}
	if output.GoCVE != goCVE {
		t.Errorf("GoCVE = %q, want %q", output.GoCVE, goCVE)
	}
	if output.Branch != branch {
		t.Errorf("Branch = %q, want %q", output.Branch, branch)
	}
	if output.Repository != testDataRepo {
		t.Errorf("Repository = %q, want %q", output.Repository, testDataRepo)
	}
	if output.Unsafe != wantUnsafe {
		t.Errorf("Unsafe = %v, want %v", output.Unsafe, wantUnsafe)
	}
	if output.Reflect != wantReflect {
		t.Errorf("Reflect = %v, want %v", output.Reflect, wantReflect)
	}
	if output.Files == nil {
		t.Error("Files is nil")
	}
	if files != nil {
		if len(output.Files) != len(files) {
			t.Errorf("Files has %d dirs, want %d", len(output.Files), len(files))
		}
		for modDir, expectedSets := range files {
			sets, ok := output.Files[modDir]
			if !ok {
				t.Errorf("Files missing module dir %q", modDir)
				continue
			}
			if len(sets) != len(expectedSets) {
				t.Errorf("Files[%q] has %d file sets, want %d", modDir, len(sets), len(expectedSets))
				continue
			}
			for i, expected := range expectedSets {
				if !slices.Equal(sets[i], expected) {
					t.Errorf("Files[%q][%d] = %v, want %v", modDir, i, sets[i], expected)
				}
			}
		}
	}
	if usedImportDirs != nil {
		var gotDirs []string
		for dir := range output.UsedImports {
			gotDirs = append(gotDirs, dir)
		}
		sort.Strings(gotDirs)
		sort.Strings(usedImportDirs)
		if !slices.Equal(gotDirs, usedImportDirs) {
			t.Errorf("UsedImports dirs = %v, want %v", gotDirs, usedImportDirs)
		}
	}
	if len(output.Errors) > 0 {
		t.Errorf("Errors = %v, want nil", output.Errors)
	}
}

func TestCallgraphIntegration(t *testing.T) {
	startTestServer(t)

	// --- Full JSON validation tests ---

	singleMainFiles := map[string][][]string{".": {{"main.go"}}}
	xnetSymbols := []string{"Parse", "ParseWithOptions", "htmlIntegrationPoint", "inBodyIM", "inTableIM", "parseDoctype"}
	// RTA includes package initialization and the types registered by net/http init.
	stdlibSymbols := []string{
		"(*net/http.Client).Do", "(*net/http.Client).Get", "(*net/http.Cookie).String",
		"(*net/http.Request).AddCookie", "(*net/http.Request).Write", "(*net/http.Response).Cookies",
		"(*net/http.Transport).CancelRequest", "(*net/http.Transport).RoundTrip", "(*net/http.body).Close",
		"(*net/http.body).Read", "(*net/http.bodyEOFSignal).Close", "(*net/http.bodyEOFSignal).Read",
		"(*net/http.bodyLocked).Read", "(*net/http.bufioFlushWriter).Write", "(*net/http.cancelTimerBody).Close",
		"(*net/http.cancelTimerBody).Read", "(*net/http.connectMethodKey).String", "(*net/http.gzipReader).Close",
		"(*net/http.gzipReader).Read", "(*net/http.http2ClientConn).Close", "(*net/http.http2ClientConn).Ping",
		"(*net/http.http2ClientConn).RoundTrip", "(*net/http.persistConn).Read", "(*net/http.persistConnWriter).ReadFrom",
		"(*net/http.persistConnWriter).Write", "(*net/http.readTrackingBody).Close", "(*net/http.readTrackingBody).Read",
		"(*net/http.readWriteCloserBody).Read", "(*net/http.socksDialer).DialWithConn", "(*net/http.socksUsernamePassword).Authenticate",
		"(*net/http.stringWriter).WriteString", "(*net/http.transportReadFromServerError).Error", "(net/http.Header).Add",
		"(net/http.Header).Del", "(net/http.Header).Get", "(net/http.Header).Set",
		"(net/http.Header).Write", "(net/http.bodyLocked).Read", "(net/http.bufioFlushWriter).Write",
		"(net/http.connectMethodKey).String", "(net/http.http2ClientConn).Close", "(net/http.http2ClientConn).Ping",
		"(net/http.http2ClientConn).RoundTrip", "(net/http.persistConnWriter).ReadFrom", "(net/http.persistConnWriter).Write",
		"(net/http.stringWriter).WriteString", "(net/http.transportReadFromServerError).Error", "CanonicalHeaderKey",
		"Client.Do", "Client.Get", "Cookie.String",
		"Error", "Get", "Head",
		"Header.Add", "Header.Del", "Header.Get",
		"Header.Set", "Header.Write", "NewRequest",
		"NewRequestWithContext", "ProxyFromEnvironment", "ReadResponse",
		"Redirect", "Request.AddCookie", "Request.Write",
		"Response.Cookies", "Serve", "SetCookie",
		"Transport.CancelRequest", "Transport.RoundTrip", "body.Close",
		"body.Read", "bodyEOFSignal.Close", "bodyEOFSignal.Read",
		"bodyLocked.Read", "bufioFlushWriter.Write", "cancelTimerBody.Close",
		"cancelTimerBody.Read", "chunkWriter.Write", "connectMethodKey.String",
		"gzipReader.Close", "gzipReader.Read", "http2ClientConn.Close",
		"http2ClientConn.Ping", "http2ClientConn.RoundTrip", "persistConn.Read",
		"persistConnWriter.ReadFrom", "persistConnWriter.Write", "readTrackingBody.Close",
		"readTrackingBody.Read", "readWriteCloserBody.Read", "response.Flush",
		"response.FlushError", "response.Write", "response.WriteHeader",
		"response.WriteString", "socksDialer.DialWithConn", "socksUsernamePassword.Authenticate",
		"stringWriter.WriteString", "transportReadFromServerError.Error",
	}
	grpcSymbols := []string{
		"(*google.golang.org/grpc.Server).Serve", "(*google.golang.org/grpc.Server).initServerWorkers",
		"NewServer", "Server.Serve", "Server.initServerWorkers",
	}

	t.Run("full/non-stdlib vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-single-range", "CVE-2024-45338", "rta")
		assertCommon(t, output, "true", "GO-2024-3333", "vuln-single-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.23.0",
			[]string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"},
			xnetSymbols, "", "")
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/non-stdlib patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-single-range", "CVE-2024-45338", "rta")
		assertCommon(t, output, "false", "GO-2024-3333", "patched-single-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.33.0", nil,
			xnetSymbols, "", "")
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/stdlib multi-range vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-stdlib-multi-range", "CVE-2023-45288", "rta")
		assertCommon(t, output, "true", "GO-2024-2687", "vuln-stdlib-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.21.4",
			[]string{"go mod edit -go=1.21.9", "go mod tidy", "go mod vendor"},
			stdlibSymbols, "", "")
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"1.21.9", "1.22.2"})
	})

	t.Run("full/stdlib second range vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-stdlib-second-range", "CVE-2023-45288", "rta")
		assertCommon(t, output, "true", "GO-2024-2687", "vuln-stdlib-second-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.22.1",
			[]string{"go mod edit -go=1.22.2", "go mod tidy", "go mod vendor"},
			stdlibSymbols, "", "")
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"1.21.9", "1.22.2"})
	})

	t.Run("full/stdlib between ranges patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-stdlib-between-ranges", "CVE-2023-45288", "rta")
		assertCommon(t, output, "false", "GO-2024-2687", "patched-stdlib-between-ranges", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.21.9", nil,
			stdlibSymbols, "", "")
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"1.21.9", "1.22.2"})
	})

	t.Run("full/grpc multi-range vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-multi-range", "GO-2023-2153", "rta")
		assertCommon(t, output, "true", "GO-2023-2153", "vuln-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.57.0",
			[]string{"go get google.golang.org/grpc@v1.57.1", "go mod tidy", "go mod vendor"},
			grpcSymbols, "", "")
		assertAffectedImport(t, output, "google.golang.org/grpc", "non-stdlib",
			[]string{"v1.56.3 1.57.1 1.58.3"})
		assertUsedImport(t, output, ".", "google.golang.org/grpc/internal/transport", "v1.57.0", []string{"go get google.golang.org/grpc@v1.57.1", "go mod tidy", "go mod vendor"}, []string{"NewServerTransport"}, "", "")
		assertAffectedImport(t, output, "google.golang.org/grpc/internal/transport", "non-stdlib", []string{"v1.56.3 1.57.1 1.58.3"})

	})

	t.Run("full/grpc multi-range patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-multi-range", "GO-2023-2153", "rta")
		assertCommon(t, output, "false", "GO-2023-2153", "patched-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.57.1", nil,
			grpcSymbols, "", "")
		assertUsedImport(t, output, ".", "google.golang.org/grpc/internal/transport", "v1.57.1", nil, []string{"NewServerTransport"}, "", "")
		assertAffectedImport(t, output, "google.golang.org/grpc/internal/transport", "non-stdlib", []string{"v1.56.3 1.57.1 1.58.3"})

	})

	t.Run("full/grpc between ranges patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-multi-range-between", "GO-2023-2153", "rta")
		assertCommon(t, output, "false", "GO-2023-2153", "patched-multi-range-between", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.56.3", nil,
			grpcSymbols, "", "")
		assertUsedImport(t, output, ".", "google.golang.org/grpc/internal/transport", "v1.56.3", nil, []string{"NewServerTransport"}, "", "")
		assertAffectedImport(t, output, "google.golang.org/grpc/internal/transport", "non-stdlib", []string{"v1.56.3 1.57.1 1.58.3"})

	})

	t.Run("full/replace directive vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-replace-directive", "CVE-2024-45338", "rta")
		assertCommon(t, output, "true", "GO-2024-3333", "vuln-replace-directive", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.23.0",
			[]string{"go mod edit -replace=golang.org/x/net=golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"},
			xnetSymbols, "golang.org/x/net", "v0.24.0")
	})

	t.Run("full/replace directive patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-replace-directive", "CVE-2024-45338", "rta")
		assertCommon(t, output, "false", "GO-2024-3333", "patched-replace-directive", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.23.0", nil,
			xnetSymbols, "golang.org/x/net", "v0.33.0")
	})

	t.Run("full/indirect dep vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-indirect-dep", "CVE-2024-45338", "rta")
		indirectFiles := map[string][][]string{".": {{"main.go"}}, "wrapper": nil}
		assertCommon(t, output, "true", "GO-2024-3333", "vuln-indirect-dep", false, false, indirectFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.23.0",
			[]string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"},
			xnetSymbols, "", "")
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/build constraint unknown", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-build-constraint", "CVE-2024-45338", "rta")
		if output.IsVulnerable != "unknown" {
			t.Errorf("IsVulnerable = %q, want %q", output.IsVulnerable, "unknown")
		}
		if output.GoCVE != "GO-2024-3333" {
			t.Errorf("GoCVE = %q, want %q", output.GoCVE, "GO-2024-3333")
		}
		if output.Branch != "vuln-build-constraint" {
			t.Errorf("Branch = %q, want %q", output.Branch, "vuln-build-constraint")
		}
		if output.Files == nil {
			t.Error("Files is nil")
		} else {
			sets, ok := output.Files["."]
			if !ok {
				t.Error("Files missing root module dir")
			} else if len(sets) != 1 || !slices.Equal(sets[0], []string{"constrained.go", "main.go"}) {
				t.Errorf("Files[\".\"] = %v, want [[constrained.go main.go]]", sets)
			}
		}
		hasManualAnalysis := false
		for _, e := range output.Errors {
			if strings.Contains(e, "Need manual analysis") && strings.Contains(e, "constrained.go") {
				hasManualAnalysis = true
			}
		}
		if !hasManualAnalysis {
			t.Errorf("Errors should contain 'Need manual analysis' for constrained.go, got: %v", output.Errors)
		}
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/untidy gomod selected version", func(t *testing.T) {
		// go.mod says x/net v0.23.0 but helper requires v0.33.0 (patched).
		// The scan must compare against the patched version selected by Go.
		output := pollCallgraphResult(t, testDataRepo, "vuln-untidy-gomod", "CVE-2024-45338", "rta")
		untidyFiles := map[string][][]string{".": {{"main.go"}}, "helper": nil}
		assertCommon(t, output, "false", "GO-2024-3333", "vuln-untidy-gomod", false, false, untidyFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.33.0", nil,
			xnetSymbols, "", "")
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/multi-module x/net vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "multi-module", "CVE-2024-45338", "rta")
		multiModuleFiles := map[string][][]string{
			"svc-a": {{"main.go"}},
			"svc-b": {{"main.go"}},
		}
		assertCommon(t, output, "true", "GO-2024-3333", "multi-module", false, false, multiModuleFiles, []string{"svc-a", "svc-b"})

		assertUsedImport(t, output, "svc-a", "golang.org/x/net/html", "v0.23.0",
			[]string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"},
			xnetSymbols, "", "")
		assertUsedImport(t, output, "svc-b", "golang.org/x/net/html", "v0.33.0", nil,
			xnetSymbols, "", "")
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/multi-module x/crypto vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "multi-module", "CVE-2024-45337", "rta")
		multiModuleFiles := map[string][][]string{
			"svc-a": {{"main.go"}},
			"svc-b": {{"main.go"}},
		}
		assertCommon(t, output, "true", "GO-2024-3321", "multi-module", false, false, multiModuleFiles, []string{"svc-a", "svc-b"})

		assertUsedImport(t, output, "svc-a", "golang.org/x/crypto/ssh", "v0.23.0",
			[]string{"go get golang.org/x/crypto@v0.31.0", "go mod tidy", "go mod vendor"},
			[]string{"(*golang.org/x/crypto/ssh.connection).serverAuthenticate", "NewServerConn", "connection.serverAuthenticate"}, "", "")
		assertUsedImport(t, output, "svc-b", "golang.org/x/crypto/ssh", "v0.31.0", nil,
			[]string{"(*golang.org/x/crypto/ssh.connection).serverAuthenticate", "NewServerConn", "connection.serverAuthenticate"}, "", "")
		assertAffectedImport(t, output, "golang.org/x/crypto/ssh", "non-stdlib",
			[]string{"v0.31.0"})
	})

	t.Run("full/not a go repo", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "not-a-go-repo", "CVE-2024-45338", "rta")
		if output.IsVulnerable != "unknown" {
			t.Errorf("IsVulnerable = %q, want %q", output.IsVulnerable, "unknown")
		}
		if output.GoCVE != "GO-2024-3333" {
			t.Errorf("GoCVE = %q, want %q", output.GoCVE, "GO-2024-3333")
		}
		if output.Branch != "not-a-go-repo" {
			t.Errorf("Branch = %q, want %q", output.Branch, "not-a-go-repo")
		}
		if len(output.Files) != 0 {
			t.Errorf("Files = %v, want empty", output.Files)
		}
		if len(output.UsedImports) != 0 {
			t.Errorf("UsedImports = %v, want empty", output.UsedImports)
		}
	})

	// --- Full validation: x/crypto ---

	cryptoSymbols := []string{"(*golang.org/x/crypto/ssh.connection).serverAuthenticate", "NewServerConn", "connection.serverAuthenticate"}

	t.Run("full/x/crypto single range vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-single-range", "CVE-2024-45337", "rta")
		assertCommon(t, output, "true", "GO-2024-3321", "vuln-single-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/crypto/ssh", "v0.23.0",
			[]string{"go get golang.org/x/crypto@v0.31.0", "go mod tidy", "go mod vendor"},
			cryptoSymbols, "", "")
		assertAffectedImport(t, output, "golang.org/x/crypto/ssh", "non-stdlib",
			[]string{"v0.31.0"})
	})

	t.Run("full/x/crypto single range patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-single-range", "CVE-2024-45337", "rta")
		assertCommon(t, output, "false", "GO-2024-3321", "patched-single-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/crypto/ssh", "v0.31.0", nil,
			cryptoSymbols, "", "")
		assertAffectedImport(t, output, "golang.org/x/crypto/ssh", "non-stdlib",
			[]string{"v0.31.0"})
	})

	t.Run("full/stdlib multi-range patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-stdlib-multi-range", "CVE-2023-45288", "rta")
		assertCommon(t, output, "false", "GO-2024-2687", "patched-stdlib-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.22.5", nil,
			stdlibSymbols, "", "")
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"1.21.9", "1.22.2"})
	})

	// --- Algorithm and input format tests ---

	tests := []struct {
		name           string
		repo           string
		branchOrCommit string
		cve            string
		algo           string
		expected       string
		expectErrors   bool
	}{
		{
			name:           "algorithm vta",
			repo:           testDataRepo,
			branchOrCommit: "vuln-single-range",
			cve:            "CVE-2024-45338",
			algo:           "vta",
			expected:       "true",
		},
		{
			name:           "algorithm cha",
			repo:           testDataRepo,
			branchOrCommit: "vuln-single-range",
			cve:            "CVE-2024-45338",
			algo:           "cha",
			expected:       "true",
		},
		{
			name:           "algorithm static",
			repo:           testDataRepo,
			branchOrCommit: "vuln-single-range",
			cve:            "CVE-2024-45338",
			algo:           "static",
			expected:       "true",
		},
		{
			name:           "GOCVE input",
			repo:           testDataRepo,
			branchOrCommit: "vuln-single-range",
			cve:            "GO-2024-3333",
			algo:           "rta",
			expected:       "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runCallgraphTest(t, tt.repo, tt.branchOrCommit, tt.cve, tt.algo, tt.expected, tt.expectErrors)
		})
	}

	// --- Manual scan tests (library + symbol + fixversion) ---

	t.Run("manual/single version vulnerable", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "vuln-single-range",
			"golang.org/x/net/html", "Parse,ParseWithOptions", "v0.33.0", "rta")
		assertCommon(t, output, "true", "MANUAL-SCAN", "vuln-single-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.23.0",
			[]string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"},
			nil, "", "")
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("manual/single version patched", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "patched-single-range",
			"golang.org/x/net/html", "Parse,ParseWithOptions", "v0.33.0", "rta")
		assertCommon(t, output, "false", "MANUAL-SCAN", "patched-single-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.33.0", nil,
			nil, "", "")
	})

	t.Run("manual/multi-range vulnerable", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "vuln-multi-range",
			"google.golang.org/grpc", "NewServer", "0:v1.56.3,v1.57.0:v1.57.1,v1.58.0:v1.58.3", "rta")
		assertCommon(t, output, "true", "MANUAL-SCAN", "vuln-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.57.0",
			[]string{"go get google.golang.org/grpc@v1.57.1", "go mod tidy", "go mod vendor"},
			nil, "", "")
		assertAffectedImport(t, output, "google.golang.org/grpc", "non-stdlib",
			[]string{"Introduced in 0 and fixed in v1.56.3", "Introduced in v1.57.0 and fixed in v1.57.1", "Introduced in v1.58.0 and fixed in v1.58.3"})
	})

	t.Run("manual/multi-range between ranges patched", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "patched-multi-range-between",
			"google.golang.org/grpc", "NewServer", "0:v1.56.3,v1.57.0:v1.57.1,v1.58.0:v1.58.3", "rta")
		assertCommon(t, output, "false", "MANUAL-SCAN", "patched-multi-range-between", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.56.3", nil,
			nil, "", "")
	})

	t.Run("manual/multi-range patched", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "patched-multi-range",
			"google.golang.org/grpc", "NewServer", "0:v1.56.3,v1.57.0:v1.57.1,v1.58.0:v1.58.3", "rta")
		assertCommon(t, output, "false", "MANUAL-SCAN", "patched-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.57.1", nil,
			nil, "", "")
	})

	t.Run("manual/stdlib first range vulnerable", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "vuln-stdlib-multi-range",
			"net/http", "Get,NewRequest", "0:1.21.9,1.22.0:1.22.2", "rta")
		assertCommon(t, output, "true", "MANUAL-SCAN", "vuln-stdlib-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.21.4",
			[]string{"go mod edit -go=1.21.9", "go mod tidy", "go mod vendor"},
			nil, "", "")
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"Introduced in 0 and fixed in 1.21.9", "Introduced in 1.22.0 and fixed in 1.22.2"})
	})

	t.Run("manual/stdlib second range vulnerable", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "vuln-stdlib-second-range",
			"net/http", "Get,NewRequest", "0:1.21.9,1.22.0:1.22.2", "rta")
		assertCommon(t, output, "true", "MANUAL-SCAN", "vuln-stdlib-second-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.22.1",
			[]string{"go mod edit -go=1.22.2", "go mod tidy", "go mod vendor"},
			nil, "", "")
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"Introduced in 0 and fixed in 1.21.9", "Introduced in 1.22.0 and fixed in 1.22.2"})
	})

	t.Run("manual/stdlib between ranges patched", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "patched-stdlib-between-ranges",
			"net/http", "Get,NewRequest", "0:1.21.9,1.22.0:1.22.2", "rta")
		assertCommon(t, output, "false", "MANUAL-SCAN", "patched-stdlib-between-ranges", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.21.9", nil,
			nil, "", "")
	})

	t.Run("manual/stdlib patched", func(t *testing.T) {
		output := pollCallgraphManualResult(t, testDataRepo, "patched-stdlib-multi-range",
			"net/http", "Get,NewRequest", "0:1.21.9,1.22.0:1.22.2", "rta")
		assertCommon(t, output, "false", "MANUAL-SCAN", "patched-stdlib-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "net/http", "v1.22.5", nil,
			nil, "", "")
	})

	// --- Manual scan API validation tests ---

	apiValidation := []struct {
		name string
		body string
	}{
		{"library only", `{"repo":"x","branchOrCommit":"y","library":"golang.org/x/net/html"}`},
		{"library and symbol only", `{"repo":"x","branchOrCommit":"y","library":"golang.org/x/net/html","symbol":"Parse"}`},
		{"symbol and fixversion only", `{"repo":"x","branchOrCommit":"y","symbol":"Parse","fixversion":"v0.33.0"}`},
		{"fixversion only", `{"repo":"x","branchOrCommit":"y","fixversion":"v0.33.0"}`},
		{"library and fixversion only", `{"repo":"x","branchOrCommit":"y","library":"golang.org/x/net/html","fixversion":"v0.33.0"}`},
		{"symbol only", `{"repo":"x","branchOrCommit":"y","symbol":"Parse"}`},
	}

	for _, tt := range apiValidation {
		t.Run("manual/validation "+tt.name, func(t *testing.T) {
			resp, err := integrationClient.Post(testServerURL+"/callgraph", "application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestCgBinaryValidation(t *testing.T) {
	cgBin := buildIntegrationCG(t)
	t.Run("progress completion", func(t *testing.T) {
		t.Setenv("GVS_AI", "0")
		repo, _ := newLifecycleRepo(t, "v1.0.0")
		for _, algo := range []string{"rta", "vta", "cha", "static"} {
			t.Run(algo, func(t *testing.T) {
				cmd := exec.Command(cgBin, "-progress", "-algo", algo, "-library", fixtureLibrary,
					"-symbols", "Danger", "-fixversion", "v1.1.0", repo)
				var logs bytes.Buffer
				cmd.Stderr = &logs
				output, err := cmd.Output()
				if err != nil {
					t.Fatalf("scan failed: %v\n%s", err, &logs)
				}
				if !json.Valid(output) {
					t.Fatalf("invalid scanner JSON: %s", output)
				}
				if count := strings.Count(logs.String(), "Progress: 1/1 jobs completed (100.0%)"); count != 1 {
					t.Errorf("final progress appeared %d times, want 1:\n%s", count, &logs)
				}
			})
		}
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{"library only", []string{"-library", "golang.org/x/net/html", dir}},
		{"library and symbol only", []string{"-library", "golang.org/x/net/html", "-symbols", "Parse", dir}},
		{"symbol and fixversion only", []string{"-symbols", "Parse", "-fixversion", "v0.33.0", dir}},
		{"fixversion only", []string{"-fixversion", "v0.33.0", dir}},
		{"library and fixversion only", []string{"-library", "golang.org/x/net/html", "-fixversion", "v0.33.0", dir}},
		{"symbol only", []string{"-symbols", "Parse", dir}},
		{"no args", []string{}},
		{"cve only no dir", []string{"CVE-2024-45338"}},
		{"invalid directory", []string{"CVE-2024-45338", "/nonexistent/path"}},
		{"manual no directory", []string{"-library", "golang.org/x/net/html", "-symbols", "Parse", "-fixversion", "v0.33.0"}},
		{"manual too many args", []string{"-library", "golang.org/x/net/html", "-symbols", "Parse", "-fixversion", "v0.33.0", "CVE-2024-45338", dir, "extra"}},
		{"invalid algo", []string{"-algo", "invalid", "CVE-2024-45338", dir}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(cgBin, tt.args...)
			cmd.Env = os.Environ()
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("expected CLI validation exit, got %v: %s", err, out)
			}
			if exitErr.ExitCode() != 1 {
				t.Errorf("exit code = %d, want 1: %s", exitErr.ExitCode(), out)
			}
			want := "all three fields are mandatory"
			switch tt.name {
			case "no args", "cve only no dir", "manual no directory", "manual too many args":
				want = "Usage:"
			case "invalid directory":
				want = "Invalid directory:"
			case "invalid algo":
				want = "Invalid algorithm"
			}
			if !strings.Contains(string(out), want) {
				t.Errorf("diagnostic = %q, want %q", out, want)
			}
		})
	}
}

func assertResponseContract(t *testing.T, output cgOutput, request map[string]interface{}) {
	t.Helper()
	cve, _ := request["cve"].(string)
	if output.CVE != cve {
		t.Errorf("CVE = %q, want %q", output.CVE, cve)
	}
	if output.Repository != request["repo"] {
		t.Errorf("Repository = %q, want %q", output.Repository, request["repo"])
	}
	// A commit checkout reports its abbreviated HEAD rather than a branch name.
	branch, _ := request["branchOrCommit"].(string)
	if output.Branch != branch && !(len(output.Branch) >= 7 && strings.HasPrefix(branch, output.Branch)) {
		t.Errorf("Branch = %q, want branch or abbreviated commit %q", output.Branch, branch)
	}
	var want map[string][]string
	if library, manual := request["library"].(string); manual {
		symbols := strings.Split(request["symbol"].(string), ",")
		for i := range symbols {
			symbols[i] = strings.TrimSpace(symbols[i])
		}
		want = map[string][]string{library: symbols}
		if cve == "" && output.GoCVE != "MANUAL-SCAN" {
			t.Errorf("GoCVE = %q, want MANUAL-SCAN", output.GoCVE)
		}
	} else {
		data, err := os.ReadFile(filepath.Join("testdata", "advisories", output.GoCVE+".json"))
		if err != nil {
			t.Fatalf("expected advisory snapshot: %v", err)
		}
		if err := json.Unmarshal(data, &want); err != nil {
			t.Fatal(err)
		}
	}
	got := make(map[string][]string)
	for pkg, details := range output.AffectedImports {
		got[pkg] = slices.Clone(details.Symbols)
		slices.Sort(got[pkg])
	}
	for pkg := range want {
		slices.Sort(want[pkg])
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("affected package/symbol set = %v, want %v", got, want)
	}
	usedSymbols := 0
	for dir, pkgs := range output.UsedImports {
		if _, ok := output.Files[dir]; !ok {
			t.Errorf("UsedImports has unexpected module %q", dir)
		}
		for pkg, details := range pkgs {
			if _, ok := want[pkg]; !ok {
				t.Errorf("unexpected used package %q", pkg)
			}
			usedSymbols += len(details.Symbols)
		}
	}
	if output.IsVulnerable == "true" && usedSymbols > 0 && len(output.GraphPaths) == 0 {
		t.Error("reachable vulnerable symbols have no graph output")
	}
	if output.IsVulnerable != "true" && len(output.GraphPaths) != 0 {
		t.Errorf("non-vulnerable result has graph output: %v", output.GraphPaths)
	}
	seen := map[string]bool{}
	for _, url := range output.GraphPaths {
		if !strings.HasPrefix(url, testServerURL+"/graph/") {
			t.Errorf("invalid graph URL %q", url)
			continue
		}
		if seen[url] {
			t.Errorf("duplicate graph URL %q", url)
		}
		seen[url] = true
		resp, err := integrationClient.Get(url)
		if err != nil {
			t.Error(err)
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Error(err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("graph status = %d: %s", resp.StatusCode, data)
			continue
		}
		var svg struct{ XMLName xml.Name }
		if err := xml.Unmarshal(data, &svg); err != nil || svg.XMLName.Local != "svg" {
			t.Errorf("invalid SVG at %s: %v", url, err)
		}
	}
	if request["repo"] == testDataRepo && !strings.HasPrefix(branch, "reflection-") && len(output.ReflectionRisks) != 0 {
		t.Errorf("unexpected reflection risks: %+v", output.ReflectionRisks)
	}
}

func TestCallgraphMatrixIntegration(t *testing.T) {
	startTestServer(t)
	for _, tc := range []struct{ branch, version, status string }{
		{"vuln-replace-directive", "v0.23.0", "true"},
		{"patched-replace-directive", "v0.31.0", "false"},
		{"vuln-build-constraint", "v0.23.0", "true"},
		{"vuln-untidy-gomod", "v0.31.0", "false"},
	} {
		t.Run("crypto/"+tc.branch, func(t *testing.T) {
			out := pollCallgraphResult(t, testDataRepo, tc.branch, "CVE-2024-45337", "rta")
			if out.IsVulnerable != tc.status {
				t.Errorf("status = %s, want %s", out.IsVulnerable, tc.status)
			}
			if len(out.Errors) != 0 {
				t.Errorf("errors: %v", out.Errors)
			}
			var fixes []string
			if tc.status == "true" {
				fixes = []string{"go get golang.org/x/crypto@v0.31.0", "go mod tidy", "go mod vendor"}
			}
			assertUsedImport(t, out, ".", "golang.org/x/crypto/ssh", tc.version, fixes,
				[]string{"(*golang.org/x/crypto/ssh.connection).serverAuthenticate", "NewServerConn", "connection.serverAuthenticate"}, "", "")
			assertAffectedImport(t, out, "golang.org/x/crypto/ssh", "non-stdlib", []string{"v0.31.0"})
		})
	}
	for _, branch := range []string{"vuln-replace-directive", "patched-replace-directive", "vuln-indirect-dep", "vuln-build-constraint", "vuln-untidy-gomod", "multi-module"} {
		t.Run("manual/"+branch, func(t *testing.T) {
			out := pollCallgraphManualResult(t, testDataRepo, branch, "golang.org/x/net/html", "Parse", "v0.33.0", "rta")
			want := "true"
			if branch == "patched-replace-directive" || branch == "vuln-untidy-gomod" {
				want = "false"
			}
			if branch == "vuln-build-constraint" {
				want = "unknown"
			}
			if out.IsVulnerable != want {
				t.Errorf("status = %q, want %q", out.IsVulnerable, want)
			}
			if want == "unknown" {
				if !strings.Contains(strings.Join(out.Errors, "\n"), "Need manual analysis") {
					t.Errorf("missing build constraint diagnostic: %v", out.Errors)
				}
			} else if len(out.Errors) > 0 {
				t.Errorf("errors: %v", out.Errors)
			}
			dirs := []string{"."}
			if branch == "multi-module" {
				dirs = []string{"svc-a", "svc-b"}
			}
			if len(out.UsedImports) != len(dirs) {
				t.Errorf("used module count = %d, want %d", len(out.UsedImports), len(dirs))
			}
			for _, dir := range dirs {
				version, replacement := "v0.23.0", ""
				if branch == "vuln-untidy-gomod" {
					version = "v0.33.0"
				}
				var fixes []string
				if want == "true" {
					fixes = []string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"}
				}
				if dir == "svc-b" {
					version, fixes = "v0.33.0", nil
				}
				if branch == "vuln-replace-directive" {
					replacement = "v0.24.0"
					fixes[0] = "go mod edit -replace=golang.org/x/net=golang.org/x/net@v0.33.0"
				}
				if branch == "patched-replace-directive" {
					replacement = "v0.33.0"
				}
				replacementModule := ""
				if replacement != "" {
					replacementModule = "golang.org/x/net"
				}
				symbols := []string{"Parse"}
				if want == "unknown" {
					symbols = []string{}
				}
				assertUsedImport(t, out, dir, "golang.org/x/net/html", version, fixes, symbols, replacementModule, replacement)
			}
			assertAffectedImport(t, out, "golang.org/x/net/html", "non-stdlib", []string{"v0.33.0"})
		})
	}
	for _, algo := range []string{"vta", "cha", "static"} {
		for _, tc := range []struct{ branch, status string }{
			{"patched-single-range", "false"}, {"vuln-indirect-dep", "true"},
			{"patched-replace-directive", "false"}, {"vuln-build-constraint", "unknown"}, {"multi-module", "true"},
		} {
			t.Run(algo+"/"+tc.branch, func(t *testing.T) {
				runCallgraphTest(t, testDataRepo, tc.branch, "CVE-2024-45338", algo, tc.status, tc.status == "unknown")
			})
		}
	}
}

const fixtureLibrary = "example.com/vulnerable"

type fixtureModule struct{ dir, scenario, version string }

// Lifecycle tests need private repositories they can remove or modify without
// changing the shared scanner fixtures on GitHub.
func newLifecycleRepo(t *testing.T, version string) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	if err := os.MkdirAll(filepath.Join(dir, "dep"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"go.mod":            fmt.Sprintf("module example.com/app\n\ngo 1.22.0\n\nrequire example.com/vulnerable %s\nreplace example.com/vulnerable => ./dep\n", version),
		"main.go":           "package main\nimport \"example.com/vulnerable\"\nfunc main() { println(vulnerable.Danger()) }\n",
		"dep/go.mod":        "module example.com/vulnerable\n\ngo 1.22.0\n",
		"dep/vulnerable.go": "package vulnerable\nfunc Danger() int { return 42 }\nfunc Safe() int { return 0 }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	gitFixture(t, dir, "init", "-b", "main")
	gitFixture(t, dir, "add", ".")
	gitFixture(t, dir, "-c", "user.name=GVS Tests", "-c", "user.email=tests@example.com", "-c", "commit.gpgsign=false", "commit", "-m", "integration fixture")
	return dir, strings.TrimSpace(gitFixture(t, dir, "rev-parse", "HEAD"))
}

func gitFixture(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func fixtureRequest(repo, ref, algo string) map[string]interface{} {
	return map[string]interface{}{"repo": repo, "branchOrCommit": ref, "library": fixtureLibrary, "symbol": "Danger", "fixversion": "v1.1.0", "algo": algo}
}

func TestCallgraphFixturesIntegration(t *testing.T) {
	startTestServer(t)
	for _, tc := range []struct{ branch, scenario, version string }{
		{"reachability-direct", "direct", "v1.0.0"}, {"reachability-patched", "direct", "v1.1.0"},
		{"unreachable-symbol", "unreachable", "v1.0.0"}, {"test-only-symbol", "only-tests", "v1.0.0"},
		{"dependency-not-imported", "absent", "v1.0.0"}, {"interface-dispatch", "interface", "v1.0.0"},
		{"init-call", "direct", "v1.0.0"}, {"goroutine-call", "direct", "v1.0.0"}, {"deferred-call", "direct", "v1.0.0"}, {"generic-call", "direct", "v1.0.0"},
		{"reflection-helper", "reflection", "v1.0.0"},
		{"callback-dispatch", "callback", "v1.0.0"}, {"reflection-call", "reflection", "v1.0.0"}, {"unsafe-call", "unsafe", "v1.0.0"},
	} {
		t.Run(tc.branch, func(t *testing.T) {
			for _, algo := range []string{"rta", "vta", "cha", "static"} {
				t.Run(algo, func(t *testing.T) {
					out := pollCallgraphRequest(t, fixtureRequest(testDataRepo, tc.branch, algo))
					reachable := tc.scenario != "unreachable" && tc.scenario != "only-tests" && tc.scenario != "absent"
					if algo == "static" && (tc.scenario == "interface" || tc.scenario == "callback" || tc.scenario == "reflection") {
						reachable = false
					}
					// Only RTA models calls through reflect.Value.Call.
					if tc.scenario == "reflection" && algo != "rta" {
						reachable = false
					}
					want := "false"
					if reachable && tc.version == "v1.0.0" {
						want = "true"
					}
					if out.IsVulnerable != want {
						t.Errorf("status = %q, want %q", out.IsVulnerable, want)
					}
					if len(out.Errors) != 0 {
						t.Errorf("errors: %v", out.Errors)
					}
					if out.Unsafe != (tc.scenario == "unsafe") {
						t.Errorf("unsafe = %v", out.Unsafe)
					}
					if out.Reflect != (tc.scenario == "reflection") {
						t.Errorf("reflect = %v", out.Reflect)
					}
					assertAffectedImport(t, out, fixtureLibrary, "non-stdlib", []string{"v1.1.0"})
					if reachable {
						var fixes []string
						if want == "true" {
							fixes = []string{"go get example.com/vulnerable@v1.1.0", "go mod tidy", "go mod vendor"}
						}
						assertUsedImport(t, out, ".", fixtureLibrary, tc.version, fixes, []string{"Danger"}, "", "")
					} else if tc.scenario == "absent" || tc.scenario == "only-tests" {
						if len(out.UsedImports) != 0 {
							t.Errorf("absent package reported as present: %v", out.UsedImports)
						}
					} else {
						assertUsedImport(t, out, ".", fixtureLibrary, tc.version, nil, []string{}, "", "")
					}
					if tc.scenario == "reflection" {
						found := map[string]bool{}
						for _, risk := range out.ReflectionRisks {
							if risk.Association != "target_linked" || risk.Symbol != "Danger" || risk.Package != fixtureLibrary || risk.Confidence != "medium" {
								t.Errorf("incorrect reflection target or confidence: %+v", risk)
							}
							if !(strings.Contains(risk.Location, "main.go:") || strings.Contains(risk.Location, "helper.go:")) || len(risk.Evidence) == 0 {
								t.Errorf("reflection evidence missing source attribution: %+v", risk)
							}
							if found[risk.Type] {
								t.Errorf("duplicate reflection observation: %+v", risk)
							}
							found[risk.Type] = true
						}
						if len(out.ReflectionRisks) != 2 || !found["value_of"] || !found["reflection_call"] {
							t.Errorf("expected affected value reference and reflected invocation: %+v", out.ReflectionRisks)
						}
					} else if len(out.ReflectionRisks) != 0 {
						t.Errorf("unexpected reflection risks: %v", out.ReflectionRisks)
					}
				})
			}
		})
	}
	for _, tc := range []struct {
		name, status string
		modules      []fixtureModule
	}{
		{"all-patched", "false", []fixtureModule{{"a", "direct", "v1.1.0"}, {"b", "direct", "v1.1.0"}}},
		{"vulnerable-patched", "true", []fixtureModule{{"a", "direct", "v1.0.0"}, {"b", "direct", "v1.1.0"}}},
		{"patched-unknown", "unknown", []fixtureModule{{"a", "direct", "v1.1.0"}, {"b", "unknown", "v1.0.0"}}},
		{"unknown-patched", "unknown", []fixtureModule{{"a", "unknown", "v1.0.0"}, {"b", "direct", "v1.1.0"}}},
		{"vulnerable-unknown", "true", []fixtureModule{{"a", "direct", "v1.0.0"}, {"b", "unknown", "v1.0.0"}}},
		{"unknown-vulnerable", "true", []fixtureModule{{"a", "unknown", "v1.0.0"}, {"b", "direct", "v1.0.0"}}},
		{"all-unknown", "unknown", []fixtureModule{{"a", "unknown", "v1.0.0"}, {"b", "unknown", "v1.0.0"}}},
	} {
		t.Run("multi-module/"+tc.name, func(t *testing.T) {
			out := pollCallgraphRequest(t, fixtureRequest(testDataRepo, "multi-module-"+tc.name, "rta"))
			if out.IsVulnerable != tc.status {
				t.Errorf("status = %q, want %q", out.IsVulnerable, tc.status)
			}
			unknowns := 0
			for _, mod := range tc.modules {
				symbols := []string{"Danger"}
				var fixes []string
				if mod.scenario == "unknown" {
					unknowns++
					if _, ok := out.UsedImports[mod.dir]; ok {
						t.Errorf("excluded imports reported as present in module %s", mod.dir)
					}
					continue
				} else if mod.version == "v1.0.0" {
					fixes = []string{"go get example.com/vulnerable@v1.1.0", "go mod tidy", "go mod vendor"}
				}
				assertUsedImport(t, out, mod.dir, fixtureLibrary, mod.version, fixes, symbols, "", "")
			}
			if len(out.UsedImports) != len(tc.modules)-unknowns {
				t.Errorf("used modules = %v", out.UsedImports)
			}
			if len(out.Errors) != unknowns {
				t.Errorf("errors = %v, want %d build constraint diagnostics", out.Errors, unknowns)
			}
			for _, err := range out.Errors {
				if !strings.Contains(err, "Need manual analysis") {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
	t.Run("commit checkout", func(t *testing.T) {
		// Pinned commit of the reachability-direct fixture.
		out := pollCallgraphRequest(t, fixtureRequest(testDataRepo, "f426435e1da63f0dd405068fbe7a571ff06d9876", "rta"))
		if out.IsVulnerable != "true" || len(out.Errors) != 0 {
			t.Fatalf("commit scan: %+v", out)
		}
	})
}

type integrationTask struct {
	Status TaskStatus      `json:"status"`
	Output json.RawMessage `json:"output"`
	Error  string          `json:"error"`
	Logs   string          `json:"logs"`
}

func postIntegrationJSON(t *testing.T, endpoint string, body any, wantStatus int, output any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := integrationClient.Post(testServerURL+endpoint, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s status = %d, want %d: %s", endpoint, resp.StatusCode, wantStatus, data)
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			t.Fatalf("%s JSON: %v: %s", endpoint, err, data)
		}
	}
}

func submitIntegrationTask(t *testing.T, request map[string]interface{}) string {
	t.Helper()
	waitIntegrationIdle(t)
	var out struct {
		TaskID string `json:"taskId"`
	}
	postIntegrationJSON(t, "/callgraph", request, http.StatusOK, &out)
	if out.TaskID == "" {
		t.Fatal("empty task ID")
	}
	return out.TaskID
}

func awaitIntegrationTask(t *testing.T, id string) integrationTask {
	t.Helper()
	var task integrationTask
	awaitIntegrationCondition(t, "task completion", func() bool {
		postIntegrationJSON(t, "/status", map[string]string{"taskId": id}, http.StatusOK, &task)
		return task.Status == StatusCompleted || task.Status == StatusFailed || task.Status == StatusCancelled
	})
	waitIntegrationIdle(t)
	// Re-read after the worker has exited to catch cancellation being overwritten.
	postIntegrationJSON(t, "/status", map[string]string{"taskId": id}, http.StatusOK, &task)
	return task
}

func awaitIntegrationCondition(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func writeIntegrationWrapper(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nset -eu\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestCallgraphLifecycleIntegration(t *testing.T) {
	startTestServer(t)
	t.Run("progress line IDs", func(t *testing.T) {
		repo, _ := newLifecycleRepo(t, "v1.0.0")
		request := fixtureRequest(repo, "main", "rta")
		request["symbol"] = "Safe"
		id := submitIntegrationTask(t, request)
		response, err := integrationClient.Get(testServerURL + "/progress/" + id)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		stream, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("progress stream: status=%d error=%v body=%s", response.StatusCode, err, stream)
		}
		task := awaitIntegrationTask(t, id)
		if task.Status != StatusCompleted {
			t.Fatalf("scan failed: %+v", task)
		}
		lines := strings.Split(task.Logs, "\n")
		count := 0
		for _, event := range strings.Split(string(stream), "\n\n") {
			if !strings.HasPrefix(event, "id: scanner-") {
				continue
			}
			fields := strings.SplitN(event, "\n", 2)
			line, err := strconv.Atoi(strings.TrimPrefix(fields[0], "id: scanner-"))
			if err != nil || line < 1 || line > len(lines) || len(fields) != 2 {
				t.Fatalf("invalid event: %q", event)
			}
			if want := "data: " + strings.TrimSuffix(lines[line-1], "\r"); fields[1] != want {
				t.Errorf("line %d: event=%q, want %q", line, fields[1], want)
			}
			count++
		}
		if count == 0 {
			t.Fatal("no scanner line IDs received")
		}
	})
	repo, commit := newLifecycleRepo(t, "v1.0.0")
	request := fixtureRequest(repo, "main", "rta")
	realCG, err := exec.LookPath("cg")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("cache reuse and isolation", func(t *testing.T) {
		wrappers := t.TempDir()
		calls := filepath.Join(wrappers, "calls")
		writeIntegrationWrapper(t, wrappers, "cg", "echo scan >> "+shellQuote(calls)+"\nexec "+shellQuote(realCG)+" \"$@\"\n")
		t.Setenv("PATH", wrappers+string(os.PathListSeparator)+os.Getenv("PATH"))
		count := func() int { data, _ := os.ReadFile(calls); return strings.Count(string(data), "scan\n") }
		first := awaitIntegrationTask(t, submitIntegrationTask(t, request))
		if first.Status != StatusCompleted || count() != 1 {
			t.Fatalf("initial scan = %+v, calls = %d", first, count())
		}
		second := awaitIntegrationTask(t, submitIntegrationTask(t, request))
		if second.Status != StatusCompleted || count() != 1 {
			t.Fatalf("cache miss: %+v, calls = %d", second, count())
		}
		if !bytes.Equal(first.Output, second.Output) {
			t.Error("cached output differs")
		}
		if !strings.Contains(second.Logs, "Phase 1/6") {
			t.Errorf("cached progress logs missing: %q", second.Logs)
		}
		for _, change := range []struct{ field, value, status string }{
			{"algo", "static", "true"}, {"symbol", "Safe", "false"},
			{"cve", "GO-2000-0001", "true"},
			{"fixversion", "v1.0.0", "false"}, {"library", "example.com/absent", "false"},
			{"branchOrCommit", commit, "true"},
		} {
			t.Run(change.field, func(t *testing.T) {
				next := maps.Clone(request)
				next[change.field] = change.value
				before := count()
				task := awaitIntegrationTask(t, submitIntegrationTask(t, next))
				if task.Status != StatusCompleted || count() != before+1 {
					t.Fatalf("cache key collision: %+v, calls = %d", task, count())
				}
				var out cgOutput
				if err := json.Unmarshal(task.Output, &out); err != nil {
					t.Fatal(err)
				}
				if out.IsVulnerable != change.status || len(out.Errors) != 0 {
					t.Errorf("isolated scan: %+v", out)
				}
			})
		}
		otherRepo, _ := newLifecycleRepo(t, "v1.1.0")
		next := maps.Clone(request)
		next["repo"] = otherRepo
		before := count()
		task := awaitIntegrationTask(t, submitIntegrationTask(t, next))
		var out cgOutput
		if err := json.Unmarshal(task.Output, &out); err != nil {
			t.Fatal(err)
		}
		if task.Status != StatusCompleted || count() != before+1 || out.IsVulnerable != "false" {
			t.Fatalf("repository cache collision: %+v", task)
		}
	})

	for _, tc := range []struct{ name, field, value, diagnostic string }{
		{"clone failure", "repo", filepath.Join(t.TempDir(), "missing-repo"), "not publicly accessible"},
		{"branch failure", "branchOrCommit", "missing-branch", "clone"},
		{"commit failure", "branchOrCommit", strings.Repeat("a", 40), "checkout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := maps.Clone(request)
			bad[tc.field] = tc.value
			failed := awaitIntegrationTask(t, submitIntegrationTask(t, bad))
			if failed.Status != StatusFailed || !strings.Contains(failed.Error, tc.diagnostic) {
				t.Fatalf("failure = %+v", failed)
			}
			// Use a fresh repository so recovery cannot be satisfied by the cache.
			recoveryRepo, _ := newLifecycleRepo(t, "v1.1.0")
			recovered := awaitIntegrationTask(t, submitIntegrationTask(t, fixtureRequest(recoveryRepo, "main", "rta")))
			if recovered.Status != StatusCompleted {
				t.Fatalf("recovery = %+v", recovered)
			}
		})
	}

	t.Run("cancellation stops scanner and child process", func(t *testing.T) {
		cancellationRepo, _ := newLifecycleRepo(t, "v1.0.0")
		realGo, err := exec.LookPath("go")
		if err != nil {
			t.Fatal(err)
		}
		testBinary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		wrappers := t.TempDir()
		cgPID, goPID := filepath.Join(wrappers, "cg.pid"), filepath.Join(wrappers, "go.pid")
		writeIntegrationWrapper(t, wrappers, "cg", "echo $$ > "+shellQuote(cgPID)+"\nexec "+shellQuote(realCG)+" \"$@\"\n")
		writeIntegrationWrapper(t, wrappers, "go", "case \"$1\" in\nlist) exec "+shellQuote(testBinary)+" -test.run=^TestIntegrationBlockedGoProcess$ ;;\nesac\nexec "+shellQuote(realGo)+" \"$@\"\n")
		originalPath := os.Getenv("PATH")
		t.Setenv("PATH", wrappers+string(os.PathListSeparator)+originalPath)
		t.Setenv("GVS_TEST_CHILD", goPID)
		id := submitIntegrationTask(t, fixtureRequest(cancellationRepo, "main", "rta"))
		awaitIntegrationCondition(t, "scanner child to start", func() bool { _, err := os.Stat(goPID); return err == nil })
		readPID := func(path string) int {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		scannerPID, childPID := readPID(cgPID), readPID(goPID)
		// Also clean up on assertion failure, without touching unrelated processes.
		t.Cleanup(func() { _ = syscall.Kill(scannerPID, syscall.SIGKILL); _ = syscall.Kill(childPID, syscall.SIGKILL) })
		postIntegrationJSON(t, "/callgraph", request, http.StatusTooManyRequests, nil)
		progress, err := integrationClient.Get(testServerURL + "/progress/" + id)
		if err != nil {
			t.Fatal(err)
		}
		var cancelled map[string]string
		postIntegrationJSON(t, "/cancel", map[string]string{"taskId": id}, http.StatusOK, &cancelled)
		if cancelled["status"] != "cancelled" {
			t.Fatalf("cancel response = %v", cancelled)
		}
		logs, err := io.ReadAll(progress.Body)
		progress.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if progress.StatusCode != http.StatusOK || !strings.Contains(string(logs), "data:") {
			t.Errorf("progress stream = %d %s", progress.StatusCode, logs)
		}
		task := awaitIntegrationTask(t, id)
		if task.Status != StatusCancelled {
			t.Errorf("terminal status = %s, want cancelled: %s", task.Status, task.Error)
		}
		awaitIntegrationCondition(t, "scanner and child to exit", func() bool {
			return syscall.Kill(scannerPID, 0) == syscall.ESRCH && syscall.Kill(childPID, 0) == syscall.ESRCH
		})
		t.Setenv("PATH", originalPath)
		recovered := awaitIntegrationTask(t, submitIntegrationTask(t, fixtureRequest(cancellationRepo, "main", "rta")))
		if recovered.Status != StatusCompleted {
			t.Fatalf("scan after cancellation = %+v", recovered)
		}
		var out cgOutput
		if err := json.Unmarshal(recovered.Output, &out); err != nil {
			t.Fatal(err)
		}
		if out.IsVulnerable != "true" || len(out.Errors) != 0 {
			t.Errorf("cancelled result was cached: %+v", out)
		}
	})
}

// Executed only by the go shim, as a child of the real scanner. This blocks at
// a deterministic phase so the test can prove cancellation reaches subprocesses.
func TestIntegrationBlockedGoProcess(t *testing.T) {
	path := os.Getenv("GVS_TEST_CHILD")
	if path == "" {
		return
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		os.Exit(2)
	}
	for {
		fmt.Fprintln(os.Stderr, "waiting for cancellation")
		time.Sleep(time.Second)
	}
}

func TestCallgraphScanLogicIntegration(t *testing.T) {
	startTestServer(t)
	for _, tc := range []struct{ branch, status, version string }{
		{"broken-package", "unknown", "v1.0.0"},
		{"missing-dependency", "unknown", "v1.0.0"},
		{"selected-dependency-version", "false", "v1.1.0"},
		{"prerelease-version", "true", "v1.1.0-rc.1"},
		{"pseudo-version", "true", "v1.0.1-0.20260101000000-abcdefabcdef"},
	} {
		for _, algo := range []string{"rta", "vta", "cha", "static"} {
			t.Run(tc.branch+"/"+algo, func(t *testing.T) {
				out := pollCallgraphRequest(t, fixtureRequest(testDataRepo, tc.branch, algo))
				if out.IsVulnerable != tc.status {
					t.Errorf("status = %q, want %q", out.IsVulnerable, tc.status)
				}
				if tc.status == "unknown" {
					if !strings.Contains(strings.Join(out.Errors, "\n"), "load") {
						t.Errorf("missing package-load diagnostic: %v", out.Errors)
					}
					if len(out.UsedImports) != 0 {
						t.Errorf("failed load must not establish package presence: %v", out.UsedImports)
					}
					return
				} else if len(out.Errors) != 0 {
					t.Errorf("errors: %v", out.Errors)
				}
				symbols := []string{"Danger"}
				var fixes []string
				if tc.status == "true" {
					fixes = []string{"go get example.com/vulnerable@v1.1.0", "go mod tidy", "go mod vendor"}
				}
				assertUsedImport(t, out, ".", fixtureLibrary, tc.version, fixes, symbols, "", "")
			})
		}
	}
	t.Run("no fixed version", func(t *testing.T) {
		req := fixtureRequest(testDataRepo, "reachability-direct", "rta")
		req["fixversion"] = "Introduced in 1.0.0 - "
		out := pollCallgraphRequest(t, req)
		if out.IsVulnerable != "true" || len(out.Errors) != 0 {
			t.Fatalf("open range scan: %+v", out)
		}
		assertUsedImport(t, out, ".", fixtureLibrary, "v1.0.0", nil, []string{"Danger"}, "", "")
	})
	t.Run("replacement downgrade", func(t *testing.T) {
		out := pollCallgraphManualResult(t, testDataRepo, "replacement-downgrade", "golang.org/x/net/html", "Parse", "v0.33.0", "rta")
		if out.IsVulnerable != "true" || len(out.Errors) != 0 {
			t.Fatalf("downgrade scan: %+v", out)
		}
		assertUsedImport(t, out, ".", "golang.org/x/net/html", "v0.33.0", []string{"go mod edit -replace=golang.org/x/net=golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"}, []string{"Parse"}, "golang.org/x/net", "v0.24.0")
	})
	t.Run("fork replacement", func(t *testing.T) {
		out := pollCallgraphManualResult(t, testDataRepo, "fork-replacement", "github.com/dgrijalva/jwt-go", "Parse", "v3.2.1+incompatible", "rta")
		if out.IsVulnerable != "unknown" {
			t.Fatalf("fork scan: %+v", out)
		}
		if !strings.Contains(strings.Join(out.Errors, "\n"), "different module") {
			t.Errorf("missing fork diagnostic: %v", out.Errors)
		}
		assertUsedImport(t, out, ".", "github.com/dgrijalva/jwt-go", "v3.2.0+incompatible", nil, []string{"Parse"}, "github.com/golang-jwt/jwt", "v3.2.2+incompatible")
	})
	for _, algo := range []string{"rta", "vta", "cha", "static"} {
		t.Run("graph paths/"+algo, func(t *testing.T) {
			req := fixtureRequest(testDataRepo, "multi-symbol-paths", algo)
			req["symbol"] = "Other,Danger"
			out := pollCallgraphRequest(t, req)
			if out.IsVulnerable != "true" || len(out.Errors) != 0 || len(out.GraphPaths) != 2 {
				t.Fatalf("multi-symbol scan: %+v", out)
			}
			for _, graphURL := range out.GraphPaths {
				resp, err := integrationClient.Get(graphURL)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				decoder := xml.NewDecoder(resp.Body)
				var titles []string
				for {
					token, err := decoder.Token()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if start, ok := token.(xml.StartElement); ok && start.Name.Local == "title" {
						var title string
						if err := decoder.DecodeElement(&title, &start); err != nil {
							t.Fatal(err)
						}
						titles = append(titles, title)
					}
				}
				symbol, caller := "Danger", "alpha"
				if strings.Contains(graphURL, "-Other.svg") {
					symbol, caller = "Other", "beta"
				}
				wantEdge := "example.com/app." + caller + "->example.com/vulnerable." + symbol
				if !slices.Contains(titles, "example.com/vulnerable."+symbol) || !slices.Contains(titles, wantEdge) {
					t.Errorf("graph %s does not reach its reported symbol via %s: %v", graphURL, wantEdge, titles)
				}
			}
		})
	}
}

func TestCallgraphConcurrencyIntegration(t *testing.T) {
	startTestServer(t)
	for _, workers := range []string{"1", "4", "8"} {
		t.Run("workers="+workers, func(t *testing.T) {
			t.Setenv("WORKER_COUNT", workers)
			// Each count must execute the race-instrumented scanner, not reuse cached output.
			previousCache := cacheDir
			cacheDir = t.TempDir()
			t.Cleanup(func() { cacheDir = previousCache })
			for repetition := 0; repetition < 2; repetition++ {
				cacheDir = t.TempDir()
				out := pollCallgraphRequest(t, fixtureRequest(testDataRepo, "multi-module-vulnerable-patched", "rta"))
				if out.IsVulnerable != "true" || len(out.Errors) != 0 || len(out.UsedImports) != 2 {
					t.Fatalf("concurrent modules: %+v", out)
				}
			}
			// This advisory covers two packages sharing the same SSA build and result.
			out := pollCallgraphResult(t, testDataRepo, "vuln-multi-range", "GO-2023-2153", "rta")
			if out.IsVulnerable != "true" || len(out.Errors) != 0 || len(out.UsedImports["."]) != 2 {
				t.Fatalf("concurrent packages: %+v", out)
			}
		})
	}
}
