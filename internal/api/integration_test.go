//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	testServerPort = "8087"
	testServerURL  = "http://localhost:" + testServerPort
	testDataRepo   = "https://github.com/k37y/gvs-testdata"
)

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
	CVE             string                      `json:"CVE"`
	IsVulnerable    string                      `json:"IsVulnerable"`
	GoCVE           string                      `json:"GoCVE"`
	Repository      string                      `json:"Repository"`
	Branch          string                      `json:"Branch"`
	Errors          []string                    `json:"Errors"`
	Unsafe          bool                        `json:"unsafe"`
	Reflect         bool                        `json:"reflect"`
	Files           map[string][][]string       `json:"Files"`
	UsedImports     map[string]map[string]cgUsedImport `json:"UsedImports"`
	AffectedImports map[string]cgAffectedImport `json:"AffectedImports"`
}

func startTestServer(t *testing.T) {
	t.Helper()

	t.Log("Clearing cache directory...")
	if err := os.RemoveAll("/tmp/gvs-cache"); err != nil && !os.IsNotExist(err) {
		t.Logf("Warning: Failed to clear cache: %v", err)
	}

	t.Log("Building binaries with make...")
	buildCmd := exec.Command("make", "gvs", "cg")
	buildCmd.Dir = "../../"
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build binaries: %v", err)
	}

	t.Log("Starting gvs server on port " + testServerPort + "...")
	serverCmd := exec.Command("./bin/gvs")
	serverCmd.Dir = "../../"
	binDir, _ := filepath.Abs("../../bin")
	serverCmd.Env = append(os.Environ(),
		"GVS_PORT="+testServerPort,
		"PATH="+binDir+":"+os.Getenv("PATH"),
	)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Failed to start gvs server: %v", err)
	}

	t.Cleanup(func() {
		t.Log("Killing gvs server...")
		if err := exec.Command("pkill", "-f", "./bin/gvs").Run(); err != nil {
			t.Logf("Warning: pkill failed: %v", err)
		}
		if serverCmd.Process != nil {
			serverCmd.Process.Signal(syscall.SIGTERM)
		}
	})

	t.Log("Waiting for server to be ready...")
	if err := waitForServer(testServerURL+"/healthz", 30*time.Second); err != nil {
		t.Fatalf("Server did not start in time: %v", err)
	}
}

func pollCallgraphResult(t *testing.T, repo, branchOrCommit, cve, algo string) cgOutput {
	t.Helper()

	requestBody := map[string]interface{}{
		"repo":           repo,
		"branchOrCommit": branchOrCommit,
		"cve":            cve,
		"algo":           algo,
	}

	reqJSON, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(
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

	maxAttempts := 540
	for i := 0; i < maxAttempts; i++ {
		statusReq := map[string]string{"taskId": taskID}
		statusJSON, err := json.Marshal(statusReq)
		if err != nil {
			t.Fatalf("Failed to marshal status request: %v", err)
		}

		statusResp, err := http.Post(
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
			return output
		} else if statusResult.Status == "failed" {
			t.Fatalf("Task failed with error: %s", statusResult.Error)
		}

		time.Sleep(1 * time.Second)
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
	stdlibSymbols := []string{
		"(*net/http.Client).Do", "(*net/http.Client).Get",
		"(*net/http.Request).AddCookie", "(*net/http.Response).Cookies",
		"(*net/http.cancelTimerBody).Close", "(*net/http.cancelTimerBody).Read",
		"(net/http.Header).Del", "(net/http.Header).Get", "(net/http.Header).Set",
		"CanonicalHeaderKey", "Client.Do", "Client.Get",
		"Error", "Get", "Head",
		"Header.Del", "Header.Get", "Header.Set",
		"NewRequest", "NewRequestWithContext", "Redirect",
		"Request.AddCookie", "Response.Cookies", "SetCookie",
		"cancelTimerBody.Close", "cancelTimerBody.Read",
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
	})

	t.Run("full/grpc multi-range patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-multi-range", "GO-2023-2153", "rta")
		assertCommon(t, output, "false", "GO-2023-2153", "patched-multi-range", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.57.1", nil,
			grpcSymbols, "", "")
	})

	t.Run("full/grpc between ranges patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-multi-range-between", "GO-2023-2153", "rta")
		assertCommon(t, output, "false", "GO-2023-2153", "patched-multi-range-between", false, false, singleMainFiles, []string{"."})

		assertUsedImport(t, output, ".", "google.golang.org/grpc", "v1.56.3", nil,
			grpcSymbols, "", "")
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

	t.Run("full/untidy gomod false positive", func(t *testing.T) {
		// go.mod says x/net v0.23.0 but helper requires v0.33.0 (patched).
		// MVS resolves to v0.33.0, but findModuleInGoMod reads the original
		// go.mod and sees v0.23.0. This is a known false positive — safer
		// than a false negative. Users should run go mod tidy.
		output := pollCallgraphResult(t, testDataRepo, "vuln-untidy-gomod", "CVE-2024-45338", "rta")
		untidyFiles := map[string][][]string{".": {{"main.go"}}, "helper": nil}
		assertCommon(t, output, "true", "GO-2024-3333", "vuln-untidy-gomod", false, false, untidyFiles, []string{"."})

		assertUsedImport(t, output, ".", "golang.org/x/net/html", "v0.23.0",
			[]string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"},
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
}

func waitForServer(healthURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for server")
}
