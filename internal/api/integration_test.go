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
	Dir            []string `json:"Dir"`
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
	UsedImports     map[string]cgUsedImport     `json:"UsedImports"`
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

func assertUsedImport(t *testing.T, output cgOutput, pkg, currentVersion string, fixCommands []string) {
	t.Helper()
	ui, ok := output.UsedImports[pkg]
	if !ok {
		t.Errorf("UsedImports missing package %q", pkg)
		return
	}
	if ui.CurrentVersion != currentVersion {
		t.Errorf("UsedImports[%q].CurrentVersion = %q, want %q", pkg, ui.CurrentVersion, currentVersion)
	}
	if len(fixCommands) == 0 {
		if len(ui.FixCommands) > 0 {
			t.Errorf("UsedImports[%q].FixCommands = %v, want nil", pkg, ui.FixCommands)
		}
	} else {
		if !slices.Equal(ui.FixCommands, fixCommands) {
			t.Errorf("UsedImports[%q].FixCommands = %v, want %v", pkg, ui.FixCommands, fixCommands)
		}
	}
	if len(ui.Symbols) == 0 {
		t.Errorf("UsedImports[%q].Symbols is empty", pkg)
	}
	if output.IsVulnerable == "true" && len(ui.Dir) == 0 {
		t.Errorf("UsedImports[%q].Dir is empty", pkg)
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

func assertCommon(t *testing.T, output cgOutput, isVuln, goCVE, branch string) {
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
	if output.Files == nil {
		t.Error("Files is nil")
	}
	if len(output.Errors) > 0 {
		t.Errorf("Errors = %v, want nil", output.Errors)
	}
}

func TestCallgraphIntegration(t *testing.T) {
	startTestServer(t)

	// --- Full JSON validation tests ---

	t.Run("full/non-stdlib vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-single-range", "CVE-2024-45338", "rta")
		assertCommon(t, output, "true", "GO-2024-3333", "vuln-single-range")

		if output.Unsafe {
			t.Error("unsafe = true, want false")
		}
		if output.Reflect {
			t.Error("reflect = true, want false")
		}

		assertUsedImport(t, output, "golang.org/x/net/html", "v0.23.0",
			[]string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"})
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/non-stdlib patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-single-range", "CVE-2024-45338", "rta")
		assertCommon(t, output, "false", "GO-2024-3333", "patched-single-range")

		assertUsedImport(t, output, "golang.org/x/net/html", "v0.33.0", nil)
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	t.Run("full/stdlib multi-range vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-stdlib-multi-range", "CVE-2023-45288", "rta")
		assertCommon(t, output, "true", "GO-2024-2687", "vuln-stdlib-multi-range")

		assertUsedImport(t, output, "net/http", "v1.21.4",
			[]string{"go mod edit -go=1.21.9", "go mod tidy", "go mod vendor"})
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"1.21.9", "1.22.2"})
	})

	t.Run("full/stdlib second range vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-stdlib-second-range", "CVE-2023-45288", "rta")
		assertCommon(t, output, "true", "GO-2024-2687", "vuln-stdlib-second-range")

		assertUsedImport(t, output, "net/http", "v1.22.1",
			[]string{"go mod edit -go=1.22.2", "go mod tidy", "go mod vendor"})
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"1.21.9", "1.22.2"})
	})

	t.Run("full/stdlib between ranges patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-stdlib-between-ranges", "CVE-2023-45288", "rta")
		assertCommon(t, output, "false", "GO-2024-2687", "patched-stdlib-between-ranges")

		assertUsedImport(t, output, "net/http", "v1.21.9", nil)
		assertAffectedImport(t, output, "net/http", "stdlib",
			[]string{"1.21.9", "1.22.2"})
	})

	t.Run("full/grpc multi-range vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-multi-range", "GO-2023-2153", "rta")
		assertCommon(t, output, "true", "GO-2023-2153", "vuln-multi-range")

		assertUsedImport(t, output, "google.golang.org/grpc", "v1.57.0",
			[]string{"go get google.golang.org/grpc@v1.57.1", "go mod tidy", "go mod vendor"})
		assertAffectedImport(t, output, "google.golang.org/grpc", "non-stdlib",
			[]string{"v1.56.3 1.57.1 1.58.3"})
	})

	t.Run("full/grpc multi-range patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-multi-range", "GO-2023-2153", "rta")
		assertCommon(t, output, "false", "GO-2023-2153", "patched-multi-range")

		assertUsedImport(t, output, "google.golang.org/grpc", "v1.57.1", nil)
	})

	t.Run("full/grpc between ranges patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-multi-range-between", "GO-2023-2153", "rta")
		assertCommon(t, output, "false", "GO-2023-2153", "patched-multi-range-between")

		assertUsedImport(t, output, "google.golang.org/grpc", "v1.56.3", nil)
	})

	t.Run("full/replace directive vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-replace-directive", "CVE-2024-45338", "rta")
		assertCommon(t, output, "true", "GO-2024-3333", "vuln-replace-directive")

		assertUsedImport(t, output, "golang.org/x/net/html", "v0.23.0",
			[]string{"go mod edit -replace=golang.org/x/net=golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"})
	})

	t.Run("full/replace directive patched", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "patched-replace-directive", "CVE-2024-45338", "rta")
		assertCommon(t, output, "false", "GO-2024-3333", "patched-replace-directive")

		assertUsedImport(t, output, "golang.org/x/net/html", "v0.23.0", nil)
	})

	t.Run("full/indirect dep vulnerable", func(t *testing.T) {
		output := pollCallgraphResult(t, testDataRepo, "vuln-indirect-dep", "CVE-2024-45338", "rta")
		assertCommon(t, output, "true", "GO-2024-3333", "vuln-indirect-dep")

		assertUsedImport(t, output, "golang.org/x/net/html", "v0.23.0",
			[]string{"go get golang.org/x/net@v0.33.0", "go mod tidy", "go mod vendor"})
		assertAffectedImport(t, output, "golang.org/x/net/html", "non-stdlib",
			[]string{"v0.33.0"})
	})

	// --- IsVulnerable-only tests ---

	tests := []struct {
		name           string
		repo           string
		branchOrCommit string
		cve            string
		algo           string
		expected       string
		expectErrors   bool
	}{
		// CVE-2024-45337: golang.org/x/crypto/ssh
		{
			name:           "x/crypto single range vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "vuln-single-range",
			cve:            "CVE-2024-45337",
			algo:           "rta",
			expected:       "true",
		},
		{
			name:           "x/crypto single range patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-single-range",
			cve:            "CVE-2024-45337",
			algo:           "rta",
			expected:       "false",
		},

		// stdlib patched
		{
			name:           "stdlib multi-range patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-stdlib-multi-range",
			cve:            "CVE-2023-45288",
			algo:           "rta",
			expected:       "false",
		},

		// Multi-module
		{
			name:           "multi-module x/net vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "multi-module",
			cve:            "CVE-2024-45338",
			algo:           "rta",
			expected:       "true",
		},
		{
			name:           "multi-module x/crypto vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "multi-module",
			cve:            "CVE-2024-45337",
			algo:           "rta",
			expected:       "true",
		},

		// Not a Go repository
		{
			name:           "not a go repo",
			repo:           testDataRepo,
			branchOrCommit: "not-a-go-repo",
			cve:            "CVE-2024-45338",
			algo:           "rta",
			expected:       "unknown",
			expectErrors:   true,
		},

		// Algorithm variations
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

		// GOCVE ID input
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
