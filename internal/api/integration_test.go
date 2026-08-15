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
	"syscall"
	"testing"
	"time"
)

const (
	testServerPort = "8087"
	testServerURL  = "http://localhost:" + testServerPort
	testDataRepo   = "https://github.com/k37y/gvs-testdata"
)

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

func runCallgraphTest(t *testing.T, repo, branchOrCommit, cve, algo, expectedResult string) {
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

	var isVulnerable string
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
			var output struct {
				IsVulnerable string `json:"IsVulnerable"`
			}
			if err := json.Unmarshal(statusResult.Output, &output); err != nil {
				t.Fatalf("Failed to parse output: %v", err)
			}

			isVulnerable = output.IsVulnerable
			t.Logf("Task completed! IsVulnerable: %s", isVulnerable)
			break
		} else if statusResult.Status == "failed" {
			t.Fatalf("Task failed with error: %s", statusResult.Error)
		}

		time.Sleep(1 * time.Second)
	}

	if isVulnerable == "" {
		t.Fatal("Task did not complete within timeout")
	}

	if isVulnerable != expectedResult {
		t.Errorf("Expected IsVulnerable: %s, got: %s", expectedResult, isVulnerable)
	}
}

func TestCallgraphIntegration(t *testing.T) {
	startTestServer(t)

	tests := []struct {
		name           string
		repo           string
		branchOrCommit string
		cve            string
		algo           string
		expected       string
	}{
		// CVE-2024-45338: golang.org/x/net/html (single range, 0→0.33.0)
		{
			name:           "x/net single range vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "vuln-single-range",
			cve:            "CVE-2024-45338",
			algo:           "rta",
			expected:       "true",
		},
		{
			name:           "x/net single range patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-single-range",
			cve:            "CVE-2024-45338",
			algo:           "rta",
			expected:       "false",
		},
		{
			name:           "x/net replace directive vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "vuln-replace-directive",
			cve:            "CVE-2024-45338",
			algo:           "rta",
			expected:       "true",
		},

		// CVE-2024-45337: golang.org/x/crypto/ssh (single range, 0→0.31.0)
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

		// CVE-2023-45288: net/http stdlib (multi-range, 0→1.21.9, 1.22.0-0→1.22.2)
		{
			name:           "stdlib multi-range vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "vuln-stdlib-multi-range",
			cve:            "CVE-2023-45288",
			algo:           "rta",
			expected:       "true",
		},
		{
			name:           "stdlib multi-range patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-stdlib-multi-range",
			cve:            "CVE-2023-45288",
			algo:           "rta",
			expected:       "false",
		},
		{
			name:           "stdlib multi-range second range vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "vuln-stdlib-second-range",
			cve:            "CVE-2023-45288",
			algo:           "rta",
			expected:       "true",
		},
		{
			name:           "stdlib multi-range between ranges patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-stdlib-between-ranges",
			cve:            "CVE-2023-45288",
			algo:           "rta",
			expected:       "false",
		},

		// GO-2023-2153: google.golang.org/grpc (multi-range, 0→1.56.3, 1.57.0→1.57.1, 1.58.0→1.58.3)
		{
			name:           "grpc multi-range vulnerable",
			repo:           testDataRepo,
			branchOrCommit: "vuln-multi-range",
			cve:            "GO-2023-2153",
			algo:           "rta",
			expected:       "true",
		},
		{
			name:           "grpc multi-range patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-multi-range",
			cve:            "GO-2023-2153",
			algo:           "rta",
			expected:       "false",
		},
		{
			name:           "grpc multi-range between ranges patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-multi-range-between",
			cve:            "GO-2023-2153",
			algo:           "rta",
			expected:       "false",
		},

		// Multi-module: svc-a vulnerable, svc-b patched
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

		// Replace directive pointing to patched version
		{
			name:           "x/net replace directive patched",
			repo:           testDataRepo,
			branchOrCommit: "patched-replace-directive",
			cve:            "CVE-2024-45338",
			algo:           "rta",
			expected:       "false",
		},

		// Not a Go repository
		{
			name:           "not a go repo",
			repo:           testDataRepo,
			branchOrCommit: "not-a-go-repo",
			cve:            "CVE-2024-45338",
			algo:           "rta",
			expected:       "unknown",
		},

		// Algorithm variations (all should detect the same vulnerability)
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

		// GOCVE ID input (GO-2024-3333 == CVE-2024-45338)
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
			runCallgraphTest(t, tt.repo, tt.branchOrCommit, tt.cve, tt.algo, tt.expected)
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
