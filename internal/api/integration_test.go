package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestCallgraphIntegration(t *testing.T) {
	// Step 0: Clear cache
	t.Log("Clearing cache directory...")
	if err := os.RemoveAll("/tmp/gvs-cache"); err != nil && !os.IsNotExist(err) {
		t.Logf("Warning: Failed to clear cache: %v", err)
	}

	// Step 1: Build binaries
	t.Log("Building binaries with make...")
	buildCmd := exec.Command("make", "gvs", "cg")
	buildCmd.Dir = "../../" // Go to project root
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build binaries: %v", err)
	}

	// Step 2: Start gvs server
	t.Log("Starting gvs server on port 8087...")
	serverCmd := exec.Command("./bin/gvs")
	serverCmd.Dir = "../../" // Run from project root so bin/cg can be found
	serverCmd.Env = append(os.Environ(), "GVS_PORT=8087")
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Failed to start gvs server: %v", err)
	}

	// Ensure cleanup
	defer func() {
		t.Log("Killing gvs server...")
		if err := exec.Command("pkill", "-f", "./bin/gvs").Run(); err != nil {
			t.Logf("Warning: pkill failed: %v", err)
		}
		// Also try to kill by PID as backup
		if serverCmd.Process != nil {
			serverCmd.Process.Signal(syscall.SIGTERM)
		}
	}()

	// Wait for server to start
	t.Log("Waiting for server to be ready...")
	if err := waitForServer("http://localhost:8087/healthz", 30*time.Second); err != nil {
		t.Fatalf("Server did not start in time: %v", err)
	}

	// Step 3: Make POST request to /callgraph with non-vulnerable commit
	t.Log("Sending callgraph request for non-vulnerable commit...")
	requestBody := map[string]interface{}{
		"repo":           "https://github.com/openshift/metallb",
		"branchOrCommit": "3bc20ed6603faa47e087032bf7a6aef90911d903",
		"cve":            "CVE-2024-45339",
		"runFix":         false,
	}

	reqJSON, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(
		"http://localhost:8087/callgraph",
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

	// Step 4: Poll /status endpoint
	t.Log("Polling status endpoint...")
	var isVulnerable string
	maxAttempts := 540 // 9 minutes with 1 second intervals

	for i := 0; i < maxAttempts; i++ {
		statusReq := map[string]string{"taskId": taskID}
		statusJSON, err := json.Marshal(statusReq)
		if err != nil {
			t.Fatalf("Failed to marshal status request: %v", err)
		}

		statusResp, err := http.Post(
			"http://localhost:8087/status",
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

		t.Logf("Attempt %d: Status = %s", i+1, statusResult.Status)

		if statusResult.Status == "completed" {
			// Parse the output to get IsVulnerable
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

		// Wait before next poll
		time.Sleep(1 * time.Second)
	}

	if isVulnerable == "" {
		t.Fatal("Task did not complete within timeout")
	}

	// Step 5: Verify the result - this commit should be non-vulnerable
	t.Logf("Final result - IsVulnerable: %s", isVulnerable)

	// This commit should not be vulnerable
	if isVulnerable != "false" {
		t.Errorf("Expected IsVulnerable: false, got: %s", isVulnerable)
	}
}

func TestCallgraphIntegrationVulnerable(t *testing.T) {
	// Step 0: Clear cache
	t.Log("Clearing cache directory...")
	if err := os.RemoveAll("/tmp/gvs-cache"); err != nil && !os.IsNotExist(err) {
		t.Logf("Warning: Failed to clear cache: %v", err)
	}

	// Step 1: Build binaries
	t.Log("Building binaries with make...")
	buildCmd := exec.Command("make", "gvs", "cg")
	buildCmd.Dir = "../../" // Go to project root
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build binaries: %v", err)
	}

	// Step 2: Start gvs server
	t.Log("Starting gvs server on port 8087...")
	serverCmd := exec.Command("./bin/gvs")
	serverCmd.Dir = "../../" // Run from project root so bin/cg can be found
	serverCmd.Env = append(os.Environ(), "GVS_PORT=8087")
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Failed to start gvs server: %v", err)
	}

	// Ensure cleanup
	defer func() {
		t.Log("Killing gvs server...")
		if err := exec.Command("pkill", "-f", "./bin/gvs").Run(); err != nil {
			t.Logf("Warning: pkill failed: %v", err)
		}
		// Also try to kill by PID as backup
		if serverCmd.Process != nil {
			serverCmd.Process.Signal(syscall.SIGTERM)
		}
	}()

	// Wait for server to start
	t.Log("Waiting for server to be ready...")
	if err := waitForServer("http://localhost:8087/healthz", 30*time.Second); err != nil {
		t.Fatalf("Server did not start in time: %v", err)
	}

	// Step 3: Make POST request to /callgraph with vulnerable commit
	t.Log("Sending callgraph request for vulnerable commit...")
	requestBody := map[string]interface{}{
		"repo":           "https://github.com/openshift/metallb",
		"branchOrCommit": "aee829d4d0938e0e2dc5462f886e448e86544db1",
		"cve":            "CVE-2024-45339",
		"runFix":         false,
	}

	reqJSON, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(
		"http://localhost:8087/callgraph",
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

	// Step 4: Poll /status endpoint
	t.Log("Polling status endpoint...")
	var isVulnerable string
	maxAttempts := 540 // 9 minutes with 1 second intervals

	for i := 0; i < maxAttempts; i++ {
		statusReq := map[string]string{"taskId": taskID}
		statusJSON, err := json.Marshal(statusReq)
		if err != nil {
			t.Fatalf("Failed to marshal status request: %v", err)
		}

		statusResp, err := http.Post(
			"http://localhost:8087/status",
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

		t.Logf("Attempt %d: Status = %s", i+1, statusResult.Status)

		if statusResult.Status == "completed" {
			// Parse the output to get IsVulnerable
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

		// Wait before next poll
		time.Sleep(1 * time.Second)
	}

	if isVulnerable == "" {
		t.Fatal("Task did not complete within timeout")
	}

	// Step 5: Verify the result - this commit should be vulnerable
	t.Logf("Final result - IsVulnerable: %s", isVulnerable)

	// This commit should be vulnerable
	if isVulnerable != "true" {
		t.Errorf("Expected IsVulnerable: true, got: %s", isVulnerable)
	}
}

// waitForServer waits for the server to be ready by polling the health endpoint
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
