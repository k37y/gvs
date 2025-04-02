package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// ScanRequest represents the input JSON for scanning a repo
type ScanRequest struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

// ScanResponse represents the API response
type ScanResponse struct {
	Success  bool        `json:"success"`
	ExitCode int         `json:"exit_code"`
	Output   interface{} `json:"output,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// SARIF struct to parse govulncheck output
type Sarif struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		} `json:"results"`
	} `json:"runs"`
}

func cloneRepo(repoURL, branch, cloneDir string) error {
	cmd := exec.Command("git", "clone", "--branch", branch, "--single-branch", repoURL, cloneDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("git clone failed: %v\n%s", err, stderr.String())
	}

	return nil
}

func runGovulncheck(directory, target string) (string, int, error) {
	cmd := exec.Command("govulncheck", "-format", "sarif", "-C", directory, target)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := cmd.ProcessState.ExitCode()

	if err != nil && exitCode != 3 {
		log.Printf("govulncheck failed: %v\nSTDERR:\n%s", err, stderr.String())
		return stderr.String(), exitCode, fmt.Errorf("govulncheck failed: %v", err)
	}

	return out.String(), exitCode, nil
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	clientIP := r.RemoteAddr

	var scanRequest ScanRequest
	err := json.NewDecoder(r.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	log.Printf("Received request - Repo: %s, Branch: %s, Client IP: %s", scanRequest.Repo, scanRequest.Branch, clientIP)

	cloneDir := "/tmp/repo_scan"
	target := "./..."

	_ = os.RemoveAll(cloneDir)

	err = cloneRepo(scanRequest.Repo, scanRequest.Branch, cloneDir)
	if err != nil {
		log.Printf("Clone failed for Repo: %s, Branch: %s, Error: %s", scanRequest.Repo, scanRequest.Branch, err.Error())
		response, _ := json.Marshal(ScanResponse{Success: false, Error: err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	output, exitCode, err := runGovulncheck(cloneDir, target)
	if err != nil && exitCode != 3 {
		log.Printf("Govulncheck failed for Repo: %s, Branch: %s, Exit Code: %d, Error: %s", scanRequest.Repo, scanRequest.Branch, exitCode, err.Error())
		response, _ := json.Marshal(ScanResponse{Success: false, ExitCode: exitCode, Error: err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	var sarif Sarif
	err = json.Unmarshal([]byte(output), &sarif)
	if err != nil {
		log.Printf("Failed to parse govulncheck output for Repo: %s, Branch: %s", scanRequest.Repo, scanRequest.Branch)
		response, _ := json.Marshal(ScanResponse{Success: false, Error: "Failed to parse govulncheck output"})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	var findings []map[string]interface{}
	for _, run := range sarif.Runs {
		for _, result := range run.Results {
			findings = append(findings, map[string]interface{}{
				"ruleId":  result.RuleID,
				"message": result.Message.Text,
			})
		}
	}

	response, _ := json.Marshal(ScanResponse{Success: true, ExitCode: exitCode, Output: findings})
	w.WriteHeader(http.StatusOK)
	w.Write(response)

	timeTaken := time.Since(startTime)
	log.Printf("Request completed - Time Taken: %s", timeTaken)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	os.Setenv("GOCACHE", "/tmp/go-build")
	os.MkdirAll("/tmp/go-build", os.ModePerm)
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.Handle("/", http.FileServer(http.Dir("./")))
	port := "8082"
	fmt.Printf("Server started on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
