package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

var (
	scanMutex      sync.Mutex
	scanInProgress bool
)

// cloneRepo checks if the repo is public before cloning
func cloneRepo(repoURL, branch, cloneDir string) error {
	os.Setenv("GIT_TERMINAL_PROMPT", "0")

	checkCmd := exec.Command("git", "ls-remote", "--exit-code", repoURL)
	var checkStderr bytes.Buffer
	checkCmd.Stderr = &checkStderr

	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("repository is not publicly accessible: %s", checkStderr.String())
	}

	cmd := exec.Command("git", "clone", "--branch", branch, "--single-branch", repoURL, cloneDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("git clone failed: %v\n%s", err, stderr.String())
	}
	return nil
}

// findGoModDirs finds directories containing go.mod, excluding vendor
func findGoModDirs(root string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "vendor" {
			return filepath.SkipDir
		}
		if d.Name() == "go.mod" {
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})
	return dirs, err
}

// runGovulncheck executes the vulnerability check
func runGovulncheck(directory, target string) (string, int, error) {
	cmd := exec.Command("govulncheck", "-format", "sarif", "-C", directory, target)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	if err != nil && exitCode != 3 {
		log.Printf("govulncheck failed: %v\nSTDERR:\n%s", err, stderr.String())
		return stderr.String(), 1, fmt.Errorf("govulncheck failed: %v", err)
	}

	return out.String(), exitCode, nil
}

// scanHandler handles incoming scan requests
func scanHandler(w http.ResponseWriter, r *http.Request) {
	if scanInProgress {
		http.Error(w, `{"error": "Another scan is in progress. Please wait."}`, http.StatusTooManyRequests)
		return
	}

	scanMutex.Lock()
	scanInProgress = true
	defer func() {
		scanInProgress = false
		scanMutex.Unlock()
	}()

	startTime := time.Now()
	clientIP := r.RemoteAddr

	var scanRequest ScanRequest
	err := json.NewDecoder(r.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	log.Printf("Received request - Repo: %s, Branch: %s, Client IP: %s", scanRequest.Repo, scanRequest.Branch, clientIP)

	repoName := filepath.Base(scanRequest.Repo)
	cloneDir := filepath.Join("/tmp", repoName)
	_ = os.RemoveAll(cloneDir)

	err = cloneRepo(scanRequest.Repo, scanRequest.Branch, cloneDir)
	if err != nil {
		log.Printf("Clone failed for Repo: %s, Branch: %s, Error: %s", scanRequest.Repo, scanRequest.Branch, err.Error())
		response, _ := json.Marshal(ScanResponse{Success: false, ExitCode: 1, Error: err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	moduleDirs, err := findGoModDirs(cloneDir)
	if err != nil || len(moduleDirs) == 0 {
		log.Printf("No go.mod files found in Repo: %s", scanRequest.Repo)
		response, _ := json.Marshal(ScanResponse{Success: false, ExitCode: 1, Error: "No Go modules found"})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	var combinedOutput []map[string]interface{}
	finalExitCode := 0

	for _, modDir := range moduleDirs {
		output, exitCode, err := runGovulncheck(modDir, "./...")
		if exitCode > finalExitCode {
			finalExitCode = exitCode
		}

		if err != nil && exitCode != 3 {
			log.Printf("govulncheck failed in %s: %v", modDir, err)
			continue
		}

		var sarif Sarif
		err = json.Unmarshal([]byte(output), &sarif)
		if err != nil {
			log.Printf("Failed to parse govulncheck output in %s", modDir)
			continue
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

		var relativePath string
		if modDir == cloneDir {
			relativePath = repoName
		} else {
			relativePath = filepath.Join(repoName, strings.TrimPrefix(modDir, cloneDir+"/"))
		}

		combinedOutput = append(combinedOutput, map[string]interface{}{
			"directory": relativePath,
			"results":   findings,
		})
	}

	response, _ := json.Marshal(ScanResponse{
		Success:  true,
		ExitCode: finalExitCode,
		Output:   combinedOutput,
	})
	w.WriteHeader(http.StatusOK)
	w.Write(response)

	log.Printf("Request completed - Time Taken: %s", time.Since(startTime))
}

// healthHandler provides a simple health check endpoint
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
