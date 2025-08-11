package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/k37y/gvs"
)

var (
	requestMutex sync.Mutex
	inProgress   bool
	taskStore    = make(map[string]*TaskResult)
	taskMutex    sync.Mutex
)

type TaskStatus string

const (
	StatusPending   TaskStatus = "pending"
	StatusRunning   TaskStatus = "running"
	StatusCompleted TaskStatus = "completed"
	StatusFailed    TaskStatus = "failed"
)

type TaskResult struct {
	Status TaskStatus `json:"status"`
	Output string     `json:"output,omitempty"`
	Error  string     `json:"error,omitempty"`
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if inProgress {
		http.Error(w, `{"error": "Another scan is in progress. Please wait."}`, http.StatusTooManyRequests)
		return
	}

	requestMutex.Lock()
	inProgress = true
	defer func() {
		inProgress = false
		requestMutex.Unlock()
	}()

	startTime := time.Now()
	clientIP := r.RemoteAddr

	var scanRequest gvs.ScanRequest
	err := json.NewDecoder(r.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	log.Printf("Received request - Repo: %s, Branch: %s, Client IP: %s", scanRequest.Repo, scanRequest.Branch, clientIP)

	cacheKey := scanRequest.Repo + "@" + scanRequest.Branch
	if cachedData, err := retrieveCacheFromDisk(cacheKey); err == nil {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(cachedData); err != nil {
			log.Printf("failed to write response: %v", err)
		}
		log.Print("Retrieved from cache")
		return
	}

	repoName := filepath.Base(scanRequest.Repo)
	cloneDir, err := os.MkdirTemp("", "gvc-"+path.Base(repoName)+"-*")
	if err != nil {
		log.Printf("failed to create temp dir: %v", err)
		response, _ := json.Marshal(gvs.ScanResponse{Success: false, ExitCode: 1, Error: err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write(response); err != nil {
			log.Printf("failed to write response: %v", err)
		}
		return
	}

	err = gvs.CloneRepo(scanRequest.Repo, scanRequest.Branch, cloneDir)
	if err != nil {
		log.Printf("Clone failed for Repo: %s, Branch: %s, Error: %s", scanRequest.Repo, scanRequest.Branch, err.Error())
		response, _ := json.Marshal(gvs.ScanResponse{Success: false, ExitCode: 1, Error: err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write(response); err != nil {
			log.Printf("failed to write response: %v", err)
		}
		return
	}

	moduleDirs, err := gvs.FindGoModDirs(cloneDir)
	if err != nil || len(moduleDirs) == 0 {
		log.Printf("No go.mod files found in Repo: %s", scanRequest.Repo)
		response, _ := json.Marshal(gvs.ScanResponse{Success: false, ExitCode: 1, Error: "No Go modules found"})
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write(response); err != nil {
			log.Printf("failed to write response: %v", err)
		}
		return
	}

	var combinedOutput []map[string]any
	finalExitCode := 0

	for _, modDir := range moduleDirs {
		output, exitCode, err := gvs.RunGovulncheck(modDir, "./...")
		if exitCode > finalExitCode {
			finalExitCode = exitCode
		}

		if err != nil && exitCode != 3 {
			log.Printf("govulncheck failed in %s: %v", modDir, err)
			continue
		}

		var sarif gvs.Sarif
		err = json.Unmarshal([]byte(output), &sarif)
		if err != nil {
			log.Printf("Failed to parse govulncheck output in %s", modDir)
			continue
		}

		var findings []map[string]any
		for _, run := range sarif.Runs {
			for _, result := range run.Results {
				findings = append(findings, map[string]any{
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

		combinedOutput = append(combinedOutput, map[string]any{
			"directory": relativePath,
			"results":   findings,
		})
	}

	response, _ := json.Marshal(gvs.ScanResponse{
		Success:  true,
		ExitCode: finalExitCode,
		Output:   combinedOutput,
	})
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		log.Printf("failed to write response: %v", err)
	}

	if err = saveCacheToDisk(cacheKey, response); err != nil {
		log.Printf("Error saving the cache to disk: %v", err)
	}

	log.Printf("Request completed - Time Taken: %s", time.Since(startTime))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

func callgraphHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo   string `json:"repo"`
		Branch string `json:"branch"`
		CVE    string `json:"cve"`
		RunFix bool   `json:"runFix"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	requestMutex.Lock()
	if inProgress {
		requestMutex.Unlock()
		writeJSONError(w, http.StatusTooManyRequests, "Another task is in progress")
		return
	}
	inProgress = true
	requestMutex.Unlock()

	taskId := fmt.Sprintf("%d", time.Now().UnixNano())

	taskMutex.Lock()
	taskStore[taskId] = &TaskResult{Status: StatusPending}
	taskMutex.Unlock()

	go func(taskId, repo, branch, cve string, runFix bool) {
		defer func() {
			requestMutex.Lock()
			inProgress = false
			requestMutex.Unlock()
		}()

		updateStatus := func(status TaskStatus, output, errMsg string) {
			taskMutex.Lock()
			defer taskMutex.Unlock()
			taskStore[taskId] = &TaskResult{Status: status, Output: output, Error: errMsg}
		}

		updateStatus(StatusRunning, "", "")

		cacheKey := fmt.Sprintf("%s@%s:%s:runFix=%t", repo, branch, cve, runFix)
		if cachedData, err := retrieveCacheFromDisk(cacheKey); err == nil {
			updateStatus(StatusCompleted, string(cachedData), "")
			log.Printf("[Task %s] Retrieved callgraph from cache", taskId)
			return
		}

		cloneDir, err := os.MkdirTemp("", "cg-"+path.Base(repo)+"-*")
		if err != nil {
			updateStatus(StatusFailed, "", fmt.Sprintf("failed to create temp dir: %v", err))
			return
		}

		log.Printf("[Task %s] Cloning repository %s (%s) ...", taskId, repo, branch)
		if err := gvs.CloneRepo(repo, branch, cloneDir); err != nil {
			updateStatus(StatusFailed, "", fmt.Sprintf("git clone failed: %v", err))
			return
		}
		log.Printf("[Task %s] Clone successful", taskId)

		log.Printf("[Task %s] Running cg ...", taskId)
		start := time.Now()
		var cmd *exec.Cmd
		if runFix {
			cmd = exec.Command("bin/cg", "-runfix", cve, cloneDir)
		} else {
			cmd = exec.Command("bin/cg", cve, cloneDir)
		}
		output, err := cmd.CombinedOutput()

		if err != nil {
			log.Printf("[Task %s] cg execution failed: %v", taskId, err)
			updateStatus(StatusFailed, string(output), err.Error())
			return
		}

		elapsed := time.Since(start)
		log.Printf("[Task %s] cg execution completed - Took %s", taskId, elapsed)
		updateStatus(StatusCompleted, string(output), "")

		if err := saveCacheToDisk(cacheKey, output); err != nil {
			log.Printf("[Task %s] Failed to save cache: %v", taskId, err)
		}
	}(taskId, req.Repo, req.Branch, req.CVE, req.RunFix)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"taskId": taskId}); err != nil {
		log.Printf("failed to write taskId response: %v", err)
	}
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskID string `json:"taskId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TaskID == "" {
		writeJSONError(w, http.StatusBadRequest, "Invalid or missing taskId")
		return
	}

	taskMutex.Lock()
	result, exists := taskStore[req.TaskID]
	taskMutex.Unlock()

	if !exists {
		writeJSONError(w, http.StatusNotFound, "Task not found")
		return
	}

	resp := map[string]any{
		"status": result.Status,
	}

	if result.Output != "" {
		var parsed any
		if err := json.Unmarshal([]byte(result.Output), &parsed); err == nil {
			resp["output"] = parsed
		} else {
			resp["output"] = result.Output
		}
	}

	if result.Error != "" {
		resp["error"] = result.Error
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to write status response: %v", err)
	}
}
