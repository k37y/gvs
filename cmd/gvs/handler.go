package main

import (
	"bufio"
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
	"github.com/k37y/gvs"
)

var (
	scanMutex      sync.Mutex
	scanInProgress bool
)

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
		w.Write(cachedData)
		log.Print("Retrieved from cache")
		return
	}

	repoName := filepath.Base(scanRequest.Repo)
	cloneDir := filepath.Join("/tmp", repoName)
	_ = os.RemoveAll(cloneDir)

	err = gvs.CloneRepo(scanRequest.Repo, scanRequest.Branch, cloneDir)
	if err != nil {
		log.Printf("Clone failed for Repo: %s, Branch: %s, Error: %s", scanRequest.Repo, scanRequest.Branch, err.Error())
		response, _ := json.Marshal(gvs.ScanResponse{Success: false, ExitCode: 1, Error: err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	moduleDirs, err := gvs.FindGoModDirs(cloneDir)
	if err != nil || len(moduleDirs) == 0 {
		log.Printf("No go.mod files found in Repo: %s", scanRequest.Repo)
		response, _ := json.Marshal(gvs.ScanResponse{Success: false, ExitCode: 1, Error: "No Go modules found"})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	var combinedOutput []map[string]interface{}
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

	response, _ := json.Marshal(gvs.ScanResponse{
		Success:  true,
		ExitCode: finalExitCode,
		Output:   combinedOutput,
	})
	w.WriteHeader(http.StatusOK)
	w.Write(response)

	if err = saveCacheToDisk(cacheKey, response); err != nil {
		log.Printf("Error saving the cache to disk: %v", err)
	}

	log.Printf("Request completed - Time Taken: %s", time.Since(startTime))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func sseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	repo := r.URL.Query().Get("repo")
	branch := r.URL.Query().Get("branch")
	cve := r.URL.Query().Get("cve")

	if repo == "" || branch == "" || cve == "" {
		http.Error(w, "Missing query parameters", http.StatusBadRequest)
		return
	}

	repoName := filepath.Base(repo)
	cloneDir := filepath.Join("/tmp", repoName)
	_ = os.RemoveAll(cloneDir)

	err := gvs.CloneRepo(repo, branch, cloneDir)
	if err != nil {
		fmt.Fprintf(w, "data: Clone failed: %s\n\n", err.Error())
		flusher.Flush()
		return
	}

	cmd := exec.Command("bash", "hack/callgraph.sh", cve, cloneDir)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprint(w, "data: Failed to get stdout\n\n")
		flusher.Flush()
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprint(w, "data: Failed to start script\n\n")
		flusher.Flush()
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(w, "data: %s\n\n", line)
		flusher.Flush()
	}

	cmd.Wait()
	fmt.Fprint(w, "data: Completed!\n\n")
	flusher.Flush()
}
