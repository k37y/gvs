package api

import (
	"bufio"
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

	"github.com/k37y/gvs/internal/common"
	"github.com/k37y/gvs/pkg/cmd/gvc"
)

var (
	requestMutex    sync.Mutex
	inProgress      bool
	taskStore       = make(map[string]*TaskResult)
	taskMutex       sync.Mutex
	progressStreams = make(map[string]chan string)
	progressMutex   sync.Mutex
	counterURL      = os.Getenv("GVS_COUNTER_URL")
)

func trackAPICall() {
	if counterURL != "" {
		go func() {
			if resp, err := http.Get(counterURL); err == nil {
				resp.Body.Close()
			}
		}()
	}
}

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

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	trackAPICall()
	var req struct {
		Repo           string `json:"repo"`
		BranchOrCommit string `json:"branchOrCommit"`
		ShowProgress   bool   `json:"showProgress"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Convert to legacy format for backward compatibility
	scanRequest := gvc.ScanRequest{
		Repo:           req.Repo,
		BranchOrCommit: req.BranchOrCommit,
	}

	requestMutex.Lock()
	if inProgress {
		requestMutex.Unlock()
		writeJSONError(w, http.StatusTooManyRequests, "Another scan is in progress. Please wait.")
		return
	}
	inProgress = true
	requestMutex.Unlock()

	// Create task ID for progress tracking
	taskId := fmt.Sprintf("%d", time.Now().UnixNano())

	taskMutex.Lock()
	taskStore[taskId] = &TaskResult{Status: StatusPending}
	taskMutex.Unlock()

	// Always initialize progress stream
	progressMutex.Lock()
	progressStreams[taskId] = make(chan string, 100)
	progressMutex.Unlock()

	go func(taskId string, scanRequest gvc.ScanRequest) {
		defer func() {
			requestMutex.Lock()
			inProgress = false
			requestMutex.Unlock()

			// Always close progress stream
			progressMutex.Lock()
			if ch, exists := progressStreams[taskId]; exists {
				close(ch)
				delete(progressStreams, taskId)
			}
			progressMutex.Unlock()
		}()

		updateStatus := func(status TaskStatus, output, errMsg string) {
			taskMutex.Lock()
			defer taskMutex.Unlock()
			taskStore[taskId] = &TaskResult{Status: status, Output: output, Error: errMsg}
		}

		sendProgress := func(message string) {
			progressMutex.Lock()
			if ch, exists := progressStreams[taskId]; exists {
				select {
				case ch <- message:
				default:
					// Channel full, skip message
				}
			}
			progressMutex.Unlock()
		}

		updateStatus(StatusRunning, "", "")
		startTime := time.Now()
		clientIP := r.RemoteAddr

		log.Printf("[Task %s] Received request - Repo: %s, Branch: %s, Client IP: %s", taskId, scanRequest.Repo, scanRequest.BranchOrCommit, clientIP)

		cacheKey := scanRequest.Repo + "@" + scanRequest.BranchOrCommit
		if cachedData, err := RetrieveCacheFromDisk(cacheKey); err == nil {
			updateStatus(StatusCompleted, string(cachedData), "")
			log.Printf("[Task %s] Retrieved from cache", taskId)
			return
		}

		repoName := filepath.Base(scanRequest.Repo)
		cloneDir, err := os.MkdirTemp("", "gvc-"+path.Base(repoName)+"-*")
		if err != nil {
			log.Printf("[Task %s] failed to create temp dir: %v", taskId, err)
			updateStatus(StatusFailed, "", fmt.Sprintf("failed to create temp dir: %v", err))
			return
		}

		start := time.Now()
		log.Printf("[Task %s] Cloning repository %s (%s)...", taskId, scanRequest.Repo, scanRequest.BranchOrCommit)
		sendProgress(fmt.Sprintf("Cloning repository %s (%s)...", scanRequest.Repo, scanRequest.BranchOrCommit))
		err = common.CloneRepo(scanRequest.Repo, scanRequest.BranchOrCommit, cloneDir)
		if err != nil {
			log.Printf("[Task %s] Clone failed for Repo: %s, Branch: %s, Error: %s", taskId, scanRequest.Repo, scanRequest.BranchOrCommit, err.Error())
			updateStatus(StatusFailed, "", fmt.Sprintf("git clone failed: %v", err))
			return
		}
		log.Printf("[Task %s] Clone successful - Took %s", taskId, time.Since(start))
		sendProgress(fmt.Sprintf("Clone successful - Took %s", time.Since(start)))

		sendProgress("Discovering Go modules...")
		moduleDirs, err := common.FindGoModDirs(cloneDir)
		if err != nil || len(moduleDirs) == 0 {
			log.Printf("[Task %s] No go.mod files found in Repo: %s", taskId, scanRequest.Repo)
			updateStatus(StatusFailed, "", "No Go modules found")
			return
		}
		sendProgress(fmt.Sprintf("Found %d Go module(s)", len(moduleDirs)))

		var combinedOutput []map[string]any
		finalExitCode := 0

		for i, modDir := range moduleDirs {
			sendProgress(fmt.Sprintf("Running govulncheck on module %d/%d", i+1, len(moduleDirs)))
			output, exitCode, err := runGovulncheckWithProgress(modDir, "./...", sendProgress)
			if exitCode > finalExitCode {
				finalExitCode = exitCode
			}

			if err != nil && exitCode != 3 {
				log.Printf("[Task %s] govulncheck failed in %s: %v", taskId, modDir, err)
				continue
			}

			var sarif gvc.Sarif
			err = json.Unmarshal([]byte(output), &sarif)
			if err != nil {
				log.Printf("[Task %s] Failed to parse govulncheck output in %s", taskId, modDir)
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

		response, _ := json.Marshal(gvc.ScanResponse{
			Success:  true,
			ExitCode: finalExitCode,
			Output:   combinedOutput,
		})

		updateStatus(StatusCompleted, string(response), "")

		if err := SaveCacheToDisk(cacheKey, response); err != nil {
			log.Printf("[Task %s] Error saving the cache to disk: %v", taskId, err)
		}

		log.Printf("[Task %s] Request completed - Time Taken: %s", taskId, time.Since(startTime))
	}(taskId, scanRequest)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"taskId": taskId}); err != nil {
		log.Printf("failed to write taskId response: %v", err)
	}
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
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

func CallgraphHandler(w http.ResponseWriter, r *http.Request) {
	trackAPICall()
	var req struct {
		Repo           string `json:"repo"`
		BranchOrCommit string `json:"branchOrCommit"`
		CVE            string `json:"cve"`
		Library        string `json:"library"`
		Symbol         string `json:"symbol"`
		FixVersion     string `json:"fixversion"`
		Algo           string `json:"algo"`
		Graph          bool   `json:"graph"`
		ShowProgress   bool   `json:"showProgress"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate that library, symbol, and fixversion are all provided together
	libraryProvided := req.Library != ""
	symbolProvided := req.Symbol != ""
	fixversionProvided := req.FixVersion != ""
	anyManualScanFieldProvided := libraryProvided || symbolProvided || fixversionProvided

	if anyManualScanFieldProvided {
		if !libraryProvided || !symbolProvided || !fixversionProvided {
			errorMsg := fmt.Sprintf("When using manual scan mode, all three fields are mandatory: library (%v), symbol (%v), fixversion (%v). Please provide all three fields or none.",
				libraryProvided, symbolProvided, fixversionProvided)
			writeJSONError(w, http.StatusBadRequest, errorMsg)
			return
		}
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

	// Always initialize progress stream
	progressMutex.Lock()
	progressStreams[taskId] = make(chan string, 100)
	progressMutex.Unlock()

	// Get the base URL from the request for graph path conversion
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// Check for X-Forwarded-Proto header (for reverse proxy setups)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	go func(taskId, repo, branchOrCommit, cve, library, symbol, fixversion, algo, baseURL string, graph bool) {
		defer func() {
			requestMutex.Lock()
			inProgress = false
			requestMutex.Unlock()

			// Always close progress stream
			progressMutex.Lock()
			if ch, exists := progressStreams[taskId]; exists {
				close(ch)
				delete(progressStreams, taskId)
			}
			progressMutex.Unlock()
		}()

		updateStatus := func(status TaskStatus, output, errMsg string) {
			taskMutex.Lock()
			defer taskMutex.Unlock()
			taskStore[taskId] = &TaskResult{Status: status, Output: output, Error: errMsg}
		}

		sendProgress := func(message string) {
			progressMutex.Lock()
			if ch, exists := progressStreams[taskId]; exists {
				select {
				case ch <- message:
				default:
					// Channel full, skip message
				}
			}
			progressMutex.Unlock()
		}

		updateStatus(StatusRunning, "", "")

		// Include library, symbol, fixversion, algo, and graph in cache key if provided
		cacheKey := fmt.Sprintf("%s@%s:%s:lib=%s:sym=%s:fixver=%s:algo=%s:graph=%t", repo, branchOrCommit, cve, library, symbol, fixversion, algo, graph)
		if cachedData, err := RetrieveCacheFromDisk(cacheKey); err == nil {
			updateStatus(StatusCompleted, string(cachedData), "")
			log.Printf("[Task %s] Retrieved callgraph from cache", taskId)
			return
		}

		cloneDir, err := os.MkdirTemp("", "cg-"+path.Base(repo)+"-*")
		if err != nil {
			updateStatus(StatusFailed, "", fmt.Sprintf("failed to create temp dir: %v", err))
			return
		}

		start := time.Now()
		log.Printf("[Task %s] Cloning repository %s (%s) ...", taskId, repo, branchOrCommit)
		sendProgress(fmt.Sprintf("Cloning repository %s (%s)...", repo, branchOrCommit))
		if err := common.CloneRepo(repo, branchOrCommit, cloneDir); err != nil {
			updateStatus(StatusFailed, "", fmt.Sprintf("git clone failed: %v", err))
			return
		}
		log.Printf("[Task %s] Clone successful - Took %s", taskId, time.Since(start))
		sendProgress(fmt.Sprintf("Clone successful - Took %s", time.Since(start)))

		log.Printf("[Task %s] Running cg ...", taskId)
		// Display algorithm being used (default to rta if not specified)
		algoName := algo
		if algoName == "" {
			algoName = "rta"
		}
		sendProgress(fmt.Sprintf("Running vulnerability analysis (algorithm: %s)...", algoName))
		start = time.Now()
		var cmd *exec.Cmd
		// Build command arguments based on whether library/symbols are provided
		args := []string{"-progress"}
		if algo != "" {
			args = append(args, fmt.Sprintf("-algo=%s", algo))
		}
		if graph {
			// Create subdirectory structure: /graph/CVE-XXXX/repo/branch/algo/
			// Sanitize repo name (extract just the repo name from URL)
			repoName := path.Base(repo)
			repoName = strings.TrimSuffix(repoName, ".git")
			// Sanitize branch/commit for filesystem
			sanitizedBranch := strings.ReplaceAll(branchOrCommit, "/", "-")
			// Sanitize CVE for filesystem
			sanitizedCVE := strings.ReplaceAll(cve, "/", "-")
			if sanitizedCVE == "" {
				sanitizedCVE = "unknown-cve"
			}

			graphDir := filepath.Join("/tmp/gvs-cache/graph", sanitizedCVE, repoName, sanitizedBranch, algoName)
			if err := os.MkdirAll(graphDir, 0755); err != nil {
				log.Printf("[Task %s] Failed to create graph directory: %v", taskId, err)
			}
			args = append(args, fmt.Sprintf("-graph=%s", graphDir))
		}
		if library != "" && symbol != "" {
			args = append(args, "-library", library, "-symbols", symbol)
		}
		if fixversion != "" {
			args = append(args, "-fixversion", fixversion)
		}
		args = append(args, cve, cloneDir)
		cmd = exec.Command("bin/cg", args...)

		output, err := runCgWithProgressCapture(cmd, sendProgress)

		if err != nil {
			log.Printf("[Task %s] cg execution failed: %v", taskId, err)
			updateStatus(StatusFailed, string(output), err.Error())
			return
		}

		log.Printf("[Task %s] cg execution completed - Took %s", taskId, time.Since(start))

		// If graph generation was requested, convert file paths to web-accessible URLs
		if graph {
			output = convertGraphPathsToURLs(output, baseURL)
		}

		updateStatus(StatusCompleted, string(output), "")

		if err := SaveCacheToDisk(cacheKey, output); err != nil {
			log.Printf("[Task %s] Failed to save cache: %v", taskId, err)
		}
	}(taskId, req.Repo, req.BranchOrCommit, req.CVE, req.Library, req.Symbol, req.FixVersion, req.Algo, baseURL, req.Graph)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"taskId": taskId}); err != nil {
		log.Printf("failed to write taskId response: %v", err)
	}
}

func StatusHandler(w http.ResponseWriter, r *http.Request) {
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

func ProgressHandler(w http.ResponseWriter, r *http.Request) {
	// Extract taskId from URL path
	taskId := strings.TrimPrefix(r.URL.Path, "/progress/")
	if taskId == "" {
		http.Error(w, "Missing task ID", http.StatusBadRequest)
		return
	}

	// Check if progress stream exists
	progressMutex.Lock()
	progressChan, exists := progressStreams[taskId]
	progressMutex.Unlock()

	if !exists {
		http.Error(w, "Progress stream not found", http.StatusNotFound)
		return
	}

	// Set headers for Server-Sent Events
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create a flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Stream progress messages
	for {
		select {
		case message, ok := <-progressChan:
			if !ok {
				// Channel closed, end stream silently
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", message)
			flusher.Flush()
		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

func runCgWithProgressCapture(cmd *exec.Cmd, sendProgress func(string)) ([]byte, error) {
	// Create pipes for stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var outputBuffer strings.Builder
	var wg sync.WaitGroup

	// Read stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			outputBuffer.WriteString(line + "\n")
		}
	}()

	// Read stderr (progress output)
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			sendProgress(line)
		}
	}()

	// Wait for command to finish
	err = cmd.Wait()
	wg.Wait()

	return []byte(outputBuffer.String()), err
}

func runGovulncheckWithProgress(directory, target string, sendProgress func(string)) (string, int, error) {
	sendProgress(fmt.Sprintf("Running govulncheck in %s", directory))

	// Use the existing RunGovulncheck function
	output, exitCode, err := common.RunGovulncheck(directory, target)

	if err != nil && exitCode != 3 {
		sendProgress(fmt.Sprintf("govulncheck completed with exit code %d", exitCode))
	} else {
		sendProgress(fmt.Sprintf("govulncheck completed successfully"))
	}

	return output, exitCode, err
}

// convertGraphPathsToURLs converts file paths in GraphPaths to web-accessible URLs
// Paths are expected to be like: /tmp/gvs-cache/graph/CVE-XXXX/repo/branch/algo/library-symbol.svg
// Converts to: http://host:port/graph/CVE-XXXX/repo/branch/algo/library-symbol.svg
func convertGraphPathsToURLs(jsonOutput []byte, baseURL string) []byte {
	var result map[string]interface{}
	if err := json.Unmarshal(jsonOutput, &result); err != nil {
		log.Printf("Failed to parse JSON for graph path conversion: %v", err)
		return jsonOutput
	}

	// Check if GraphPaths field exists
	graphPaths, ok := result["GraphPaths"].([]interface{})
	if !ok || len(graphPaths) == 0 {
		return jsonOutput
	}

	// Convert file paths to full URLs
	// Extract the path relative to /tmp/gvs-cache/graph and prefix with baseURL/graph/
	webPaths := make([]string, 0, len(graphPaths))
	const cacheDir = "/tmp/gvs-cache/graph/"
	for _, p := range graphPaths {
		if pathStr, ok := p.(string); ok {
			// Extract the relative path after /tmp/gvs-cache/graph/
			if strings.HasPrefix(pathStr, cacheDir) {
				relativePath := strings.TrimPrefix(pathStr, cacheDir)
				webURL := baseURL + "/graph/" + relativePath
				webPaths = append(webPaths, webURL)
			} else {
				// Fallback: just use the filename
				filename := filepath.Base(pathStr)
				webURL := baseURL + "/graph/" + filename
				webPaths = append(webPaths, webURL)
			}
		}
	}

	result["GraphPaths"] = webPaths

	// Re-encode to JSON
	modifiedJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("Failed to re-encode JSON after graph path conversion: %v", err)
		return jsonOutput
	}

	return modifiedJSON
}
