package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/k37y/gvs/internal/common"
	"github.com/k37y/gvs/pkg/cmd/gvc"
)

func runRepositoryScan(ctx context.Context, taskId string, scanRequest gvc.ScanRequest, clientIP string) (result taskCompletion) {
	result.Status = StatusFailed
	updateStatus := func(status TaskStatus, output, message string) {
		result.Status, result.Output, result.Error = status, output, message
	}
	sendProgress := func(message string) { sendTaskProgress(taskId, message) }
	startTime := time.Now()

	log.Printf("[Task %s] Received request - Repo: %s, Branch: %s, Client IP: %s", taskId, scanRequest.Repo, scanRequest.BranchOrCommit, clientIP)

	cacheKey := scanRequest.Repo + "@" + scanRequest.BranchOrCommit
	result.CacheKey = cacheKey
	if cachedData, err := RetrieveCacheFromDisk(cacheKey); err == nil {
		result.Cached = true
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

	defer registerDirectory(cloneDir)()
	start := time.Now()
	log.Printf("[Task %s] Cloning repository %s (%s)...", taskId, scanRequest.Repo, scanRequest.BranchOrCommit)
	sendProgress(fmt.Sprintf("Cloning repository %s (%s)...", scanRequest.Repo, scanRequest.BranchOrCommit))
	err = common.CloneRepo(ctx, scanRequest.Repo, scanRequest.BranchOrCommit, cloneDir)
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
		output, exitCode, err := runGovulncheckWithProgress(ctx, modDir, "./...", sendProgress)
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

	log.Printf("[Task %s] Request completed - Time Taken: %s", taskId, time.Since(startTime))
	return result
}

func runGovulncheckWithProgress(ctx context.Context, directory, target string, sendProgress func(string)) (string, int, error) {
	output, exitCode, err := common.RunGovulncheck(ctx, directory, target)
	if err != nil && exitCode != 3 {
		sendProgress(fmt.Sprintf("govulncheck completed with exit code %d", exitCode))
	} else {
		sendProgress(fmt.Sprintf("govulncheck completed successfully"))
	}
	return output, exitCode, err
}
