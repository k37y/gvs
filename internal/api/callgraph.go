package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/k37y/gvs/internal/common"
)

type CallgraphRequest struct {
	Repo           string `json:"repo"`
	BranchOrCommit string `json:"branchOrCommit"`
	CVE            string `json:"cve"`
	Library        string `json:"library"`
	Symbol         string `json:"symbol"`
	FixVersion     string `json:"fixversion"`
	Algo           string `json:"algo"`
	RequestID      string `json:"requestId,omitempty"`
}

func StartCallgraph(req CallgraphRequest, baseURL string) (TaskSnapshot, error) {
	if req.Repo == "" || req.BranchOrCommit == "" {
		return TaskSnapshot{}, &TaskError{"invalid_argument", "repo and branchOrCommit are required"}
	}
	manual := req.Library != "" || req.Symbol != "" || req.FixVersion != ""
	if manual && (req.Library == "" || req.Symbol == "" || req.FixVersion == "") {
		return TaskSnapshot{}, &TaskError{"invalid_argument", "When using manual scan mode, library, symbol, and fixversion are all mandatory"}
	}
	if !manual && req.CVE == "" {
		return TaskSnapshot{}, &TaskError{"invalid_argument", "cve is required unless all manual scan fields are supplied"}
	}
	if utf8.RuneCountInString(req.RequestID) > 128 {
		return TaskSnapshot{}, &TaskError{"invalid_argument", "requestId must not exceed 128 characters"}
	}
	if req.Algo == "" {
		req.Algo = "rta"
	}
	switch req.Algo {
	case "rta", "vta", "cha", "static":
	default:
		return TaskSnapshot{}, &TaskError{"invalid_argument", "algo must be rta, vta, cha, or static"}
	}
	args := req
	args.RequestID = ""
	fingerprint, err := json.Marshal(args)
	if err != nil {
		return TaskSnapshot{}, err
	}
	return startTask(req.RequestID, string(fingerprint), func(ctx context.Context, id string) taskCompletion {
		return runCallgraph(ctx, id, req, baseURL)
	})
}

func callgraphCacheKey(req CallgraphRequest) string {
	return fmt.Sprintf("%s@%s:%s:lib=%s:sym=%s:fixver=%s:algo=%s", req.Repo, req.BranchOrCommit, req.CVE, req.Library, req.Symbol, req.FixVersion, req.Algo)
}

func runCallgraph(ctx context.Context, id string, req CallgraphRequest, baseURL string) taskCompletion {
	result := taskCompletion{Status: StatusFailed, CacheKey: callgraphCacheKey(req)}
	if output, err := RetrieveCacheFromDisk(result.CacheKey); err == nil {
		logs, _ := RetrieveCacheLogFromDisk(result.CacheKey)
		result.Status, result.Output, result.Logs, result.Cached = StatusCompleted, string(convertGraphPathsToURLs(output, baseURL)), string(logs), true
		log.Printf("[Task %s] Cache hit", id)
		return result
	}
	cloneDir, err := os.MkdirTemp("", "cg-"+path.Base(req.Repo)+"-*")
	if err != nil {
		result.Error = fmt.Sprintf("failed to create temp dir: %v", err)
		return result
	}
	defer registerDirectory(cloneDir)()
	sendProgress := func(message string) { sendTaskProgress(id, message) }
	sendProgress(fmt.Sprintf("Cloning repository %s (%s)...", req.Repo, req.BranchOrCommit))
	if err := common.CloneRepo(ctx, req.Repo, req.BranchOrCommit, cloneDir); err != nil {
		result.Error = fmt.Sprintf("git clone failed: %v", err)
		return result
	}
	sendProgress(fmt.Sprintf("Running vulnerability analysis (algorithm: %s)...", req.Algo))
	graphDir := filepath.Join(getGraphCacheDir(), graphComponent(req.CVE, "unknown-cve"), graphComponent(strings.TrimSuffix(path.Base(req.Repo), ".git"), "repository"), graphComponent(req.BranchOrCommit, "branch"), req.Algo)
	if err := os.MkdirAll(graphDir, 0755); err != nil {
		result.Error = fmt.Sprintf("create graph directory: %v", err)
		return result
	}
	cmd := exec.CommandContext(ctx, "cg", callgraphArgs(req, cloneDir, graphDir)...)
	cleanupScanner := configureScannerProcess(cmd)
	cmd.WaitDelay = 5 * time.Second
	output, logs, err := runCgWithProgressCapture(cmd, sendProgress)
	cleanupScanner()
	result.Output, result.Logs = string(convertGraphPathsToURLs(output, baseURL)), string(logs)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Status = StatusCompleted
	return result
}

func graphComponent(value, fallback string) string {
	value = strings.NewReplacer("/", "-", "\\", "-").Replace(value)
	if value == "" || value == "." || value == ".." {
		return fallback
	}
	return value
}

func callgraphArgs(req CallgraphRequest, directory, graphDirectory string) []string {
	args := []string{"-progress", "-algo=" + req.Algo, "-graph=" + graphDirectory}
	if req.Library != "" {
		args = append(args, "-library", req.Library, "-symbols", req.Symbol, "-fixversion", req.FixVersion)
	}
	args = append(args, "--")
	if req.CVE != "" {
		args = append(args, req.CVE)
	}
	return append(args, directory)
}
