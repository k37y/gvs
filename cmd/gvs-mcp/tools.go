package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/go/callgraph"

	"github.com/k37y/gvs/internal/common"
	"github.com/k37y/gvs/pkg/cmd/cg"
	"github.com/k37y/gvs/pkg/cmd/gvc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// logProgress logs a progress message with tool context
func logProgress(tool, step string) {
	log.Printf("[%s] %s", tool, step)
}

// validAlgorithms lists supported call graph algorithms
var validAlgorithms = map[string]bool{
	"static": true,
	"cha":    true,
	"rta":    true,
	"vta":    true,
}

// setAlgorithm validates and sets the ALGO environment variable
func setAlgorithm(algo, defaultAlgo string) string {
	if algo == "" {
		algo = defaultAlgo
	}
	algo = strings.ToLower(algo)
	if !validAlgorithms[algo] {
		log.Printf("[algorithm] Invalid algorithm '%s', using default '%s'", algo, defaultAlgo)
		algo = defaultAlgo
	}
	os.Setenv("ALGO", algo)
	return algo
}

// Input types for each tool - schemas are auto-generated from struct tags

// Valid algorithm values: static, cha, rta, vta
// - static: fastest, lowest precision
// - cha: fast, class hierarchy analysis
// - rta: medium speed, good for reflection (default)
// - vta: slowest, highest precision

type ScanVulnerabilityInput struct {
	Repo          string `json:"repo" jsonschema:"Git repository URL"`
	Branch        string `json:"branch,omitempty" jsonschema:"Branch name or commit hash (optional, defaults to detected default)"`
	CVE           string `json:"cve" jsonschema:"CVE ID or GO-ID to check for"`
	Algorithm     string `json:"algorithm,omitempty" jsonschema:"Call graph algorithm: static, cha, rta (default), or vta"`
	GenerateGraph bool   `json:"generate_graph,omitempty" jsonschema:"Generate SVG call graph visualization"`
}

type LookupCVEInput struct {
	CVE string `json:"cve" jsonschema:"CVE ID or GO-ID to lookup"`
}

type CheckPackageVersionInput struct {
	Package string `json:"package" jsonschema:"Go package path"`
	Version string `json:"version" jsonschema:"Package version"`
}

type GetCallGraphInput struct {
	Repo      string `json:"repo" jsonschema:"Git repository URL"`
	Branch    string `json:"branch,omitempty" jsonschema:"Branch name or commit hash (optional)"`
	CVE       string `json:"cve" jsonschema:"CVE ID to trace"`
	Symbol    string `json:"symbol,omitempty" jsonschema:"Specific symbol to trace (optional, defaults to first found)"`
	Algorithm string `json:"algorithm,omitempty" jsonschema:"Call graph algorithm: static, cha, rta (default), or vta"`
}

type ScanAllVulnerabilitiesInput struct {
	Repo   string `json:"repo" jsonschema:"Git repository URL"`
	Branch string `json:"branch,omitempty" jsonschema:"Branch name or commit hash (optional, defaults to detected default)"`
}

type AnalyzeReflectionRisksInput struct {
	Repo      string `json:"repo" jsonschema:"Git repository URL"`
	Branch    string `json:"branch,omitempty" jsonschema:"Branch name or commit hash (optional)"`
	CVE       string `json:"cve,omitempty" jsonschema:"CVE ID for targeted analysis (optional)"`
	Algorithm string `json:"algorithm,omitempty" jsonschema:"Call graph algorithm: static, cha, rta (default for reflection), or vta"`
}

// Output types

type ScanResult struct {
	IsVulnerable    string                 `json:"is_vulnerable"`
	CVE             string                 `json:"cve"`
	GoCVE           string                 `json:"go_cve,omitempty"`
	Repository      string                 `json:"repository,omitempty"`
	Branch          string                 `json:"branch,omitempty"`
	Algorithm       string                 `json:"algorithm,omitempty"`
	UsedImports     map[string]interface{} `json:"used_imports,omitempty"`
	AffectedImports map[string]interface{} `json:"affected_imports,omitempty"`
	ReflectionRisks []cg.ReflectionRisk    `json:"reflection_risks,omitempty"`
	Summary         string                 `json:"summary,omitempty"`
	Errors          []string               `json:"errors,omitempty"`
	GraphSVG        string                 `json:"graph_svg,omitempty"`
}

type CVEInfo struct {
	GoID     string                   `json:"go_id"`
	CVEID    string                   `json:"cve_id"`
	Aliases  []string                 `json:"aliases,omitempty"`
	Affected []map[string]interface{} `json:"affected"`
}

type PackageVersionResult struct {
	Package         string                   `json:"package"`
	Version         string                   `json:"version"`
	Status          string                   `json:"status"`
	Count           int                      `json:"count"`
	Vulnerabilities []map[string]interface{} `json:"vulnerabilities"`
}

type AllVulnerabilitiesResult struct {
	Repo                 string                   `json:"repo"`
	Branch               string                   `json:"branch"`
	ModulesScanned       int                      `json:"modules_scanned"`
	TotalVulnerabilities int                      `json:"total_vulnerabilities"`
	Output               []map[string]interface{} `json:"output"`
}

type ReflectionAnalysisResult struct {
	Repo                  string              `json:"repo"`
	Branch                string              `json:"branch"`
	Algorithm             string              `json:"algorithm"`
	UnsafeUsage           bool                `json:"unsafe_usage"`
	ReflectUsage          bool                `json:"reflect_usage"`
	ReflectionRisks       []cg.ReflectionRisk `json:"reflection_risks"`
	RiskCount             int                 `json:"risk_count"`
	HighConfidenceRisks   int                 `json:"high_confidence_risks"`
	MediumConfidenceRisks int                 `json:"medium_confidence_risks"`
	LowConfidenceRisks    int                 `json:"low_confidence_risks"`
	Summary               string              `json:"summary"`
}

// ScanVulnerability performs deep CVE analysis with optional call graph
func ScanVulnerability(ctx context.Context, req *mcp.CallToolRequest, input ScanVulnerabilityInput) (*mcp.CallToolResult, ScanResult, error) {
	const tool = "scan_vulnerability"
	logProgress(tool, fmt.Sprintf("Starting scan for repo=%s, cve=%s", input.Repo, input.CVE))

	if input.Repo == "" || input.CVE == "" {
		return nil, ScanResult{}, fmt.Errorf("repo and cve are required")
	}

	branch := input.Branch
	if branch == "" {
		branch = detectDefaultBranch(input.Repo)
		logProgress(tool, fmt.Sprintf("No branch specified, detected default: %s", branch))
	}

	// Clone repository
	logProgress(tool, fmt.Sprintf("Cloning repository (branch: %s)...", branch))
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-*")
	if err != nil {
		return nil, ScanResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		logProgress(tool, fmt.Sprintf("Clone failed: %v", err))
		return nil, ScanResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	logProgress(tool, "Clone completed successfully")

	// Set algorithm (defaults to rta for good reflection tracking)
	algo := setAlgorithm(input.Algorithm, "rta")
	logProgress(tool, fmt.Sprintf("Using algorithm: %s", algo))

	// Initialize and run scan
	logProgress(tool, "Initializing vulnerability analysis...")
	result := cg.InitResult(input.CVE, cloneDir, false, "", "", "")

	// Run vulnerability analysis
	logProgress(tool, "Running call graph analysis...")
	runVulnerabilityAnalysis(result)
	logProgress(tool, fmt.Sprintf("Analysis complete. Vulnerable: %s", result.IsVulnerable))

	// Generate summary
	logProgress(tool, "Generating AI summary...")
	cg.GenerateSummaryWithGemini(result)
	logProgress(tool, "Scan complete")

	// Build output
	output := ScanResult{
		IsVulnerable:    result.IsVulnerable,
		CVE:             result.CVE,
		GoCVE:           result.GoCVE,
		Repository:      result.Repository,
		Branch:          result.Branch,
		Algorithm:       algo,
		ReflectionRisks: result.ReflectionRisks,
		Summary:         result.Summary,
		Errors:          result.Errors,
	}

	// Convert UsedImports
	if result.UsedImports != nil {
		output.UsedImports = make(map[string]interface{})
		for k, v := range result.UsedImports {
			output.UsedImports[k] = map[string]interface{}{
				"symbols":         v.Symbols,
				"current_version": v.CurrentVersion,
				"replace_version": v.ReplaceVersion,
				"fix_commands":    v.FixCommands,
			}
		}
	}

	// Convert AffectedImports
	if result.AffectedImports != nil {
		output.AffectedImports = make(map[string]interface{})
		for k, v := range result.AffectedImports {
			output.AffectedImports[k] = map[string]interface{}{
				"symbols":       v.Symbols,
				"type":          v.Type,
				"fixed_version": v.FixedVersion,
			}
		}
	}

	// Add graph if requested and vulnerable symbols found
	if input.GenerateGraph && len(result.UsedImports) > 0 {
		for pkg, details := range result.UsedImports {
			for _, symbol := range details.Symbols {
				svgData, err := generateCallGraphSVG(result, cloneDir, pkg, symbol)
				if err == nil && len(svgData) > 0 {
					output.GraphSVG = string(svgData)
					break
				}
			}
			break
		}
	}

	return nil, output, nil
}

// LookupCVE fetches CVE details from the Go vulnerability database
func LookupCVE(ctx context.Context, req *mcp.CallToolRequest, input LookupCVEInput) (*mcp.CallToolResult, CVEInfo, error) {
	const tool = "lookup_cve"
	logProgress(tool, fmt.Sprintf("Looking up CVE: %s", input.CVE))

	if input.CVE == "" {
		return nil, CVEInfo{}, fmt.Errorf("cve is required")
	}

	// Determine if it's a GO-ID or CVE-ID
	var goID string
	if common.IsGOCVEID(input.CVE) {
		goID = input.CVE
		logProgress(tool, fmt.Sprintf("Input is GO-ID: %s", goID))
	} else if common.IsCVEID(input.CVE) {
		// Convert CVE to GO-ID
		logProgress(tool, "Converting CVE to GO-ID...")
		goID = fetchGoVulnID(input.CVE)
		if goID == "" {
			logProgress(tool, "No Go vulnerability found for this CVE")
			return nil, CVEInfo{}, fmt.Errorf("no Go vulnerability found for %s", input.CVE)
		}
		logProgress(tool, fmt.Sprintf("Found GO-ID: %s", goID))
	} else {
		return nil, CVEInfo{}, fmt.Errorf("invalid CVE format: %s", input.CVE)
	}

	// Fetch vulnerability details
	logProgress(tool, "Fetching vulnerability details from Go database...")
	client := http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("%s/ID/%s.json", cg.VulnsURL, goID)

	resp, err := client.Get(url)
	if err != nil {
		return nil, CVEInfo{}, fmt.Errorf("failed to fetch CVE details: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, CVEInfo{}, fmt.Errorf("CVE not found: %s", goID)
	}

	var detail cg.VulnReport
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, CVEInfo{}, fmt.Errorf("failed to parse response: %v", err)
	}

	// Build response
	output := CVEInfo{
		GoID:    goID,
		CVEID:   input.CVE,
		Aliases: detail.Aliases,
	}

	// Extract affected packages and symbols
	for _, aff := range detail.Affected {
		for _, imp := range aff.EcosystemSpecific.Imports {
			var fixedVersions []string
			for _, r := range aff.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						fixedVersions = append(fixedVersions, e.Fixed)
					}
				}
			}
			output.Affected = append(output.Affected, map[string]interface{}{
				"package":        imp.Path,
				"symbols":        imp.Symbols,
				"type":           aff.Package.Name,
				"fixed_versions": fixedVersions,
			})
		}
	}

	return nil, output, nil
}

// CheckPackageVersion checks if a package version has known vulnerabilities
func CheckPackageVersion(ctx context.Context, req *mcp.CallToolRequest, input CheckPackageVersionInput) (*mcp.CallToolResult, PackageVersionResult, error) {
	if input.Package == "" || input.Version == "" {
		return nil, PackageVersionResult{}, fmt.Errorf("package and version are required")
	}

	// Fetch all vulnerabilities
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(cg.VulnsURL + "/index/vulns.json")
	if err != nil {
		return nil, PackageVersionResult{}, fmt.Errorf("failed to fetch vulnerability index: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, PackageVersionResult{}, fmt.Errorf("failed to read response: %v", err)
	}

	var vulns []cg.VulnReport
	if err := json.Unmarshal(body, &vulns); err != nil {
		return nil, PackageVersionResult{}, fmt.Errorf("failed to parse vulnerabilities: %v", err)
	}

	output := PackageVersionResult{
		Package: input.Package,
		Version: input.Version,
	}

	// Find vulnerabilities affecting this package (limit to first 20 for performance)
	checked := 0
	for _, vuln := range vulns {
		if checked >= 20 {
			break
		}

		// Fetch full details for each vulnerability
		detailResp, err := client.Get(fmt.Sprintf("%s/ID/%s.json", cg.VulnsURL, vuln.ID))
		if err != nil {
			continue
		}

		var detail cg.VulnReport
		if err := json.NewDecoder(detailResp.Body).Decode(&detail); err != nil {
			detailResp.Body.Close()
			continue
		}
		detailResp.Body.Close()
		checked++

		for _, aff := range detail.Affected {
			for _, imp := range aff.EcosystemSpecific.Imports {
				if strings.HasPrefix(imp.Path, input.Package) || strings.HasPrefix(input.Package, imp.Path) {
					var fixedVersion string
					for _, r := range aff.Ranges {
						for _, e := range r.Events {
							if e.Fixed != "" {
								fixedVersion = e.Fixed
							}
						}
					}

					output.Vulnerabilities = append(output.Vulnerabilities, map[string]interface{}{
						"go_id":         vuln.ID,
						"aliases":       vuln.Aliases,
						"package":       imp.Path,
						"symbols":       imp.Symbols,
						"fixed_version": fixedVersion,
					})
					break
				}
			}
		}
	}

	output.Count = len(output.Vulnerabilities)
	if output.Count == 0 {
		output.Status = "No known vulnerabilities found"
	} else {
		output.Status = fmt.Sprintf("Found %d potential vulnerabilities", output.Count)
	}

	return nil, output, nil
}

// CallGraphResult wraps the SVG output
type CallGraphResult struct {
	SVG string `json:"svg" jsonschema:"SVG visualization of the call graph"`
}

// GetCallGraph generates an SVG visualization of the call path
func GetCallGraph(ctx context.Context, req *mcp.CallToolRequest, input GetCallGraphInput) (*mcp.CallToolResult, CallGraphResult, error) {
	if input.Repo == "" || input.CVE == "" {
		return nil, CallGraphResult{}, fmt.Errorf("repo and cve are required")
	}

	branch := input.Branch
	if branch == "" {
		branch = "main"
	}

	// Clone repository
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-graph-*")
	if err != nil {
		return nil, CallGraphResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		return nil, CallGraphResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}

	// Set algorithm (defaults to rta)
	setAlgorithm(input.Algorithm, "rta")

	// Initialize result to get affected symbols
	result := cg.InitResult(input.CVE, cloneDir, false, "", "", "")

	// Run analysis to find call paths
	runVulnerabilityAnalysis(result)

	// Find the symbol to trace
	symbol := input.Symbol
	pkg := ""
	if symbol == "" {
		// Use first found symbol
		for p, details := range result.UsedImports {
			if len(details.Symbols) > 0 {
				pkg = p
				symbol = details.Symbols[0]
				break
			}
		}
	}

	if symbol == "" {
		return nil, CallGraphResult{}, fmt.Errorf("no vulnerable symbols found in the repository")
	}

	// Generate SVG
	svgData, err := generateCallGraphSVG(result, cloneDir, pkg, symbol)
	if err != nil {
		return nil, CallGraphResult{}, fmt.Errorf("failed to generate call graph: %v", err)
	}

	return nil, CallGraphResult{SVG: string(svgData)}, nil
}

// ScanAllVulnerabilities runs govulncheck to find all vulnerabilities
func ScanAllVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, input ScanAllVulnerabilitiesInput) (*mcp.CallToolResult, AllVulnerabilitiesResult, error) {
	const tool = "scan_all_vulnerabilities"
	logProgress(tool, fmt.Sprintf("Starting full scan for repo=%s", input.Repo))

	if input.Repo == "" {
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("repo is required")
	}

	branch := input.Branch
	if branch == "" {
		branch = detectDefaultBranch(input.Repo)
		logProgress(tool, fmt.Sprintf("No branch specified, detected default: %s", branch))
	}

	// Clone repository
	logProgress(tool, fmt.Sprintf("Cloning repository (branch: %s)...", branch))
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-scan-*")
	if err != nil {
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		logProgress(tool, fmt.Sprintf("Clone failed: %v", err))
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	logProgress(tool, "Clone completed successfully")

	// Find Go modules
	logProgress(tool, "Finding Go modules...")
	moduleDirs, err := common.FindGoModDirs(cloneDir)
	if err != nil || len(moduleDirs) == 0 {
		logProgress(tool, "No Go modules found")
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("no Go modules found in repository")
	}
	logProgress(tool, fmt.Sprintf("Found %d Go module(s)", len(moduleDirs)))

	output := AllVulnerabilitiesResult{
		Repo:           input.Repo,
		Branch:         branch,
		ModulesScanned: len(moduleDirs),
	}

	for i, modDir := range moduleDirs {
		logProgress(tool, fmt.Sprintf("Running govulncheck on module %d/%d...", i+1, len(moduleDirs)))
		govulnOutput, exitCode, err := common.RunGovulncheck(modDir, "./...")
		if err != nil && exitCode != 3 {
			logProgress(tool, fmt.Sprintf("govulncheck failed for module %d: %v", i+1, err))
			continue
		}

		var sarif gvc.Sarif
		if err := json.Unmarshal([]byte(govulnOutput), &sarif); err != nil {
			continue
		}

		var findings []interface{}
		for _, run := range sarif.Runs {
			for _, result := range run.Results {
				findings = append(findings, map[string]interface{}{
					"ruleId":  result.RuleID,
					"message": result.Message.Text,
				})
			}
		}

		repoName := filepath.Base(input.Repo)
		var relativePath string
		if modDir == cloneDir {
			relativePath = repoName
		} else {
			relativePath = filepath.Join(repoName, strings.TrimPrefix(modDir, cloneDir+"/"))
		}

		output.Output = append(output.Output, map[string]interface{}{
			"directory": relativePath,
			"results":   findings,
		})
		output.TotalVulnerabilities += len(findings)
		logProgress(tool, fmt.Sprintf("Module %d: found %d vulnerabilities", i+1, len(findings)))
	}

	logProgress(tool, fmt.Sprintf("Scan complete. Total vulnerabilities: %d", output.TotalVulnerabilities))
	return nil, output, nil
}

// AnalyzeReflectionRisks analyzes code for reflection-based vulnerability risks
func AnalyzeReflectionRisks(ctx context.Context, req *mcp.CallToolRequest, input AnalyzeReflectionRisksInput) (*mcp.CallToolResult, ReflectionAnalysisResult, error) {
	const tool = "analyze_reflection_risks"
	logProgress(tool, fmt.Sprintf("Starting reflection analysis for repo=%s", input.Repo))

	if input.Repo == "" {
		return nil, ReflectionAnalysisResult{}, fmt.Errorf("repo is required")
	}

	branch := input.Branch
	if branch == "" {
		branch = detectDefaultBranch(input.Repo)
		logProgress(tool, fmt.Sprintf("No branch specified, detected default: %s", branch))
	}

	// Clone repository
	logProgress(tool, fmt.Sprintf("Cloning repository (branch: %s)...", branch))
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-reflect-*")
	if err != nil {
		return nil, ReflectionAnalysisResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		logProgress(tool, fmt.Sprintf("Clone failed: %v", err))
		return nil, ReflectionAnalysisResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	logProgress(tool, "Clone completed successfully")

	// Set algorithm (defaults to rta - best for reflection tracking)
	algo := setAlgorithm(input.Algorithm, "rta")
	logProgress(tool, fmt.Sprintf("Using algorithm: %s", algo))
	logProgress(tool, "Analyzing reflection patterns...")

	// Initialize result
	cve := input.CVE
	if cve == "" {
		cve = "REFLECTION-SCAN" // Placeholder for general scan
	}

	var result *cg.Result

	// If CVE provided, get affected symbols
	if input.CVE != "" && (common.IsCVEID(input.CVE) || common.IsGOCVEID(input.CVE)) {
		result = cg.InitResult(input.CVE, cloneDir, false, "", "", "")
	} else {
		result = &cg.Result{
			CVE:          cve,
			Directory:    cloneDir,
			IsVulnerable: "unknown",
		}
	}

	// Detect unsafe and reflect usage
	cg.DetectUnsafeReflectUsage(result, nil)

	// Run vulnerability analysis if CVE was provided
	if input.CVE != "" && len(result.AffectedImports) > 0 {
		runVulnerabilityAnalysis(result)
	}

	// Build response
	output := ReflectionAnalysisResult{
		Repo:            input.Repo,
		Branch:          branch,
		Algorithm:       algo,
		UnsafeUsage:     result.Unsafe,
		ReflectUsage:    result.Reflect,
		ReflectionRisks: result.ReflectionRisks,
		RiskCount:       len(result.ReflectionRisks),
	}

	// Categorize risks by confidence
	for _, risk := range result.ReflectionRisks {
		switch risk.Confidence {
		case "high":
			output.HighConfidenceRisks++
		case "medium":
			output.MediumConfidenceRisks++
		case "low":
			output.LowConfidenceRisks++
		}
	}

	// Add summary
	if output.HighConfidenceRisks > 0 {
		output.Summary = fmt.Sprintf("WARNING: Found %d high-confidence reflection patterns that may invoke vulnerable symbols at runtime", output.HighConfidenceRisks)
	} else if output.MediumConfidenceRisks > 0 {
		output.Summary = fmt.Sprintf("Found %d medium-confidence reflection patterns that warrant review", output.MediumConfidenceRisks)
	} else if output.LowConfidenceRisks > 0 {
		output.Summary = fmt.Sprintf("Found %d low-confidence patterns (informational)", output.LowConfidenceRisks)
	} else if result.Reflect {
		output.Summary = "Reflect package is used but no specific vulnerable patterns detected"
	} else {
		output.Summary = "No reflection-based risks detected"
	}

	return nil, output, nil
}

// Helper functions

// detectDefaultBranch tries to detect the default branch of a repository
// by checking common branch names via git ls-remote
func detectDefaultBranch(repoURL string) string {
	// Try to get the default branch from git ls-remote
	cmd := exec.Command("git", "ls-remote", "--symref", repoURL, "HEAD")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ref: refs/heads/") {
				// Extract branch name from "ref: refs/heads/main	HEAD"
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					branch := strings.TrimPrefix(parts[1], "refs/heads/")
					if branch != "" && branch != "HEAD" {
						log.Printf("[detectDefaultBranch] Detected default branch: %s", branch)
						return branch
					}
				}
			}
		}
	}

	// Fallback to "main" (most common default now)
	log.Printf("[detectDefaultBranch] Could not detect, defaulting to 'main'")
	return "main"
}

func fetchGoVulnID(cveID string) string {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(cg.VulnsURL + "/index/vulns.json")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var vulns []cg.VulnReport
	if err := json.Unmarshal(body, &vulns); err != nil {
		return ""
	}

	for _, v := range vulns {
		if slices.Contains(v.Aliases, cveID) {
			return v.ID
		}
	}
	return ""
}

func runVulnerabilityAnalysis(result *cg.Result) {
	defaultWorkers := runtime.NumCPU() / 2
	if defaultWorkers < 1 {
		defaultWorkers = 1
	}

	jobs := make(chan cg.Job)
	results := make(chan *cg.Result)

	var wg sync.WaitGroup

	for i := 0; i < defaultWorkers; i++ {
		wg.Add(1)
		go cg.Worker(jobs, results, &wg, result)
	}

	go func() {
		for modDir, sets := range result.Files {
			for _, fset := range sets {
				for pkg, syms := range result.AffectedImports {
					jobs <- cg.Job{Package: pkg, Symbols: syms.Symbols, Dir: modDir, Files: fset}
				}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	mergedImports := make(map[string]cg.UsedImportsDetails)
	hasVulnerable := false
	hasUnknown := false

	for res := range results {
		switch res.IsVulnerable {
		case "true":
			hasVulnerable = true
		case "unknown":
			hasUnknown = true
		}

		for pkg, symbols := range res.UsedImports {
			entry := mergedImports[pkg]
			entry.Paths = append(entry.Paths, symbols.Paths...)
			for _, sym := range symbols.Symbols {
				if strings.HasPrefix(sym, pkg+".") {
					sym = strings.TrimPrefix(sym, pkg+".")
				}
				entry.Symbols = append(entry.Symbols, sym)
			}
			if entry.CurrentVersion == "" {
				entry.CurrentVersion = symbols.CurrentVersion
			}
			if entry.ReplaceVersion == "" {
				entry.ReplaceVersion = symbols.ReplaceVersion
			}
			if entry.FixCommands == nil {
				entry.FixCommands = symbols.FixCommands
			}
			result.Mu.Lock()
			mergedImports[pkg] = entry
			result.Mu.Unlock()
		}
	}

	// Deduplicate symbols
	for pkg, details := range mergedImports {
		seen := make(map[string]bool)
		var unique []string
		for _, sym := range details.Symbols {
			if !seen[sym] {
				seen[sym] = true
				unique = append(unique, sym)
			}
		}
		details.Symbols = unique

		if len(details.Symbols) == 0 && details.CurrentVersion == "" && details.ReplaceVersion == "" {
			delete(mergedImports, pkg)
		} else {
			mergedImports[pkg] = details
		}
	}

	if hasVulnerable {
		result.IsVulnerable = "true"
	} else if hasUnknown {
		result.IsVulnerable = "unknown"
	} else {
		result.IsVulnerable = "false"
	}
	result.UsedImports = mergedImports
}

func generateCallGraphSVG(result *cg.Result, directory, pkg, symbol string) ([]byte, error) {
	// Get the first main file set
	var files []string
	var modDir string

	for dir, sets := range result.Files {
		if len(sets) > 0 && len(sets[0]) > 0 {
			files = sets[0]
			modDir = dir
			break
		}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no main files found")
	}

	fullModDir := filepath.Join(directory, modDir)

	// Generate call graph
	tempResult := &cg.Result{
		Directory: directory,
		Errors:    []string{},
	}

	cgGraph, err := tempResult.GenerateCallGraphObject(fullModDir, files)
	if err != nil {
		return nil, err
	}

	// Find entry points and path to symbol
	var entryPoints []*callgraph.Node
	for _, node := range cgGraph.Nodes {
		if node.Func != nil && node.Func.Name() == "main" {
			entryPoints = append(entryPoints, node)
		}
	}

	if len(entryPoints) == 0 {
		return nil, fmt.Errorf("no entry points found")
	}

	// Search for path
	fullSymbol := fmt.Sprintf("%s.%s", pkg, symbol)
	var foundPath []*callgraph.Node

	for _, entry := range entryPoints {
		path, found := cg.FindPathToSymbolExported(entry, pkg, fullSymbol, false)
		if found {
			foundPath = path
			break
		}
	}

	if len(foundPath) == 0 {
		return nil, fmt.Errorf("no path found to symbol")
	}

	// Convert to DOT format
	dotOutput := pathToDOT(foundPath)

	// Render with sfdp (if available) or return DOT
	sfdpCmd := exec.Command("sfdp", "-Tsvg", "-Goverlap=scale")
	sfdpCmd.Stdin = strings.NewReader(dotOutput)
	svgOutput, err := sfdpCmd.Output()
	if err != nil {
		// Fallback: return DOT as text
		return []byte(dotOutput), nil
	}

	return svgOutput, nil
}

func pathToDOT(path []*callgraph.Node) string {
	var b strings.Builder
	b.WriteString("digraph callgraph {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box];\n")

	for i := 0; i < len(path)-1; i++ {
		callerName := "unknown"
		calleeName := "unknown"

		if path[i].Func != nil {
			callerName = path[i].Func.String()
		}
		if path[i+1].Func != nil {
			calleeName = path[i+1].Func.String()
		}

		b.WriteString(fmt.Sprintf("  %q -> %q\n", callerName, calleeName))
	}

	b.WriteString("}\n")
	return b.String()
}
