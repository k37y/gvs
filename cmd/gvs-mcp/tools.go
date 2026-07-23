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

type CheckSymbolReachabilityInput struct {
	Repo          string `json:"repo" jsonschema:"Git repository URL"`
	Branch        string `json:"branch,omitempty" jsonschema:"Branch name or commit hash (optional, defaults to detected default)"`
	Package       string `json:"package" jsonschema:"Full Go package path (e.g., golang.org/x/crypto/ssh)"`
	Symbol        string `json:"symbol" jsonschema:"Symbol name to check (e.g., NewServerConn, or package.Symbol)"`
	Algorithm     string `json:"algorithm,omitempty" jsonschema:"Call graph algorithm: static, cha, rta (default), or vta"`
	GenerateGraph bool   `json:"generate_graph,omitempty" jsonschema:"Generate SVG call graph visualization if reachable"`
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

type SymbolReachabilityResult struct {
	Repo        string   `json:"repo"`
	Branch      string   `json:"branch"`
	Package     string   `json:"package"`
	Symbol      string   `json:"symbol"`
	Algorithm   string   `json:"algorithm"`
	IsReachable bool     `json:"is_reachable"`
	CallPath    []string `json:"call_path,omitempty"`
	EntryPoint  string   `json:"entry_point,omitempty"`
	GraphSVG    string   `json:"graph_svg,omitempty"`
	Summary     string   `json:"summary"`
}

// ScanVulnerability performs deep CVE analysis with optional call graph
func ScanVulnerability(ctx context.Context, req *mcp.CallToolRequest, input ScanVulnerabilityInput) (*mcp.CallToolResult, ScanResult, error) {
	const tool = "scan_vulnerability"

	// Helper to send progress notifications to Claude
	sendProgress := func(message string, current, total float64) {
		if token := req.Params.GetProgressToken(); token != nil {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				Message:       message,
				ProgressToken: token,
				Progress:      current,
				Total:         total,
			})
		}
		logProgress(tool, message)
	}

	sendProgress(fmt.Sprintf("Starting vulnerability scan for %s (CVE: %s). ETA: 1-5 minutes", input.Repo, input.CVE), 0, 6)

	if input.Repo == "" || input.CVE == "" {
		return nil, ScanResult{}, fmt.Errorf("repo and cve are required")
	}

	sendProgress("Detecting repository default branch...", 1, 6)
	branch := input.Branch
	if branch == "" {
		branch = detectDefaultBranch(input.Repo)
		logProgress(tool, fmt.Sprintf("No branch specified, detected default: %s", branch))
	}

	// Clone repository
	sendProgress(fmt.Sprintf("Cloning repository (branch: %s)... This may take 10-30 seconds", branch), 2, 6)
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-*")
	if err != nil {
		return nil, ScanResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		logProgress(tool, fmt.Sprintf("Clone failed: %v", err))
		return nil, ScanResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	sendProgress("Clone completed successfully", 3, 6)

	// Set algorithm (defaults to rta for good reflection tracking)
	algo := setAlgorithm(input.Algorithm, "rta")
	sendProgress(fmt.Sprintf("Initializing vulnerability analysis (algorithm: %s)...", algo), 3.5, 6)
	result := cg.InitResult(input.CVE, cloneDir, false, "", "", "")

	// Run vulnerability analysis
	sendProgress("Building call graph and analyzing reachability... This may take 30 seconds to 3 minutes depending on repository size and algorithm", 4, 6)
	runVulnerabilityAnalysis(result)
	sendProgress(fmt.Sprintf("Call graph analysis complete. Vulnerability status: %s", result.IsVulnerable), 5, 6)

	// Generate summary
	sendProgress("Generating AI-powered summary (2-5 seconds)...", 5.5, 6)
	cg.GenerateSummaryWithGemini(result)
	sendProgress("Scan complete!", 6, 6)

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

	// Helper to send progress notifications to Claude
	sendProgress := func(message string, current, total float64) {
		if token := req.Params.GetProgressToken(); token != nil {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				Message:       message,
				ProgressToken: token,
				Progress:      current,
				Total:         total,
			})
		}
		logProgress(tool, message)
	}

	sendProgress(fmt.Sprintf("Looking up CVE: %s", input.CVE), 0, 3)

	if input.CVE == "" {
		return nil, CVEInfo{}, fmt.Errorf("cve is required")
	}

	// Determine if it's a GO-ID or CVE-ID
	var goID string
	if common.IsGOCVEID(input.CVE) {
		goID = input.CVE
		sendProgress(fmt.Sprintf("Input is GO-ID: %s", goID), 1, 3)
	} else if common.IsCVEID(input.CVE) {
		// Convert CVE to GO-ID
		sendProgress("Converting CVE to GO-ID...", 1, 3)
		goID = fetchGoVulnID(input.CVE)
		if goID == "" {
			logProgress(tool, "No Go vulnerability found for this CVE")
			return nil, CVEInfo{}, fmt.Errorf("no Go vulnerability found for %s", input.CVE)
		}
		sendProgress(fmt.Sprintf("Found GO-ID: %s", goID), 1.5, 3)
	} else {
		return nil, CVEInfo{}, fmt.Errorf("invalid CVE format: %s", input.CVE)
	}

	// Fetch vulnerability details
	sendProgress("Fetching vulnerability details from Go database...", 2, 3)
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

	sendProgress("CVE lookup complete", 3, 3)
	return nil, output, nil
}

// CheckPackageVersion checks if a package version has known vulnerabilities
func CheckPackageVersion(ctx context.Context, req *mcp.CallToolRequest, input CheckPackageVersionInput) (*mcp.CallToolResult, PackageVersionResult, error) {
	const tool = "check_package_version"

	// Helper to send progress notifications to Claude
	sendProgress := func(message string, current, total float64) {
		if token := req.Params.GetProgressToken(); token != nil {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				Message:       message,
				ProgressToken: token,
				Progress:      current,
				Total:         total,
			})
		}
		logProgress(tool, message)
	}

	sendProgress(fmt.Sprintf("Checking package %s@%s for vulnerabilities. ETA: 5-15 seconds", input.Package, input.Version), 0, 20)

	if input.Package == "" || input.Version == "" {
		return nil, PackageVersionResult{}, fmt.Errorf("package and version are required")
	}

	// Fetch all vulnerabilities
	sendProgress("Fetching vulnerability index from Go database...", 1, 20)
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

	sendProgress("Vulnerability index loaded. Checking first 20 vulnerabilities for matches...", 2, 20)

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

		// Send progress update every 2 checks
		if checked%2 == 0 {
			sendProgress(fmt.Sprintf("Checking vulnerability %d/20...", checked+1), float64(2+checked), 20)
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
		sendProgress(fmt.Sprintf("Check complete! No vulnerabilities found for %s@%s", input.Package, input.Version), 20, 20)
	} else {
		output.Status = fmt.Sprintf("Found %d potential vulnerabilities", output.Count)
		sendProgress(fmt.Sprintf("Check complete! Found %d vulnerabilities for %s@%s", output.Count, input.Package, input.Version), 20, 20)
	}

	return nil, output, nil
}

// CallGraphResult wraps the SVG output
type CallGraphResult struct {
	SVG string `json:"svg" jsonschema:"SVG visualization of the call graph"`
}

// GetCallGraph generates an SVG visualization of the call path
func GetCallGraph(ctx context.Context, req *mcp.CallToolRequest, input GetCallGraphInput) (*mcp.CallToolResult, CallGraphResult, error) {
	const tool = "get_call_graph"

	// Helper to send progress notifications to Claude
	sendProgress := func(message string, current, total float64) {
		if token := req.Params.GetProgressToken(); token != nil {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				Message:       message,
				ProgressToken: token,
				Progress:      current,
				Total:         total,
			})
		}
		logProgress(tool, message)
	}

	sendProgress(fmt.Sprintf("Generating call graph for CVE %s. ETA: 1-3 minutes", input.CVE), 0, 5)

	if input.Repo == "" || input.CVE == "" {
		return nil, CallGraphResult{}, fmt.Errorf("repo and cve are required")
	}

	branch := input.Branch
	if branch == "" {
		branch = "main"
	}

	// Clone repository
	sendProgress(fmt.Sprintf("Cloning repository (branch: %s)... This may take 10-30 seconds", branch), 1, 5)
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-graph-*")
	if err != nil {
		return nil, CallGraphResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		return nil, CallGraphResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	sendProgress("Clone completed successfully", 2, 5)

	// Set algorithm (defaults to rta)
	algo := setAlgorithm(input.Algorithm, "rta")
	sendProgress(fmt.Sprintf("Initializing vulnerability analysis (algorithm: %s)...", algo), 2.5, 5)

	// Initialize result to get affected symbols
	result := cg.InitResult(input.CVE, cloneDir, false, "", "", "")

	// Run analysis to find call paths
	sendProgress("Building call graph and analyzing reachability... This may take 30 seconds to 2 minutes", 3, 5)
	runVulnerabilityAnalysis(result)
	sendProgress("Call graph analysis complete", 4, 5)

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
	sendProgress(fmt.Sprintf("Generating SVG visualization for symbol %s...", symbol), 4.5, 5)
	svgData, err := generateCallGraphSVG(result, cloneDir, pkg, symbol)
	if err != nil {
		return nil, CallGraphResult{}, fmt.Errorf("failed to generate call graph: %v", err)
	}

	sendProgress("SVG call graph generated successfully!", 5, 5)
	return nil, CallGraphResult{SVG: string(svgData)}, nil
}

// ScanAllVulnerabilities runs govulncheck to find all vulnerabilities
func ScanAllVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, input ScanAllVulnerabilitiesInput) (*mcp.CallToolResult, AllVulnerabilitiesResult, error) {
	const tool = "scan_all_vulnerabilities"

	// Helper to send progress notifications to Claude
	sendProgress := func(message string, current, total float64) {
		if token := req.Params.GetProgressToken(); token != nil {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				Message:       message,
				ProgressToken: token,
				Progress:      current,
				Total:         total,
			})
		}
		logProgress(tool, message)
	}

	sendProgress(fmt.Sprintf("Starting full vulnerability scan for %s. ETA: 1-10 minutes", input.Repo), 0, 10)

	if input.Repo == "" {
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("repo is required")
	}

	sendProgress("Detecting repository default branch...", 1, 10)
	branch := input.Branch
	if branch == "" {
		branch = detectDefaultBranch(input.Repo)
		logProgress(tool, fmt.Sprintf("No branch specified, detected default: %s", branch))
	}

	// Clone repository
	sendProgress(fmt.Sprintf("Cloning repository (branch: %s)... This may take 10-30 seconds", branch), 2, 10)
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-scan-*")
	if err != nil {
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		logProgress(tool, fmt.Sprintf("Clone failed: %v", err))
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	sendProgress("Clone completed successfully", 3, 10)

	// Find Go modules
	sendProgress("Finding Go modules...", 4, 10)
	moduleDirs, err := common.FindGoModDirs(cloneDir)
	if err != nil || len(moduleDirs) == 0 {
		logProgress(tool, "No Go modules found")
		return nil, AllVulnerabilitiesResult{}, fmt.Errorf("no Go modules found in repository")
	}
	sendProgress(fmt.Sprintf("Found %d Go module(s). Starting govulncheck scans...", len(moduleDirs)), 5, 10)

	output := AllVulnerabilitiesResult{
		Repo:           input.Repo,
		Branch:         branch,
		ModulesScanned: len(moduleDirs),
	}

	// Calculate progress increments (reserve 5 steps for setup, use remaining for modules)
	moduleSteps := 5.0
	stepPerModule := moduleSteps / float64(len(moduleDirs))

	for i, modDir := range moduleDirs {
		currentProgress := 5.0 + (float64(i) * stepPerModule)
		sendProgress(fmt.Sprintf("Running govulncheck on module %d/%d... This may take 1-2 minutes per module", i+1, len(moduleDirs)), currentProgress, 10)

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
		sendProgress(fmt.Sprintf("Module %d/%d complete: found %d vulnerabilities", i+1, len(moduleDirs), len(findings)), 5.0+((float64(i)+1)*stepPerModule), 10)
	}

	sendProgress(fmt.Sprintf("Full scan complete! Total vulnerabilities found: %d", output.TotalVulnerabilities), 10, 10)
	return nil, output, nil
}

// AnalyzeReflectionRisks analyzes code for reflection-based vulnerability risks
func AnalyzeReflectionRisks(ctx context.Context, req *mcp.CallToolRequest, input AnalyzeReflectionRisksInput) (*mcp.CallToolResult, ReflectionAnalysisResult, error) {
	const tool = "analyze_reflection_risks"

	// Helper to send progress notifications to Claude
	sendProgress := func(message string, current, total float64) {
		if token := req.Params.GetProgressToken(); token != nil {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				Message:       message,
				ProgressToken: token,
				Progress:      current,
				Total:         total,
			})
		}
		logProgress(tool, message)
	}

	sendProgress(fmt.Sprintf("Starting reflection analysis for %s. ETA: 1-3 minutes", input.Repo), 0, 5)

	if input.Repo == "" {
		return nil, ReflectionAnalysisResult{}, fmt.Errorf("repo is required")
	}

	sendProgress("Detecting repository default branch...", 1, 5)
	branch := input.Branch
	if branch == "" {
		branch = detectDefaultBranch(input.Repo)
		logProgress(tool, fmt.Sprintf("No branch specified, detected default: %s", branch))
	}

	// Clone repository
	sendProgress(fmt.Sprintf("Cloning repository (branch: %s)... This may take 10-30 seconds", branch), 2, 5)
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-reflect-*")
	if err != nil {
		return nil, ReflectionAnalysisResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		logProgress(tool, fmt.Sprintf("Clone failed: %v", err))
		return nil, ReflectionAnalysisResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	sendProgress("Clone completed successfully", 3, 5)

	// Set algorithm (defaults to rta - best for reflection tracking)
	algo := setAlgorithm(input.Algorithm, "rta")
	sendProgress(fmt.Sprintf("Analyzing reflection patterns (algorithm: %s)... This may take 30 seconds to 2 minutes", algo), 4, 5)

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

	sendProgress(fmt.Sprintf("Reflection analysis complete! Found %d total risks (%d high, %d medium, %d low confidence)", output.RiskCount, output.HighConfidenceRisks, output.MediumConfidenceRisks, output.LowConfidenceRisks), 5, 5)
	return nil, output, nil
}

// CheckSymbolReachability checks if a specific symbol is reachable from entry points
func CheckSymbolReachability(ctx context.Context, req *mcp.CallToolRequest, input CheckSymbolReachabilityInput) (*mcp.CallToolResult, SymbolReachabilityResult, error) {
	const tool = "check_symbol_reachability"

	// Helper to send progress notifications to Claude
	sendProgress := func(message string, current, total float64) {
		if token := req.Params.GetProgressToken(); token != nil {
			req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				Message:       message,
				ProgressToken: token,
				Progress:      current,
				Total:         total,
			})
		}
		logProgress(tool, message)
	}

	sendProgress(fmt.Sprintf("Starting reachability check for %s.%s in %s. ETA: 1-3 minutes", input.Package, input.Symbol, input.Repo), 0, 6)

	if input.Repo == "" || input.Package == "" || input.Symbol == "" {
		return nil, SymbolReachabilityResult{}, fmt.Errorf("repo, package, and symbol are required")
	}

	sendProgress("Detecting repository default branch...", 1, 6)
	branch := input.Branch
	if branch == "" {
		branch = detectDefaultBranch(input.Repo)
		logProgress(tool, fmt.Sprintf("No branch specified, detected default: %s", branch))
	}

	// Clone repository
	sendProgress(fmt.Sprintf("Cloning repository (branch: %s)... This may take 10-30 seconds", branch), 2, 6)
	cloneDir, err := os.MkdirTemp("", "gvs-mcp-reach-*")
	if err != nil {
		return nil, SymbolReachabilityResult{}, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cloneDir)

	if err := common.CloneRepo(input.Repo, branch, cloneDir); err != nil {
		logProgress(tool, fmt.Sprintf("Clone failed: %v", err))
		return nil, SymbolReachabilityResult{}, fmt.Errorf("failed to clone repository: %v", err)
	}
	sendProgress("Clone completed successfully", 3, 6)

	// Set algorithm
	algo := setAlgorithm(input.Algorithm, "rta")
	sendProgress(fmt.Sprintf("Building call graph (algorithm: %s)... This may take 30 seconds to 2 minutes", algo), 4, 6)

	output := SymbolReachabilityResult{
		Repo:      input.Repo,
		Branch:    branch,
		Package:   input.Package,
		Symbol:    input.Symbol,
		Algorithm: algo,
	}

	// Build full symbol name
	fullSymbol := input.Symbol
	if !strings.Contains(input.Symbol, ".") {
		fullSymbol = input.Package + "." + input.Symbol
	}

	// Create a Result to find main files
	tempResult := &cg.Result{
		Directory: cloneDir,
		Errors:    []string{},
	}
	cg.FindMainGoFiles(tempResult)

	if len(tempResult.Files) == 0 {
		return nil, SymbolReachabilityResult{}, fmt.Errorf("no main packages found in repository")
	}

	sendProgress(fmt.Sprintf("Searching for symbol reachability across %d module(s)...", len(tempResult.Files)), 5, 6)

	// Try each module and file set
	for modDir, fileSets := range tempResult.Files {
		fullModDir := filepath.Join(cloneDir, modDir)
		logProgress(tool, fmt.Sprintf("Analyzing module: %s", modDir))

		for _, files := range fileSets {
			if len(files) == 0 {
				continue
			}

			// Generate call graph
			cgGraph, err := tempResult.GenerateCallGraphObject(fullModDir, files)
			if err != nil {
				logProgress(tool, fmt.Sprintf("Failed to generate call graph: %v", err))
				continue
			}

			// Find entry points (main functions)
			var entryPoints []*callgraph.Node
			for _, node := range cgGraph.Nodes {
				if node.Func != nil && node.Func.Name() == "main" {
					entryPoints = append(entryPoints, node)
				}
			}

			if len(entryPoints) == 0 {
				continue
			}

			// Search for path to the symbol
			for _, entry := range entryPoints {
				path, found := cg.FindPathToSymbolExported(entry, input.Package, fullSymbol, false)
				if found && len(path) > 0 {
					output.IsReachable = true
					output.EntryPoint = entry.Func.String()

					// Build call path as string slice
					for _, node := range path {
						if node.Func != nil {
							output.CallPath = append(output.CallPath, node.Func.String())
						}
					}

					sendProgress(fmt.Sprintf("Symbol found! Reachable via %d-step call path", len(path)), 5.5, 6)

					// Generate graph if requested
					if input.GenerateGraph {
						sendProgress("Generating SVG call graph visualization...", 5.7, 6)
						dotOutput := pathToDOT(path)
						sfdpCmd := exec.Command("sfdp", "-Tsvg", "-Goverlap=scale")
						sfdpCmd.Stdin = strings.NewReader(dotOutput)
						svgOutput, err := sfdpCmd.Output()
						if err == nil {
							output.GraphSVG = string(svgOutput)
						} else {
							output.GraphSVG = dotOutput // Fallback to DOT format
						}
					}

					output.Summary = fmt.Sprintf("Symbol %s IS reachable from %s via %d function calls", fullSymbol, output.EntryPoint, len(path)-1)
					sendProgress(fmt.Sprintf("Analysis complete! Symbol IS REACHABLE via %d function calls", len(path)-1), 6, 6)
					return nil, output, nil
				}
			}
		}
	}

	// Symbol not reachable
	output.IsReachable = false
	output.Summary = fmt.Sprintf("Symbol %s is NOT reachable from any entry point in the repository", fullSymbol)
	sendProgress(fmt.Sprintf("Analysis complete! Symbol %s is NOT reachable", input.Symbol), 6, 6)

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
