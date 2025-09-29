// Package cg provides call graph analysis for vulnerability scanning
//
// Call Graph Algorithms:
// The scanner supports multiple call graph algorithms, configurable via the ALGO environment variable:
//
// - vta (default): Variable Type Analysis - Most precise but slower. Recommended for accuracy.
// - cha: Class Hierarchy Analysis - Fast but less precise. Good for large codebases where speed matters.
// - rta: Rapid Type Analysis - Good balance of speed and precision. Suitable for most use cases.
// - static: Static analysis - Very fast but least precise (only direct calls). Use for quick scans.
//
// Usage:
//
//	export ALGO=rta  # Use Rapid Type Analysis
//	export ALGO=cha  # Use Class Hierarchy Analysis
//	export ALGO=static  # Use static analysis
//	# Default (no env var set) uses VTA
//
// Algorithm Trade-offs:
// - Precision: static < cha < rta < vta
// - Speed: vta < rta < cha < static
package cg

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/k37y/gvs/internal/cli"
	"github.com/k37y/gvs/internal/common"
)

func InitResult(cve, dir string, fix bool) *Result {
	r := &Result{
		CVE:          cve,
		Directory:    dir,
		IsVulnerable: "unknown",
	}

	// Only initialize fix-related fields if fix is true
	// When fix is false, these fields remain as nil pointers
	// and will be omitted from JSON due to the omitempty tags
	if fix {
		cursorCmd := fmt.Sprintf("cursor --remote ssh-remote+gvs-host %s", dir)
		r.CursorCommand = &cursorCmd
		fixErrors := []string{}
		fixSuccess := []string{}
		r.FixErrors = &fixErrors
		r.FixSuccess = &fixSuccess
	}

	fetchGoVulnID(r)
	fetchAffectedSymbols(r)
	findMainGoFiles(r)
	getGitBranch(r)
	getGitURL(r)
	DetectUnsafeReflectUsage(r, nil)

	if r.GoCVE == "" {
		r = &Result{
			GoCVE:        "No Go CVE ID found",
			IsVulnerable: "unknown",
			CVE:          r.CVE,
			Directory:    r.Directory,
			Branch:       r.Branch,
			Repository:   r.Repository,
			Unsafe:       r.Unsafe,
			Reflect:      r.Reflect,
		}
		jsonOutput, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("Failed to marshal results to JSON: %v", err)
			r.Errors = append(r.Errors, errMsg)
		}
		fmt.Println(string(jsonOutput))
		os.Exit(0)
	}
	return r
}

func Worker(jobs <-chan Job, results chan<- *Result, wg *sync.WaitGroup, result *Result) {
	defer wg.Done()
	for job := range jobs {
		res := job.isVulnerable(result)
		results <- res
	}
}

func (j Job) isVulnerable(result *Result) *Result {
	curVer := getCurrentVersion(j.Package, filepath.Join(result.Directory, j.Dir), result)
	modPath := getModPath(j.Package, filepath.Join(result.Directory, j.Dir), result)
	repVer := getReplaceVersion(modPath, filepath.Join(result.Directory, j.Dir), result)
	fixVer := getFixedVersion(result.GoCVE, modPath, result)
	fixVer = common.ExtractFormattedFixedVersions(fixVer)
	fv := common.SemVersion(strings.Join(fixVer, " "))

	used := false
	unknown := false

	isUsed := result.isSymbolUsed(j.Package, filepath.Join(result.Directory, j.Dir), j.Symbols, j.Files)
	switch isUsed {
	case "true":
		used = true
	case "unknown":
		unknown = true
	}

	result.Mu.Lock()
	if result.AffectedImports == nil {
		result.AffectedImports = make(map[string]AffectedImportsDetails)
	}
	aentry := result.AffectedImports[j.Package]
	if result.AffectedImports[j.Package].Type != "stdlib" {
		aentry.FixedVersion = strings.Split(common.SemVersion(fv), ",")
	} else {
		aentry.FixedVersion = fixVer
	}
	result.AffectedImports[j.Package] = aentry
	result.Mu.Unlock()

	result.Mu.Lock()
	if result.UsedImports == nil {
		result.UsedImports = make(map[string]UsedImportsDetails)
	}
	uentry := result.UsedImports[j.Package]
	uentry.CurrentVersion = curVer
	uentry.ReplaceVersion = repVer
	if used {
		// Determine the version to compare against (prefer replace version if available)
		compareVer := curVer
		if repVer != "" {
			compareVer = repVer
		}

		if result.AffectedImports[j.Package].Type != "stdlib" {
			// For non-stdlib packages: vulnerable if current/replace version is less than fixed version
			if semver.Compare(compareVer, fv) < 0 {
				result.IsVulnerable = "true"
			} else {
				result.IsVulnerable = "false"
			}
		} else {
			// For stdlib packages: compare against the Go version fix
			if len(fixVer) > 0 {
				// Get the actual Go toolchain version
				goToolchainVersion := getGoToolchainVersion(filepath.Join(result.Directory, j.Dir), result)

				// Find the appropriate fixed version for the current Go major.minor version
				isVulnerable := false
				if goToolchainVersion != "" {
					appropriateFixVersion := findAppropriateFixVersion(goToolchainVersion, fixVer)
					if appropriateFixVersion != "" {
						if semver.Compare(goToolchainVersion, appropriateFixVersion) < 0 {
							isVulnerable = true
						}
					} else {
						// No appropriate fix version found, assume vulnerable
						isVulnerable = true
					}
				}

				if goToolchainVersion == "" {
					result.IsVulnerable = "unknown"
				} else if isVulnerable {
					result.IsVulnerable = "true"
				} else {
					result.IsVulnerable = "false"
				}
			} else {
				result.IsVulnerable = "unknown"
			}
		}
	} else if unknown {
		result.IsVulnerable = "unknown"
	} else {
		result.IsVulnerable = "false"
	}
	if repVer != "" && semver.Compare(curVer, repVer) <= 0 {
		uentry.FixCommands = []string{
			fmt.Sprintf("go mod edit -replace=%s=%s@%s", modPath, modPath, fv),
			"go mod tidy",
			"go mod vendor",
		}
	} else if result.IsVulnerable == "true" {
		if result.AffectedImports[j.Package].Type == "stdlib" {
			// For stdlib packages, select the appropriate Go version to upgrade to
			goToolchainVersion := getGoToolchainVersion(filepath.Join(result.Directory, j.Dir), result)
			selectedFixVersion := selectFixVersionForCurrentGoVersion(goToolchainVersion, fixVer)
			uentry.FixCommands = []string{
				fmt.Sprintf("go mod edit -go=%s", selectedFixVersion),
				"go mod tidy",
				"go mod vendor",
			}
		} else {
			uentry.FixCommands = []string{
				fmt.Sprintf("go get %s@%s", modPath, fv),
				"go mod tidy",
				"go mod vendor",
			}
		}
	}
	result.UsedImports[j.Package] = uentry
	result.Mu.Unlock()

	return result
}

func fetchGoVulnID(result *Result) string {
	client := http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf(VulnsURL + "/index/vulns.json")

	resp, err := client.Get(url)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get response from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to read response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
	}

	var vulns []VulnReport
	if err := json.Unmarshal(body, &vulns); err != nil {
		errMsg := fmt.Sprintf("Failed to marshal response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
	}

	for _, v := range vulns {
		if slices.Contains(v.Aliases, result.CVE) {
			result.GoCVE = v.ID
		}
	}

	return ""
}

func findMainGoFiles(res *Result) {
	result := make(map[string][][]string)
	var modDirs []string

	err := filepath.WalkDir(res.Directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() && d.Name() == "vendor" {
			return filepath.SkipDir
		}
		if d.Name() == "go.mod" {
			modDirs = append(modDirs, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run filepath.WalkDir in %s: %v", res.Directory, err)
		res.Errors = append(res.Errors, errMsg)
	}

	for _, modDir := range modDirs {
		cmd := "go"
		args := []string{"list", "-f", `{{if eq .Name "main"}}{{.Name}}: {{.Dir}}{{end}}`, "./..."}
		out, err := cli.RunCommand(modDir, cmd, args...)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), modDir, strings.TrimSpace(string(out)))
			res.Errors = append(res.Errors, errMsg)
			continue
		}

		modKey, err := filepath.Rel(res.Directory, modDir)
		if err != nil {
			modKey = modDir
		}

		var sets [][]string

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "main") {
				continue
			}
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) != 2 {
				continue
			}
			dirPath := parts[1]
			files, _ := filepath.Glob(filepath.Join(dirPath, "*.go"))
			var group []string
			for _, file := range files {
				if strings.HasSuffix(file, "_test.go") || strings.Contains(filepath.Base(file), "windows") {
					continue
				}
				rel, _ := filepath.Rel(modDir, file)
				group = append(group, rel)
			}
			if len(group) > 0 {
				sort.Strings(group)
				sets = append(sets, group)
			}
		}

		result[modKey] = sets
	}

	res.Files = make(map[string][][]string)
	res.Files = result
}

func fetchAffectedSymbols(result *Result) {
	client := http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf(VulnsURL+"/ID/%s.json", result.GoCVE)

	resp, err := client.Get(url)
	if err != nil {
		errMsg := fmt.Sprintf("Failed HTTP request to %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)

	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Failed to connect %s: %s", url, resp.Status)
		result.Errors = append(result.Errors, errMsg)

	}

	var detail VulnReport

	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		errMsg := fmt.Sprintf("Failed to parse JSON: %v", err)
		result.Errors = append(result.Errors, errMsg)

	}

	imports := make(map[string]AffectedImportsDetails)

	for _, aff := range detail.Affected {
		typ := "non-stdlib"
		if aff.Package.Name == "stdlib" {
			typ = "stdlib"
		}
		for _, imp := range aff.EcosystemSpecific.Imports {
			entry := imports[imp.Path]
			entry.Symbols = append(entry.Symbols, imp.Symbols...)
			entry.Type = typ
			imports[imp.Path] = entry
		}

		result.AffectedImports = imports
	}
}

func (r *Result) isSymbolUsed(pkg, dir string, symbols, files []string) string {
	for _, symbol := range symbols {
		symbols = append(symbols, fmt.Sprintf("%s.%s", pkg, symbol))
		symbols = append(symbols, fmt.Sprintf("(%s).%s", pkg, symbol))
		symbols = append(symbols, fmt.Sprintf("(*%s).%s", pkg, symbol))
	}

	// Use callgraph library to list all the Callers and Callees (algorithm configurable via ALGO env var)
	callGraphOutput, err := r.generateCallGraphWithLib(dir, files)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to generate call graph in %s: %v", dir, err)
		r.Errors = append(r.Errors, errMsg)
		return "unknown"
	}

	// Convert to bytes for compatibility with existing matchSymbol function
	out := []byte(callGraphOutput)

	var wg sync.WaitGroup
	found := false

	for _, symbol := range symbols {
		wg.Add(1)
		go func(sym string) {
			defer wg.Done()
			if matchSymbol(out, sym) {
				r.Mu.Lock()
				if r.UsedImports == nil {
					r.UsedImports = make(map[string]UsedImportsDetails)
				}
				entry := r.UsedImports[pkg]
				entry.Symbols = append(entry.Symbols, sym)
				r.UsedImports[pkg] = entry
				r.Mu.Unlock()
				found = true
			}
		}(symbol)
	}

	wg.Wait()

	if found {
		return "true"
	}
	return "false"
}

// generateCallGraphWithLib creates a call graph using the callgraph library
func (r *Result) generateCallGraphWithLib(dir string, files []string) (string, error) {
	// Determine package patterns to load based on the files
	packagePatterns := make(map[string]bool)

	// Add the current directory and any subdirectories containing the files
	packagePatterns["."] = true
	for _, file := range files {
		packageDir := filepath.Dir(file)
		if packageDir != "." {
			packagePatterns["./"+packageDir] = true
		}
	}

	var patterns []string
	for pattern := range packagePatterns {
		patterns = append(patterns, pattern)
	}

	// Load packages with comprehensive mode to handle all dependencies
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax, // This loads everything needed for analysis
		Dir:  dir,
		Env:  append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off"),
	}

	// Load packages
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return "", fmt.Errorf("failed to load packages: %v", err)
	}

	if len(pkgs) == 0 {
		return "", fmt.Errorf("no packages loaded")
	}

	// Check for package errors and try to filter out packages with issues
	var validPkgs []*packages.Package
	for _, pkg := range pkgs {
		if len(pkg.Errors) == 0 && pkg.Types != nil && pkg.TypesInfo != nil {
			validPkgs = append(validPkgs, pkg)
		}
	}

	// If no valid packages, try loading with less strict requirements
	if len(validPkgs) == 0 {
		// Try with just the module root pattern
		cfg = &packages.Config{
			Mode: packages.LoadSyntax,
			Dir:  dir,
			Env:  append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off"),
		}

		pkgs, err = packages.Load(cfg, "./...")
		if err != nil {
			return "", fmt.Errorf("failed to load packages with fallback: %v", err)
		}

		for _, pkg := range pkgs {
			if len(pkg.Errors) == 0 {
				validPkgs = append(validPkgs, pkg)
			}
		}
	}

	if len(validPkgs) == 0 {
		return "", fmt.Errorf("no valid packages found after loading")
	}

	// Create SSA program with InstantiateGenerics for call graph analysis
	prog, _ := ssautil.AllPackages(validPkgs, ssa.InstantiateGenerics)
	prog.Build()

	// Get the algorithm from environment variable and build call graph
	algo := getCallGraphAlgorithm()
	cg := buildCallGraph(prog, algo)

	// Convert call graph to string format matching callgraph binary output
	var output strings.Builder
	for _, node := range cg.Nodes {
		if node.Func == nil {
			continue
		}

		caller := node.Func.String()
		for _, edge := range node.Out {
			if edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}

			callee := edge.Callee.Func.String()
			output.WriteString(fmt.Sprintf("%s %s\n", caller, callee))
		}
	}

	return output.String(), nil
}

func matchSymbol(out []byte, symbol string) bool {
	pattern := regexp.MustCompile(`\s` + regexp.QuoteMeta(symbol) + `$`)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if pattern.MatchString(scanner.Text()) {
			return true
		}
	}
	return false
}

// getCallGraphAlgorithm returns the algorithm to use for call graph generation
// based on the ALGO environment variable.
// Supported algorithms: vta (default), cha, rta, static
func getCallGraphAlgorithm() string {
	algo := os.Getenv("ALGO")
	if algo == "" {
		algo = "vta" // default algorithm
	}
	return strings.ToLower(algo)
}

// buildCallGraph builds a call graph using the specified algorithm
func buildCallGraph(prog *ssa.Program, algo string) *callgraph.Graph {
	allFuncs := ssautil.AllFunctions(prog)

	switch algo {
	case "cha":
		// Class Hierarchy Analysis - fast but less precise
		return cha.CallGraph(prog)
	case "rta":
		// Rapid Type Analysis - good balance of speed and precision
		return buildRTACallGraph(prog, allFuncs)
	case "static":
		// Static analysis - very fast but least precise (only direct calls)
		return static.CallGraph(prog)
	case "vta":
		// Variable Type Analysis - most precise but slower (default)
		return vta.CallGraph(allFuncs, nil)
	default:
		// Default to VTA if unknown algorithm specified
		return vta.CallGraph(allFuncs, nil)
	}
}

// buildRTACallGraph safely builds an RTA call graph with panic recovery
func buildRTACallGraph(prog *ssa.Program, allFuncs map[*ssa.Function]bool) (result *callgraph.Graph) {
	// RTA can panic on certain code patterns, so we recover and fallback
	defer func() {
		if r := recover(); r != nil {
			// RTA panicked, fallback to static analysis
			result = static.CallGraph(prog)
		}
	}()

	var roots []*ssa.Function
	for fn := range allFuncs {
		if fn.Pkg != nil && fn.Pkg.Pkg.Name() == "main" && fn.Name() == "main" {
			roots = append(roots, fn)
		}
	}
	// If no main function found, fall back to static analysis
	if len(roots) == 0 {
		return static.CallGraph(prog)
	}

	// Try RTA analysis
	rtaResult := rta.Analyze(roots, true)
	if rtaResult != nil {
		return rtaResult.CallGraph
	}
	// Fallback to static if RTA returns nil
	return static.CallGraph(prog)
}

func getCurrentVersion(pkg string, dir string, result *Result) string {
	// Check if this is a stdlib package
	if result.AffectedImports != nil {
		if details, exists := result.AffectedImports[pkg]; exists && details.Type == "stdlib" {
			return getGoToolchainVersion(dir, result)
		}
	}

	cmd := "go"
	args := []string{"list", "-f", "{{if .Module}}{{.Module.Version}}{{end}}", pkg}
	out, err := cli.RunCommand(dir, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getGoToolchainVersion(dir string, result *Result) string {
	cmd := "go"
	args := []string{"mod", "edit", "-json"}
	out, err := cli.RunCommand(dir, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
		return ""
	}

	var goModEdit GoModEdit
	err = json.Unmarshal(out, &goModEdit)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to parse go.mod JSON in %s: %v", dir, err)
		result.Errors = append(result.Errors, errMsg)
		return ""
	}

	// Get the Go version from go.mod
	if goModEdit.Go != "" {
		goVersion := goModEdit.Go
		// Add 'v' prefix for semver compatibility if not present
		if !strings.HasPrefix(goVersion, "v") {
			goVersion = "v" + goVersion
		}
		return goVersion
	}

	return ""
}

func getReplaceVersion(pkg string, dir string, result *Result) string {
	cmd := "go"
	args := []string{"mod", "edit", "-json"}
	out, err := cli.RunCommand(dir, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
		return ""
	}

	var goModEdit GoModEdit
	err = json.Unmarshal(out, &goModEdit)
	if err != nil {
		return ""
	}

	for _, r := range goModEdit.Replace {
		if r.Old.Path == pkg {
			if r.New.Version != "" {
				return r.New.Version
			}
		}
	}

	return ""
}

func getFixedVersion(id, pkg string, result *Result) []string {
	url := fmt.Sprintf(VulnsURL+"/ID/%s.json", id)
	resp, err := http.Get(url)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get response from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)

	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to read response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)

	}

	var detail VulnReport
	if err := json.Unmarshal(body, &detail); err != nil {
		errMsg := fmt.Sprintf("Failed to unmarshal response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
	}

	for _, a := range detail.Affected {
		if a.Package.Name == pkg {
			for _, r := range a.Ranges {
				if r.Type == "SEMVER" {
					return formatIntroducedFixed(r.Events)
				}
			}
		} else if a.Package.Name == "stdlib" {
			for _, r := range a.Ranges {
				if r.Type == "SEMVER" {
					return formatIntroducedFixed(r.Events)
				}
			}
		}
	}

	return nil
}

func getModPath(pkg, dir string, result *Result) string {
	cmd := "go"
	args := []string{"list", "-f", "{{if .Module}}{{.Module.Path}}{{end}}", pkg}
	out, err := cli.RunCommand(dir, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getGitBranch(result *Result) {
	cmd := "git"
	args := []string{"rev-parse", "--abbrev-ref", "HEAD"}
	out, err := cli.RunCommand(result.Directory, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), result.Directory, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
		return
	}

	branchName := strings.TrimSpace(string(out))

	// If we're in detached HEAD state (happens when checking out a commit hash),
	// get the actual commit hash instead of "HEAD"
	if branchName == "HEAD" {
		commitCmd := "git"
		commitArgs := []string{"rev-parse", "HEAD"}
		commitOut, err := cli.RunCommand(result.Directory, commitCmd, commitArgs...)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", commitCmd, strings.Join(commitArgs, " "), result.Directory, strings.TrimSpace(string(commitOut)))
			result.Errors = append(result.Errors, errMsg)
			result.Branch = branchName // fallback to "HEAD"
		} else {
			result.Branch = strings.TrimSpace(string(commitOut))
		}
	} else {
		result.Branch = branchName
	}
}

func getGitURL(result *Result) {
	cmd := "git"
	args := []string{"remote", "get-url", "origin"}
	out, err := cli.RunCommand(result.Directory, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), result.Directory, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
	}
	result.Repository = strings.TrimSpace(string(out))
}

func formatIntroducedFixed(events []Event) []string {
	var result []string
	var introduced string

	for _, e := range events {
		if e.Introduced != "" {
			introduced = e.Introduced
		}
		if e.Fixed != "" && introduced != "" {
			pair := fmt.Sprintf("Introduced in %s and fixed in %s", introduced, e.Fixed)
			result = append(result, pair)
			introduced = ""
		}
	}

	if introduced != "" {
		result = append(result, fmt.Sprintf("Introdued in %s - ", introduced))
	}

	return result
}

// extractGoVersion extracts a Go version from various formats like "go1.21.4", "1.21.4", etc.
func extractGoVersion(fixedVersion string) string {
	// Handle various formats of Go version strings
	fixedVersion = strings.TrimSpace(fixedVersion)

	// Extract version from "Introduced in X and fixed in Y" format
	if strings.Contains(fixedVersion, "fixed in") {
		parts := strings.Split(fixedVersion, "fixed in")
		if len(parts) > 1 {
			fixedVersion = strings.TrimSpace(parts[1])
		}
	}

	// Remove "go" prefix if present
	fixedVersion = strings.TrimPrefix(fixedVersion, "go")

	// Ensure it's a valid semver format (add "v" prefix if missing)
	if regexp.MustCompile(`^\d+\.\d+`).MatchString(fixedVersion) {
		fixedVersion = "v" + strings.TrimPrefix(fixedVersion, "v")
	}

	return fixedVersion
}

// findAppropriateFixVersion finds the fixed version that corresponds to the same major.minor branch
// as the current Go version. For example, if current is v1.23.8 and fixes are ["1.23.8", "1.24.2"],
// it returns "v1.23.8" since they're on the same 1.23.x branch.
func findAppropriateFixVersion(currentGoVersion string, fixedVersions []string) string {
	currentVersion := extractGoVersion(currentGoVersion)
	if currentVersion == "" {
		return ""
	}

	// Extract major.minor from current version (e.g., "v1.23.8" -> "v1.23")
	currentMajorMinor := getMajorMinor(currentVersion)
	if currentMajorMinor == "" {
		return ""
	}

	// Find a fixed version that matches the same major.minor
	for _, fixVer := range fixedVersions {
		fixVersion := extractGoVersion(fixVer)
		if fixVersion == "" {
			continue
		}

		fixMajorMinor := getMajorMinor(fixVersion)
		if fixMajorMinor == currentMajorMinor {
			return fixVersion
		}
	}

	// If no exact major.minor match, find the closest applicable version
	// This handles cases where the fix might be in a newer major.minor branch
	var bestMatch string
	for _, fixVer := range fixedVersions {
		fixVersion := extractGoVersion(fixVer)
		if fixVersion == "" {
			continue
		}

		// If this fix version is greater than or equal to current, it's applicable
		if semver.Compare(fixVersion, currentVersion) >= 0 {
			if bestMatch == "" || semver.Compare(fixVersion, bestMatch) < 0 {
				bestMatch = fixVersion
			}
		}
	}

	return bestMatch
}

// getMajorMinor extracts the major.minor version from a semver string
// e.g., "v1.23.8" -> "v1.23"
func getMajorMinor(version string) string {
	if !strings.HasPrefix(version, "v") {
		return ""
	}

	parts := strings.Split(version[1:], ".")
	if len(parts) < 2 {
		return ""
	}

	return "v" + parts[0] + "." + parts[1]
}

// selectFixVersionForCurrentGoVersion selects the appropriate fixed version from a slice of fixed versions
// based on the current Go version. It returns the smallest fixed version that is greater than the current version.
func selectFixVersionForCurrentGoVersion(currentGoVersion string, fixedVersions []string) string {
	if len(fixedVersions) == 0 {
		return ""
	}

	// If there's only one fixed version, return it
	if len(fixedVersions) == 1 {
		return extractGoVersion(fixedVersions[0])
	}

	// Extract and normalize the current Go version
	currentVersion := extractGoVersion(currentGoVersion)
	if currentVersion == "" {
		// If we can't determine the current version, return the first fixed version
		return extractGoVersion(fixedVersions[0])
	}

	// Find the smallest fixed version that is greater than the current version
	var bestFix string
	for _, fixVer := range fixedVersions {
		fixVersion := extractGoVersion(fixVer)
		if fixVersion == "" {
			continue
		}

		// If this fixed version is greater than current version
		if semver.Compare(fixVersion, currentVersion) > 0 {
			// If we haven't found a best fix yet, or this one is smaller than our current best
			if bestFix == "" || semver.Compare(fixVersion, bestFix) < 0 {
				bestFix = fixVersion
			}
		}
	}

	// If no version is greater than current (shouldn't happen in vulnerable cases),
	// return the latest fixed version
	if bestFix == "" {
		return extractGoVersion(fixedVersions[len(fixedVersions)-1])
	}

	// Remove the 'v' prefix for go.mod compatibility
	bestFix = strings.TrimPrefix(bestFix, "v")

	return bestFix
}

// ProgressCallback is a function type for progress reporting
type ProgressCallback func(message string)

// DetectUnsafeReflectUsage scans the repository for usage of unsafe and reflect packages
// Uses AST parsing to avoid false positives from comments, strings, etc.
// progressFn is optional - pass nil for no progress reporting
func DetectUnsafeReflectUsage(result *Result, progressFn ProgressCallback) {
	// Initialize to false
	result.Unsafe = false
	result.Reflect = false

	var fileCount int
	var processedFiles int

	// Count files if progress reporting is enabled
	if progressFn != nil {
		filepath.WalkDir(result.Directory, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), ".go") &&
				!strings.Contains(path, "/vendor/") && !strings.HasSuffix(d.Name(), "_test.go") {
				fileCount++
			}
			return nil
		})
		progressFn(fmt.Sprintf("  Scanning %d Go files for unsafe/reflect usage...", fileCount))
	}

	// Walk through all Go files in the directory
	err := filepath.WalkDir(result.Directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-Go files
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		// Skip vendor directories and test files for cleaner analysis
		if strings.Contains(path, "/vendor/") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}

		if progressFn != nil {
			processedFiles++
		}

		// Parse the Go file using AST
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			// Don't fail the entire scan for parse errors, just log
			errMsg := fmt.Sprintf("Failed to parse Go file %s for unsafe/reflect detection: %v", path, err)
			result.Errors = append(result.Errors, errMsg)
			return nil
		}

		// Check imports and usage using AST
		hasUnsafe, hasReflect := analyzeASTForPackages(node)

		if hasUnsafe && !result.Unsafe {
			result.Unsafe = true
			if progressFn != nil {
				progressFn(fmt.Sprintf("    Found unsafe package usage in: %s", path))
			}
		}

		if hasReflect && !result.Reflect {
			result.Reflect = true
			if progressFn != nil {
				progressFn(fmt.Sprintf("    Found reflect package usage in: %s", path))
			}
		}

		// Early exit if both are found
		if result.Unsafe && result.Reflect {
			if progressFn != nil {
				progressFn(fmt.Sprintf("  ✓ Both unsafe and reflect usage detected (processed %d/%d files)", processedFiles, fileCount))
			}
			return filepath.SkipAll
		}

		return nil
	})

	if err != nil {
		errMsg := fmt.Sprintf("Failed to scan directory for unsafe/reflect usage: %v", err)
		result.Errors = append(result.Errors, errMsg)
	}

	if progressFn != nil {
		progressFn(fmt.Sprintf("  ✓ Package usage detection complete: unsafe=%t, reflect=%t", result.Unsafe, result.Reflect))
	}
}

// analyzeASTForPackages analyzes an AST node for actual usage of unsafe and reflect packages
// Returns (hasUnsafe, hasReflect)
func analyzeASTForPackages(node *ast.File) (bool, bool) {
	hasUnsafe := false
	hasReflect := false

	// Track imported package names and their aliases
	importedPackages := make(map[string]string) // alias -> package path

	// First pass: collect imports
	for _, imp := range node.Imports {
		if imp.Path == nil {
			continue
		}

		pkgPath := strings.Trim(imp.Path.Value, `"`)
		var alias string

		if imp.Name != nil {
			// Explicit alias (import alias "package" or import . "package")
			alias = imp.Name.Name
		} else {
			// Default alias is the last part of the package path
			parts := strings.Split(pkgPath, "/")
			alias = parts[len(parts)-1]
		}

		importedPackages[alias] = pkgPath
	}

	// Check if unsafe or reflect are imported
	for alias, pkgPath := range importedPackages {
		if pkgPath == "unsafe" {
			hasUnsafe = true
		}
		if pkgPath == "reflect" {
			hasReflect = true
		}
		// Handle dot imports
		if alias == "." && (pkgPath == "unsafe" || pkgPath == "reflect") {
			if pkgPath == "unsafe" {
				hasUnsafe = true
			}
			if pkgPath == "reflect" {
				hasReflect = true
			}
		}
	}

	// Second pass: look for actual usage in the code
	// Only check for usage if the packages are imported
	if hasUnsafe || hasReflect {
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				// Check for package.Function calls (e.g., unsafe.Pointer, reflect.TypeOf)
				if ident, ok := x.X.(*ast.Ident); ok {
					if pkgPath, exists := importedPackages[ident.Name]; exists {
						if pkgPath == "unsafe" {
							hasUnsafe = true
						}
						if pkgPath == "reflect" {
							hasReflect = true
						}
					}
				}
			case *ast.CallExpr:
				// Handle dot imports where functions are called directly
				if _, ok := x.Fun.(*ast.Ident); ok {
					// Check if this could be a function from a dot-imported package
					// This is less precise but catches dot import usage
					for alias, pkgPath := range importedPackages {
						if alias == "." {
							// For dot imports, we assume usage if the package is imported
							// since we can't easily distinguish between local and imported functions
							if pkgPath == "unsafe" {
								hasUnsafe = true
							}
							if pkgPath == "reflect" {
								hasReflect = true
							}
						}
					}
				}
			}
			return true
		})
	}

	return hasUnsafe, hasReflect
}

// ConvertUsedImports converts from cmd/cg UsedImportsDetails to common interface format
func ConvertUsedImports(input map[string]UsedImportsDetails) map[string]interface{} {
	if input == nil {
		return nil
	}

	result := make(map[string]interface{})
	for key, details := range input {
		result[key] = map[string]interface{}{
			"Symbols":        details.Symbols,
			"CurrentVersion": details.CurrentVersion,
			"ReplaceVersion": details.ReplaceVersion,
			"FixCommands":    details.FixCommands,
		}
	}
	return result
}

// ConvertAffectedImports converts from AffectedImportsDetails to interface format
func ConvertAffectedImports(input map[string]AffectedImportsDetails) map[string]interface{} {
	if input == nil {
		return nil
	}

	result := make(map[string]interface{})
	for key, details := range input {
		result[key] = map[string]interface{}{
			"Symbols":      details.Symbols,
			"Type":         details.Type,
			"FixedVersion": details.FixedVersion,
		}
	}
	return result
}
