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

	if r.GoCVE == "" {
		r = &Result{
			GoCVE:        "No Go CVE ID found",
			IsVulnerable: "unknown",
			CVE:          r.CVE,
			Directory:    r.Directory,
			Branch:       r.Branch,
			Repository:   r.Repository,
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
		if result.AffectedImports[j.Package].Type != "stdlib" {
			if semver.Compare(curVer, fv) <= 0 {
				result.IsVulnerable = "true"
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
			uentry.FixCommands = []string{
				fmt.Sprintf("go mod edit -go=%s", fixVer),
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
	}
	result.Branch = strings.TrimSpace(string(out))
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
