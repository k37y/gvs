package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/k37y/gvs/internal/cli"
	"github.com/k37y/gvs/internal/common"
	"github.com/k37y/gvs/pkg/cmd/cg"
	"github.com/k37y/gvs/pkg/utils"
)

func main() {
	tools := []string{"go", "digraph", "git"}
	if !utils.ValidateTools(tools) {
		os.Exit(1)
	}

	// Define flags
	var fix = flag.Bool("fix", false, "run fix commands after analysis")
	var algo = flag.String("algo", "vta", "call graph algorithm: vta (default), cha, rta, static")
	var progress = flag.Bool("progress", false, "show progress of completed and pending jobs")
	var library = flag.String("library", "", "override library path to scan (e.g., golang.org/x/net/html)")
	var symbols = flag.String("symbols", "", "override symbol(s) to scan for (comma-separated, e.g., Parse,Render)")
	var fixversion = flag.String("fixversion", "", "fixed version for manual scans (e.g., v1.9.4)")

	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <CVE ID> <directory>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSupported algorithms: vta (default), cha, rta, static\n")
		fmt.Fprintf(os.Stderr, "\nLibrary/Symbol Override:\n")
		fmt.Fprintf(os.Stderr, "  When -library and -symbols are provided, they take precedence over CVE-based symbol lookup.\n")
		fmt.Fprintf(os.Stderr, "  Optionally use -fixversion to specify the fixed version for version comparison.\n")
		fmt.Fprintf(os.Stderr, "  This allows scanning for specific library/symbol combinations directly.\n")
	}

	// Parse flags
	flag.Parse()

	// Get positional arguments
	args := flag.Args()
	if len(args) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	cveID := args[0]
	directory := args[1]

	// Validate that library, symbols, and fixversion are all provided together
	libraryProvided := *library != ""
	symbolsProvided := *symbols != ""
	fixversionProvided := *fixversion != ""
	anyManualScanFieldProvided := libraryProvided || symbolsProvided || fixversionProvided

	if anyManualScanFieldProvided {
		if !libraryProvided || !symbolsProvided || !fixversionProvided {
			fmt.Fprintf(os.Stderr, "Error: When using manual scan mode, all three fields are mandatory:\n")
			fmt.Fprintf(os.Stderr, "  -library    : %v\n", libraryProvided)
			fmt.Fprintf(os.Stderr, "  -symbols    : %v\n", symbolsProvided)
			fmt.Fprintf(os.Stderr, "  -fixversion : %v\n", fixversionProvided)
			fmt.Fprintf(os.Stderr, "\nPlease provide all three fields or none.\n")
			os.Exit(1)
		}
	}

	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		fmt.Printf("Invalid directory: %s\n", directory)
		os.Exit(1)
	}

	// Validate and set algorithm (always has a value due to default)
	validAlgos := []string{"vta", "cha", "rta", "static"}
	isValid := false
	algoLower := strings.ToLower(*algo)
	for _, valid := range validAlgos {
		if algoLower == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		fmt.Printf("Error: Invalid algorithm '%s'\n", *algo)
		fmt.Printf("Supported algorithms: vta, cha, rta, static\n")
		os.Exit(1)
	}
	// Always set environment variable for the scanner to use
	os.Setenv("ALGO", algoLower)

	defaultWorkers := runtime.NumCPU() / 2
	if defaultWorkers < 1 {
		defaultWorkers = 1
	}

	if envVal, ok := os.LookupEnv("WORKER_COUNT"); ok {
		if n, err := strconv.Atoi(envVal); err == nil && n > 0 {
			defaultWorkers = n
		}
	}

	// Initialize result with progress tracking if enabled
	var result *cg.Result
	if *progress {
		fmt.Fprintf(os.Stderr, "Initializing vulnerability scan...\n")
		result = initResultWithProgress(cveID, directory, *fix, *library, *symbols, *fixversion)
	} else {
		result = cg.InitResult(cveID, directory, *fix, *library, *symbols, *fixversion)
	}

	jobs := make(chan cg.Job)
	results := make(chan *cg.Result)

	var wg sync.WaitGroup

	// Progress tracking variables
	var totalJobs int64
	var completedJobs int64
	var progressDone = make(chan bool)
	var lastPrintedPercentage float64 = -1

	workerCount := defaultWorkers

	// Start progress display goroutine if progress flag is enabled
	if *progress {
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-progressDone:
					return
				case <-ticker.C:
					completed := atomic.LoadInt64(&completedJobs)
					total := atomic.LoadInt64(&totalJobs)
					if total > 0 {
						percentage := float64(completed) / float64(total) * 100
						// Only print if percentage has changed
						if percentage != lastPrintedPercentage {
							fmt.Fprintf(os.Stderr, "Progress: %d/%d jobs completed (%.1f%%)\n", completed, total, percentage)
							lastPrintedPercentage = percentage
						}
					}
				}
			}
		}()
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go cg.Worker(jobs, results, &wg, result)
	}

	go func() {
		// Count total jobs first if progress is enabled
		if *progress {
			for _, sets := range result.Files {
				for range sets {
					for range result.AffectedImports {
						atomic.AddInt64(&totalJobs, 1)
					}
				}
			}
		}

		// Send jobs to workers
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
	hasProcessedAny := false

	for res := range results {
		hasProcessedAny = true

		// Increment completed jobs counter for progress tracking
		if *progress {
			atomic.AddInt64(&completedJobs, 1)
		}

		// Track the overall vulnerability status across all packages
		switch res.IsVulnerable {
		case "true":
			hasVulnerable = true
		case "unknown":
			hasUnknown = true
		}

		// Only merge imports for vulnerable packages
		if res.IsVulnerable == "true" {
			for pkg, symbols := range res.UsedImports {
				for _, sym := range symbols.Symbols {
					if strings.HasPrefix(sym, pkg+".") {
						sym = strings.TrimPrefix(sym, pkg+".")
					}

					entry := mergedImports[pkg]
					entry.Symbols = append(entry.Symbols, sym)

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
		}
	}

	// Stop progress display
	if *progress {
		close(progressDone)
		completed := atomic.LoadInt64(&completedJobs)
		total := atomic.LoadInt64(&totalJobs)
		// Only print final progress if 100% hasn't been printed yet
		if lastPrintedPercentage != 100.0 {
			fmt.Fprintf(os.Stderr, "Progress: %d/%d jobs completed (100.0%%)\n", completed, total)
		}
	}

	for pkg, details := range mergedImports {
		deduped := common.UniqueStrings(details.Symbols)
		isSymbolsEmpty := len(deduped) == 0
		isCurrentVersionEmpty := details.CurrentVersion == ""
		isReplaceVersionEmpty := details.ReplaceVersion == ""

		if isSymbolsEmpty && isCurrentVersionEmpty && isReplaceVersionEmpty {
			delete(mergedImports, pkg)
			continue
		}

		if !isSymbolsEmpty {
			sort.Strings(deduped)
			details.Symbols = deduped
		}
		mergedImports[pkg] = details
	}

	// Properly determine final vulnerability status
	if hasVulnerable {
		result.IsVulnerable = "true"
		result.UsedImports = mergedImports
	} else if hasUnknown {
		result.IsVulnerable = "unknown"
		result.UsedImports = nil
	} else if hasProcessedAny {
		result.IsVulnerable = "false"
		result.UsedImports = nil
	} else {
		// No packages were processed (shouldn't happen, but safe fallback)
		result.IsVulnerable = "unknown"
		result.UsedImports = nil
	}

	// Run fix commands BEFORE generating output (only if fix is true)
	if *fix {
		// Convert to cli.Result for shared function compatibility
		// Include all CVE assessment data for complete output
		fixResult := &cli.Result{
			IsVulnerable:    result.IsVulnerable,
			UsedImports:     cg.ConvertUsedImports(result.UsedImports),
			Files:           result.Files,
			AffectedImports: cg.ConvertAffectedImports(result.AffectedImports),
			GoCVE:           result.GoCVE,
			CVE:             result.CVE,
			Repository:      result.Repository,
			Branch:          result.Branch,
			Directory:       result.Directory,
			CursorCommand:   result.CursorCommand,
			Errors:          result.Errors,
			FixErrors:       result.FixErrors,
			FixSuccess:      result.FixSuccess,
			Summary:         result.Summary,
		}

		// Count packages with fix commands for progress tracking
		packagesWithFixes := 0
		for _, details := range result.UsedImports {
			if len(details.FixCommands) > 0 {
				packagesWithFixes++
			}
		}

		if packagesWithFixes > 0 && *progress {
			fmt.Fprintf(os.Stderr, "Running fix commands for %d package(s)...\n", packagesWithFixes)
		}

		processedPackages := 0
		for pkg, details := range result.UsedImports {
			if len(details.FixCommands) > 0 {
				if *progress {
					processedPackages++
					fmt.Fprintf(os.Stderr, "Fix progress: %d/%d packages processed (%.1f%%) - Running fixes for %s\n",
						processedPackages, packagesWithFixes,
						float64(processedPackages)/float64(packagesWithFixes)*100, pkg)
				}
				cli.RunFixCommands(pkg, result.Directory, details.FixCommands, fixResult)
			}
		}

		if packagesWithFixes > 0 && *progress {
			fmt.Fprintf(os.Stderr, "Fix commands completed for all packages\n")
		}

		// Read gvs-output.txt to populate fix results (only if fixes were run)
		cli.ReadFixResults(fixResult)

		// Copy back the results
		result.FixErrors = fixResult.FixErrors
		result.FixSuccess = fixResult.FixSuccess
		result.Errors = fixResult.Errors
	}

	// Generate summary and output JSON
	cg.GenerateSummaryWithGemini(result)
	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		errMsg := "Failed to marshal result to JSON: " + err.Error()
		result.Errors = append(result.Errors, errMsg)
	} else {
		fmt.Println(string(jsonOutput))
	}
}

// initResultWithProgress initializes the result with progress tracking for each phase
func initResultWithProgress(cve, dir string, fix bool, library, symbols, fixversion string) *cg.Result {
	r := &cg.Result{
		CVE:          cve,
		Directory:    dir,
		IsVulnerable: "unknown",
	}

	// Only initialize fix-related fields if fix is true
	if fix {
		cursorCmd := fmt.Sprintf("cursor --remote ssh-remote+gvs-host %s", dir)
		r.CursorCommand = &cursorCmd
		fixErrors := []string{}
		fixSuccess := []string{}
		r.FixErrors = &fixErrors
		r.FixSuccess = &fixSuccess
	}

	// Check if library and symbols are provided for direct scanning (takes precedence)
	if library != "" && symbols != "" {
		fmt.Fprintf(os.Stderr, "Phase 1/6: Using provided library and symbol override...\n")
		fmt.Fprintf(os.Stderr, "  Library: %s\n", library)
		fmt.Fprintf(os.Stderr, "  Symbol(s): %s\n", symbols)

		// Set a placeholder GoCVE to indicate manual scanning
		if cve != "" {
			if common.IsGOCVEID(cve) {
				r.GoCVE = cve
			} else if common.IsCVEID(cve) {
				fetchGoVulnIDWithProgress(r)
			}
		} else {
			r.GoCVE = "MANUAL-SCAN"
		}

		// Phase 2: Use provided library and symbols instead of fetching
		fmt.Fprintf(os.Stderr, "Phase 2/6: Using provided library and symbols...\n")
		symbolList := strings.Split(symbols, ",")
		for i := range symbolList {
			symbolList[i] = strings.TrimSpace(symbolList[i])
		}

		details := cg.AffectedImportsDetails{
			Symbols: symbolList,
			Type:    "non-stdlib",
		}

		// Add fixed version if provided
		if fixversion != "" {
			details.FixedVersion = []string{fixversion}
			fmt.Fprintf(os.Stderr, "  Using fixed version: %s\n", fixversion)
		}

		r.AffectedImports = map[string]cg.AffectedImportsDetails{
			library: details,
		}

		// Check if it's a stdlib package
		if strings.HasPrefix(library, "crypto/") || strings.HasPrefix(library, "net/") ||
		   strings.HasPrefix(library, "encoding/") || strings.HasPrefix(library, "os/") ||
		   !strings.Contains(library, ".") {
			entry := r.AffectedImports[library]
			entry.Type = "stdlib"
			r.AffectedImports[library] = entry
		}
		fmt.Fprintf(os.Stderr, "  ✓ Using %d symbol(s) for library %s\n", len(symbolList), library)
	} else {
		// Phase 1: Determine vulnerability ID type and fetch if needed
		fmt.Fprintf(os.Stderr, "Phase 1/6: Processing vulnerability identifier...\n")
		if common.IsGOCVEID(cve) {
			// Input is already a GOCVE ID, use it directly
			r.GoCVE = cve
			fmt.Fprintf(os.Stderr, "  ✓ Using provided GOCVE ID: %s\n", cve)
		} else if common.IsCVEID(cve) {
			// Input is a CVE ID, convert to GOCVE ID
			fmt.Fprintf(os.Stderr, "  Converting CVE ID to GOCVE ID...\n")
			fetchGoVulnIDWithProgress(r)
		} else {
			// Invalid input format
			r = &cg.Result{
				GoCVE:        "Invalid input format",
				IsVulnerable: "unknown",
				CVE:          r.CVE,
				Directory:    r.Directory,
				Branch:       r.Branch,
				Repository:   r.Repository,
				Unsafe:       r.Unsafe,
				Reflect:      r.Reflect,
				Errors:       []string{"Invalid input format. Please provide either a CVE ID (CVE-YYYY-NNNN) or GOCVE ID (GO-YYYY-NNNN)"},
			}
			jsonOutput, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				errMsg := fmt.Sprintf("Failed to marshal results to JSON: %v", err)
				r.Errors = append(r.Errors, errMsg)
			}
			fmt.Println(string(jsonOutput))
			os.Exit(0)
		}

		// Phase 2: Fetch affected symbols
		fmt.Fprintf(os.Stderr, "Phase 2/6: Fetching affected symbols...\n")
		fetchAffectedSymbolsWithProgress(r)
	}

	// Phase 3: Find main Go files and directories
	fmt.Fprintf(os.Stderr, "Phase 3/6: Discovering Go modules and main files...\n")
	findMainGoFilesWithProgress(r)

	// Phase 4: Get git branch
	fmt.Fprintf(os.Stderr, "Phase 4/6: Getting git branch information...\n")
	getGitBranchWithProgress(r)

	// Phase 5: Get git URL
	fmt.Fprintf(os.Stderr, "Phase 5/6: Getting git repository URL...\n")
	getGitURLWithProgress(r)

	// Phase 6: Detect unsafe/reflect usage
	fmt.Fprintf(os.Stderr, "Phase 6/6: Detecting unsafe and reflect package usage...\n")
	cg.DetectUnsafeReflectUsage(r, func(msg string) {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
	})

	if r.GoCVE == "" {
		r = &cg.Result{
			GoCVE:        "",
			IsVulnerable: "unknown",
			CVE:          r.CVE,
			Directory:    r.Directory,
			Branch:       r.Branch,
			Repository:   r.Repository,
			Unsafe:       r.Unsafe,
			Reflect:      r.Reflect,
			Errors:       []string{"No Go CVE ID found"},
		}
		jsonOutput, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			errMsg := "Failed to marshal results to JSON: " + err.Error()
			r.Errors = append(r.Errors, errMsg)
		}
		fmt.Println(string(jsonOutput))
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Initialization complete. Starting vulnerability analysis...\n")
	return r
}

// Progress-aware wrapper functions for initialization phases

func fetchGoVulnIDWithProgress(result *cg.Result) {
	client := http.Client{Timeout: 10 * time.Second}
	url := "https://vuln.go.dev/index/vulns.json"

	resp, err := client.Get(url)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get response from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to read response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
		return
	}

	var vulns []cg.VulnReport
	if err := json.Unmarshal(body, &vulns); err != nil {
		errMsg := fmt.Sprintf("Failed to marshal response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
		return
	}

	for _, v := range vulns {
		if slices.Contains(v.Aliases, result.CVE) {
			result.GoCVE = v.ID
			break
		}
	}

	fmt.Fprintf(os.Stderr, "  ✓ Go vulnerability ID fetched: %s\n", result.GoCVE)
}

func fetchAffectedSymbolsWithProgress(result *cg.Result) {
	client := http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://vuln.go.dev/ID/%s.json", result.GoCVE)

	resp, err := client.Get(url)
	if err != nil {
		errMsg := fmt.Sprintf("Failed HTTP request to %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Failed to connect %s: %s", url, resp.Status)
		result.Errors = append(result.Errors, errMsg)
		return
	}

	var detail cg.VulnReport
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		errMsg := fmt.Sprintf("Failed to parse JSON: %v", err)
		result.Errors = append(result.Errors, errMsg)
		return
	}

	// Validate that required fields are not empty
	if len(detail.Affected) == 0 {
		result.Errors = append(result.Errors, "Affected packages list is empty")
		fmt.Fprintf(os.Stderr, "  ✗ Error: Affected packages list is empty\n")
		return
	}

	imports := make(map[string]cg.AffectedImportsDetails)
	symbolCount := 0
	hasValidImports := false

	for _, aff := range detail.Affected {
		typ := "non-stdlib"
		if aff.Package.Name == "stdlib" {
			typ = "stdlib"
		}

		// Check if imports are empty
		if len(aff.EcosystemSpecific.Imports) == 0 {
			continue
		}

		for _, imp := range aff.EcosystemSpecific.Imports {
			// Skip imports with empty path or symbols
			if imp.Path == "" || len(imp.Symbols) == 0 {
				continue
			}

			entry := imports[imp.Path]
			entry.Symbols = append(entry.Symbols, imp.Symbols...)
			entry.Type = typ
			imports[imp.Path] = entry
			symbolCount += len(imp.Symbols)
			hasValidImports = true
		}
	}

	// Validate that we found at least one valid import with symbols
	if !hasValidImports {
		result.Errors = append(result.Errors, "No imports or symbols found in vulnerability data")
		fmt.Fprintf(os.Stderr, "  ✗ Error: No imports or symbols found in vulnerability data\n")
		return
	}

	result.AffectedImports = imports
	fmt.Fprintf(os.Stderr, "  ✓ Affected symbols fetched: %d symbols across %d packages\n", symbolCount, len(imports))
}

func findMainGoFilesWithProgress(result *cg.Result) {
	fmt.Fprintf(os.Stderr, "  Scanning directory structure...\n")

	fileResult := make(map[string][][]string)
	var modDirs []string

	// Walk directory with progress feedback
	err := filepath.WalkDir(result.Directory, func(path string, d os.DirEntry, err error) error {
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
			fmt.Fprintf(os.Stderr, "  Found Go module: %s\n", filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run filepath.WalkDir in %s: %v", result.Directory, err)
		result.Errors = append(result.Errors, errMsg)
	}

	fmt.Fprintf(os.Stderr, "  Analyzing %d Go modules...\n", len(modDirs))

	for i, modDir := range modDirs {
		fmt.Fprintf(os.Stderr, "  Processing module %d/%d: %s\n", i+1, len(modDirs), modDir)

		cmd := "go"
		args := []string{"list", "-f", `{{if eq .Name "main"}}{{.Name}}: {{.Dir}}{{end}}`, "./..."}
		out, err := cli.RunCommand(modDir, cmd, args...)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), modDir, strings.TrimSpace(string(out)))
			result.Errors = append(result.Errors, errMsg)
			continue
		}

		modKey, err := filepath.Rel(result.Directory, modDir)
		if err != nil {
			modKey = modDir
		}

		var sets [][]string
		mainPackageCount := 0

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
				mainPackageCount++
			}
		}

		if mainPackageCount > 0 {
			fmt.Fprintf(os.Stderr, "    Found %d main package(s) with %d file set(s)\n", mainPackageCount, len(sets))
		}

		fileResult[modKey] = sets
	}

	result.Files = fileResult
	fmt.Fprintf(os.Stderr, "  ✓ Directory and fileset discovery complete\n")
}

func getGitBranchWithProgress(result *cg.Result) {
	cmd := "git"
	args := []string{"rev-parse", "--abbrev-ref", "HEAD"}
	out, err := cli.RunCommand(result.Directory, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), result.Directory, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
	}
	result.Branch = strings.TrimSpace(string(out))
	fmt.Fprintf(os.Stderr, "  ✓ Git branch information retrieved: %s\n", result.Branch)
}

func getGitURLWithProgress(result *cg.Result) {
	cmd := "git"
	args := []string{"remote", "get-url", "origin"}
	out, err := cli.RunCommand(result.Directory, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), result.Directory, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
	}
	result.Repository = strings.TrimSpace(string(out))
	fmt.Fprintf(os.Stderr, "  ✓ Git repository URL retrieved: %s\n", result.Repository)
}
