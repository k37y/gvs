package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/tools/go/callgraph"

	"github.com/k37y/gvs/internal/common"
	"github.com/k37y/gvs/pkg/cmd/cg"
	"github.com/k37y/gvs/pkg/utils"
)

var version string

func main() {
	// Note: sfdp is checked conditionally when -graph flag is used
	// digraph is no longer required - we use the callgraph.Graph directly with BFS
	tools := []string{"go", "git"}
	if !utils.ValidateTools(tools, os.Stderr) {
		os.Exit(1)
	}

	// Define flags
	var algo = flag.String("algo", "rta", "call graph algorithm: rta (default), cha, vta, static")
	var progress = flag.Bool("progress", false, "show progress of completed and pending jobs")
	var library = flag.String("library", "", "override library path to scan (e.g., golang.org/x/net/html)")
	var symbols = flag.String("symbols", "", "override symbol(s) to scan for (comma-separated, e.g., Parse,Render)")
	var fixversion = flag.String("fixversion", "", "fixed version for manual scans (e.g., v1.9.4)")
	var graph = flag.String("graph", "", "generate call graph SVG visualization (default: ./site/callgraph.svg if flag used without value)")
	var showVersion = flag.Bool("version", false, "print version and exit")

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
		fmt.Fprintf(os.Stderr, "  -fixversion supports version ranges as introduced:fixed pairs (comma-separated):\n")
		fmt.Fprintf(os.Stderr, "    -fixversion v1.9.4                              (single fix version)\n")
		fmt.Fprintf(os.Stderr, "    -fixversion \"0:2.7.26,2.9.13:2.11.14\"           (version ranges)\n")
		fmt.Fprintf(os.Stderr, "\nCall Graph Visualization:\n")
		fmt.Fprintf(os.Stderr, "  Use -graph to generate an SVG visualization of the call graph.\n")
		fmt.Fprintf(os.Stderr, "  -graph          : Saves to ./site/callgraph-<random>.svg (default)\n")
		fmt.Fprintf(os.Stderr, "  -graph=./path   : Saves to ./path/callgraph-<random>.svg (directory)\n")
		fmt.Fprintf(os.Stderr, "  -graph=file.svg : Saves to file.svg (specific file)\n")
		fmt.Fprintf(os.Stderr, "  Requires: graphviz (sfdp tool) to be installed\n")
	}

	// Parse flags
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

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

	// Get positional arguments
	// Manual scan mode: CVE is optional, only directory required
	// Normal mode: both CVE and directory required
	args := flag.Args()
	var cveID, directory string
	if anyManualScanFieldProvided {
		switch len(args) {
		case 1:
			directory = args[0]
		case 2:
			cveID = args[0]
			directory = args[1]
		default:
			fmt.Fprintf(os.Stderr, "Usage: %s [options] -library <pkg> -symbols <syms> -fixversion <ver> [CVE ID] <directory>\n", os.Args[0])
			os.Exit(1)
		}
	} else {
		if len(args) != 2 {
			flag.Usage()
			os.Exit(1)
		}
		cveID = args[0]
		directory = args[1]
	}

	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Invalid directory: %s\n", directory)
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
		fmt.Fprintf(os.Stderr, "Error: Invalid algorithm '%s'\n", *algo)
		fmt.Fprintf(os.Stderr, "Supported algorithms: vta, cha, rta, static\n")
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

	// Initialize result
	result := &cg.Result{
		ScanConfig: cg.ScanConfig{
			CVE:       cveID,
			Directory: directory,
		},
		IsVulnerable: "unknown",
	}
	if *progress {
		result.ProgressFunc = func(msg string) {
			fmt.Fprintf(os.Stderr, "%s\n", msg)
		}
	}

	scanStart := time.Now()
	if result.ProgressFunc != nil {
		result.ProgressFunc(fmt.Sprintf("cg version %s", version))
	}
	cg.LogClaudeStatus(result.ProgressFunc)

	// Setup: library mode or CVE mode
	var done bool
	if anyManualScanFieldProvided {
		done = cg.SetupLibraryMode(result, *library, *symbols, *fixversion)
	} else {
		done = cg.SetupCVEMode(result)
	}
	if !done {
		done = cg.Prepare(result)
	}
	if done {
		jsonOutput, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonOutput))
		os.Exit(0)
	}

	// Set progress flag on result for scanner to use
	result.Progress = *progress

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
					if total > 0 && completed > 0 {
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
		seen := make(map[string]bool)
		for modDir := range result.Files {
			for pkg, syms := range result.AffectedImports {
				key := modDir + "\x00" + pkg
				if seen[key] {
					continue
				}
				seen[key] = true
				atomic.AddInt64(&totalJobs, 1)
				jobs <- cg.Job{Package: pkg, Symbols: syms.Symbols, Dir: modDir}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	hasVulnerable := false
	hasUnknown := false
	hasProcessedAny := false

	for res := range results {
		hasProcessedAny = true

		if *progress {
			completed := atomic.AddInt64(&completedJobs, 1)
			total := atomic.LoadInt64(&totalJobs)
			if total > 0 {
				percentage := float64(completed) / float64(total) * 100
				fmt.Fprintf(os.Stderr, "Progress: %d/%d jobs completed (%.1f%%)\n", completed, total, percentage)
				lastPrintedPercentage = percentage
			}
		}

		switch res.IsVulnerable {
		case "true":
			hasVulnerable = true
		case "unknown":
			hasUnknown = true
		}
	}

	// Stop progress display
	if *progress {
		close(progressDone)
		completed := atomic.LoadInt64(&completedJobs)
		total := atomic.LoadInt64(&totalJobs)
		if lastPrintedPercentage != 100.0 {
			fmt.Fprintf(os.Stderr, "Progress: %d/%d jobs completed (100.0%%)\n", completed, total)
		}
	}

	// Deduplicate and normalize symbols within each dir/pkg entry
	for dir, pkgs := range result.UsedImports {
		for pkg, details := range pkgs {
			for i, sym := range details.Symbols {
				if strings.HasPrefix(sym, pkg+".") {
					details.Symbols[i] = strings.TrimPrefix(sym, pkg+".")
				}
			}
			deduped := common.UniqueStrings(details.Symbols)
			if len(deduped) == 0 && details.CurrentVersion == "" && details.ReplaceVersion == "" {
				delete(pkgs, pkg)
				continue
			}
			if len(deduped) > 0 {
				sort.Strings(deduped)
				details.Symbols = deduped
			}
			pkgs[pkg] = details
		}
		if len(pkgs) == 0 {
			delete(result.UsedImports, dir)
		}
	}

	if hasVulnerable {
		result.IsVulnerable = "true"
	} else if hasUnknown {
		result.IsVulnerable = "unknown"
	} else if hasProcessedAny {
		result.IsVulnerable = "false"
	} else {
		result.IsVulnerable = "unknown"
	}

	// Generate call graph visualizations if requested (one per affected symbol)
	if *graph != "" || isFlagPassed("graph") {
		// Validate that sfdp is available
		if !utils.ValidateTools([]string{"sfdp"}, os.Stderr) {
			errMsg := "sfdp tool not found. Please install graphviz (provides sfdp) to generate call graph visualizations"
			result.Errors = append(result.Errors, errMsg)
			if *progress {
				fmt.Fprintf(os.Stderr, "✗ %s\n", errMsg)
			}
	} else if result.IsVulnerable == "true" && len(result.UsedImports) > 0 {
			if *progress {
				fmt.Fprintf(os.Stderr, "Generating call graph visualizations for affected symbols...\n")
			}

			outputDir := *graph
			if outputDir == "" {
				// Default to ./site/ directory
				outputDir = "./site"
			}

			// Ensure output directory exists
			if info, err := os.Stat(outputDir); err != nil {
				// Directory doesn't exist, create it
				if err := os.MkdirAll(outputDir, 0755); err != nil {
					errMsg := fmt.Sprintf("Failed to create directory %s: %v", outputDir, err)
					result.Errors = append(result.Errors, errMsg)
					if *progress {
						fmt.Fprintf(os.Stderr, "✗ %s\n", errMsg)
					}
				}
			} else if !info.IsDir() {
				// Path exists but is not a directory
				errMsg := fmt.Sprintf("Output path %s exists but is not a directory", outputDir)
				result.Errors = append(result.Errors, errMsg)
				if *progress {
					fmt.Fprintf(os.Stderr, "✗ %s\n", errMsg)
				}
			}

			// Generate a graph for each vulnerable symbol
			result.GraphPaths = []string{}
			for _, pkgs := range result.UsedImports {
				for pkg, details := range pkgs {
					for _, symbol := range details.Symbols {
						sanitizedLib := strings.ReplaceAll(pkg, "/", "-")
						sanitizedSymbol := strings.ReplaceAll(symbol, "/", "-")
						sanitizedSymbol = strings.ReplaceAll(sanitizedSymbol, ".", "-")
						sanitizedSymbol = strings.ReplaceAll(sanitizedSymbol, "*", "ptr")
						sanitizedSymbol = strings.ReplaceAll(sanitizedSymbol, "(", "")
						sanitizedSymbol = strings.ReplaceAll(sanitizedSymbol, ")", "")

						filename := fmt.Sprintf("%s-%s.svg", sanitizedLib, sanitizedSymbol)
						outputPath := filepath.Join(outputDir, filename)

						if *progress {
							fmt.Fprintf(os.Stderr, "  Generating graph for %s.%s...\n", pkg, symbol)
						}

						svgPath, err := generateCallGraphSVGForSymbol(result, directory, pkg, symbol, outputPath, *progress)
						if err != nil {
							errMsg := fmt.Sprintf("Failed to generate call graph for %s.%s: %v", pkg, symbol, err)
							result.Errors = append(result.Errors, errMsg)
							if *progress {
								fmt.Fprintf(os.Stderr, "  ✗ Failed: %v\n", err)
							}
						} else {
							if *progress {
								fmt.Fprintf(os.Stderr, "  ✓ Saved to: %s\n", svgPath)
							}
							result.GraphPaths = append(result.GraphPaths, svgPath)
						}
					}
				}
			}

			if *progress && len(result.GraphPaths) > 0 {
				fmt.Fprintf(os.Stderr, "✓ Generated %d call graph visualization(s)\n", len(result.GraphPaths))
			}
		} else if *progress {
			fmt.Fprintf(os.Stderr, "Skipping graph generation: No symbol usage found\n")
		}
	}

	// Verify with Claude and generate summary
	cg.VerifyAndSummarizeWithClaude(result, directory)
	result.FreeSSABuilds()
	if *progress {
		fmt.Fprintf(os.Stderr, "Scan completed in %s\n", time.Since(scanStart).Round(time.Millisecond))
	}
	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		errMsg := "Failed to marshal result to JSON: " + err.Error()
		result.Errors = append(result.Errors, errMsg)
	} else {
		fmt.Println(string(jsonOutput))
	}
}

// isFlagPassed checks if a flag was explicitly set on the command line
func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// generateRandomFilename creates a random 8-character hex string
func generateRandomFilename() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if random fails
		return fmt.Sprintf("%d", time.Now().Unix())
	}
	return hex.EncodeToString(b)
}

// pathToDOT converts a call path to DOT format for visualization
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

// generateCallGraphSVGForSymbol generates an SVG visualization of the call graph for a specific symbol
func generateCallGraphSVGForSymbol(result *cg.Result, directory, pkg, symbol, outputPath string, showProgress bool) (string, error) {
	// Try to use the stored path from the result first (most efficient)
	for _, pkgs := range result.UsedImports {
		if details, ok := pkgs[pkg]; ok && len(details.Paths) > 0 {
			for i, sym := range details.Symbols {
				if sym == symbol && i < len(details.Paths) {
					path := details.Paths[i]
					if len(path) > 0 {
						if showProgress {
							fmt.Fprintf(os.Stderr, "    Using stored path (%d nodes)...\n", len(path))
						}
						return generateSVGFromPath(path, outputPath, showProgress)
					}
				}
			}
			if len(details.Paths[0]) > 0 {
				if showProgress {
					fmt.Fprintf(os.Stderr, "    Using first available path (%d nodes)...\n", len(details.Paths[0]))
				}
				return generateSVGFromPath(details.Paths[0], outputPath, showProgress)
			}
		}
	}

	// Fallback: generate a new path using BFS
	if showProgress {
		fmt.Fprintf(os.Stderr, "    No stored path found, generating new path...\n")
	}

	// Get the first main file set to generate the call graph
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
		return "", fmt.Errorf("no main files found for call graph generation")
	}

	fullModDir := filepath.Join(directory, modDir)

	// Generate call graph using the scanner's function
	tempResult := &cg.Result{
		ScanConfig: cg.ScanConfig{Directory: directory},
		Errors:     []string{},
	}

	if showProgress {
		fmt.Fprintf(os.Stderr, "    Building call graph from %s...\n", fullModDir)
	}

	cgGraph, err := tempResult.GenerateCallGraphObject(fullModDir, files)
	if err != nil {
		return "", fmt.Errorf("failed to generate call graph: %v", err)
	}

	// Find entry points and search for the symbol
	if showProgress {
		fmt.Fprintf(os.Stderr, "    Finding path to symbol %s...\n", symbol)
	}

	// Get all entry points (main functions for simplicity in fallback)
	var entryPoints []*callgraph.Node
	for _, node := range cgGraph.Nodes {
		if node.Func != nil && node.Func.Name() == "main" {
			entryPoints = append(entryPoints, node)
		}
	}

	if len(entryPoints) == 0 {
		return "", fmt.Errorf("no entry points found for call graph")
	}

	// Search for the symbol using BFS
	var foundPath []*callgraph.Node
	fullSymbol := fmt.Sprintf("%s.%s", pkg, symbol)

	for _, entry := range entryPoints {
		path, found := cg.FindPathToSymbolExported(entry, pkg, fullSymbol, showProgress)
		if found {
			foundPath = path
			break
		}
	}

	if len(foundPath) == 0 {
		return "", fmt.Errorf("no path found to symbol %s.%s", pkg, symbol)
	}

	return generateSVGFromPath(foundPath, outputPath, showProgress)
}

// generateSVGFromPath converts a callgraph path to SVG using DOT and sfdp
func generateSVGFromPath(path []*callgraph.Node, outputPath string, showProgress bool) (string, error) {
	if showProgress {
		fmt.Fprintf(os.Stderr, "    Converting to DOT format...\n")
	}

	// Convert path to DOT format directly (no digraph needed)
	dotOutput := pathToDOT(path)

	if showProgress {
		fmt.Fprintf(os.Stderr, "    Rendering SVG with sfdp layout...\n")
	}

	// Convert DOT to SVG using sfdp
	sfdpCmd := exec.Command("sfdp", "-Tsvg", "-Goverlap=scale")
	sfdpCmd.Stdin = strings.NewReader(dotOutput)
	svgOutput, err := sfdpCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to render SVG: %v", err)
	}

	// Write SVG to file
	if err := os.WriteFile(outputPath, svgOutput, 0644); err != nil {
		return "", fmt.Errorf("failed to write SVG file: %v", err)
	}

	return outputPath, nil
}

