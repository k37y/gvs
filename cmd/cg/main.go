package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

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

	var runFix bool
	var cveID, directory string

	// Parse command line arguments
	args := os.Args[1:]

	for _, arg := range args {
		if arg == "-runfix" {
			runFix = true
		} else if cveID == "" {
			cveID = arg
		} else if directory == "" {
			directory = arg
		}
	}

	if cveID == "" || directory == "" {
		fmt.Printf("Usage: %s [-runfix] <CVE ID> <directory>\n", os.Args[0])
		os.Exit(1)
	}

	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		fmt.Printf("Invalid directory: %s\n", directory)
		fmt.Printf("Usage: %s [-runfix] <CVE ID> <directory>\n", os.Args[0])
		os.Exit(1)
	}

	defaultWorkers := runtime.NumCPU() / 2
	if defaultWorkers < 1 {
		defaultWorkers = 1
	}

	if envVal, ok := os.LookupEnv("WORKER_COUNT"); ok {
		if n, err := strconv.Atoi(envVal); err == nil && n > 0 {
			defaultWorkers = n
		}
	}

	result := cg.InitResult(cveID, directory, runFix)

	jobs := make(chan cg.Job)
	results := make(chan *cg.Result)

	var wg sync.WaitGroup

	workerCount := defaultWorkers

	for i := 0; i < workerCount; i++ {
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

	for res := range results {
		if res.IsVulnerable != "true" {
			continue
		}

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

	if len(mergedImports) > 0 {
		result.IsVulnerable = "true"
		result.UsedImports = mergedImports
	} else {
		result.UsedImports = nil
	}

	// Run fix commands BEFORE generating output (only if runFix is true)
	if runFix {
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

		for pkg, details := range result.UsedImports {
			if len(details.FixCommands) > 0 {
				cli.RunFixCommands(pkg, result.Directory, details.FixCommands, fixResult)
			}
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
		errMsg := fmt.Sprintf("Failed to marshal result to JSON: %v\n", err)
		result.Errors = append(result.Errors, errMsg)
	} else {
		fmt.Println(string(jsonOutput))
	}
}
