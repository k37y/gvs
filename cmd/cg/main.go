package main

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
	"runtime"
	"strconv"

	"golang.org/x/mod/semver"
)

func main() {
	tools := []string{"go", "digraph", "callgraph", "git"}
	if !validateTools(tools) {
		os.Exit(1)
	}

	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <CVE ID> <directory>\n", os.Args[0])
		os.Exit(1)
	}

	if info, err := os.Stat(os.Args[2]); err != nil || !info.IsDir() {
		fmt.Printf("Invalid directory: %s\n", os.Args[2])
		fmt.Printf("Usage: %s <CVE ID> <directory>\n", os.Args[0])
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


	result := InitResult(os.Args[1], os.Args[2])

	jobs := make(chan Job)
	results := make(chan *Result)

	var wg sync.WaitGroup

	workerCount := defaultWorkers

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, result)
	}

	go func() {
		for modDir, sets := range result.Files {
			for _, fset := range sets {
				for pkg, syms := range result.AffectedImports {
					jobs <- Job{Package: pkg, Symbols: syms.Symbols, Dir: modDir, Files: fset}
				}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	mergedImports := make(map[string]UsedImportsDetails)

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

				result.mu.Lock()
				mergedImports[pkg] = entry
				result.mu.Unlock()
			}
		}
	}

	for pkg, details := range mergedImports {
		deduped := uniqueStrings(details.Symbols)
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
		generateSummaryWithGemini(result)
		jsonOutput, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("Failed to marshal result to JSON: %v\n", err)
			result.Errors = append(result.Errors, errMsg)
		} else {
			fmt.Println(string(jsonOutput))
		}
	} else {
		result.UsedImports = nil
		generateSummaryWithGemini(result)
		jsonOutput, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("Failed to marshal result to JSON: %v\n", err)
			result.Errors = append(result.Errors, errMsg)
		} else {
			fmt.Println(string(jsonOutput))
		}
	}
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

func InitResult(cve, dir string) *Result {
	r := &Result{
		CVE:          cve,
		Directory:    dir,
		IsVulnerable: "unknown",
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

func worker(jobs <-chan Job, results chan<- *Result, wg *sync.WaitGroup, result *Result) {
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
	fixVer = extractFormattedFixedVersions(fixVer)
	fv := semVersion(strings.Join(fixVer, " "))

	used := false
	unknown := false

	isUsed := result.isSymbolUsed(j.Package, filepath.Join(result.Directory, j.Dir), j.Symbols, j.Files)
	switch isUsed {
	case "true":
		used = true
	case "unknown":
		unknown = true
	}

	result.mu.Lock()
	if result.AffectedImports == nil {
		result.AffectedImports = make(map[string]AffectedImportsDetails)
	}
	aentry := result.AffectedImports[j.Package]
	if result.AffectedImports[j.Package].Type != "stdlib" {
		aentry.FixedVersion = strings.Split(semVersion(fv), ",")
	} else {
		aentry.FixedVersion = fixVer
	}
	result.AffectedImports[j.Package] = aentry
	result.mu.Unlock()

	result.mu.Lock()
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
	result.mu.Unlock()

	return result
}

func fetchGoVulnID(result *Result) string {
	client := http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf(vulnsURL + "/index/vulns.json")

	resp, err := client.Get(url)
	if err != nil {
		errMsg := fmt.Sprint("Failed to get response from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprint("Failed to read response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)
	}

	var vulns []VulnReport
	if err := json.Unmarshal(body, &vulns); err != nil {
		errMsg := fmt.Sprint("Failed to marshal response body from %s: %v", url, err)
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
		out, err := runCommand(modDir, cmd, args...)
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
	url := fmt.Sprintf(vulnsURL+"/ID/%s.json", result.GoCVE)

	resp, err := client.Get(url)
	if err != nil {
		errMsg := fmt.Sprint("Failed HTTP request to %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)

	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprint("Failed to connect %s: %s", url, resp.Status)
		result.Errors = append(result.Errors, errMsg)

	}

	var detail VulnReport

	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		errMsg := fmt.Sprint("Failed to parse JSON: %v", err)
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
	cmd := "callgraph"
	args := append([]string{"-format={{.Caller}} {{.Callee}}"}, files...)
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s\n", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		r.Errors = append(r.Errors, errMsg)
		return "unknown"
	}

	var wg sync.WaitGroup
	found := false

	for _, symbol := range symbols {
		wg.Add(1)
		go func(sym string) {
			defer wg.Done()
			if matchSymbol(out, sym) {
				r.mu.Lock()
				if r.UsedImports == nil {
					r.UsedImports = make(map[string]UsedImportsDetails)
				}
				entry := r.UsedImports[pkg]
				entry.Symbols = append(entry.Symbols, sym)
				r.UsedImports[pkg] = entry
				r.mu.Unlock()
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

func getCurrentVersion(pkg string, dir string, result *Result) string {
	cmd := "go"
	args := []string{"list", "-f", "{{if .Module}}{{.Module.Version}}{{end}}", pkg}
	out, err := runCommand(dir, cmd, args...)
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
	out, err := runCommand(dir, cmd, args...)
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
	url := fmt.Sprintf(vulnsURL+"/ID/%s.json", id)
	resp, err := http.Get(url)
	if err != nil {
		errMsg := fmt.Sprint("Failed to get response from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)

	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprint("Failed to read response body from %s: %v", url, err)
		result.Errors = append(result.Errors, errMsg)

	}

	var detail VulnReport
	if err := json.Unmarshal(body, &detail); err != nil {
		errMsg := fmt.Sprint("Failed to unmarshal response body from %s: %v", url, err)
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
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
		return ""
	}
	return strings.TrimSpace(string(out))
}
