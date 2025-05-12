package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

type Job struct {
	Symbol string
	Dir    string
	Files  []string
}

type Result struct {
	Symbol     string
	Files      []string
	IsVulnerable bool
	CurrentVer string
	FixedVer   string
	ReplaceVer string
	Directory  string
	Repository string
	Branch     string
	CVE        string
	GoCVE      string
}

type VulnReport struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases"`
	Affected []Affected `json:"affected"`
}

type Affected struct {
	Package           Package           `json:"package"`
	Ranges            []Range           `json:"ranges"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

type EcosystemSpecific struct {
	Imports []Import `json:"imports"`
}

type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type PathVersion struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
}

type Replace struct {
	Old PathVersion
	New PathVersion
}

type GoModEdit struct {
	Replace []Replace
}

func main() {
	if len(os.Args) < 3 {
		PrintError("Usage: %s <CVE ID> <directory>", os.Args[0])
		os.Exit(0)
	}

	cve := os.Args[1]
	dir := os.Args[2]

	tools := []string{"go", "digraph", "callgraph", "git"}
	if !validateTools(tools) {
		os.Exit(0)
	}

	repository := getGitURL(dir)
	branch := getGitBranch(dir)

	validateDir(dir)

	id := fetchGoVulnID(cve)

	result := Result{
		CVE:        cve,
		Directory:  dir,
		Repository: repository,
		Branch:     branch,
		GoCVE:      id,
	}

	result.validateVulnID()

	files := findMainGoFiles(dir)

	imports := fetchAffectedSymbols(id)

	jobs := make(chan Job)
	results := make(chan Result)

	var wg sync.WaitGroup
	workerCount := 18

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, &result)
	}

	go func() {
		for modDir, sets := range files {
			for _, fset := range sets {
				for _, sym := range imports {
					jobs <- Job{Symbol: sym, Dir: modDir, Files: fset}
				}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var finalResults []Result

	for res := range results {
		if res.IsVulnerable {
			finalResults = append(finalResults, res)
		}
	}

	if len(finalResults) > 0 {
		jsonOutput, err := json.MarshalIndent(finalResults, "", "  ")
		if err != nil {
			PrintError("Failed to marshal results to JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
	} else {
		jsonOutput, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			PrintError("Failed to marshal results to JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
	}
}

func worker(jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup, result *Result) {
	defer wg.Done()
	for job := range jobs {
		res := job.isVulnerable(result)
		results <- res
	}
}

func (r Result) FixInstructions(modDir string) string {
	pkgPath := strings.TrimSuffix(r.Symbol, "."+strings.Split(r.Symbol, ".")[1])
	if semver.Compare(r.FixedVer, r.CurrentVer) >= 0 {
		return fmt.Sprintf("Vulnerable symbol found: %s in files: %v\nCurrent version: %s\nFixed version: %s\nNo action required", r.Symbol, r.Files, r.CurrentVer, r.FixedVer)
	}
	if r.ReplaceVer != "" {
		path := getModPath(trimAfterLastDot(pkgPath), modDir)
		return fmt.Sprintf("Vulnerable symbol found: %s in files: %v\nCurrent version: %s\nFixed version: %s\nCommands to fix it:\ngo mod edit -replace=%s=%s@%s\ngo mod tidy\ngo mod vendor", r.Symbol, r.Files, r.ReplaceVer, r.FixedVer, path, path, r.FixedVer)
	}
	return fmt.Sprintf("Vulnerable symbol found: %s in files: %v\nCurrent version: %s\nFixed version: %s\nCommands to fix it:\ngo get %s@%s\ngo mod tidy\ngo mod vendor", r.Symbol, r.Files, r.CurrentVer, r.FixedVer, pkgPath, r.FixedVer)
}

func (j Job) isVulnerable(result *Result) Result {
	pkgPath := trimAfterLastDot(strings.NewReplacer("(", "", ")", "", "*", "").Replace(j.Symbol))
	curVer := getCurrentVersion(pkgPath, filepath.Join(result.Directory, j.Dir))
	modPath := getModPath(pkgPath, filepath.Join(result.Directory, j.Dir))
	repVer := getReplaceVersion(modPath, filepath.Join(result.Directory, j.Dir))
	fixVer := getFixedVersion(result.GoCVE, pkgPath)
	isUsed := isSymbolUsed(j.Symbol, filepath.Join(result.Directory, j.Dir), j.Files)
	if !isUsed {
		if semver.Compare(result.FixedVer, result.CurrentVer) >= 0 {
			return Result{
				Symbol:     j.Symbol,
				Files:      j.Files,
				IsVulnerable: false,
				CurrentVer: curVer,
				FixedVer:   fixVer,
				ReplaceVer: repVer,
				CVE:        result.CVE,
				GoCVE:      result.GoCVE,
				Directory:  result.Directory,
				Branch:     result.Branch,
				Repository: result.Repository,
			}
		}

		if result.ReplaceVer != "" {
			return Result{
				Symbol:     j.Symbol,
				Files:      j.Files,
				IsVulnerable: true,
				CurrentVer: curVer,
				FixedVer:   fixVer,
				ReplaceVer: repVer,
				CVE:        result.CVE,
				GoCVE:      result.GoCVE,
				Directory:  result.Directory,
				Branch:     result.Branch,
				Repository: result.Repository,
			}

		}

	}

	return Result{
		Symbol:     j.Symbol,
		Files:      j.Files,
		IsVulnerable: true,
		CurrentVer: curVer,
		FixedVer:   fixVer,
		ReplaceVer: repVer,
		CVE:        result.CVE,
		GoCVE:      result.GoCVE,
		Directory:  result.Directory,
		Branch:     result.Branch,
		Repository: result.Repository,
	}
}

func fetchGoVulnID(cve string) string {
	resp, err := http.Get("https://vuln.go.dev/index/vulns.json")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var vulns []VulnReport
	if err := json.Unmarshal(body, &vulns); err != nil {
		log.Fatal(err)
	}

	for _, v := range vulns {
		for _, alias := range v.Aliases {
			if alias == cve {
				return v.ID
			}
		}
	}

	return ""
}

func findMainGoFiles(root string) map[string][][]string {
	result := make(map[string][][]string)
	var modDirs []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
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
		log.Fatal(err)
	}

	for _, modDir := range modDirs {
		cmd := "go"
		args := []string{"list", "-f", "{{.Name}}: {{.Dir}}", "./..."}
		out, err := runCommand(modDir, cmd, args...)
		if err != nil {
			PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), modDir, strings.TrimSpace(string(out)))
			continue
		}

		modKey, err := filepath.Rel(root, modDir)
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

	return result
}

func fetchAffectedSymbols(id string) []string {
	client := http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://vuln.go.dev/ID/%s.json", id)

	resp, err := client.Get(url)
	if err != nil {
		PrintError("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("failed to fetch vulnerability data: %s", resp.Status)
	}

	var detail VulnReport

	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		log.Fatalf("failed to parse JSON: %v", err)
	}

	var imports []string
	for _, aff := range detail.Affected {
		for _, imp := range aff.EcosystemSpecific.Imports {
			for _, sym := range imp.Symbols {
				imports = append(imports, fmt.Sprintf("%s.%s", imp.Path, sym))
				imports = append(imports, fmt.Sprintf("(%s).%s", imp.Path, sym))
				imports = append(imports, fmt.Sprintf("(*%s).%s", imp.Path, sym))
			}
		}
	}

	return imports
}

func isSymbolUsed(symbol, dir string, files []string) bool {
	cmd := "callgraph"
	args := append([]string{"-format=digraph"}, files...)
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		return false
	}

	grep := exec.Command("digraph", "somepath", "command-line-arguments.main", symbol)
	grep.Stdin = bytes.NewReader(out)
	result, err := grep.CombinedOutput()

	if !bytes.Contains(result, []byte("digraph: no such")) {
		return true
	}

	return false
}

func getCurrentVersion(pkg string, dir string) string {
	cmd := "go"
	args := []string{"list", "-mod=mod", "-f", "{{.Module.Path}}@{{.Module.Version}}", pkg}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		return ""
	}
	parts := strings.Split(string(out), "@")
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func getReplaceVersion(pkg string, dir string) string {
	cmd := "go"
	args := []string{"mod", "edit", "-json"}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
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

func getFixedVersion(id, pkg string) string {
	url := fmt.Sprintf("https://vuln.go.dev/ID/%s.json", id)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var detail VulnReport
	if err := json.Unmarshal(body, &detail); err != nil {
		log.Fatal(err)
	}

	for _, a := range detail.Affected {
		for _, r := range a.Ranges {
			if r.Type == "SEMVER" {
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
	}

	return ""
}

func trimAfterLastDot(input string) string {
	if i := strings.LastIndex(input, "."); i != -1 {
		return input[:i]
	}
	return input
}

func getModPath(pkg, dir string) string {
	cmd := "go"
	args := []string{"list", "-mod=mod", "-f", "{{.Module.Path}}", pkg}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
		return ""
	}
	return strings.TrimSpace(string(out))
}

func runCommand(dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return out, err
}

func PrintError(format string, a ...any) {
	if os.Getenv("GVS_MODE") != "cli" {
		fmt.Printf("Error: "+format+"\n", a...)
	} else {
		fmt.Printf(colorRed+"Error: "+format+colorReset+"\n", a...)
	}
}

func PrintWarning(format string, a ...any) {
	if os.Getenv("GVS_MODE") != "cli" {
		fmt.Printf(format+"\n", a...)
	} else {
		fmt.Printf(colorYellow+format+colorReset+"\n", a...)
	}
}

func PrintSuccess(format string, a ...any) {
	if os.Getenv("GVS_MODE") != "cli" {
		fmt.Printf(format+"\n", a...)
	} else {
		fmt.Printf(colorGreen+format+colorReset+"\n", a...)
	}
}

func validateDir(dir string) {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		PrintError("Invalid directory: %s", dir)
		os.Exit(1)
	}
}

func (r *Result) validateVulnID() {
	if r.GoCVE == "" {
		r = &Result{
			GoCVE:      "No Go CVE ID found",
			CVE:        r.CVE,
			Directory:  r.Directory,
			Branch:     r.Branch,
			Repository: r.Repository,
		}
		jsonOutput, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			PrintError("Failed to marshal results to JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
		os.Exit(0)
	}
}

func validateTools(tools []string) bool {
	allAvailable := true
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			allAvailable = false
			PrintError("Failed finding %s package: %s", tool, err)
		}
	}
	return allAvailable
}

func getGitBranch(dir string) string {
	cmd := "git"
	args := []string{"rev-parse", "--abbrev-ref", "HEAD"}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}

func getGitURL(dir string) string {
	cmd := "git"
	args := []string{"remote", "get-url", "origin"}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}
