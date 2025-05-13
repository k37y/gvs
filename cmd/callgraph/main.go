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

type Job struct {
	Symbol string
	Dir    string
	Files  []string
}

type Result struct {
	Symbol       string
	Files        []string
	IsVulnerable string
	CurrentVer   string
	FixedVer     string
	ReplaceVer   string
	Directory    string
	Repository   string
	Branch       string
	CVE          string
	GoCVE        string
	Errors       []string
	FixCommands  []string
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
	tools := []string{"go", "digraph", "callgraph", "git"}
	if !validateTools(tools) {
		os.Exit(0)
	}

	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <CVE ID> <directory>\n", os.Args[0])
		os.Exit(0)
	}

	if info, err := os.Stat(os.Args[2]); err != nil || !info.IsDir() {
		fmt.Printf("Invalid directory: %s\n", os.Args[2])
		fmt.Printf("Usage: %s <CVE ID> <directory>\n", os.Args[0])
		os.Exit(0)
	}

	result := InitResult(os.Args[1], os.Args[2])

	files := result.findMainGoFiles()
	imports := fetchAffectedSymbols(result.GoCVE)

	jobs := make(chan Job)
	results := make(chan Result)

	var wg sync.WaitGroup
	workerCount := 18

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, result)
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
		if res.IsVulnerable == "true" {
			finalResults = append(finalResults, res)
		}
	}

	if len(finalResults) > 0 {
		jsonOutput, err := json.MarshalIndent(finalResults, "", "  ")
		if err != nil {
			fmt.Printf("Failed to marshal results to JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
	} else {
		jsonOutput, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Printf("Failed to marshal results to JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
	}
}

func InitResult(cve, dir string) *Result {
	r := &Result{
		CVE:        cve,
		Directory:  dir,
		IsVulnerable: "unknown",
		Repository: getGitURL(dir),
		Branch:     getGitBranch(dir),
		GoCVE:      fetchGoVulnID(cve),
	}
	if r.GoCVE == "" {
		r = &Result{
			GoCVE:      "No Go CVE ID found",
			IsVulnerable: "unknown",
			CVE:        r.CVE,
			Directory:  r.Directory,
			Branch:     r.Branch,
			Repository: r.Repository,
		}
		jsonOutput, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			fmt.Printf("Failed to marshal results to JSON: %v", err)
		}
		fmt.Println(string(jsonOutput))
		os.Exit(0)
	}
	return r
}

func worker(jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup, result *Result) {
	defer wg.Done()
	for job := range jobs {
		res := job.isVulnerable(result)
		results <- res
	}
}

func (j Job) isVulnerable(result *Result) Result {
	pkgPath := trimAfterLastDot(strings.NewReplacer("(", "", ")", "", "*", "").Replace(j.Symbol))
	curVer := getCurrentVersion(pkgPath, filepath.Join(result.Directory, j.Dir))
	modPath := getModPath(pkgPath, filepath.Join(result.Directory, j.Dir))
	repVer := getReplaceVersion(modPath, filepath.Join(result.Directory, j.Dir))
	fixVer := getFixedVersion(result.GoCVE, pkgPath)
	isUsed := isSymbolUsed(j.Symbol, filepath.Join(result.Directory, j.Dir), j.Files)
	if !isUsed {
		if semver.Compare(fixVer, curVer) >= 0 {
			return Result{
				Symbol:       j.Symbol,
				Files:        j.Files,
				IsVulnerable: "false",
				CurrentVer:   curVer,
				FixedVer:     fixVer,
				ReplaceVer:   repVer,
				CVE:          result.CVE,
				GoCVE:        result.GoCVE,
				Directory:    result.Directory,
				Branch:       result.Branch,
				Repository:   result.Repository,
			}
		}

		if repVer != "" {
			return Result{
				Symbol:       j.Symbol,
				Files:        j.Files,
				IsVulnerable: "true",
				CurrentVer:   curVer,
				FixedVer:     fixVer,
				ReplaceVer:   repVer,
				CVE:          result.CVE,
				GoCVE:        result.GoCVE,
				Directory:    result.Directory,
				Branch:       result.Branch,
				Repository:   result.Repository,
				FixCommands:  []string{fmt.Sprintf("go mod edit -replace=%s=%s@%s", modPath, modPath, fixVer), "go mod tidy", "go mod vendor",},
			}

		}

	}

	return Result{
		Symbol:       j.Symbol,
		Files:        j.Files,
		IsVulnerable: "true",
		CurrentVer:   curVer,
		FixedVer:     fixVer,
		ReplaceVer:   repVer,
		CVE:          result.CVE,
		GoCVE:        result.GoCVE,
		Directory:    result.Directory,
		Branch:       result.Branch,
		Repository:   result.Repository,
		FixCommands:  []string{fmt.Sprintf("go get %s@%s", modPath, fixVer), "go mod tidy", "go mod vendor",},
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

func (r *Result) findMainGoFiles() map[string][][]string {
	result := make(map[string][][]string)
	var modDirs []string

	err := filepath.WalkDir(r.Directory, func(path string, d os.DirEntry, err error) error {
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
			errMsg := fmt.Sprintf("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), modDir, strings.TrimSpace(string(out)))
			r.Errors = append(r.Errors, errMsg)
			continue
		}

		modKey, err := filepath.Rel(r.Directory, modDir)
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
		fmt.Printf("HTTP request failed: %v", err)
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
		fmt.Printf("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
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
		fmt.Printf("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
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
		fmt.Printf("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
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
		fmt.Fprintf(os.Stderr, "Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
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

func validateTools(tools []string) bool {
	allAvailable := true
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			allAvailable = false
			fmt.Printf("Failed finding %s package: %s", tool, err)
		}
	}
	return allAvailable
}

func getGitBranch(dir string) string {
	cmd := "git"
	args := []string{"rev-parse", "--abbrev-ref", "HEAD"}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		fmt.Printf("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}

func getGitURL(dir string) string {
	cmd := "git"
	args := []string{"remote", "get-url", "origin"}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		fmt.Printf("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}
