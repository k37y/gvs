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

type Vuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type VulnDetail struct {
	ID       string     `json:"id"`
	Affected []Affected `json:"affected"`
}

type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
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

type Job struct {
	Symbol string
	Dir    string
	Files  []string
}

type Result struct {
	Symbol     string
	Files      []string
	Vulnerable bool
	CurrentVer string
	FixedVer   string
	ReplaceVer string
}

type ModPath struct {
	Path    string
	Version string
}

type ModReplace struct {
	Old ModPath
	New ModPath
}

type GoMod struct {
	Replace []ModReplace
}

func main() {
	if len(os.Args) < 3 {
		PrintError("Usage: %s <CVE ID> <directory>", os.Args[0])
		os.Exit(0)
	}
	cve := os.Args[1]
	dir := os.Args[2]

	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		PrintError("Invalid directory: %s", dir)
		os.Exit(1)
	}

	id := fetchGoVulnID(cve)
	if id == "" {
		PrintError("No Go CVE ID found for %s", cve)
		os.Exit(1)
	}
	PrintSuccess("Go CVE ID found: %s", id)

	files := findMainGoFiles(dir)

	imports := fetchAffectedSymbols(id)

	jobs := make(chan Job)
	results := make(chan Result)

	var wg sync.WaitGroup
	workerCount := 18

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(i, dir, jobs, results, &wg, id)
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

	for res := range results {
		if res.Vulnerable {
			if semver.Compare(res.FixedVer, res.CurrentVer) >= 0 {
				PrintSuccess("Vulnerable symbol found: %s in files: %v\nCurrent version: %s\nFixed version: %s\nNo action required", res.Symbol, res.Files, res.CurrentVer, res.FixedVer)
			} else if res.ReplaceVer != "" {
				pkgPath := strings.TrimSuffix(res.Symbol, "."+strings.Split(res.Symbol, ".")[1])
				PrintWarning("Vulnerable symbol found: %s in files: %v\nCurrent version: %s\nFixed version: %s\nCommands to fix it:\ngo mod edit -replace=%s=%s@%s\ngo mod tidy\ngo mod vendor", res.Symbol, res.Files, res.ReplaceVer, res.FixedVer, getModPath(trimAfterLastDot(pkgPath), dir), getModPath(trimAfterLastDot(pkgPath), dir), res.FixedVer)
			} else {
				pkgPath := strings.TrimSuffix(res.Symbol, "."+strings.Split(res.Symbol, ".")[1])
				PrintWarning("Vulnerable symbol found: %s in files: %v\nCurrent version: %s\nFixed version: %s\nCommands to fix it:\ngo get %s@%s\ngo mod tidy\ngo mod vendor", res.Symbol, res.Files, res.CurrentVer, res.FixedVer, pkgPath, res.FixedVer)
			}
		}
	}
}

func worker(id int, dir string, jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup, vulnID string) {
	defer wg.Done()
	for job := range jobs {
		vuln := isVulnerable(job.Symbol, dir+"/"+job.Dir, job.Files)
		if vuln {
			pkgPath := trimAfterLastDot(strings.NewReplacer("(", "", ")", "", "*", "").Replace(job.Symbol))
			curVer := getCurrentVersion(pkgPath, dir+"/"+job.Dir)
			modPath := getModPath(pkgPath, dir+"/"+job.Dir)
			repVer := getReplaceVersion(modPath, dir+"/"+job.Dir)
			fixVer := getFixedVersion(vulnID, pkgPath)
			results <- Result{job.Symbol, job.Files, true, curVer, fixVer, repVer}
		} else {
			results <- Result{job.Symbol, job.Files, false, "", "", ""}
		}
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

	var vulns []Vuln
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
			PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), modDir, string(out))
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

	var detail VulnDetail

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

func isVulnerable(symbol, dir string, files []string) bool {
	cmd := "callgraph"
	args := append([]string{"-format=digraph"}, files...)
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, string(out))
		return false
	}

	grep := exec.Command("digraph", "somepath", "command-line-arguments.main", symbol)
	grep.Stdin = bytes.NewReader(out)
	result, err := grep.CombinedOutput()

	if !bytes.Contains(result, []byte("digraph: no such")) {
		// PrintSuccess("Symbol found: %s", symbol)
		return true
	}

	return false
}

func getCurrentVersion(pkg string, dir string) string {
	cmd := "go"
	args := []string{"list", "-mod=mod", "-f", "{{.Module.Path}}@{{.Module.Version}}", pkg}
	out, err := runCommand(dir, cmd, args...)
	if err != nil {
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, string(out))
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
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, string(out))
		return ""
	}

	var modFile GoMod
	err = json.Unmarshal(out, &modFile)
	if err != nil {
		return ""
	}

	for _, r := range modFile.Replace {
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

	var detail VulnDetail
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
		PrintError("Failed running %s %s in %s: %s", cmd, strings.Join(args, " "), dir, string(out))
		return ""
	}
	return string(out)
}

func runCommand(dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return out, err
}

func PrintError(format string, a ...interface{}) {
	if os.Getenv("GVS_MODE") != "cli" {
		fmt.Printf("Error: "+format+"\n", a...)
	} else {
		fmt.Printf(colorRed+"Error: "+format+colorReset+"\n", a...)
	}
}

func PrintWarning(format string, a ...interface{}) {
	if os.Getenv("GVS_MODE") != "cli" {
		fmt.Printf(format+"\n", a...)
	} else {
		fmt.Printf(colorYellow+format+colorReset+"\n", a...)
	}
}

func PrintSuccess(format string, a ...interface{}) {
	if os.Getenv("GVS_MODE") != "cli" {
		fmt.Printf(format+"\n", a...)
	} else {
		fmt.Printf(colorGreen+format+colorReset+"\n", a...)
	}
}
