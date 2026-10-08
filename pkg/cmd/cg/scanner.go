// Package cg provides call graph analysis for vulnerability scanning
//
// Call Graph Algorithms:
// The scanner supports multiple call graph algorithms, configurable via the ALGO environment variable:
//
// - rta (default): Rapid Type Analysis - Good balance of speed and precision. Best for reflection tracking.
// - cha: Class Hierarchy Analysis - Fast but less precise. Good for large codebases where speed matters.
// - vta: Variable Type Analysis - Most precise for direct calls but slower. Less effective for reflection.
// - static: Static analysis - Very fast but least precise (only direct calls). Use for quick scans.
//
// Usage:
//
//	export ALGO=vta    # Use Variable Type Analysis
//	export ALGO=cha    # Use Class Hierarchy Analysis
//	export ALGO=static # Use static analysis
//	# Default (no env var set) uses RTA
//
// Algorithm Trade-offs:
// - Precision for direct calls: static < cha < rta < vta
// - Reflection tracking: vta < static < cha < rta
// - Speed: vta < rta < cha < static
package cg

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"
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

type ssaBuild struct {
	prog        *ssa.Program
	cg          *callgraph.Graph
	loadedPkgs  []*packages.Package
	entryPoints []*callgraph.Node
	err         error
	once        sync.Once
}

// getSSABuild returns the SSA build for a directory, building it on first access.
// Concurrent callers for the same directory block until the build completes.
// Different directories build in parallel.
func (r *Result) getSSABuild(dir string) *ssaBuild {
	r.Mu.Lock()
	if r.ssaBuilds == nil {
		r.ssaBuilds = make(map[string]*ssaBuild)
	}
	build, ok := r.ssaBuilds[dir]
	if !ok {
		build = &ssaBuild{}
		r.ssaBuilds[dir] = build
	}
	r.Mu.Unlock()

	build.once.Do(func() {
		relDir := dir
		if r.Directory != "" && strings.HasPrefix(dir, r.Directory) {
			relDir = strings.TrimPrefix(dir, r.Directory)
			relDir = strings.TrimPrefix(relDir, "/")
		}
		if relDir == "" {
			relDir = "."
		}

		if r.Progress {
			fmt.Fprintf(os.Stderr, "[%s] Building SSA + call graph...\n", relDir)
		}

		prog, cg, loadedPkgs, err := r.buildSSAAndCallGraph(dir)
		if err != nil {
			build.err = err
			r.Mu.Lock()
			r.Errors = append(r.Errors, fmt.Sprintf("Failed to generate call graph in %s: %v", dir, err))
			r.Mu.Unlock()
			if r.Progress {
				fmt.Fprintf(os.Stderr, "[%s] ✗ Failed: %v\n", relDir, err)
			}
			return
		}

		repoModulePath := getRepoModulePath(dir, r)
		entryPoints := extractEntryPointNodes(cg, repoModulePath, false)

		build.prog = prog
		build.cg = cg
		build.loadedPkgs = loadedPkgs
		build.entryPoints = entryPoints

		if r.Progress {
			fmt.Fprintf(os.Stderr, "[%s] Loaded %d packages, call graph built (%d nodes, %d entry points)\n", relDir, len(loadedPkgs), len(cg.Nodes), len(entryPoints))
		}
	})

	if build.err != nil {
		return nil
	}
	return build
}

func (r *Result) firstSSABuild() *ssaBuild {
	for _, b := range r.ssaBuilds {
		return b
	}
	return nil
}

func (r *Result) FreeSSABuilds() {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	for k, b := range r.ssaBuilds {
		b.prog = nil
		b.cg = nil
		b.loadedPkgs = nil
		b.entryPoints = nil
		delete(r.ssaBuilds, k)
	}
	r.ssaBuilds = nil
	r.reflectionBuilds = nil
}

func (r *Result) ctx() context.Context {
	if r.Ctx != nil {
		return r.Ctx
	}
	return context.Background()
}

func (r *Result) runner() cli.CommandRunner {
	if r.Runner != nil {
		return r.Runner
	}
	return cli.DefaultRunner{}
}

func (r *Result) httpClient() HTTPClient {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (r *Result) progress(msg string) {
	if r.ProgressFunc != nil {
		r.ProgressFunc(msg)
	}
}

// SetupLibraryMode configures a Result for direct library/symbol scanning.
// Returns true if the result has a terminal error and scanning should stop.
func SetupLibraryMode(r *Result, library, symbols, fixversion string) bool {
	if library == "" || symbols == "" || fixversion == "" {
		r.Errors = append(r.Errors, "When using library mode, all three flags are required: -library, -symbols, and -fixversion")
		return true
	}

	if strings.TrimSpace(library) == "" || strings.TrimSpace(symbols) == "" || strings.TrimSpace(fixversion) == "" {
		r.Errors = append(r.Errors, "Library mode parameters cannot be empty or whitespace only")
		return true
	}

	r.progress("Phase 1/6: Using provided library and symbol override...")
	r.progress(fmt.Sprintf("  Library: %s", library))
	r.progress(fmt.Sprintf("  Symbol(s): %s", symbols))

	if r.CVE != "" {
		if common.IsGOCVEID(r.CVE) {
			r.GoCVE = r.CVE
		} else if common.IsCVEID(r.CVE) {
			fetchGoVulnID(r)
		}
	} else {
		r.GoCVE = "MANUAL-SCAN"
	}

	r.progress("Phase 2/6: Using provided library and symbols...")
	symbolList := strings.Split(symbols, ",")
	for i := range symbolList {
		symbolList[i] = strings.TrimSpace(symbolList[i])
	}

	hasValidSymbol := false
	for _, sym := range symbolList {
		if sym != "" {
			hasValidSymbol = true
			break
		}
	}
	if !hasValidSymbol {
		r.Errors = append(r.Errors, "At least one non-empty symbol is required")
		return true
	}

	details := AffectedImportsDetails{
		Symbols: symbolList,
		Type:    "non-stdlib",
	}

	if strings.Contains(fixversion, ":") {
		for _, pair := range strings.Split(fixversion, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				details.FixedVersion = append(details.FixedVersion,
					fmt.Sprintf("Introduced in %s and fixed in %s", parts[0], parts[1]))
			}
		}
	} else {
		details.FixedVersion = []string{fixversion}
	}
	r.progress(fmt.Sprintf("  Using fixed version: %s", fixversion))

	r.AffectedImports = map[string]AffectedImportsDetails{
		library: details,
	}

	if strings.HasPrefix(library, "crypto/") || strings.HasPrefix(library, "net/") ||
		strings.HasPrefix(library, "encoding/") || strings.HasPrefix(library, "os/") ||
		!strings.Contains(library, ".") {
		entry := r.AffectedImports[library]
		entry.Type = "stdlib"
		r.AffectedImports[library] = entry
	}
	r.progress(fmt.Sprintf("  ✓ Using %d symbol(s) for library %s", len(symbolList), library))
	return false
}

// SetupCVEMode configures a Result by fetching vulnerability data from vuln.go.dev.
// Returns true if the result has a terminal error and scanning should stop.
func SetupCVEMode(r *Result) bool {
	r.progress("Phase 1/6: Processing vulnerability identifier...")
	if common.IsGOCVEID(r.CVE) {
		r.GoCVE = r.CVE
		r.progress(fmt.Sprintf("  ✓ Using provided GOCVE ID: %s", r.CVE))
	} else if common.IsCVEID(r.CVE) {
		r.progress("  Converting CVE ID to GOCVE ID...")
		fetchGoVulnID(r)
	} else {
		r.GoCVE = "Invalid input format"
		r.Errors = append(r.Errors, "Invalid input format. Please provide either a CVE ID (CVE-YYYY-NNNN) or GOCVE ID (GO-YYYY-NNNN)")
		return true
	}

	r.progress("Phase 2/6: Fetching affected symbols...")
	fetchAffectedSymbols(r)
	return false
}

// Prepare runs the discovery and detection phases on a fully configured Result.
// Call after SetupLibraryMode or SetupCVEMode. Returns true if scanning should stop.
func Prepare(r *Result) bool {
	if len(r.AffectedImports) == 0 {
		r.progress("Scan aborted: No vulnerable symbols to analyze.")
		r.IsVulnerable = "unknown"
		return true
	}

	r.progress("Phase 3/6: Discovering Go modules and main files...")
	findMainGoFiles(r)
	r.progress("Phase 4/6: Getting git branch information...")
	getGitBranch(r)
	r.progress("Phase 5/6: Getting git repository URL...")
	getGitURL(r)
	r.progress("Phase 6/6: Detecting unsafe and reflect package usage...")
	DetectUnsafeReflectUsage(r, r.ProgressFunc)

	if r.GoCVE == "" {
		r.Errors = append(r.Errors, "No Go CVE ID found")
		return true
	}
	r.progress("Initialization complete. Starting vulnerability analysis...")
	return false
}

func Worker(jobs <-chan Job, results chan<- *Result, wg *sync.WaitGroup, result *Result) {
	defer wg.Done()
	for job := range jobs {
		select {
		case <-result.ctx().Done():
			results <- &Result{IsVulnerable: "unknown"}
			continue
		default:
		}
		res := job.isVulnerable(result)
		results <- res
	}
}

func (r *Result) isModuleInGoModOrSum(pkg, dir string) bool {
	if r.isModuleInGoMod(pkg, dir) {
		return true
	}
	data, err := r.readModFile(filepath.Join(dir, "go.sum"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == pkg || strings.HasPrefix(pkg, fields[0]+"/") {
			return true
		}
	}
	return false
}

type VulnerabilityResult struct {
	DirVulnerable   bool
	Status          string // "true", "false", or "unknown"
	NeedsReplaceFix bool
	FixVersion      string
}

func parseVersionRanges(rawFixVer []string) [][2]string {
	var ranges [][2]string
	for _, entry := range rawFixVer {
		var introduced, fixed string
		if strings.Contains(entry, "Introduced in") && strings.Contains(entry, "fixed in") {
			parts := strings.Split(entry, "and fixed in")
			if len(parts) == 2 {
				introduced = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[0]), "Introduced in"))
				fixed = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(strings.TrimSpace(entry), "Introduced in ") && strings.HasSuffix(strings.TrimSpace(entry), " -") {
			introduced = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(entry), "Introduced in "), " -"))
			if introduced != "" {
				ranges = append(ranges, [2]string{common.SemVersion(introduced), ""})
			}
		} else {
			fixed = strings.TrimSpace(entry)
		}
		if fixed != "" {
			introduced = common.SemVersion(introduced)
			fixed = common.SemVersion(fixed)
			ranges = append(ranges, [2]string{introduced, fixed})
		}
	}
	return ranges
}

func isVersionInVulnerableRange(version string, rawFixVer []string) (bool, string) {
	version = common.SemVersion(version)
	ranges := parseVersionRanges(rawFixVer)
	for _, r := range ranges {
		introduced, fixed := r[0], r[1]
		// In advisories, introduced "0" means every earlier version, including
		// v0.0.0 pseudo-versions that sort before the v0.0.0 release.
		if (introduced == "v0" || semver.Compare(version, introduced) >= 0) && (fixed == "" || semver.Compare(version, fixed) < 0) {
			return true, fixed
		}
	}
	return false, ""
}

func hasIntroducedInfo(rawFixVer []string) bool {
	for _, entry := range rawFixVer {
		if strings.Contains(entry, "Introduced in") {
			return true
		}
	}
	return false
}

// checkDirVulnerability determines whether a directory is vulnerable based on
// version comparisons. It returns the vulnerability status and whether a
// replace-directive fix is needed.
func checkDirVulnerability(curVer, repVer string, used, unknown, isStdlib bool, goToolchainVersion string, rawFixVer []string) VulnerabilityResult {
	vr := VulnerabilityResult{Status: "false"}

	if used {
		compareVer := curVer
		if repVer != "" {
			compareVer = repVer
		}

		if isStdlib {
			compareVer = goToolchainVersion
		}

		if !semver.IsValid(common.SemVersion(compareVer)) {
			vr.Status = "unknown"
			vr.DirVulnerable = true
		} else if len(rawFixVer) > 0 {
			vuln, matchedFix := isVersionInVulnerableRange(compareVer, rawFixVer)
			if vuln {
				vr.Status = "true"
				vr.DirVulnerable = true
				vr.FixVersion = matchedFix
			} else if isStdlib && hasIntroducedInfo(rawFixVer) {
				fixVer := common.ExtractFormattedFixedVersions(rawFixVer)
				if len(fixVer) == 0 {
					fixVer = rawFixVer
				}
				appropriateFixVersion := findAppropriateFixVersion(compareVer, fixVer)
				if appropriateFixVersion != "" {
					if semver.Compare(compareVer, appropriateFixVersion) < 0 {
						vr.Status = "true"
						vr.DirVulnerable = true
						vr.FixVersion = appropriateFixVersion
					}
				} else {
					highestFix := ""
					for _, fv := range fixVer {
						v := extractGoVersion(fv)
						if v != "" && (highestFix == "" || semver.Compare(v, highestFix) > 0) {
							highestFix = v
						}
					}
					if highestFix == "" || semver.Compare(compareVer, highestFix) < 0 {
						vr.Status = "true"
						vr.DirVulnerable = true
					}
				}
			}
		} else {
			vr.Status = "unknown"
			vr.DirVulnerable = true
		}
	} else if unknown {
		vr.Status = "unknown"
		vr.DirVulnerable = true
	}

	if repVer != "" {
		vuln, matchedFix := isVersionInVulnerableRange(repVer, rawFixVer)
		if vuln {
			vr.DirVulnerable = true
			vr.NeedsReplaceFix = true
			if vr.FixVersion == "" {
				vr.FixVersion = matchedFix
			}
		}
	}

	return vr
}

func (r *Result) findModuleInGoMod(pkg, dir string) (modPath, version string, found bool) {
	data, err := r.readModFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return "", "", false
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return "", "", false
	}
	var best string
	var bestVer string
	for _, req := range f.Require {
		if pkg == req.Mod.Path || strings.HasPrefix(pkg, req.Mod.Path+"/") {
			if len(req.Mod.Path) > len(best) {
				best = req.Mod.Path
				bestVer = req.Mod.Version
			}
		}
	}
	if best != "" {
		return best, bestVer, true
	}
	return "", "", false
}

func (r *Result) isModuleInGoMod(pkg, dir string) bool {
	_, _, found := r.findModuleInGoMod(pkg, dir)
	return found
}

func (j Job) isVulnerable(result *Result) *Result {
	dir := filepath.Join(result.Directory, j.Dir)

	curVer := getCurrentVersion(j.Package, dir, j.Dir, result)
	modPath := getModPath(j.Package, dir, result)
	repPath, repVer := getReplaceVersion(modPath, dir, result)

	var rawFixVer []string
	result.Mu.Lock()
	if existing := result.AffectedImports[j.Package]; len(existing.versionRanges) > 0 {
		rawFixVer = existing.versionRanges
	} else if len(existing.FixedVersion) > 0 {
		rawFixVer = existing.FixedVersion
	} else {
		fixPkg := modPath
		if fixPkg == "" && result.AffectedImports[j.Package].Type == "stdlib" {
			fixPkg = "stdlib"
		}
		if fixPkg == "" {
			fixPkg = j.Package
		}
		rawFixVer = getFixedVersion(result.GoCVE, fixPkg, result)
	}
	result.Mu.Unlock()

	fixVer := common.ExtractFormattedFixedVersions(rawFixVer)
	if len(fixVer) == 0 {
		fixVer = rawFixVer
	}

	used := false
	unknown := false

	isUsed := result.isSymbolUsed(j.Package, dir, j.Dir, j.Symbols, j.Files)
	switch isUsed {
	case "true":
		used = true
	case "unknown":
		unknown = true
	}

	// Resolve presence and versions from actual imports, including transitive
	// dependencies. A go.mod/go.sum entry alone does not establish package use.
	present := false
	if build := result.getSSABuild(dir); build != nil {
		packages.Visit(build.loadedPkgs, nil, func(p *packages.Package) {
			if p.PkgPath == j.Package {
				present = true
				if result.AffectedImports[j.Package].Type != "stdlib" && p.Module != nil {
					curVer, modPath = p.Module.Version, p.Module.Path
					repPath, repVer = "", ""
					if p.Module.Replace != nil && p.Module.Replace.Version != "" {
						repPath, repVer = p.Module.Replace.Path, p.Module.Replace.Version
					}
				}
			}
		})
	}

	goToolchainVersion := ""
	if result.AffectedImports[j.Package].Type == "stdlib" {
		if v, ok := result.GoToolchainVersions[j.Dir]; ok {
			goToolchainVersion = v
		} else {
			goToolchainVersion = curVer
		}
	}

	vr := checkDirVulnerability(curVer, repVer, used, unknown,
		result.AffectedImports[j.Package].Type == "stdlib", goToolchainVersion, rawFixVer)

	result.Mu.Lock()
	if used && repPath != "" && repPath != modPath {
		vr = VulnerabilityResult{Status: "unknown", DirVulnerable: true}
		result.Errors = append(result.Errors, fmt.Sprintf("Replacement for %s uses different module %s; advisory versions cannot establish its vulnerability status", modPath, repPath))
	}

	if present || used {
		if result.UsedImports == nil {
			result.UsedImports = make(map[string]map[string]UsedImportsDetails)
		}
		if result.UsedImports[j.Dir] == nil {
			result.UsedImports[j.Dir] = make(map[string]UsedImportsDetails)
		}
		uentry := result.UsedImports[j.Dir][j.Package]
		uentry.CurrentVersion = curVer
		if repVer != "" {
			uentry.ReplaceModule = repPath
			uentry.ReplaceVersion = repVer
		}
		if (used || unknown) && vr.NeedsReplaceFix && vr.FixVersion != "" {
			uentry.FixCommands = []string{
				fmt.Sprintf("go mod edit -replace=%s=%s@%s", modPath, modPath, vr.FixVersion),
				"go mod tidy",
				"go mod vendor",
			}
		} else if vr.Status == "true" && vr.FixVersion != "" {
			if result.AffectedImports[j.Package].Type == "stdlib" {
				selectedFixVersion := selectFixVersionForCurrentGoVersion(goToolchainVersion, fixVer)
				uentry.FixCommands = []string{
					fmt.Sprintf("go mod edit -go=%s", selectedFixVersion),
					"go mod tidy",
					"go mod vendor",
				}
			} else {
				uentry.FixCommands = []string{
					fmt.Sprintf("go get %s@%s", modPath, vr.FixVersion),
					"go mod tidy",
					"go mod vendor",
				}
			}
		}
		result.UsedImports[j.Dir][j.Package] = uentry
	}
	result.Mu.Unlock()

	// Each worker must publish its own status; the shared result may already
	// have been updated by another module when the collector reads it.
	return &Result{IsVulnerable: vr.Status}
}

func readVulnerabilityJSON(result *Result, url string, target any) bool {
	req, err := http.NewRequestWithContext(result.ctx(), http.MethodGet, url, nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to create request for %s: %v", url, err))
		return false
	}
	resp, err := result.httpClient().Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed HTTP request to %s: %v", url, err))
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed HTTP request to %s: status %d", url, resp.StatusCode))
		return false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read vulnerability response from %s: %v", url, err))
		return false
	}
	if err := json.Unmarshal(body, target); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse vulnerability JSON from %s: %v", url, err))
		return false
	}
	return true
}

func fetchGoVulnID(result *Result) string {
	url := VulnsURL + "/index/vulns.json"

	var vulns []VulnReport
	if !readVulnerabilityJSON(result, url, &vulns) {
		return ""
	}

	for _, v := range vulns {
		if slices.Contains(v.Aliases, result.CVE) {
			result.GoCVE = v.ID
		}
	}

	result.progress(fmt.Sprintf("  ✓ Go vulnerability ID fetched: %s", result.GoCVE))
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

	cacheGoToolchainVersions(res, modDirs)
	cacheModuleFiles(res, modDirs)

	for _, modDir := range modDirs {
		modKey, err := filepath.Rel(res.Directory, modDir)
		if err != nil {
			modKey = modDir
		}

		mainDirs := make(map[string]bool)
		filepath.WalkDir(modDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			parsed, parseErr := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly)
			if parseErr != nil {
				return nil
			}
			if parsed.Name.Name == "main" {
				mainDirs[filepath.Dir(path)] = true
			}
			return nil
		})

		var sets [][]string
		for dirPath := range mainDirs {
			files, _ := filepath.Glob(filepath.Join(dirPath, "*.go"))
			var group []string
			for _, file := range files {
				if strings.HasSuffix(file, "_test.go") {
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

	res.Files = result
	res.progress("  ✓ Directory and fileset discovery complete")
}

func fetchAffectedSymbols(result *Result) {
	url := fmt.Sprintf(VulnsURL+"/ID/%s.json", result.GoCVE)

	var detail VulnReport
	if !readVulnerabilityJSON(result, url, &detail) {
		return
	}

	// Validate that required fields are not empty
	if len(detail.Affected) == 0 {
		result.Errors = append(result.Errors, "Affected packages list is empty")
		return
	}

	imports := make(map[string]AffectedImportsDetails)
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
			for _, versionRange := range aff.Ranges {
				if versionRange.Type == "SEMVER" {
					entry.versionRanges = append(entry.versionRanges, formatIntroducedFixed(versionRange.Events)...)
				}
			}
			fixes := common.ExtractFormattedFixedVersions(entry.versionRanges)
			if len(fixes) == 0 {
				entry.FixedVersion = slices.Clone(entry.versionRanges)
			} else if typ == "stdlib" {
				entry.FixedVersion = fixes
			} else {
				entry.FixedVersion = []string{common.SemVersion(strings.Join(fixes, " "))}
			}
			imports[imp.Path] = entry
			hasValidImports = true
		}

		result.AffectedImports = imports
	}

	// Validate that we found at least one valid import with symbols
	if !hasValidImports {
		result.Errors = append(result.Errors, "No imports or symbols found in vulnerability data")
		result.progress("  ✗ Error: No imports or symbols found in vulnerability data")
		return
	}

	symbolCount := 0
	for _, imp := range imports {
		symbolCount += len(imp.Symbols)
	}
	result.progress(fmt.Sprintf("  ✓ Affected symbols fetched: %d symbols across %d packages", symbolCount, len(imports)))
}

func (r *Result) isSymbolUsed(pkg, dir, modDir string, symbols, files []string) string {
	symbols = slices.Clone(symbols)
	files = slices.Clone(files)
	// Store original symbols for reflection analysis
	originalSymbols := make([]string, len(symbols))
	copy(originalSymbols, symbols)

	// Prepare symbol variations for direct call detection
	for _, symbol := range originalSymbols {
		// Check if symbol contains a dot (e.g., "Entry.Writer" or "Type.Method")
		if strings.Contains(symbol, ".") {
			// Symbol is Type.Method format - generate proper receiver patterns
			parts := strings.SplitN(symbol, ".", 2)
			if len(parts) == 2 {
				typeName := parts[0]
				methodName := parts[1]
				// Generate: (pkg.Type).Method and (*pkg.Type).Method
				symbols = append(symbols, fmt.Sprintf("(%s.%s).%s", pkg, typeName, methodName))
				symbols = append(symbols, fmt.Sprintf("(*%s.%s).%s", pkg, typeName, methodName))
			}
		} else {
			// Symbol is a simple function or type - use original pattern
			symbols = append(symbols, fmt.Sprintf("%s.%s", pkg, symbol))
			symbols = append(symbols, fmt.Sprintf("(%s).%s", pkg, symbol))
			symbols = append(symbols, fmt.Sprintf("(*%s).%s", pkg, symbol))
		}
	}

	// Check for direct usage via call graph analysis
	directUsage := r.checkDirectUsage(pkg, dir, modDir, symbols, files)

	// Include loaded helper packages, not just files declaring package main.
	if build := r.getSSABuild(dir); build != nil {
		for _, p := range build.loadedPkgs {
			for _, file := range p.CompiledGoFiles {
				if rel, err := filepath.Rel(dir, file); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					files = append(files, rel)
				}
			}
		}
		files = common.UniqueStrings(files)
	}
	// Check for reflection-based usage
	reflectionRisks := r.detectReflectionVulnerabilities(pkg, dir, originalSymbols, files)

	// Store reflection risks for informational purposes only
	// Note: Reflection risks do NOT affect IsVulnerable status - only call graph findings do
	if len(reflectionRisks) > 0 {
		r.Mu.Lock()
		r.ReflectionRisks = mergeReflectionRisks(r.ReflectionRisks, reflectionRisks)
		r.Mu.Unlock()
	}

	// Only return "true" if call graph found direct usage
	// Reflection risks are informational only and don't determine vulnerability status
	return directUsage
}

// checkDirectUsage handles the call graph analysis using BFS on the callgraph.Graph directly
func (r *Result) checkDirectUsage(pkg, dir, modDir string, symbols []string, files []string) string {
	progress := r.Progress

	build := r.getSSABuild(dir)
	if build == nil {
		return "unknown"
	}

	if len(build.entryPoints) == 0 {
		errMsg := fmt.Sprintf("No entry points found in call graph for %s", dir)
		r.Mu.Lock()
		r.Errors = append(r.Errors, errMsg)
		r.Mu.Unlock()
		return "unknown"
	}

	relDir := modDir
	if relDir == "" {
		relDir = "."
	}

	if progress {
		fmt.Fprintf(os.Stderr, "[%s] BFS: searching %d entry points for %d %s symbols...\n", relDir, len(build.entryPoints), len(symbols), pkg)
	}

	found, visited := findAllSymbolsFromAny(build.entryPoints, pkg, symbols, r.ctx())

	if progress {
		fmt.Fprintf(os.Stderr, "[%s] BFS: visited %d nodes, found %d/%d %s symbols\n", relDir, visited, len(found), len(symbols), pkg)
	}

	if len(found) > 0 {
		r.Mu.Lock()
		if r.UsedImports == nil {
			r.UsedImports = make(map[string]map[string]UsedImportsDetails)
		}
		if r.UsedImports[modDir] == nil {
			r.UsedImports[modDir] = make(map[string]UsedImportsDetails)
		}
		entry := r.UsedImports[modDir][pkg]
		for sym, path := range found {
			entry.Symbols = append(entry.Symbols, sym)
			entry.Paths = append(entry.Paths, path)
		}
		r.UsedImports[modDir][pkg] = entry
		r.Mu.Unlock()
		return "true"
	}

	if warnings := checkIgnoredFiles(build.loadedPkgs, pkg); len(warnings) > 0 {
		r.Mu.Lock()
		r.Errors = append(r.Errors, warnings...)
		r.Mu.Unlock()
		return "unknown"
	}

	return "false"
}

// checkIgnoredFiles parses files excluded by build constraints and returns
// warnings for any that import the vulnerable package.
func checkIgnoredFiles(pkgs []*packages.Package, vulnPkg string) []string {
	var warnings []string
	seen := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, f := range pkg.IgnoredFiles {
			if seen[f] {
				continue
			}
			seen[f] = true
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				continue
			}
			for _, imp := range parsed.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				if importPath == vulnPkg || strings.HasPrefix(importPath, vulnPkg+"/") {
					warnings = append(warnings, fmt.Sprintf(
						"File %s imports %s but was excluded by build constraints. Need manual analysis",
						f, importPath))
				}
			}
		}
	}
	return warnings
}

func getRepoModulePath(dir string, result *Result) string {
	data, err := result.readModFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return ""
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return ""
	}
	if f.Module != nil {
		return f.Module.Mod.Path
	}
	return ""
}

// GenerateCallGraphForVisualization is a public wrapper for call graph generation for visualization
func (r *Result) GenerateCallGraphForVisualization(dir string, files []string) (string, error) {
	output, _, _, _, err := r.generateCallGraphWithLibInternal(dir, files)
	return output, err
}

// GenerateCallGraphObject returns the callgraph.Graph object for direct manipulation
func (r *Result) GenerateCallGraphObject(dir string, files []string) (*callgraph.Graph, error) {
	_, _, cg, _, err := r.generateCallGraphWithLibInternal(dir, files)
	return cg, err
}

// generateCallGraphWithLib creates a call graph using the callgraph library (backward compat wrapper)
func (r *Result) generateCallGraphWithLib(dir string, files []string) (string, error) {
	output, _, _, _, err := r.generateCallGraphWithLibInternal(dir, files)
	return output, err
}

func (r *Result) packagesEnv(dir string) []string {
	return append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off", "GOTOOLCHAIN=local")
}

func (r *Result) buildSSAAndCallGraph(dir string) (*ssa.Program, *callgraph.Graph, []*packages.Package, error) {
	cfg := &packages.Config{
		Mode:    packages.LoadAllSyntax | packages.NeedModule,
		Dir:     dir,
		Env:     r.packagesEnv(dir),
		Context: r.ctx(),
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load packages: %v", err)
	}

	if len(pkgs) == 0 {
		return nil, nil, nil, fmt.Errorf("no packages loaded")
	}

	var loadErrors []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			loadErrors = append(loadErrors, err.Error())
		}
	})
	if len(loadErrors) > 0 {
		sort.Strings(loadErrors)
		return nil, nil, pkgs, fmt.Errorf("incomplete package load: %s", strings.Join(common.UniqueStrings(loadErrors), "; "))
	}
	for _, pkg := range pkgs {
		if pkg.Types == nil || pkg.TypesInfo == nil || pkg.IllTyped {
			return nil, nil, pkgs, fmt.Errorf("incomplete package load for %s", pkg.PkgPath)
		}
	}

	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	algo := getCallGraphAlgorithm()
	cg := buildCallGraph(prog, algo)

	return prog, cg, pkgs, nil
}

func (r *Result) generateCallGraphWithLibInternal(dir string, files []string) (string, *ssa.Program, *callgraph.Graph, []*packages.Package, error) {
	prog, cg, pkgs, err := r.buildSSAAndCallGraph(dir)
	if err != nil {
		return "", nil, nil, nil, err
	}

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

	return output.String(), prog, cg, pkgs, nil
}

// extractEntryPoints finds all main functions in the call graph (string-based, for backward compat)
func extractEntryPoints(callGraphOutput string) []string {
	var entryPoints []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(callGraphOutput))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			caller := fields[0]
			// Look for main functions (e.g., "command-line-arguments.main", "package.main")
			if strings.HasSuffix(caller, ".main") && !seen[caller] {
				entryPoints = append(entryPoints, caller)
				seen[caller] = true
			}
		}
	}

	return entryPoints
}

// extractEntryPointNodes finds all entry point nodes in the call graph
// Entry points include: main functions, init functions, HTTP handlers, and exported functions in main package
// Only considers entry points from repo code (not vendor/external packages)
func extractEntryPointNodes(graph *callgraph.Graph, repoModulePath string, progress bool) []*callgraph.Node {
	var entries []*callgraph.Node
	skippedCount := 0

	for _, node := range graph.Nodes {
		if node.Func == nil || node.Func.Pkg == nil {
			continue
		}

		// Skip vendor and external packages
		pkgPath := node.Func.Pkg.Pkg.Path()
		if strings.Contains(pkgPath, "/vendor/") {
			skippedCount++
			continue
		}
		if !isRepoPackage(pkgPath, repoModulePath) {
			skippedCount++
			continue
		}

		name := node.Func.Name()

		// main and init functions
		if name == "main" || name == "init" {
			entries = append(entries, node)
			continue
		}

		// HTTP handler signature: func(http.ResponseWriter, *http.Request)
		if isHTTPHandler(node.Func.Signature) {
			entries = append(entries, node)
			continue
		}

		// Exported functions in main package (potential entry points)
		if node.Func.Pkg.Pkg.Name() == "main" && ast.IsExported(name) {
			entries = append(entries, node)
		}
	}

	if progress {
		fmt.Fprintf(os.Stderr, "  Found %d entry points in repo code\n", len(entries))
		fmt.Fprintf(os.Stderr, "  Skipped %d nodes from vendor/external packages\n", skippedCount)
	}

	return entries
}

// isRepoPackage checks if the package path belongs to the repository
func isRepoPackage(pkgPath, repoModulePath string) bool {
	return strings.HasPrefix(pkgPath, repoModulePath) ||
		pkgPath == "command-line-arguments"
}

// isHTTPHandler checks if the function signature matches http.Handler pattern
// func(http.ResponseWriter, *http.Request)
func isHTTPHandler(sig *types.Signature) bool {
	params := sig.Params()
	if params.Len() != 2 {
		return false
	}

	// Check first param is http.ResponseWriter
	p0 := params.At(0).Type().String()
	if !strings.Contains(p0, "http.ResponseWriter") {
		return false
	}

	// Check second param is *http.Request
	p1 := params.At(1).Type().String()
	return strings.Contains(p1, "http.Request")
}

// findPathToSymbol performs BFS from entry point to find a path to the target symbol
// Returns the path and whether the symbol was found
func findPathToSymbol(entry *callgraph.Node, pkg, symbol string, progress bool) ([]*callgraph.Node, bool) {
	queue := []*callgraph.Node{entry}
	parent := map[*callgraph.Node]*callgraph.Node{entry: nil}
	visited := 0

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		visited++

		if matchesSymbol(node, pkg, symbol) {
			path := reconstructPath(node, parent)
			if progress {
				fmt.Fprintf(os.Stderr, "    ✓ Found path to %s (%d hops, %d nodes)\n", symbol, len(path), visited)
			}
			return path, true
		}

		for _, edge := range node.Out {
			if _, seen := parent[edge.Callee]; !seen {
				parent[edge.Callee] = node
				queue = append(queue, edge.Callee)
			}
		}
	}

	return nil, false
}

// findPathToSymbolFromAny searches from multiple entry points to find the first path to the symbol
func findPathToSymbolFromAny(entries []*callgraph.Node, pkg, symbol string, progress bool) ([]*callgraph.Node, bool) {
	for _, entry := range entries {
		if path, found := findPathToSymbol(entry, pkg, symbol, progress); found {
			return path, true
		}
	}
	return nil, false
}

// findAllSymbolsFromAny does multi-source BFS from all entry points simultaneously.
// Each node is visited exactly once regardless of entry point count.
// Returns a map of symbol -> path for each symbol found reachable, and total nodes visited.
func findAllSymbolsFromAny(entries []*callgraph.Node, pkg string, symbols []string, ctx ...context.Context) (map[string][]*callgraph.Node, int) {
	found := make(map[string][]*callgraph.Node)
	parent := make(map[*callgraph.Node]*callgraph.Node, len(entries))
	queue := make([]*callgraph.Node, 0, len(entries))

	for _, entry := range entries {
		if _, seen := parent[entry]; !seen {
			parent[entry] = nil
			queue = append(queue, entry)
		}
	}

	remaining := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		remaining[s] = true
	}

	var cancelCtx context.Context
	if len(ctx) > 0 && ctx[0] != nil {
		cancelCtx = ctx[0]
	}

	visited := 0
	for len(queue) > 0 && len(remaining) > 0 {
		if cancelCtx != nil && visited%1000 == 0 {
			select {
			case <-cancelCtx.Done():
				return found, visited
			default:
			}
		}

		node := queue[0]
		queue = queue[1:]
		visited++

		var matched []string
		for sym := range remaining {
			if matchesSymbol(node, pkg, sym) {
				matched = append(matched, sym)
			}
		}
		for _, sym := range matched {
			found[sym] = reconstructPath(node, parent)
			delete(remaining, sym)
		}

		for _, edge := range node.Out {
			if _, seen := parent[edge.Callee]; !seen {
				parent[edge.Callee] = node
				queue = append(queue, edge.Callee)
			}
		}
	}

	return found, visited
}

// reconstructPath walks parent pointers backward to build the path from entry to target
func reconstructPath(target *callgraph.Node, parent map[*callgraph.Node]*callgraph.Node) []*callgraph.Node {
	var path []*callgraph.Node
	for node := target; node != nil; node = parent[node] {
		path = append([]*callgraph.Node{node}, path...)
	}
	return path
}

// FindPathToSymbolExported is an exported wrapper for findPathToSymbol
func FindPathToSymbolExported(entry *callgraph.Node, pkg, symbol string, progress bool) ([]*callgraph.Node, bool) {
	return findPathToSymbol(entry, pkg, symbol, progress)
}

// matchesSymbol checks if the node's function matches the target symbol from the specified package
func matchesSymbol(node *callgraph.Node, pkg, symbol string) bool {
	if node.Func == nil {
		return false
	}

	funcStr := node.Func.String()

	// FIRST: Verify the function belongs to the target package
	// This prevents matching (*log.Logger).Writer when searching for logrus
	if pkg != "" && !strings.Contains(funcStr, pkg) {
		return false
	}

	// Direct match
	if funcStr == symbol {
		return true
	}

	// Check if the function string contains the symbol
	// This handles cases like "(pkg.Type).Method" matching "pkg.Type.Method"
	if strings.Contains(funcStr, symbol) {
		return true
	}

	// Handle receiver variations: (Type).Method, (*Type).Method
	// The symbol might be "pkg.Method" but the function is "(pkg.Type).Method"
	if strings.Contains(symbol, ".") {
		parts := strings.Split(symbol, ".")
		if len(parts) >= 2 {
			methodName := parts[len(parts)-1]
			pkgPrefix := strings.Join(parts[:len(parts)-1], ".")

			// Check if function ends with the method name and contains the package
			if strings.HasSuffix(funcStr, "."+methodName) && strings.Contains(funcStr, pkgPrefix) {
				return true
			}
		}
	}

	return false
}

// getCallGraphAlgorithm returns the algorithm to use for call graph generation
// based on the ALGO environment variable.
// Supported algorithms: rta (default), cha, vta, static
// RTA is the default because it better handles reflection-based calls
// (e.g., reflect.ValueOf(func).Call()) compared to VTA.
func getCallGraphAlgorithm() string {
	algo := os.Getenv("ALGO")
	if algo == "" {
		algo = "rta" // default algorithm - better for reflection tracking
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
		// Better at tracking reflection-based calls (e.g., reflect.ValueOf(func).Call())
		return buildRTACallGraph(prog, allFuncs)
	case "static":
		// Static analysis - very fast but least precise (only direct calls)
		return static.CallGraph(prog)
	case "vta":
		// Variable Type Analysis - most precise for direct calls but slower
		return vta.CallGraph(allFuncs, nil)
	default:
		// Default to RTA if unknown algorithm specified (best for reflection tracking)
		return buildRTACallGraph(prog, allFuncs)
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
		if fn.Pkg != nil && fn.Pkg.Pkg.Name() == "main" && (fn.Name() == "main" || fn.Name() == "init") {
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

func getCurrentVersion(pkg string, dir string, modDir string, result *Result) string {
	if result.AffectedImports != nil {
		if details, exists := result.AffectedImports[pkg]; exists && details.Type == "stdlib" {
			if v, ok := result.GoToolchainVersions[modDir]; ok {
				return v
			}
			return getGoToolchainVersion(dir, result)
		}
	}

	_, ver, found := result.findModuleInGoMod(pkg, dir)
	if !found {
		return ""
	}
	return ver
}

func cacheGoToolchainVersions(r *Result, modDirs []string) {
	r.GoToolchainVersions = make(map[string]string)
	for _, fullDir := range modDirs {
		modKey, err := filepath.Rel(r.Directory, fullDir)
		if err != nil {
			modKey = fullDir
		}
		ver := getGoToolchainVersion(fullDir, r)
		if ver != "" {
			r.GoToolchainVersions[modKey] = ver
		}
	}
}

func cacheModuleFiles(r *Result, modDirs []string) {
	r.moduleFiles = make(map[string][]byte)
	for _, dir := range modDirs {
		for _, name := range []string{"go.mod", "go.sum"} {
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			r.moduleFiles[path] = data
		}
	}
}

func (r *Result) readModFile(path string) ([]byte, error) {
	if data, ok := r.moduleFiles[path]; ok {
		return data, nil
	}
	return os.ReadFile(path)
}

func getGoToolchainVersion(dir string, result *Result) string {
	data, err := result.readModFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read go.mod in %s: %v", dir, err))
		return ""
	}

	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse go.mod in %s: %v", dir, err))
		return ""
	}

	if f.Go != nil && f.Go.Version != "" {
		v := f.Go.Version
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		return v
	}

	return ""
}

func getReplaceVersion(pkg string, dir string, result *Result) (string, string) {
	data, err := result.readModFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read go.mod in %s: %v", dir, err))
		return "", ""
	}

	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return "", ""
	}

	for _, r := range f.Replace {
		if r.Old.Path == pkg && r.New.Version != "" {
			return r.New.Path, r.New.Version
		}
	}

	return "", ""
}

func getFixedVersion(id, pkg string, result *Result) []string {
	url := fmt.Sprintf(VulnsURL+"/ID/%s.json", id)
	var detail VulnReport
	if !readVulnerabilityJSON(result, url, &detail) {
		return nil
	}

	for _, a := range detail.Affected {
		if a.Package.Name == pkg || strings.HasPrefix(pkg, a.Package.Name+"/") {
			for _, r := range a.Ranges {
				if r.Type == "SEMVER" {
					return formatIntroducedFixed(r.Events)
				}
			}
		}
	}

	if pkg != "" {
		for _, a := range detail.Affected {
			if a.Package.Name == "stdlib" {
				for _, r := range a.Ranges {
					if r.Type == "SEMVER" {
						return formatIntroducedFixed(r.Events)
					}
				}
			}
		}
	}

	return nil
}

func getModPath(pkg, dir string, result *Result) string {
	path, _, found := result.findModuleInGoMod(pkg, dir)
	if !found {
		return ""
	}
	return path
}

func getGitBranch(result *Result) {
	cmd := "git"
	args := []string{"rev-parse", "--abbrev-ref", "HEAD"}
	out, err := result.runner().RunCommandStdout(result.ctx(), result.Directory, cmd, args...)
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
		commitOut, err := result.runner().RunCommandStdout(result.ctx(), result.Directory, commitCmd, commitArgs...)
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
	result.progress(fmt.Sprintf("  ✓ Git branch information retrieved: %s", result.Branch))
}

func getGitURL(result *Result) {
	cmd := "git"
	args := []string{"remote", "get-url", "origin"}
	out, err := result.runner().RunCommandStdout(result.ctx(), result.Directory, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), result.Directory, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
	}
	result.Repository = strings.TrimSpace(string(out))
	result.progress(fmt.Sprintf("  ✓ Git repository URL retrieved: %s", result.Repository))
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
		result = append(result, fmt.Sprintf("Introduced in %s - ", introduced))
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
	// Check if it starts with a digit (e.g., "1.21.4")
	if len(fixedVersion) > 0 && fixedVersion[0] >= '0' && fixedVersion[0] <= '9' {
		fixedVersion = "v" + fixedVersion
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
