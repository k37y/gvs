package cg

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/callgraph"
)

type fakeRunner struct {
	stdout   map[string][]byte
	combined map[string][]byte
	err      map[string]error
}

func (f *fakeRunner) key(command string, args ...string) string {
	s := command
	for _, a := range args {
		s += " " + a
	}
	return s
}

func (f *fakeRunner) RunCommand(dir string, command string, args ...string) ([]byte, error) {
	k := f.key(command, args...)
	if e, ok := f.err[k]; ok {
		return f.combined[k], e
	}
	return f.combined[k], nil
}

func (f *fakeRunner) RunCommandStdout(dir string, command string, args ...string) ([]byte, error) {
	k := f.key(command, args...)
	if e, ok := f.err[k]; ok {
		return f.stdout[k], e
	}
	return f.stdout[k], nil
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		stdout:   make(map[string][]byte),
		combined: make(map[string][]byte),
		err:      make(map[string]error),
	}
}

func TestCheckDirVulnerability(t *testing.T) {
	tests := []struct {
		name               string
		curVer             string
		repVer             string
		fv                 string
		used               bool
		unknown            bool
		isStdlib           bool
		goToolchainVersion string
		fixVer             []string
		wantDirVuln        bool
		wantStatus         string
		wantReplaceFix     bool
	}{
		// --- Non-stdlib, symbol used ---
		{
			name:       "non-stdlib used, current below fix, no replace",
			curVer:     "v0.23.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true,
		},
		{
			name:       "non-stdlib used, current equals fix, no replace",
			curVer:     "v0.33.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, current above fix, no replace",
			curVer:     "v0.34.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true,
		},
		{
			name:       "non-stdlib used, replace equals fix",
			curVer:     "v0.23.0",
			repVer:     "v0.33.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, replace above fix",
			curVer:     "v0.23.0",
			repVer:     "v0.34.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},

		// --- Non-stdlib, symbol not used ---
		{
			name:       "non-stdlib not used, current below fix",
			curVer:     "v0.23.0",
			fv:         "v0.33.0",
			used:       false,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib not used, replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       false,
			wantStatus: "false", wantDirVuln: true, wantReplaceFix: true,
		},

		// --- Unknown reachability ---
		{
			name:       "unknown reachability",
			curVer:     "v0.23.0",
			fv:         "v0.33.0",
			unknown:    true,
			wantStatus: "unknown", wantDirVuln: true,
		},
		{
			name:       "unknown reachability with replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			unknown:    true,
			wantStatus: "unknown", wantDirVuln: true, wantReplaceFix: true,
		},

		// --- Stdlib, symbol used ---
		{
			name:               "stdlib used, toolchain below fix",
			curVer:             "v1.21.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.21.4",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "true", wantDirVuln: true,
		},
		{
			name:               "stdlib used, toolchain at fix",
			curVer:             "v1.21.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.21.8",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},
		{
			name:               "stdlib used, toolchain above fix",
			curVer:             "v1.21.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.22.5",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},
		{
			name:               "stdlib used, no matching fix for branch",
			curVer:             "v1.20.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.20.5",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "true", wantDirVuln: true,
		},
		{
			name:     "stdlib used, empty toolchain version",
			curVer:   "v1.21.0",
			fv:       "v1.21.8",
			used:     true,
			isStdlib: true,
			fixVer:   []string{"1.21.8"},
			wantStatus: "unknown", wantDirVuln: true,
		},
		{
			name:     "stdlib used, no fix versions available",
			curVer:   "v1.21.0",
			fv:       "",
			used:     true,
			isStdlib: true,
			wantStatus: "unknown", wantDirVuln: true,
		},

		// --- Real-world mod-dir scenarios ---
		{
			name:       "mod-dir root: require v0.23.0, replace v0.24.0, fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true,
		},
		{
			name:       "mod-dir bar: require v0.33.0, replace v0.24.0, fix v0.33.0",
			curVer:     "v0.33.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true,
		},
		{
			name:       "mod-dir foo: require v0.23.0, replace v0.33.0 (fixed), fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.33.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vr := checkDirVulnerability(tt.curVer, tt.repVer, tt.fv,
				tt.used, tt.unknown, tt.isStdlib, tt.goToolchainVersion, tt.fixVer)

			if vr.DirVulnerable != tt.wantDirVuln {
				t.Errorf("DirVulnerable = %v, want %v", vr.DirVulnerable, tt.wantDirVuln)
			}
			if vr.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", vr.Status, tt.wantStatus)
			}
			if vr.NeedsReplaceFix != tt.wantReplaceFix {
				t.Errorf("NeedsReplaceFix = %v, want %v", vr.NeedsReplaceFix, tt.wantReplaceFix)
			}
		})
	}
}

func TestExtractGoVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"go1.21.4", "v1.21.4"},
		{"1.21.4", "v1.21.4"},
		{"v1.21.4", "v1.21.4"},
		{"Introduced in 0 and fixed in 1.21.8", "v1.21.8"},
		{"Introduced in 0 and fixed in go1.22.2", "v1.22.2"},
		{"  go1.23.0  ", "v1.23.0"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractGoVersion(tt.input)
			if got != tt.want {
				t.Errorf("extractGoVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetMajorMinor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v1.23.8", "v1.23"},
		{"v1.21.0", "v1.21"},
		{"v2.0.0", "v2.0"},
		{"1.23.8", ""},  // missing v prefix
		{"v1", ""},      // too few parts
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := getMajorMinor(tt.input)
			if got != tt.want {
				t.Errorf("getMajorMinor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindAppropriateFixVersion(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		fixedVersions  []string
		want           string
	}{
		{
			name:           "same branch match",
			currentVersion: "v1.23.4",
			fixedVersions:  []string{"1.23.8", "1.24.2"},
			want:           "v1.23.8",
		},
		{
			name:           "different branch, nearest applicable",
			currentVersion: "v1.20.5",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "v1.21.8",
		},
		{
			name:           "already at fix version",
			currentVersion: "v1.23.8",
			fixedVersions:  []string{"1.23.8"},
			want:           "v1.23.8",
		},
		{
			name:           "empty current version",
			currentVersion: "",
			fixedVersions:  []string{"1.23.8"},
			want:           "",
		},
		{
			name:           "empty fix versions",
			currentVersion: "v1.23.4",
			fixedVersions:  nil,
			want:           "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findAppropriateFixVersion(tt.currentVersion, tt.fixedVersions)
			if got != tt.want {
				t.Errorf("findAppropriateFixVersion(%q, %v) = %q, want %q", tt.currentVersion, tt.fixedVersions, got, tt.want)
			}
		})
	}
}

func TestSelectFixVersionForCurrentGoVersion(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		fixedVersions  []string
		want           string
	}{
		{
			name:           "single fix version",
			currentVersion: "v1.21.4",
			fixedVersions:  []string{"1.21.8"},
			want:           "v1.21.8", // single version returns extractGoVersion result directly
		},
		{
			name:           "multiple fix versions, picks smallest greater",
			currentVersion: "v1.21.4",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "1.21.8",
		},
		{
			name:           "empty fix versions",
			currentVersion: "v1.21.4",
			fixedVersions:  nil,
			want:           "",
		},
		{
			name:           "current above all fixes",
			currentVersion: "v1.25.0",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "v1.22.2", // fallback returns extractGoVersion result directly
		},
		{
			name:           "empty current version",
			currentVersion: "",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "v1.21.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectFixVersionForCurrentGoVersion(tt.currentVersion, tt.fixedVersions)
			if got != tt.want {
				t.Errorf("selectFixVersionForCurrentGoVersion(%q, %v) = %q, want %q", tt.currentVersion, tt.fixedVersions, got, tt.want)
			}
		})
	}
}

func TestFormatIntroducedFixed(t *testing.T) {
	tests := []struct {
		name   string
		events []Event
		want   []string
	}{
		{
			name:   "empty",
			events: nil,
			want:   nil,
		},
		{
			name:   "single pair",
			events: []Event{{Introduced: "0"}, {Fixed: "1.21.8"}},
			want:   []string{"Introduced in 0 and fixed in 1.21.8"},
		},
		{
			name:   "introduced only",
			events: []Event{{Introduced: "0"}},
			want:   []string{"Introdued in 0 - "},
		},
		{
			name:   "multiple pairs",
			events: []Event{{Introduced: "0"}, {Fixed: "1.21.8"}, {Introduced: "1.22.0"}, {Fixed: "1.22.2"}},
			want:   []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatIntroducedFixed(tt.events)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d results, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("result[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMatchesSymbol_NilFunc(t *testing.T) {
	node := &callgraph.Node{Func: nil}
	if matchesSymbol(node, "pkg", "sym") {
		t.Error("expected false for nil Func")
	}
}

func TestIsRepoPackage(t *testing.T) {
	tests := []struct {
		pkgPath        string
		repoModulePath string
		want           bool
	}{
		{"github.com/foo/bar/pkg", "github.com/foo/bar", true},
		{"github.com/foo/bar", "github.com/foo/bar", true},
		{"github.com/other/pkg", "github.com/foo/bar", false},
		{"command-line-arguments", "github.com/foo/bar", true},
		{"golang.org/x/net/html", "github.com/foo/bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.pkgPath, func(t *testing.T) {
			got := isRepoPackage(tt.pkgPath, tt.repoModulePath)
			if got != tt.want {
				t.Errorf("isRepoPackage(%q, %q) = %v, want %v", tt.pkgPath, tt.repoModulePath, got, tt.want)
			}
		})
	}
}

func TestExtractEntryPoints(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "with main functions",
			input: "command-line-arguments.main command-line-arguments.init\ncommand-line-arguments.main pkg.Foo\n",
			want:  1,
		},
		{
			name:  "no main functions",
			input: "pkg.Foo pkg.Bar\n",
			want:  0,
		},
		{
			name:  "empty",
			input: "",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEntryPoints(tt.input)
			if len(got) != tt.want {
				t.Errorf("extractEntryPoints() returned %d entries, want %d: %v", len(got), tt.want, got)
			}
		})
	}
}

func TestReconstructPath(t *testing.T) {
	node1 := &callgraph.Node{ID: 1}
	node2 := &callgraph.Node{ID: 2}
	node3 := &callgraph.Node{ID: 3}

	parent := map[*callgraph.Node]*callgraph.Node{
		node1: nil,
		node2: node1,
		node3: node2,
	}

	path := reconstructPath(node3, parent)
	if len(path) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(path))
	}
	if path[0] != node1 || path[1] != node2 || path[2] != node3 {
		t.Error("path order is wrong")
	}
}

func TestGetCallGraphAlgorithm(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		setEnv bool
		want   string
	}{
		{"default", "", false, "rta"},
		{"vta", "VTA", true, "vta"},
		{"cha", "cha", true, "cha"},
		{"static", "STATIC", true, "static"},
		{"empty string", "", true, "rta"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("ALGO", tt.envVal)
			} else {
				os.Unsetenv("ALGO")
			}
			got := getCallGraphAlgorithm()
			if got != tt.want {
				t.Errorf("getCallGraphAlgorithm() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAnalyzeASTForPackages(t *testing.T) {
	tests := []struct {
		name        string
		src         string
		wantUnsafe  bool
		wantReflect bool
	}{
		{
			name:        "no imports",
			src:         `package main`,
			wantUnsafe:  false,
			wantReflect: false,
		},
		{
			name:        "unsafe import with usage",
			src:         `package main; import "unsafe"; var _ = unsafe.Sizeof(0)`,
			wantUnsafe:  true,
			wantReflect: false,
		},
		{
			name:        "reflect import with usage",
			src:         `package main; import "reflect"; var _ = reflect.TypeOf(0)`,
			wantUnsafe:  false,
			wantReflect: true,
		},
		{
			name:        "both imports",
			src:         `package main; import "unsafe"; import "reflect"; var _ = unsafe.Sizeof(0); var _ = reflect.TypeOf(0)`,
			wantUnsafe:  true,
			wantReflect: true,
		},
		{
			name:        "fmt import only",
			src:         `package main; import "fmt"; var _ = fmt.Println`,
			wantUnsafe:  false,
			wantReflect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, "test.go", tt.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			gotUnsafe, gotReflect := analyzeASTForPackages(node)
			if gotUnsafe != tt.wantUnsafe {
				t.Errorf("unsafe = %v, want %v", gotUnsafe, tt.wantUnsafe)
			}
			if gotReflect != tt.wantReflect {
				t.Errorf("reflect = %v, want %v", gotReflect, tt.wantReflect)
			}
		})
	}
}

func TestContainsVulnerableSymbol(t *testing.T) {
	r := &Result{}
	tests := []struct {
		candidate string
		symbols   []string
		want      bool
	}{
		{"Parse", []string{"Parse", "Render"}, true},
		{"ParseFragment", []string{"Parse"}, true},
		{"Foo", []string{"Parse", "Render"}, false},
		{"", []string{"Parse"}, true}, // strings.Contains("Parse", "") is true
		{"Parse", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.candidate, func(t *testing.T) {
			got := r.containsVulnerableSymbol(tt.candidate, tt.symbols)
			if got != tt.want {
				t.Errorf("containsVulnerableSymbol(%q, %v) = %v, want %v", tt.candidate, tt.symbols, got, tt.want)
			}
		})
	}
}

func TestIsMethodByName(t *testing.T) {
	r := &Result{}

	// MethodByName call
	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "obj"},
			Sel: &ast.Ident{Name: "MethodByName"},
		},
	}
	if !r.isMethodByName(call) {
		t.Error("expected true for MethodByName")
	}

	// Non-MethodByName call
	call2 := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "obj"},
			Sel: &ast.Ident{Name: "SomeOtherMethod"},
		},
	}
	if r.isMethodByName(call2) {
		t.Error("expected false for SomeOtherMethod")
	}

	// Non-selector call
	call3 := &ast.CallExpr{
		Fun: &ast.Ident{Name: "foo"},
	}
	if r.isMethodByName(call3) {
		t.Error("expected false for non-selector call")
	}
}

func TestIsCallSlice(t *testing.T) {
	r := &Result{}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "v"},
			Sel: &ast.Ident{Name: "CallSlice"},
		},
	}
	if !r.isCallSlice(call) {
		t.Error("expected true for CallSlice")
	}
}

func TestIsFieldByName(t *testing.T) {
	r := &Result{}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "v"},
			Sel: &ast.Ident{Name: "FieldByName"},
		},
	}
	if !r.isFieldByName(call) {
		t.Error("expected true for FieldByName")
	}
}

func TestIsMethodByIndex(t *testing.T) {
	r := &Result{}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "t"},
			Sel: &ast.Ident{Name: "Method"},
		},
	}
	if !r.isMethodByIndex(call) {
		t.Error("expected true for Method")
	}
}

func TestIsConvert(t *testing.T) {
	r := &Result{}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "v"},
			Sel: &ast.Ident{Name: "Convert"},
		},
	}
	if !r.isConvert(call) {
		t.Error("expected true for Convert")
	}
}

func TestIsInterface(t *testing.T) {
	r := &Result{}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "v"},
			Sel: &ast.Ident{Name: "Interface"},
		},
	}
	if !r.isInterface(call) {
		t.Error("expected true for Interface")
	}
}

func TestIsStringToInterfaceMap(t *testing.T) {
	r := &Result{}

	// map[string]interface{}
	mapType := &ast.MapType{
		Key: &ast.Ident{Name: "string"},
		Value: &ast.InterfaceType{
			Methods: &ast.FieldList{},
		},
	}
	if !r.isStringToInterfaceMap(mapType) {
		t.Error("expected true for map[string]interface{}")
	}

	// map[int]interface{}
	mapType2 := &ast.MapType{
		Key: &ast.Ident{Name: "int"},
		Value: &ast.InterfaceType{
			Methods: &ast.FieldList{},
		},
	}
	if r.isStringToInterfaceMap(mapType2) {
		t.Error("expected false for map[int]interface{}")
	}
}

func TestExtractMethodName(t *testing.T) {
	r := &Result{}

	call := &ast.CallExpr{
		Fun: &ast.Ident{Name: "foo"},
		Args: []ast.Expr{
			&ast.BasicLit{Kind: token.STRING, Value: `"Parse"`},
		},
	}
	got := r.extractMethodName(call)
	if got != "Parse" {
		t.Errorf("extractMethodName() = %q, want %q", got, "Parse")
	}

	// No args
	call2 := &ast.CallExpr{Fun: &ast.Ident{Name: "foo"}}
	got2 := r.extractMethodName(call2)
	if got2 != "" {
		t.Errorf("extractMethodName() = %q, want empty", got2)
	}

	// Non-string arg
	call3 := &ast.CallExpr{
		Fun:  &ast.Ident{Name: "foo"},
		Args: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "42"}},
	}
	got3 := r.extractMethodName(call3)
	if got3 != "" {
		t.Errorf("extractMethodName() = %q, want empty", got3)
	}
}

func TestIsReflectValueOf(t *testing.T) {
	r := &Result{}
	pkgs := map[string]string{"reflect": "reflect"}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "reflect"},
			Sel: &ast.Ident{Name: "ValueOf"},
		},
	}
	if !r.isReflectValueOf(call, pkgs) {
		t.Error("expected true for reflect.ValueOf")
	}

	// Wrong method
	call2 := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "reflect"},
			Sel: &ast.Ident{Name: "TypeOf"},
		},
	}
	if r.isReflectValueOf(call2, pkgs) {
		t.Error("expected false for reflect.TypeOf")
	}

	// Wrong package
	call3 := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "fmt"},
			Sel: &ast.Ident{Name: "ValueOf"},
		},
	}
	if r.isReflectValueOf(call3, pkgs) {
		t.Error("expected false for fmt.ValueOf")
	}
}

func TestIsReflectTypeOf(t *testing.T) {
	r := &Result{}
	pkgs := map[string]string{"reflect": "reflect"}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "reflect"},
			Sel: &ast.Ident{Name: "TypeOf"},
		},
	}
	if !r.isReflectTypeOf(call, pkgs) {
		t.Error("expected true for reflect.TypeOf")
	}
}

func TestIsIndirect(t *testing.T) {
	r := &Result{}
	pkgs := map[string]string{"reflect": "reflect"}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "reflect"},
			Sel: &ast.Ident{Name: "Indirect"},
		},
	}
	if !r.isIndirect(call, pkgs) {
		t.Error("expected true for reflect.Indirect")
	}
}

func TestIsNewAt(t *testing.T) {
	r := &Result{}
	pkgs := map[string]string{"reflect": "reflect"}

	call := &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "reflect"},
			Sel: &ast.Ident{Name: "NewAt"},
		},
	}
	if !r.isNewAt(call, pkgs) {
		t.Error("expected true for reflect.NewAt")
	}
}

// --- getCurrentVersion tests ---

func TestGetCurrentVersion_NonStdlib(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["go list -f {{if .Module}}{{.Module.Version}}{{end}} golang.org/x/net"] = []byte("v0.23.0\n")

	r := &Result{Runner: fr}
	got := getCurrentVersion("golang.org/x/net", "/some/dir", r)
	if got != "v0.23.0" {
		t.Errorf("getCurrentVersion = %q, want %q", got, "v0.23.0")
	}
	if len(r.Errors) > 0 {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}

func TestGetCurrentVersion_Stdlib(t *testing.T) {
	fr := newFakeRunner()
	goModJSON := `{"Module":{"Path":"example.com/foo"},"Go":"1.21.4"}`
	fr.stdout["go mod edit -json"] = []byte(goModJSON)

	r := &Result{
		Runner: fr,
		AffectedImports: map[string]AffectedImportsDetails{
			"net/http": {Type: "stdlib"},
		},
	}
	got := getCurrentVersion("net/http", "/some/dir", r)
	if got != "v1.21.4" {
		t.Errorf("getCurrentVersion = %q, want %q", got, "v1.21.4")
	}
}

func TestGetCurrentVersion_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.err["go list -f {{if .Module}}{{.Module.Version}}{{end}} golang.org/x/net"] = fmt.Errorf("exit 1")
	fr.stdout["go list -f {{if .Module}}{{.Module.Version}}{{end}} golang.org/x/net"] = []byte("some error")

	r := &Result{Runner: fr}
	got := getCurrentVersion("golang.org/x/net", "/some/dir", r)
	if got != "" {
		t.Errorf("getCurrentVersion = %q, want empty", got)
	}
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

// --- getGoToolchainVersion tests ---

func TestGetGoToolchainVersion(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    string
		wantErr bool
	}{
		{
			name: "normal",
			json: `{"Module":{"Path":"example.com/foo"},"Go":"1.21.4"}`,
			want: "v1.21.4",
		},
		{
			name: "with v prefix",
			json: `{"Module":{"Path":"example.com/foo"},"Go":"v1.22.0"}`,
			want: "v1.22.0",
		},
		{
			name: "empty go version",
			json: `{"Module":{"Path":"example.com/foo"},"Go":""}`,
			want: "",
		},
		{
			name:    "invalid json",
			json:    `not json`,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fr := newFakeRunner()
			fr.stdout["go mod edit -json"] = []byte(tt.json)

			r := &Result{Runner: fr}
			got := getGoToolchainVersion("/some/dir", r)
			if got != tt.want {
				t.Errorf("getGoToolchainVersion = %q, want %q", got, tt.want)
			}
			if tt.wantErr && len(r.Errors) == 0 {
				t.Error("expected errors")
			}
		})
	}
}

func TestGetGoToolchainVersion_CmdError(t *testing.T) {
	fr := newFakeRunner()
	fr.err["go mod edit -json"] = fmt.Errorf("exit 1")

	r := &Result{Runner: fr}
	got := getGoToolchainVersion("/some/dir", r)
	if got != "" {
		t.Errorf("getGoToolchainVersion = %q, want empty", got)
	}
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

// --- getReplaceVersion tests ---

func TestGetReplaceVersion(t *testing.T) {
	goMod := GoModEdit{
		Replace: []Replace{
			{
				Old: PathVersion{Path: "golang.org/x/net", Version: "v0.23.0"},
				New: PathVersion{Path: "golang.org/x/net", Version: "v0.33.0"},
			},
		},
	}
	goModJSON, _ := json.Marshal(goMod)

	fr := newFakeRunner()
	fr.stdout["go mod edit -json"] = goModJSON

	r := &Result{Runner: fr}
	path, ver := getReplaceVersion("golang.org/x/net", "/some/dir", r)
	if path != "golang.org/x/net" || ver != "v0.33.0" {
		t.Errorf("getReplaceVersion = (%q, %q), want (%q, %q)", path, ver, "golang.org/x/net", "v0.33.0")
	}
}

func TestGetReplaceVersion_NoMatch(t *testing.T) {
	goMod := GoModEdit{
		Replace: []Replace{
			{
				Old: PathVersion{Path: "other/pkg"},
				New: PathVersion{Path: "other/pkg", Version: "v1.0.0"},
			},
		},
	}
	goModJSON, _ := json.Marshal(goMod)

	fr := newFakeRunner()
	fr.stdout["go mod edit -json"] = goModJSON

	r := &Result{Runner: fr}
	path, ver := getReplaceVersion("golang.org/x/net", "/some/dir", r)
	if path != "" || ver != "" {
		t.Errorf("getReplaceVersion = (%q, %q), want empty", path, ver)
	}
}

func TestGetReplaceVersion_CmdError(t *testing.T) {
	fr := newFakeRunner()
	fr.err["go mod edit -json"] = fmt.Errorf("exit 1")

	r := &Result{Runner: fr}
	path, ver := getReplaceVersion("golang.org/x/net", "/some/dir", r)
	if path != "" || ver != "" {
		t.Errorf("getReplaceVersion = (%q, %q), want empty", path, ver)
	}
}

// --- getModPath tests ---

func TestGetModPath(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["go list -f {{if .Module}}{{.Module.Path}}{{end}} golang.org/x/net/html"] = []byte("golang.org/x/net\n")

	r := &Result{Runner: fr}
	got := getModPath("golang.org/x/net/html", "/some/dir", r)
	if got != "golang.org/x/net" {
		t.Errorf("getModPath = %q, want %q", got, "golang.org/x/net")
	}
}

func TestGetModPath_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.err["go list -f {{if .Module}}{{.Module.Path}}{{end}} golang.org/x/net"] = fmt.Errorf("exit 1")

	r := &Result{Runner: fr}
	got := getModPath("golang.org/x/net", "/some/dir", r)
	if got != "" {
		t.Errorf("getModPath = %q, want empty", got)
	}
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

// --- getRepoModulePath tests ---

func TestGetRepoModulePath(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["go mod edit -json"] = []byte(`{"Module":{"Path":"github.com/foo/bar"}}`)

	r := &Result{Runner: fr}
	got := getRepoModulePath("/some/dir", r)
	if got != "github.com/foo/bar" {
		t.Errorf("getRepoModulePath = %q, want %q", got, "github.com/foo/bar")
	}
}

func TestGetRepoModulePath_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.err["go mod edit -json"] = fmt.Errorf("exit 1")

	r := &Result{Runner: fr}
	got := getRepoModulePath("/some/dir", r)
	if got != "" {
		t.Errorf("getRepoModulePath = %q, want empty", got)
	}
}

// --- getGitBranch tests ---

func TestGetGitBranch(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git rev-parse --abbrev-ref HEAD"] = []byte("main\n")

	r := &Result{Runner: fr, Directory: "/repo"}
	getGitBranch(r)
	if r.Branch != "main" {
		t.Errorf("Branch = %q, want %q", r.Branch, "main")
	}
}

func TestGetGitBranch_DetachedHEAD(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git rev-parse --abbrev-ref HEAD"] = []byte("HEAD\n")
	fr.stdout["git rev-parse HEAD"] = []byte("abc123def456\n")

	r := &Result{Runner: fr, Directory: "/repo"}
	getGitBranch(r)
	if r.Branch != "abc123def456" {
		t.Errorf("Branch = %q, want %q", r.Branch, "abc123def456")
	}
}

func TestGetGitBranch_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.err["git rev-parse --abbrev-ref HEAD"] = fmt.Errorf("exit 1")

	r := &Result{Runner: fr, Directory: "/repo"}
	getGitBranch(r)
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

func TestGetGitBranch_DetachedHEAD_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git rev-parse --abbrev-ref HEAD"] = []byte("HEAD\n")
	fr.err["git rev-parse HEAD"] = fmt.Errorf("exit 1")

	r := &Result{Runner: fr, Directory: "/repo"}
	getGitBranch(r)
	if r.Branch != "HEAD" {
		t.Errorf("Branch = %q, want %q", r.Branch, "HEAD")
	}
}

// --- getGitURL tests ---

func TestGetGitURL(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git remote get-url origin"] = []byte("https://github.com/foo/bar.git\n")

	r := &Result{Runner: fr, Directory: "/repo"}
	getGitURL(r)
	if r.Repository != "https://github.com/foo/bar.git" {
		t.Errorf("Repository = %q, want %q", r.Repository, "https://github.com/foo/bar.git")
	}
}

func TestGetGitURL_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.err["git remote get-url origin"] = fmt.Errorf("exit 1")

	r := &Result{Runner: fr, Directory: "/repo"}
	getGitURL(r)
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

// --- findMainGoFiles tests ---

func TestFindMainGoFiles(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0644)

	os.MkdirAll(filepath.Join(tmpDir, "cmd", "app"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "cmd", "app", "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	fr := newFakeRunner()
	fr.combined[`go list -f {{if eq .Name "main"}}{{.Name}}: {{.Dir}}{{end}} ./...`] = []byte(
		fmt.Sprintf("main: %s\n", filepath.Join(tmpDir, "cmd", "app")),
	)

	r := &Result{Runner: fr, Directory: tmpDir}
	findMainGoFiles(r)

	if r.Files == nil {
		t.Fatal("Files is nil")
	}
	if len(r.Errors) > 0 {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}

func TestFindMainGoFiles_NoGoMod(t *testing.T) {
	tmpDir := t.TempDir()

	r := &Result{Directory: tmpDir}
	findMainGoFiles(r)

	if len(r.Files) != 0 {
		t.Errorf("expected empty Files for dir without go.mod, got %d entries", len(r.Files))
	}
}

// --- HTTP function tests ---

func TestFetchGoVulnID(t *testing.T) {
	vulns := []VulnReport{
		{ID: "GO-2024-3333", Aliases: []string{"CVE-2024-45338"}},
		{ID: "GO-2024-1111", Aliases: []string{"CVE-2024-11111"}},
	}
	body, _ := json.Marshal(vulns)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		CVE:  "CVE-2024-45338",
		HTTP: ts.Client(),
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchGoVulnID(r)
	if r.GoCVE != "GO-2024-3333" {
		t.Errorf("GoCVE = %q, want %q", r.GoCVE, "GO-2024-3333")
	}
}

func TestFetchGoVulnID_NoMatch(t *testing.T) {
	vulns := []VulnReport{
		{ID: "GO-2024-1111", Aliases: []string{"CVE-2024-11111"}},
	}
	body, _ := json.Marshal(vulns)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		CVE:  "CVE-2024-99999",
		HTTP: ts.Client(),
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchGoVulnID(r)
	if r.GoCVE != "" {
		t.Errorf("GoCVE = %q, want empty", r.GoCVE)
	}
}

func TestFetchAffectedSymbols(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "golang.org/x/net", Ecosystem: "Go"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "0.33.0"}}},
				},
				EcosystemSpecific: EcosystemSpecific{
					Imports: []Import{
						{Path: "golang.org/x/net/html", Symbols: []string{"Parse", "ParseFragment"}},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		GoCVE: "GO-2024-3333",
		HTTP:  ts.Client(),
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchAffectedSymbols(r)
	if r.AffectedImports == nil {
		t.Fatal("AffectedImports is nil")
	}
	entry, ok := r.AffectedImports["golang.org/x/net/html"]
	if !ok {
		t.Fatal("expected golang.org/x/net/html in AffectedImports")
	}
	if len(entry.Symbols) != 2 {
		t.Errorf("expected 2 symbols, got %d", len(entry.Symbols))
	}
}

func TestFetchAffectedSymbols_EmptyAffected(t *testing.T) {
	report := VulnReport{ID: "GO-2024-3333"}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		GoCVE: "GO-2024-3333",
		HTTP:  ts.Client(),
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchAffectedSymbols(r)
	if len(r.Errors) == 0 {
		t.Error("expected error for empty affected list")
	}
}

func TestFetchAffectedSymbols_NoSymbols(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package:           Package{Name: "golang.org/x/net"},
				EcosystemSpecific: EcosystemSpecific{Imports: []Import{{Path: "golang.org/x/net/html"}}},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		GoCVE: "GO-2024-3333",
		HTTP:  ts.Client(),
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchAffectedSymbols(r)
	if len(r.Errors) == 0 {
		t.Error("expected error when no symbols found")
	}
}

func TestGetFixedVersion(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "golang.org/x/net"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "0.33.0"}}},
				},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{HTTP: ts.Client()}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	got := getFixedVersion("GO-2024-3333", "golang.org/x/net", r)
	if len(got) != 1 {
		t.Fatalf("expected 1 version, got %d", len(got))
	}
	if got[0] != "Introduced in 0 and fixed in 0.33.0" {
		t.Errorf("got %q", got[0])
	}
}

func TestGetFixedVersion_Stdlib(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "stdlib"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "1.21.8"}, {Introduced: "1.22.0"}, {Fixed: "1.22.2"}}},
				},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{HTTP: ts.Client()}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	got := getFixedVersion("GO-2024-3333", "net/http", r)
	if len(got) != 2 {
		t.Fatalf("expected 2 versions, got %d: %v", len(got), got)
	}
}

func TestGetFixedVersion_NoMatch(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "other/pkg"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "1.0.0"}}}},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{HTTP: ts.Client()}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	got := getFixedVersion("GO-2024-3333", "golang.org/x/net", r)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}
