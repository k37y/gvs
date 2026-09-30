package cg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestLoadSkillPrompt(t *testing.T) {
	t.Run("from GVS_SKILLS_DIR", func(t *testing.T) {
		tmpDir := t.TempDir()
		skillContent := "# Test Skill\n{{.scan_result_json}}"
		if err := os.WriteFile(filepath.Join(tmpDir, "verify-scan.md"), []byte(skillContent), 0644); err != nil {
			t.Fatal(err)
		}

		t.Setenv("GVS_SKILLS_DIR", tmpDir)

		content, found := loadSkillPrompt(&Result{})
		if !found {
			t.Fatal("expected skill prompt to be found")
		}
		if content != skillContent {
			t.Errorf("content = %q, want %q", content, skillContent)
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Setenv("GVS_SKILLS_DIR", "/nonexistent/path")
		t.Setenv("HOME", t.TempDir())
		_, found := loadSkillPrompt(&Result{})
		if found {
			t.Error("expected skill prompt to not be found from nonexistent path")
		}
	})
}

func TestCleanJSONResponse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain JSON",
			input: `{"IsVulnerable": true}`,
			want:  `{"IsVulnerable": true}`,
		},
		{
			name:  "JSON in markdown code fence",
			input: "```json\n{\"IsVulnerable\": true}\n```",
			want:  `{"IsVulnerable": true}`,
		},
		{
			name:  "JSON in plain code fence",
			input: "```\n{\"IsVulnerable\": false}\n```",
			want:  `{"IsVulnerable": false}`,
		},
		{
			name:  "JSON with leading whitespace",
			input: "  \n{\"IsVulnerable\": true}  \n",
			want:  `{"IsVulnerable": true}`,
		},
		{
			name:  "JSON embedded in prose",
			input: "The analysis shows the following:\n\n{\"IsVulnerable\": true}\n\nThat concludes my review.",
			want:  `{"IsVulnerable": true}`,
		},
		{
			name:  "JSON in markdown fence mid-text",
			input: "Here is my assessment:\n\n```json\n{\"IsVulnerable\": false}\n```\n\nDone.",
			want:  `{"IsVulnerable": false}`,
		},
		{
			name:  "nested braces in prose",
			input: "The result is: {\"a\": {\"b\": \"c\"}} end",
			want:  `{"a": {"b": "c"}}`,
		},
		{
			name:  "JSON with escaped quotes",
			input: "Text before {\"reasoning\": \"the \\\"fix\\\" is applied\"} text after",
			want:  `{"reasoning": "the \"fix\" is applied"}`,
		},
		{
			name:  "small JSON fragment before real answer",
			input: "I found sshConfig{} struct and evidence.\n\n{\"IsVulnerable\": true, \"confidence\": \"high\"}",
			want:  `{"IsVulnerable": true, "confidence": "high"}`,
		},
		{
			name:  "multiple JSON objects picks last",
			input: "{\"wrong\": true}\nSome analysis text\n{\"IsVulnerable\": false, \"confidence\": \"medium\"}",
			want:  `{"IsVulnerable": false, "confidence": "medium"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanJSONResponse(tt.input)
			if got != tt.want {
				t.Errorf("cleanJSONResponse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildVerificationPrompt(t *testing.T) {
	result := &Result{
		ScanConfig:   ScanConfig{CVE: "CVE-2024-45338"},
		IsVulnerable: "false",
		GoCVE:        "GO-2024-3333",
		Repository:   "https://github.com/example/repo",
		Branch:       "main",
		AffectedImports: map[string]AffectedImportsDetails{
			"golang.org/x/net/html": {
				Symbols:      []string{"Parse"},
				FixedVersion: []string{"v0.25.0"},
			},
		},
	}

	skillTemplate := `Scanner result: {{.is_vulnerable}}
Algorithm: {{.algorithm}}
Data: {{.scan_result_json}}
Source: {{.source_snippets}}`

	snippets := map[string]string{
		"main.go": "package main\nfunc main() {}",
	}

	os.Setenv("ALGO", "vta")
	defer os.Unsetenv("ALGO")

	prompt, err := buildVerificationPrompt(result, skillTemplate, snippets)
	if err != nil {
		t.Fatal(err)
	}

	if prompt == "" {
		t.Error("expected non-empty prompt")
	}

	// Check placeholders were replaced
	if contains(prompt, "{{.is_vulnerable}}") {
		t.Error("{{.is_vulnerable}} placeholder was not replaced")
	}
	if contains(prompt, "{{.algorithm}}") {
		t.Error("{{.algorithm}} placeholder was not replaced")
	}
	if contains(prompt, "{{.scan_result_json}}") {
		t.Error("{{.scan_result_json}} placeholder was not replaced")
	}
	if !contains(prompt, "Scanner result: withheld") {
		t.Error("expected scanner verdict to be withheld")
	}
	if !contains(prompt, "vta") {
		t.Error("expected 'vta' in prompt for algorithm")
	}
	if !contains(prompt, "GO-2024-3333") {
		t.Error("expected GoCVE in prompt")
	}
	if !contains(prompt, "main.go") {
		t.Error("expected source snippet filename in prompt")
	}
}

func TestCollectRelevantSource(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0644)

	os.MkdirAll(filepath.Join(tmpDir, "cmd"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "cmd", "main.go"), []byte(`package main

import "golang.org/x/net/html"

func main() {
	html.Parse(nil)
}
`), 0644)

	result := &Result{
		ScanConfig: ScanConfig{Directory: tmpDir},
		AffectedImports: map[string]AffectedImportsDetails{
			"golang.org/x/net/html": {
				Symbols: []string{"Parse"},
			},
		},
		Files: map[string][][]string{
			".": {{"cmd/main.go"}},
		},
	}

	snippets := collectRelevantSource(result, tmpDir)

	if _, ok := snippets["go.mod"]; !ok {
		t.Error("expected go.mod in snippets")
	}
	if _, ok := snippets["cmd/main.go"]; !ok {
		t.Error("expected cmd/main.go in snippets (imports vulnerable package)")
	}
}

func TestCollectRelevantSourceTwoHop(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0644)

	// pkg/parser wraps the vulnerable package
	os.MkdirAll(filepath.Join(tmpDir, "pkg", "parser"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "pkg", "parser", "wrap.go"), []byte(`package parser

import "golang.org/x/net/html"

func WrapParse() { html.Parse(nil) }
`), 0644)

	// cmd/main.go imports pkg/parser (2nd hop), not the vulnerable package directly
	os.MkdirAll(filepath.Join(tmpDir, "cmd"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "cmd", "main.go"), []byte(`package main

import "example.com/test/pkg/parser"

func main() { parser.WrapParse() }
`), 0644)

	result := &Result{
		ScanConfig: ScanConfig{Directory: tmpDir},
		AffectedImports: map[string]AffectedImportsDetails{
			"golang.org/x/net/html": {
				Symbols: []string{"Parse"},
			},
		},
	}

	snippets := collectRelevantSource(result, tmpDir)

	if _, ok := snippets["pkg/parser/wrap.go"]; !ok {
		t.Error("expected pkg/parser/wrap.go in snippets (direct importer)")
	}
	if _, ok := snippets["cmd/main.go"]; !ok {
		t.Error("expected cmd/main.go in snippets (2-hop importer via pkg/parser)")
	}
}

func TestCollectRelevantSourceBudget(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0644)

	result := &Result{ScanConfig: ScanConfig{Directory: tmpDir}}

	snippets := collectRelevantSource(result, tmpDir)

	total := 0
	for _, content := range snippets {
		total += len(content)
	}
	if total > maxSourceBytes {
		t.Errorf("collected %d bytes, exceeds maxSourceBytes (%d)", total, maxSourceBytes)
	}
}

func TestFormatCallTraces_Empty(t *testing.T) {
	result := &Result{}
	got := FormatCallTraces(result)
	if !strings.Contains(got, "No call graph traces") {
		t.Errorf("expected empty-traces message, got: %s", got)
	}
}

func TestFormatCallTraces_WithPaths(t *testing.T) {
	prog := &ssa.Program{}
	mainFn := &ssa.Function{Prog: prog}
	vulnFn := &ssa.Function{Prog: prog}

	node1 := &callgraph.Node{Func: mainFn, ID: 0}
	node2 := &callgraph.Node{Func: vulnFn, ID: 1}

	result := &Result{
		UsedImports: map[string]map[string]UsedImportsDetails{
			".": {
				"example.com/vuln": {
					Symbols: []string{"BadFunc"},
					Paths:   [][]*callgraph.Node{{node1, node2}},
				},
			},
		},
	}

	got := FormatCallTraces(result)
	if !strings.Contains(got, "Graph audit: 1 scanner candidate path entries") {
		t.Errorf("missing path coverage instruction: %s", got)
	}
	if !strings.Contains(got, "Trace in module . for example.com/vuln.BadFunc") {
		t.Errorf("expected trace header, got: %s", got)
	}
	if !strings.Contains(got, "1.") && !strings.Contains(got, "2.") {
		t.Errorf("expected numbered steps, got: %s", got)
	}
}

func TestGrepCodeTool(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	tool := &grepCodeTool{repoDir: tmpDir}
	if tool.Name() != "grep_code" {
		t.Errorf("Name() = %q", tool.Name())
	}

	input, _ := json.Marshal(map[string]string{"pattern": "func main"})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) == 0 {
		t.Fatal("expected result")
	}
	text := result
	if !strings.Contains(text, "func main") {
		t.Errorf("expected match for 'func main', got: %s", text)
	}
}

func TestGrepCodeTool_NoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644)

	tool := &grepCodeTool{repoDir: tmpDir}
	input, _ := json.Marshal(map[string]string{"pattern": "nonexistent_xyz_123"})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "No matches") {
		t.Errorf("expected 'No matches', got: %s", text)
	}
}

func TestReadFileTool(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "hello.go"), []byte("line1\nline2\nline3\nline4\n"), 0644)

	tool := &readFileTool{repoDir: tmpDir}
	if tool.Name() != "read_file" {
		t.Errorf("Name() = %q", tool.Name())
	}

	input, _ := json.Marshal(map[string]any{"path": "hello.go", "start_line": 2, "end_line": 3})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "2|line2") {
		t.Errorf("expected line2 content, got: %s", text)
	}
	if strings.Contains(text, "1|line1") {
		t.Errorf("should not contain line1 when start_line=2")
	}
}

func TestReadFileTool_PathEscape(t *testing.T) {
	tmpDir := t.TempDir()
	tool := &readFileTool{repoDir: tmpDir}

	input, _ := json.Marshal(map[string]string{"path": "../../../etc/passwd"})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "escapes repository root") {
		t.Errorf("expected path escape error, got: %s", text)
	}
}

func TestListFilesTool(t *testing.T) {
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, "pkg"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "pkg", "lib.go"), []byte("package pkg\n"), 0644)

	tool := &listFilesTool{repoDir: tmpDir}
	if tool.Name() != "list_files" {
		t.Errorf("Name() = %q", tool.Name())
	}

	input, _ := json.Marshal(map[string]string{})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "main.go") {
		t.Errorf("expected main.go in listing, got: %s", text)
	}
	if !strings.Contains(text, filepath.Join("pkg", "lib.go")) {
		t.Errorf("expected pkg/lib.go in listing, got: %s", text)
	}
}

func TestListFilesTool_SkipsVendor(t *testing.T) {
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, "vendor", "foo"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "vendor", "foo", "bar.go"), []byte("package foo\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644)

	tool := &listFilesTool{repoDir: tmpDir}
	input, _ := json.Marshal(map[string]string{})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if strings.Contains(text, "vendor") {
		t.Errorf("should skip vendor dir, got: %s", text)
	}
}

func TestSafePath(t *testing.T) {
	tests := []struct {
		name    string
		rel     string
		wantErr bool
	}{
		{"valid relative", "pkg/main.go", false},
		{"absolute path", "/etc/passwd", true},
		{"parent escape", "../secret", true},
		{"double escape", "foo/../../secret", true},
		{"current dir", ".", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := safePath("/repo", tt.rel)
			if (err != nil) != tt.wantErr {
				t.Errorf("safePath(%q) error = %v, wantErr %v", tt.rel, err, tt.wantErr)
			}
		})
	}
}

func TestSplitTypeName(t *testing.T) {
	tests := []struct {
		input    string
		wantPkg  string
		wantType string
	}{
		{"io.Writer", "io", "Writer"},
		{"golang.org/x/net/idna.Transformer", "golang.org/x/net/idna", "Transformer"},
		{"net/http.Handler", "net/http", "Handler"},
		{"Writer", "", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pkg, typ := splitTypeName(tt.input)
			if pkg != tt.wantPkg {
				t.Errorf("pkg = %q, want %q", pkg, tt.wantPkg)
			}
			if typ != tt.wantType {
				t.Errorf("type = %q, want %q", typ, tt.wantType)
			}
		})
	}
}

func TestFindImplementationsTool_NilProg(t *testing.T) {
	tool := &findImplementationsTool{prog: nil}
	if tool.Name() != "find_implementations" {
		t.Errorf("Name() = %q", tool.Name())
	}
	input, _ := json.Marshal(map[string]string{"interface_type": "io.Writer"})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "SSA program not available") {
		t.Errorf("expected SSA program error, got: %s", text)
	}
}

func TestFindImplementationsTool_BadInput(t *testing.T) {
	tool := &findImplementationsTool{prog: &ssa.Program{}}
	input, _ := json.Marshal(map[string]string{"interface_type": "NoPackage"})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "cannot parse") {
		t.Errorf("expected parse error, got: %s", text)
	}
}

func TestFindCallersTool_NilGraph(t *testing.T) {
	tool := &findCallersTool{graph: nil}
	if tool.Name() != "find_callers" {
		t.Errorf("Name() = %q", tool.Name())
	}
	input, _ := json.Marshal(map[string]string{"symbol": "foo.Bar"})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "call graph not available") {
		t.Errorf("expected graph error, got: %s", text)
	}
}

func TestFindCallersTool_NoMatch(t *testing.T) {
	graph := &callgraph.Graph{Nodes: make(map[*ssa.Function]*callgraph.Node)}
	tool := &findCallersTool{graph: graph}
	input, _ := json.Marshal(map[string]string{"symbol": "nonexistent.Symbol"})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "No nodes matching") {
		t.Errorf("expected no-match message, got: %s", text)
	}
}

func TestFindCallersTool_DefaultMaxDepth(t *testing.T) {
	graph := &callgraph.Graph{Nodes: make(map[*ssa.Function]*callgraph.Node)}
	tool := &findCallersTool{graph: graph}

	// max_depth=0 should default to 5
	input, _ := json.Marshal(map[string]any{"symbol": "foo.Bar", "max_depth": 0})
	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "No nodes matching") {
		t.Errorf("expected no-match message, got: %s", text)
	}

	// max_depth > 10 should be capped
	input, _ = json.Marshal(map[string]any{"symbol": "foo.Bar", "max_depth": 99})
	result, err = tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text = result
	if !strings.Contains(text, "No nodes matching") {
		t.Errorf("expected no-match message, got: %s", text)
	}
}

func TestIsEntryPointLike(t *testing.T) {
	prog := &ssa.Program{}
	fn := &ssa.Function{Prog: prog}
	node := &callgraph.Node{Func: fn}
	// nil Pkg should return false
	if isEntryPointLike(node, "") {
		t.Error("expected false for nil Pkg")
	}
}

func TestIsTestOnlyTool_TestFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "foo_test.go"), []byte("package foo\n"), 0644)

	tool := &isTestOnlyTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"file":"foo_test.go"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "YES") {
		t.Errorf("expected YES for test file, got: %s", text)
	}
}

func TestIsTestOnlyTool_ProductionFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "foo.go"), []byte("package foo\n"), 0644)

	tool := &isTestOnlyTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"file":"foo.go"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "NO") {
		t.Errorf("expected NO for production file, got: %s", text)
	}
}

func TestIsTestOnlyTool_ExternalTestPackage(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "foo.go"), []byte("package foo_test\n"), 0644)

	tool := &isTestOnlyTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"file":"foo.go"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "YES") {
		t.Errorf("expected YES for external test package, got: %s", text)
	}
}

func TestCheckBuildTagsTool_NoTags(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	tool := &checkBuildTagsTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"file":"main.go"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "none") {
		t.Errorf("expected 'none', got: %s", text)
	}
}

func TestCheckBuildTagsTool_WithTags(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "linux.go"), []byte("//go:build linux\n\npackage main\n"), 0644)

	tool := &checkBuildTagsTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"file":"linux.go"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "//go:build linux") {
		t.Errorf("expected build tag, got: %s", text)
	}
}

func TestCheckBuildTagsTool_PathEscape(t *testing.T) {
	dir := t.TempDir()
	tool := &checkBuildTagsTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"file":"../../etc/passwd"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "escapes") {
		t.Errorf("expected path escape error, got: %s", text)
	}
}

func TestCheckBuildTagsTool_LegacyBuildTag(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "old.go"), []byte("// +build darwin\n\npackage main\n"), 0644)

	tool := &checkBuildTagsTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"file":"old.go"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := result
	if !strings.Contains(text, "+build darwin") {
		t.Errorf("expected legacy build tag, got: %s", text)
	}
}

func TestListEntryPointsTool(t *testing.T) {
	dir := t.TempDir()

	// Create a Go file with main and init
	os.MkdirAll(filepath.Join(dir, "cmd", "app"), 0755)
	os.WriteFile(filepath.Join(dir, "cmd", "app", "main.go"), []byte(`package main

func init() {}
func main() {}
`), 0644)

	// Create a non-main package with init
	os.MkdirAll(filepath.Join(dir, "pkg", "lib"), 0755)
	os.WriteFile(filepath.Join(dir, "pkg", "lib", "lib.go"), []byte(`package lib

func init() {}
func Helper() {}
`), 0644)

	// Create go.mod so go list works
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.21\n"), 0644)

	tool := &listEntryPointsTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	text := result
	if !strings.Contains(text, "init()") {
		t.Errorf("expected init() entry point, got: %s", text)
	}
}

func TestCheckModuleTool(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module example.com/test

go 1.21

require golang.org/x/net v0.20.0
`), 0644)

	tool := &checkModuleTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"package":"golang.org/x/net/html","symbols":["Parse"]}`))
	if err != nil {
		t.Fatal(err)
	}

	text := result
	if !strings.Contains(text, "Module Resolution") {
		t.Errorf("expected Module Resolution header, got: %s", text)
	}
}

func TestCheckModuleTool_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	tool := &checkModuleTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`not json`))
	if err != nil {
		t.Fatal(err)
	}

	text := result
	if !strings.Contains(text, "error") {
		t.Errorf("expected error message, got: %s", text)
	}
}

func TestCheckGoVersionTool(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.21\n"), 0644)

	r := &Result{
		AffectedImports: map[string]AffectedImportsDetails{
			"net/http": {
				Type:         "stdlib",
				FixedVersion: []string{"v1.21.9", "v1.22.2"},
			},
		},
	}

	tool := &checkGoVersionTool{repoDir: dir, result: r}
	result, err := tool.Execute(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	text := result
	if !strings.Contains(text, "Go version") {
		t.Errorf("expected Go version info, got: %s", text)
	}
	if !strings.Contains(text, "net/http") {
		t.Errorf("expected net/http in output, got: %s", text)
	}
}

func TestCheckGoVersionTool_NoStdlib(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.21\n"), 0644)

	r := &Result{
		AffectedImports: map[string]AffectedImportsDetails{
			"golang.org/x/net/html": {
				Type: "module",
			},
		},
	}

	tool := &checkGoVersionTool{repoDir: dir, result: r}
	result, err := tool.Execute(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	text := result
	if !strings.Contains(text, "No stdlib") {
		t.Errorf("expected no stdlib message, got: %s", text)
	}
}

func TestCheckTransitiveDepsTool(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module example.com/test

go 1.21

require golang.org/x/net v0.20.0
`), 0644)

	tool := &checkTransitiveDepsTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`{"package":"golang.org/x/net/html"}`))
	if err != nil {
		t.Fatal(err)
	}

	text := result
	if !strings.Contains(text, "Dependency Status") {
		t.Errorf("expected Dependency Status header, got: %s", text)
	}
}

func TestCheckTransitiveDepsTool_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	tool := &checkTransitiveDepsTool{repoDir: dir}
	result, err := tool.Execute(context.Background(), []byte(`not json`))
	if err != nil {
		t.Fatal(err)
	}

	text := result
	if !strings.Contains(text, "error") {
		t.Errorf("expected error, got: %s", text)
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

const testAssessment = `{"IsVulnerable":"false","confidence":"high","reasoning":"Only tests call the symbol.","evidence":["main_test.go:3: call is test-only"],"graph_analysis":{"summary":"No production path found in the reviewed scope.","findings":[]},"dynamic_analysis":{"summary":"No dynamic candidates in the reviewed scope.","findings":[]},"uncertainties":[]}`

func clearAIEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"GVS_AI", "GVS_AI_PROVIDER", "GVS_AI_MODEL", "GVS_AI_API_KEY", "GVS_AI_BASE_URL", "GVS_AI_PROJECT_ID", "GVS_AI_LOCATION", "GVS_AI_MAX_ITERATIONS", "GVS_AI_MAX_TOKENS", "GVS_AI_CONTEXT_TOKENS", "GVS_AI_TIMEOUT", "GVS_AI_PRICING"} {
		t.Setenv(name, "")
	}
}

func TestLoadAIConfig(t *testing.T) {
	for _, tt := range []struct {
		name      string
		env       map[string]string
		wantError string
	}{
		{"vertex defaults", nil, ""},
		{"pricing", map[string]string{"GVS_AI_PRICING": `{"input":3,"output":15,"cache_read":0.3,"cache_write":3.75}`}, ""},
		{"negative pricing", map[string]string{"GVS_AI_PRICING": `{"input":-1}`}, "GVS_AI_PRICING"},
		{"unknown pricing", map[string]string{"GVS_AI_PRICING": `{"typo":3}`}, "GVS_AI_PRICING"},
		{"invalid pricing", map[string]string{"GVS_AI_PRICING": `{"input":"3"}`}, "GVS_AI_PRICING"},
		{"trailing pricing", map[string]string{"GVS_AI_PRICING": `{} {}`}, "GVS_AI_PRICING"},
		{"compatible defaults", map[string]string{"GVS_AI_PROVIDER": "openai-compatible", "GVS_AI_API_KEY": "test"}, ""},
		{"custom endpoint without key", map[string]string{"GVS_AI_PROVIDER": "openai-compatible", "GVS_AI_BASE_URL": "http://localhost:1234/v1/"}, ""},
		{"missing key", map[string]string{"GVS_AI_PROVIDER": "openai-compatible"}, "GVS_AI_API_KEY"},
		{"missing model", map[string]string{"GVS_AI_MODEL": ""}, "GVS_AI_MODEL"},
		{"missing project", map[string]string{"GVS_AI_PROJECT_ID": ""}, "GVS_AI_PROJECT_ID"},
		{"missing provider", map[string]string{"GVS_AI_PROVIDER": ""}, "GVS_AI_PROVIDER"},
		{"unknown provider", map[string]string{"GVS_AI_PROVIDER": "typo"}, "GVS_AI_PROVIDER"},
		{"bad iterations", map[string]string{"GVS_AI_MAX_ITERATIONS": "no"}, "GVS_AI_MAX_ITERATIONS"},
		{"zero iterations", map[string]string{"GVS_AI_MAX_ITERATIONS": "0"}, "GVS_AI_MAX_ITERATIONS"},
		{"negative tokens", map[string]string{"GVS_AI_MAX_TOKENS": "-1"}, "GVS_AI_MAX_TOKENS"},
		{"bad timeout", map[string]string{"GVS_AI_TIMEOUT": "-5m"}, "GVS_AI_TIMEOUT"},
		{"bad endpoint", map[string]string{"GVS_AI_PROVIDER": "openai-compatible", "GVS_AI_BASE_URL": "file:///tmp/model"}, "GVS_AI_BASE_URL"},
		{"credentials in endpoint", map[string]string{"GVS_AI_PROVIDER": "openai-compatible", "GVS_AI_BASE_URL": "https://secret@example.com/v1"}, "GVS_AI_BASE_URL"},
		{"overrides", map[string]string{"GVS_AI_MAX_ITERATIONS": "3", "GVS_AI_MAX_TOKENS": "4096", "GVS_AI_TIMEOUT": "2m", "GVS_AI_LOCATION": "us-east1"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearAIEnv(t)
			t.Setenv("GVS_AI", "1")
			t.Setenv("GVS_AI_PROVIDER", "anthropic-vertex")
			t.Setenv("GVS_AI_MODEL", "test-model")
			t.Setenv("GVS_AI_PROJECT_ID", "test-project")
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			cfg, enabled, err := loadAIConfig()
			if !enabled {
				t.Fatal("verification should be enabled")
			}
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v; want %s", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.name == "overrides" {
				if cfg.MaxIterations != 3 || cfg.MaxTokens != 4096 || cfg.Timeout != 2*time.Minute || cfg.Location != "us-east1" {
					t.Fatalf("overrides not applied: %+v", cfg)
				}
			} else if cfg.MaxIterations != 20 || cfg.MaxTokens != 16384 || cfg.Timeout != 10*time.Minute {
				t.Fatalf("unexpected defaults: %+v", cfg)
			}
			if tt.name == "vertex defaults" && cfg.Location != "global" {
				t.Fatalf("location = %s", cfg.Location)
			}
			if tt.name == "compatible defaults" && cfg.BaseURL != "https://api.openai.com/v1" {
				t.Fatalf("URL = %s", cfg.BaseURL)
			}
		})
	}
}

func TestVerifyDisabledAndConfigErrors(t *testing.T) {
	clearAIEnv(t)
	r := &Result{IsVulnerable: "true"}
	VerifyAndSummarize(r, t.TempDir())
	if len(r.Errors) != 0 || r.AIVerification != nil {
		t.Fatalf("disabled verification changed result: %+v", r)
	}
	t.Setenv("GVS_AI", "1")
	VerifyAndSummarize(r, t.TempDir())
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "GVS_AI_MODEL") {
		t.Fatalf("configuration error missing: %v", r.Errors)
	}
}

func TestStripJSONComments(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"line", "[1 // note\n]", "[1        \n]"},
		{"block", "[1/* note */]", "[1          ]"},
		{"quoted", `{"url":"https://example.com/a","source":"/* evidence */ // call","quote":"\"//"}`, `{"url":"https://example.com/a","source":"/* evidence */ // call","quote":"\"//"}`},
		{"unterminated", `[1 /* note]`, `[1 /* note]`},
		{"bare slash", `[1 / 2]`, `[1 / 2]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripJSONComments(tt.input); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseAssessment(t *testing.T) {
	for _, tt := range []struct {
		name, response string
		valid          bool
	}{
		{"valid", testAssessment, true},
		{"boolean", strings.Replace(testAssessment, `"false"`, `false`, 1), true},
		{"unknown", strings.Replace(strings.Replace(testAssessment, `"false"`, `"unknown"`, 1), `"uncertainties":[]`, `"uncertainties":["Runtime configuration unavailable"]`, 1), true},
		{"fenced", "```json\n" + testAssessment + "\n```", true},
		{"line comment after array element", strings.Replace(testAssessment, `"main_test.go:3: call is test-only"]`, "\"main_test.go:3: call is test-only\" // evidence\n]", 1), true},
		{"block comment", strings.Replace(testAssessment, `"uncertainties":[]`, `"uncertainties":[] /* no gaps */`, 1), true},
		{"comment cannot join tokens", strings.Replace(testAssessment, `"false"`, `fa/* comment */lse`, 1), false},
		{"trailing comma", strings.Replace(testAssessment, `"uncertainties":[]`, `"uncertainties":[],`, 1), false},
		{"empty", "", false},
		{"empty object", "{}", false},
		{"null", "null", false},
		{"bad verdict", strings.Replace(testAssessment, `"false"`, `"maybe"`, 1), false},
		{"bad confidence", strings.Replace(testAssessment, `"high"`, `"certain"`, 1), false},
		{"no reasoning", strings.Replace(testAssessment, "Only tests call the symbol.", "", 1), false},
		{"empty evidence", strings.Replace(testAssessment, `"main_test.go:3: call is test-only"`, `" "`, 1), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAssessment(tt.response)
			if (err == nil) != tt.valid {
				t.Fatalf("error = %v; valid = %v", err, tt.valid)
			}
		})
	}
}

func TestEscapeJSONControlCharacters(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"quoted newline", "{\"text\":\"one\ntwo\"}", `{"text":"one\u000atwo"}`},
		{"outside whitespace", "{\n\t\"text\": \"plain\"\r\n}", "{\n\t\"text\": \"plain\"\r\n}"},
		{"valid escapes and URL", `{"text":"\"quoted\"\nhttps://example.com\tpath\\"}`, `{"text":"\"quoted\"\nhttps://example.com\tpath\\"}`},
		{"escaped backslash then newline", "[\"path\\\\\nnext\"]", `["path\\\u000anext"]`},
		{"NUL and backspace", "[\"a\x00\bb\"]", `["a\u0000\u0008b"]`},
		{"invalid escape unchanged", `["\q"]`, `["\q"]`},
		{"invalid continuation unchanged", "[\"a\\\nb\"]", "[\"a\\\nb\"]"},
		{"unterminated string", `{"text":"missing close}`, `{"text":"missing close}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeJSONControlCharacters(tt.input); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseAssessmentLiteralWhitespace(t *testing.T) {
	for _, tt := range []struct{ name, reasoning string }{
		{"newline", "Only tests call the symbol.\nProduction has no call."},
		{"CRLF", "Only tests call the symbol.\r\nProduction has no call."},
		{"tab", "Only tests call the symbol.\tProduction has no call."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(testAssessment, "Only tests call the symbol.", tt.reasoning, 1)
			assessment, err := parseAssessment(raw)
			if err != nil {
				t.Fatal(err)
			}
			if assessment.Reasoning != tt.reasoning {
				t.Fatalf("changed reasoning: %q", assessment.Reasoning)
			}
			if assessment.IsVulnerable != "false" || assessment.Confidence != "high" {
				t.Fatalf("changed verdict: %+v", assessment)
			}
		})
	}
	for _, raw := range []string{
		strings.Replace(testAssessment, `"false"`, "\"fal\nse\"", 1),
		strings.Replace(testAssessment, "Only tests call the symbol.", "Only tests call the symbol.\\\nUnclear continuation", 1),
		strings.Replace(testAssessment, "Only tests call the symbol.", `Invalid \q escape`, 1),
	} {
		if _, err := parseAssessment(raw); err == nil {
			t.Fatalf("accepted invalid assessment: %q", raw)
		}
	}
}

type fakeAgent func(context.Context, string, []verificationTool) (string, error)

func (f fakeAgent) Run(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
	return f(ctx, prompt, tools)
}

func TestVerifyWithAgent(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("Assess {{.is_vulnerable}}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	for _, tt := range []struct {
		name, output string
		err          error
	}{
		{"success", testAssessment, nil},
		{"invalid response", "{}", nil},
		{"API error", "", errors.New("endpoint unavailable")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{IsVulnerable: "true"}
			agent := fakeAgent(func(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
				if !strings.Contains(prompt, "Assess withheld") || len(tools) != 9 {
					t.Fatalf("unexpected prompt/tools: %s / %d", prompt, len(tools))
				}
				return tt.output, tt.err
			})
			verifyWithAgent(context.Background(), r, repo, aiConfig{Provider: "fake", Model: "test"}, agent)
			if r.IsVulnerable != "true" {
				t.Fatal("scanner verdict was overwritten")
			}
			if tt.name != "success" {
				if r.AIVerification != nil || len(r.Errors) != 1 {
					t.Fatalf("failed verification stored a verdict or lost error: %+v", r)
				}
				return
			}
			if r.AIVerification == nil || r.AIVerification.IsVulnerable != "false" || r.AIVerification.Provider != "fake" || r.AIVerification.Model != "test" {
				t.Fatalf("unexpected assessment: %+v", r.AIVerification)
			}
			data, err := json.Marshal(r)
			if err != nil || !strings.Contains(string(data), `"AIVerification"`) || strings.Contains(string(data), "ClaudeVerification") {
				t.Fatalf("unexpected JSON: %s (%v)", data, err)
			}
		})
	}
}

func TestVerificationStatus(t *testing.T) {
	clearAIEnv(t)
	var lines []string
	log := func(s string) { lines = append(lines, s) }
	var cfg aiConfig
	var enabled bool
	var err error
	cfg, enabled, err = loadAIConfig()
	logAIStatus(cfg, enabled, err, log)
	if len(lines) != 1 || !strings.Contains(lines[0], "disabled") {
		t.Fatalf("logs: %v", lines)
	}
	t.Setenv("GVS_AI", "1")
	cfg, enabled, err = loadAIConfig()
	logAIStatus(cfg, enabled, err, log)
	if !strings.Contains(lines[1], "configuration error") {
		t.Fatalf("logs: %v", lines)
	}
	t.Setenv("GVS_AI_PROVIDER", "openai-compatible")
	t.Setenv("GVS_AI_MODEL", "test-model")
	t.Setenv("GVS_AI_API_KEY", "secret-test-token")
	cfg, enabled, err = loadAIConfig()
	logAIStatus(cfg, enabled, err, log)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "provider=openai-compatible, model=test-model") || strings.Contains(joined, "secret-test-token") {
		t.Fatalf("logs: %v", lines)
	}
}

func backendForTest(provider, baseURL string, limit int) verificationAgent {
	cfg := aiConfig{Provider: provider, Model: "test-model", BaseURL: baseURL, APIKey: "test-key", MaxIterations: limit, MaxTokens: 4096, Timeout: time.Second * 5}
	if provider == "anthropic-vertex" {
		return &anthropicAgent{cfg: cfg, client: anthropic.NewClient(option.WithBaseURL(baseURL), option.WithAPIKey("test-key"), option.WithMaxRetries(0))}
	}
	return newAgent(context.Background(), cfg, nil)
}

func replyAssessment(w http.ResponseWriter, provider string) {
	w.Header().Set("Content-Type", "application/json")
	if provider == "anthropic-vertex" {
		json.NewEncoder(w).Encode(map[string]any{"id": "msg_final", "type": "message", "role": "assistant", "model": "test-model", "stop_reason": "end_turn", "content": []any{map[string]string{"type": "text", "text": testAssessment}}})
	} else {
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": testAssessment}}}})
	}
}

func TestBackendsToolConversation(t *testing.T) {
	for _, provider := range []string{"anthropic-vertex", "openai-compatible"} {
		for _, limit := range []int{1, 3} {
			t.Run(provider+"/"+string(rune('0'+limit)), func(t *testing.T) {
				repo := t.TempDir()
				if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n"), 0600); err != nil {
					t.Fatal(err)
				}
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					var request struct {
						Model      string            `json:"model"`
						Messages   []json.RawMessage `json:"messages"`
						Tools      []json.RawMessage `json:"tools"`
						ToolChoice json.RawMessage   `json:"tool_choice"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					if request.Model != "test-model" || len(request.Tools) != 1 {
						t.Errorf("missing model or tool definitions: %+v", request)
					}
					if r.Method != "POST" {
						t.Errorf("method = %s", r.Method)
					}
					if provider == "openai-compatible" && (r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer test-key") {
						t.Errorf("wrong endpoint or auth")
					}
					if calls == 1 {
						if !strings.Contains(string(request.Tools[0]), `"type":"object"`) {
							t.Errorf("tool schema missing object type: %s", request.Tools[0])
						}
						w.Header().Set("Content-Type", "application/json")
						if provider == "anthropic-vertex" {
							json.NewEncoder(w).Encode(map[string]any{"id": "msg_1", "type": "message", "role": "assistant", "model": "test-model", "stop_reason": "tool_use", "content": []any{
								map[string]any{"type": "tool_use", "id": "call_1", "name": "read_file", "input": map[string]string{"path": "main.go"}},
								map[string]any{"type": "tool_use", "id": "call_2", "name": "missing_tool", "input": map[string]string{}},
							}})
						} else {
							json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{
								"role": "assistant", "content": nil, "reasoning_content": "Preserve this state", "tool_calls": []any{
									map[string]any{"id": "call_1", "type": "function", "function": map[string]string{"name": "read_file", "arguments": `{"path":"main.go"}`}},
									map[string]any{"id": "call_2", "type": "function", "function": map[string]string{"name": "missing_tool", "arguments": `{}`}},
								},
							}}}})
						}
						return
					}
					if calls != 2 {
						t.Errorf("unexpected request %d", calls)
					}
					transcript, _ := json.Marshal(request.Messages)
					for _, want := range []string{"call_1", "call_2", "package main", "unknown tool"} {
						if !strings.Contains(string(transcript), want) {
							t.Errorf("conversation missing %q: %s", want, transcript)
						}
					}
					if provider == "openai-compatible" && !strings.Contains(string(request.Messages[1]), "Preserve this state") {
						t.Error("assistant state lost")
					}
					if limit == 1 {
						if !strings.Contains(string(request.ToolChoice), "none") || !strings.Contains(string(request.Messages[len(request.Messages)-1]), "investigation limit") {
							t.Errorf("final request must disable tools: %+v", request)
						}
					} else if len(request.ToolChoice) != 0 {
						t.Errorf("tools disabled before limit: %s", request.ToolChoice)
					}
					if provider == "anthropic-vertex" {
						var resultMessage struct {
							Content []struct {
								Type      string `json:"type"`
								ToolUseID string `json:"tool_use_id"`
								IsError   bool   `json:"is_error"`
							} `json:"content"`
						}
						json.Unmarshal(request.Messages[2], &resultMessage)
						if len(resultMessage.Content) != 2 || resultMessage.Content[0].ToolUseID != "call_1" || !resultMessage.Content[1].IsError {
							t.Errorf("tool results missing or unpaired: %s", request.Messages[2])
						}
					} else {
						for i, id := range []string{"call_1", "call_2"} {
							var resultMessage map[string]string
							json.Unmarshal(request.Messages[i+2], &resultMessage)
							if resultMessage["role"] != "tool" || resultMessage["tool_call_id"] != id {
								t.Errorf("tool result unpaired: %v", resultMessage)
							}
						}
					}
					replyAssessment(w, provider)
				}))
				defer server.Close()
				output, err := backendForTest(provider, server.URL, limit).Run(context.Background(), "Assess", []verificationTool{&readFileTool{repoDir: repo}})
				if err != nil || output != testAssessment || calls != 2 {
					t.Fatalf("output=%q error=%v calls=%d", output, err, calls)
				}
			})
		}
	}
}

func TestBackendsFailures(t *testing.T) {
	for _, provider := range []string{"anthropic-vertex", "openai-compatible"} {
		for _, failure := range []string{"http", "malformed", "empty", "truncated", "refusal", "cancelled", "deadline"} {
			t.Run(provider+"/"+failure, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "application/json")
					switch failure {
					case "http":
						w.WriteHeader(401)
					case "malformed":
						w.Write([]byte("not json"))
					case "empty":
						w.Write([]byte("{}"))
					case "truncated", "refusal":
						if provider == "anthropic-vertex" {
							reason := "max_tokens"
							if failure == "refusal" {
								reason = "refusal"
							}
							json.NewEncoder(w).Encode(map[string]any{"id": "msg_1", "type": "message", "role": "assistant", "stop_reason": reason, "content": []any{map[string]string{"type": "text", "text": testAssessment}}})
						} else {
							reason := "length"
							message := map[string]string{"role": "assistant", "content": testAssessment}
							if failure == "refusal" {
								reason = "stop"
								message["refusal"] = "Refused"
							}
							json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": reason, "message": message}}})
						}
					case "deadline":
						<-r.Context().Done()
					default:
						t.Error("cancelled request reached server")
					}
				}))
				defer server.Close()
				ctx := context.Background()
				if failure == "cancelled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				if failure == "deadline" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
					defer cancel()
				}
				output, err := backendForTest(provider, server.URL, 1).Run(ctx, "Assess", nil)
				if err == nil || output != "" {
					t.Fatalf("failure produced assessment: %q / %v", output, err)
				}
				if failure == "cancelled" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation not propagated: %v", err)
				}
				if failure == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline not propagated: %v", err)
				}
			})
		}
	}
}

func TestExecuteToolInvalidArguments(t *testing.T) {
	_, err := executeTool(context.Background(), []verificationTool{&readFileTool{}}, "read_file", json.RawMessage("{"), nil)
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("error = %v", err)
	}
}

func TestTargetedSourceRetainsDistantCall(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, "main.go")
	// The decisive call is far below both the file header and its function declaration.
	code := "package main\nfunc dangerous() {}\nfunc main() {\n" + strings.Repeat("// unrelated padding that should not consume model context\n", 2000) + "dangerous()\n}\n"
	if err := os.WriteFile(path, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, code, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage("example.com/test", "main"), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	graph := callgraph.New(pkg.Func("main"))
	callee := graph.CreateNode(pkg.Func("dangerous"))
	for _, block := range pkg.Func("main").Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok {
				callgraph.AddEdge(graph.Root, call, callee)
			}
		}
	}
	result := &Result{UsedImports: map[string]map[string]UsedImportsDetails{
		".": {"example.com/test": {Symbols: []string{"dangerous"}, Paths: [][]*callgraph.Node{{graph.Root, callee}}}},
	}}
	if trace := FormatCallTraces(result); !strings.Contains(trace, "call site "+path+":2004") {
		t.Fatalf("missing call-site location: %s", trace)
	}
	snippets := collectRelevantSource(result, repo)
	excerpt := snippets["main.go"]
	if !strings.Contains(excerpt, "2004|dangerous()") {
		t.Fatalf("call-site evidence missing: %s", excerpt)
	}
	if !strings.Contains(excerpt, "omitted") || len(excerpt) > maxSourceFileBytes {
		t.Fatalf("excerpt not bounded or not marked: %d bytes", len(excerpt))
	}
	if len(excerpt)*10 >= len(code) {
		t.Fatalf("expected substantial reduction: %d -> %d bytes", len(code), len(excerpt))
	}
	t.Logf("Source fixture reduced from %d to %d bytes while preserving the call site", len(code), len(excerpt))
}

func TestTargetedSourceFindsSymbolAndReflection(t *testing.T) {
	repo := t.TempDir()
	code := "package main\nimport h \"golang.org/x/net/html\"\n" + strings.Repeat("// filler\n", 500) + "func parse() { h.Parse(nil) }\n" + strings.Repeat("// filler\n", 500) + "func dynamic() { println(\"reflection evidence\") }\n"
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	result := &Result{
		AffectedImports: map[string]AffectedImportsDetails{"golang.org/x/net/html": {Symbols: []string{"Parse"}}},
		ReflectionRisks: []ReflectionRisk{{Location: "main.go:1004:1"}},
	}
	excerpt := collectRelevantSource(result, repo)["main.go"]
	for _, want := range []string{"503|func parse()", "1004|func dynamic()", `import h "golang.org/x/net/html"`} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("missing %q from %s", want, excerpt)
		}
	}
}

func TestTargetedSourceBudgetAndStablePrompt(t *testing.T) {
	repo := t.TempDir()
	result := &Result{Files: map[string][][]string{".": {{}}}}
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("entry%02d.go", i)
		code := "package main\nfunc main() {\n" + strings.Repeat("//"+strings.Repeat("x", 300)+"\n", 30) + "}\n"
		if err := os.WriteFile(filepath.Join(repo, name), []byte(code), 0600); err != nil {
			t.Fatal(err)
		}
		result.Files["."][0] = append(result.Files["."][0], name)
	}
	first := collectRelevantSource(result, repo)
	if len(first) < 2 || len(first) >= 40 || sourceBytes(first) > maxSourceBytes {
		t.Fatalf("budget not enforced: %d files, %d bytes", len(first), sourceBytes(first))
	}
	prompt, err := buildVerificationPrompt(result, "{{.source_snippets}}", first)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		next, err := buildVerificationPrompt(result, "{{.source_snippets}}", collectRelevantSource(result, repo))
		if err != nil || next != prompt {
			t.Fatal("source selection or prompt ordering is nondeterministic")
		}
	}
	if !strings.Contains(prompt, "NOT evidence of absence") || !strings.Contains(finalAssessmentPrompt, "unknown") {
		t.Fatal("missing evidence handling instructions")
	}
}

func TestBoundedToolOutputCanBeRecoveredByRange(t *testing.T) {
	repo := t.TempDir()
	var source strings.Builder
	for i := 1; i <= 400; i++ {
		fmt.Fprintf(&source, "line-%d %s\n", i, strings.Repeat("é", 40))
	}
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	tools := []verificationTool{&readFileTool{repoDir: repo}}
	output, err := executeTool(context.Background(), tools, "read_file", json.RawMessage(`{"path":"main.go"}`), nil)
	if err != nil || len(output) > maxToolResultBytes || !utf8.ValidString(output) || !strings.Contains(output, "Tool output truncated") {
		t.Fatalf("bad bounded result: %d bytes, %v", len(output), err)
	}
	if strings.Contains(output, "400|line-400") {
		t.Fatal("fixture must put important evidence beyond the first chunk")
	}
	output, err = executeTool(context.Background(), tools, "read_file", json.RawMessage(`{"path":"main.go","start_line":400,"end_line":400}`), nil)
	if err != nil || !strings.Contains(output, "400|line-400") || strings.Contains(output, "truncated") {
		t.Fatalf("targeted recovery failed: %s / %v", output, err)
	}
}

func TestVerificationUsageNormalization(t *testing.T) {
	var anthropicUsage anthropic.BetaUsage
	if err := json.Unmarshal([]byte(`{"input_tokens":100,"output_tokens":20,"cache_read_input_tokens":600,"cache_creation_input_tokens":300}`), &anthropicUsage); err != nil {
		t.Fatal(err)
	}
	a := anthropicTokenUsage(anthropicUsage)
	var compatible compatibleUsage
	if err := json.Unmarshal([]byte(`{"prompt_tokens":1000,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":600,"cache_write_tokens":300}}`), &compatible); err != nil {
		t.Fatal(err)
	}
	b := compatible.normalized()
	if a.Input != 1000 || b.Input != 1000 || a.Output != 20 || b.Output != 20 || *a.CacheRead != *b.CacheRead || *a.CacheWrite != *b.CacheWrite {
		t.Fatalf("usage not normalized: %+v / %+v", a, b)
	}
	if anthropicTokenUsage(anthropic.BetaUsage{}) != nil || (&compatibleUsage{}).normalized() != nil {
		t.Fatal("missing usage treated as zero")
	}
	var zero compatibleUsage
	json.Unmarshal([]byte(`{"prompt_tokens":0,"completion_tokens":0}`), &zero)
	if u := zero.normalized(); u == nil || u.Input != 0 || u.CacheRead != nil {
		t.Fatalf("explicit zeros/missing cache detail lost: %+v", u)
	}

	var logs []string
	tracker := verificationUsageLog{progress: func(s string) { logs = append(logs, s) }}
	tracker.requests++
	tracker.record(a)
	tracker.requests++
	tracker.record(b)
	tracker.requests++
	tracker.record(nil)
	tracker.summary()
	joined := strings.Join(logs, "\n")
	for _, want := range []string{"input=1000 output=20 cache_read=600 cache_write=300 uncached=100", "input=2000 output=40 cache_read=1200 cache_write=600 requests=3 usage_reports=2", "request=3: unavailable"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}

func TestBackendsReportUsageEvenOnTruncation(t *testing.T) {
	for _, provider := range []string{"anthropic-vertex", "openai-compatible"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%v", provider, missing), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					var response map[string]any
					if provider == "anthropic-vertex" {
						response = map[string]any{"id": "msg_1", "type": "message", "role": "assistant", "stop_reason": "max_tokens", "content": []any{}}
						if !missing {
							response["usage"] = map[string]int{"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 600, "cache_creation_input_tokens": 300}
						}
					} else {
						response = map[string]any{"choices": []any{map[string]any{"finish_reason": "length", "message": map[string]string{"role": "assistant", "content": ""}}}}
						if !missing {
							response["usage"] = map[string]any{"prompt_tokens": 1000, "completion_tokens": 20, "prompt_tokens_details": map[string]int{"cached_tokens": 600, "cache_write_tokens": 300}}
						}
					}
					json.NewEncoder(w).Encode(response)
				}))
				defer server.Close()
				var logs []string
				progress := func(s string) { logs = append(logs, s) }
				agent := backendForTest(provider, server.URL, 1)
				switch a := agent.(type) {
				case *anthropicAgent:
					a.progress = progress
				case *compatibleAgent:
					a.progress = progress
				}
				if _, err := agent.Run(context.Background(), "Assess", nil); err == nil {
					t.Fatal("truncation must still fail")
				}
				joined := strings.Join(logs, "\n")
				want := "Usage reported totals: input=1000 output=20 cache_read=600 cache_write=300 requests=1 usage_reports=1"
				if missing {
					want = "Usage total: unavailable (requests=1 usage_reports=0)"
				}
				if !strings.Contains(joined, want) {
					t.Fatalf("missing usage report: %s", joined)
				}
			})
		}
	}
}

// Provider responses retain structured findings even though public JSON is compact.
func marshalAuditResponseForTest(a *AIVerification) ([]byte, error) {
	verdict, err := json.Marshal(a.IsVulnerable)
	if err != nil {
		return nil, err
	}
	return json.Marshal(verificationResponse{IsVulnerableRaw: verdict, Confidence: a.Confidence,
		Reasoning: a.Reasoning, Evidence: a.Evidence, GraphAnalysis: &a.GraphAnalysis,
		DynamicAnalysis: &a.DynamicAnalysis, Uncertainties: a.Uncertainties})
}

func auditFixture(t *testing.T) *AIVerification {
	t.Helper()
	a, err := parseAssessment(testAssessment)
	if err != nil {
		t.Fatal(err)
	}
	a.GraphAnalysis.Findings = []AIGraphFinding{{Kind: "suspected_false_negative", Module: ".", Package: "example.com/p", Symbol: "Run", GraphPath: []string{}, SourcePath: []string{"main.go:8: main -> reflected Run"}, Confidence: "medium", Reasoning: "Source invokes the target but the module graph has no corresponding edge.", Evidence: []string{"main.go:8: reflect.Call invokes Run"}, Uncertainties: []string{}}}
	a.DynamicAnalysis.Findings = []AIDynamicFinding{{Module: ".", Package: "example.com/p", Symbol: "Run", Mechanism: "reflection", Status: "supported", GraphStatus: "missing", RiskIndices: []int{0, 1}, SourcePath: []string{"main.go:8: main -> reflected Run"}, Confidence: "medium", Reasoning: "Receiver and method name resolve to Run.", Evidence: []string{"main.go:8: reflect.Call invokes Run"}, Uncertainties: []string{}}}
	return a
}

func TestAuditSchema(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*AIVerification)
		valid  bool
	}{
		{"source-backed findings", func(a *AIVerification) {}, true},
		{"invalid graph kind", func(a *AIVerification) { a.GraphAnalysis.Findings[0].Kind = "confirmed_bug" }, false},
		{"missing source chain", func(a *AIVerification) { a.GraphAnalysis.Findings[0].SourcePath = []string{} }, false},
		{"false positive without graph", func(a *AIVerification) { a.GraphAnalysis.Findings[0].Kind = "suspected_false_positive" }, false},
		{"invalid mechanism", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].Mechanism = "import" }, false},
		{"invalid dynamic status", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].Status = "maybe" }, false},
		{"supported without source", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].SourcePath = []string{} }, false},
		{"unresolved without gap", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].Status = "unresolved" }, false},
		{"unresolved with gap", func(a *AIVerification) {
			a.DynamicAnalysis.Findings[0].Status = "unresolved"
			a.DynamicAnalysis.Findings[0].Uncertainties = []string{"Receiver comes from runtime input"}
		}, true},
		{"unknown without gap", func(a *AIVerification) { a.IsVulnerable = "unknown" }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := auditFixture(t)
			tt.mutate(a)
			data, err := marshalAuditResponseForTest(a)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parseAssessment(string(data))
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
	for _, field := range []string{"graph_analysis", "dynamic_analysis", "uncertainties"} {
		var data map[string]any
		json.Unmarshal([]byte(testAssessment), &data)
		delete(data, field)
		raw, _ := json.Marshal(data)
		if _, err := parseAssessment(string(raw)); err == nil {
			t.Errorf("accepted missing %s", field)
		}
	}
}

func TestAuditTargetAndRiskCoverage(t *testing.T) {
	r := &Result{AffectedImports: map[string]AffectedImportsDetails{"example.com/p": {Symbols: []string{"Run"}}}, ReflectionRisks: []ReflectionRisk{{Symbol: "value_of"}, {Symbol: "method_by_name"}}}
	for _, tt := range []struct {
		name   string
		mutate func(*AIVerification)
		valid  bool
	}{
		{"grouped risks", func(a *AIVerification) {}, true},
		{"missing risk", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].RiskIndices = []int{0} }, false},
		{"invalid index", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].RiskIndices = []int{0, 1, 2} }, false},
		{"negative index", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].RiskIndices = []int{-1, 0, 1} }, false},
		{"risk label as affected symbol", func(a *AIVerification) { a.DynamicAnalysis.Findings[0].Symbol = "value_of" }, false},
		{"invented graph target", func(a *AIVerification) { a.GraphAnalysis.Findings[0].Package = "wrong/package" }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := auditFixture(t)
			tt.mutate(a)
			err := validateAuditTargets(r, a)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("Assess"), 0600)
	t.Setenv("GVS_SKILLS_DIR", repo)
	verifyWithAgent(context.Background(), r, repo, aiConfig{}, fakeAgent(func(context.Context, string, []verificationTool) (string, error) { return testAssessment, nil }))
	if r.AIVerification == nil || r.AIVerification.IsVulnerable != "unknown" || r.AIVerification.Coverage.ReviewedRisks != 0 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "reflection risk 0") {
		t.Fatalf("incomplete audit accepted: %+v", r)
	}
}

func TestAuditPrompt(t *testing.T) {
	template, err := os.ReadFile("../../../skills/verify-scan.md")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	r := &Result{ScanConfig: ScanConfig{Directory: repo}, Unsafe: true, Reflect: true, ReflectionRisks: []ReflectionRisk{{Location: "main.go:8", Symbol: "value_of"}}, ssaBuilds: map[string]*ssaBuild{filepath.Join(repo, "nested"): nil}}
	prompt, err := buildVerificationPrompt(r, string(template), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"reflection_risks":[`, `"unsafe":true`, `"reflect":true`, `"nested":"unavailable`, "suspected_false_positive", "suspected_false_negative", "risk_indices", "RuntimeTypes", "SVG rendering itself is not being visually inspected", "A scanner verdict of false is not a false-positive finding", "Do not require an SVG or invent a graph_path"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(prompt, "{{.") {
		t.Fatal("unexpanded prompt")
	}
}

func TestGraphToolsRequireModuleSelection(t *testing.T) {
	repo := t.TempDir()
	r := &Result{ssaBuilds: map[string]*ssaBuild{
		filepath.Join(repo, "a"):      {cg: callgraph.New(nil)},
		filepath.Join(repo, "b"):      {cg: callgraph.New(nil)},
		filepath.Join(repo, "failed"): {cg: callgraph.New(nil), err: errors.New("load failed")},
	}}
	var graphTool verificationTool
	for _, tool := range verificationTools(r, repo) {
		if tool.Name() == "find_callers" {
			graphTool = tool
		}
	}
	if graphTool == nil {
		t.Fatal("missing graph tool")
	}
	if !oneOf("module", graphTool.InputSchema().Required...) {
		t.Fatal("module must be required")
	}
	if _, err := graphTool.Execute(context.Background(), json.RawMessage(`{"function":"Run"}`)); err == nil {
		t.Fatal("ambiguous graph selected")
	}
	for _, module := range []string{"a", "b"} {
		output, err := graphTool.Execute(context.Background(), json.RawMessage(fmt.Sprintf(`{"module":%q,"function":"Run"}`, module)))
		if err != nil || !strings.HasPrefix(output, "Module: "+module+"\n") {
			t.Fatalf("selection: %s %v", output, err)
		}
	}
	if _, err := graphTool.Execute(context.Background(), json.RawMessage(`{"module":"failed","function":"Run"}`)); err == nil {
		t.Fatal("failed module graph offered")
	}
	delete(r.ssaBuilds, filepath.Join(repo, "b"))
	for _, tool := range verificationTools(r, repo) {
		if tool.Name() == "find_callers" {
			output, err := tool.Execute(context.Background(), json.RawMessage(`{"function":"Run"}`))
			if err != nil || !strings.HasPrefix(output, "Module: a\n") {
				t.Fatalf("single module: %s %v", output, err)
			}
		}
	}
}

func TestReflectionRiskBatchingAndCoverage(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("BATCH_JSON:{{.scan_result_json}}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	r := &Result{ScanConfig: ScanConfig{Directory: repo}}
	for i := 0; i < 100; i++ {
		r.ReflectionRisks = append(r.ReflectionRisks, ReflectionRisk{Association: "unresolved", Type: "reflection_call", Location: fmt.Sprintf("main.go:%d:1", i+1), Evidence: []string{strings.Repeat("dynamic value needs tracing ", 100)}})
	}
	// Exact duplicate observations share a compact entry but retain both IDs.
	r.ReflectionRisks = append(r.ReflectionRisks, r.ReflectionRisks[0])
	seen := map[int]bool{}
	batches := verificationRiskBatches(r, repo)
	if len(batches) < 2 {
		t.Fatal("large risk list not batched")
	}
	for _, batch := range batches {
		data, _ := json.Marshal(batch)
		if len(data) > maxRiskBatchBytes {
			t.Fatalf("oversized risk batch: %d", len(data))
		}
		count := 0
		for _, group := range batch {
			for _, index := range group.Indices {
				if seen[index] {
					t.Fatalf("duplicate index %d", index)
				}
				seen[index] = true
				count++
			}
		}
		if count > maxRiskBatchEntries {
			t.Fatalf("oversized response coverage: %d", count)
		}
	}
	if len(seen) != len(r.ReflectionRisks) {
		t.Fatal("risks lost during batching")
	}
	calls := 0
	agent := fakeAgent(func(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
		calls++
		var scan struct {
			Risks []verificationRisk `json:"reflection_risks"`
		}
		if err := json.Unmarshal([]byte(strings.SplitN(prompt, "BATCH_JSON:", 2)[1]), &scan); err != nil {
			t.Fatal(err)
		}
		a, err := parseAssessment(testAssessment)
		if err != nil {
			t.Fatal(err)
		}
		a.IsVulnerable = "unknown"
		a.Uncertainties = []string{"Runtime target is unavailable"}
		for _, risk := range scan.Risks {
			a.DynamicAnalysis.Findings = append(a.DynamicAnalysis.Findings, AIDynamicFinding{Module: ".", Mechanism: "reflection", Status: "unresolved", GraphStatus: "unknown", RiskIndices: risk.Indices, SourcePath: []string{}, Confidence: "low", Reasoning: "Runtime target is unavailable", Evidence: []string{risk.Location}, Uncertainties: []string{"Runtime value required"}})
		}
		data, _ := marshalAuditResponseForTest(a)
		return string(data), nil
	})
	verifyWithAgent(context.Background(), r, repo, aiConfig{}, agent)
	if calls != len(batches) || len(r.Errors) != 0 || r.AIVerification == nil {
		t.Fatalf("batch audit failed: calls=%d errors=%v", calls, r.Errors)
	}
	c := r.AIVerification.Coverage
	if c.TotalRisks != 101 || c.ReviewedRisks != 101 || len(c.PendingRiskIndices) != 0 {
		t.Fatalf("bad coverage: %+v", c)
	}
	if err := validateAuditTargets(r, r.AIVerification); err != nil {
		t.Fatal(err)
	}
	// Interrupted investigations preserve completed findings and pending IDs.
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	partial := fakeAgent(func(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
		out, err := agent.Run(ctx, prompt, tools)
		cancel()
		return out, err
	})
	verifyWithAgent(ctx, r, repo, aiConfig{}, partial)
	c = r.AIVerification.Coverage
	if c.ReviewedRisks == 0 || c.ReviewedRisks >= 101 || len(c.PendingRiskIndices) != 101-c.ReviewedRisks || r.AIVerification.IsVulnerable != "unknown" {
		t.Fatalf("partial audit lost coverage: %+v", c)
	}
}

func TestVerificationContextBudget(t *testing.T) {
	for _, provider := range []string{"anthropic-vertex", "openai-compatible"} {
		t.Run(provider, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; replyAssessment(w, provider) }))
			defer server.Close()
			agent := backendForTest(provider, server.URL, 3)
			switch a := agent.(type) {
			case *anthropicAgent:
				a.cfg.ContextTokens = 24000
			case *compatibleAgent:
				a.cfg.ContextTokens = 24000
			}
			if _, err := agent.Run(context.Background(), strings.Repeat("x", 30000), nil); err == nil || !strings.Contains(err.Error(), "context budget") {
				t.Fatalf("oversized prompt accepted: %v", err)
			}
			if calls != 0 {
				t.Fatal("oversized request reached provider")
			}
		})
	}
	cfg := aiConfig{ContextTokens: 20000, MaxTokens: 4096}
	if err := checkVerificationContext(cfg, map[string]any{"messages": []string{"small"}, "tools": strings.Repeat("x", 15000)}, 0); err == nil {
		t.Fatal("tool schemas excluded from budget")
	}
	if err := checkVerificationContext(cfg, map[string]any{"messages": []string{"small", strings.Repeat("history", 2500)}}, 0); err == nil {
		t.Fatal("history excluded from budget")
	}
}

func TestAuditBatchRejectsOutsideIndices(t *testing.T) {
	r := &Result{AffectedImports: map[string]AffectedImportsDetails{"example.com/p": {Symbols: []string{"Run"}}}, ReflectionRisks: make([]ReflectionRisk, 2)}
	if err := validateAuditBatch(r, auditFixture(t), []int{0}); err == nil {
		t.Fatal("batch claimed an unassigned risk")
	}
}

func TestRiskEvidencePagination(t *testing.T) {
	risk := ReflectionRisk{Type: "reflection_call", Evidence: []string{strings.Repeat("évidence ", 1500) + "END-OF-EVIDENCE"}}
	tool := &reflectionRisksTool{risks: []ReflectionRisk{risk}}
	offset := 0
	var recovered strings.Builder
	for i := 0; i < 10; i++ {
		input := json.RawMessage(fmt.Sprintf(`{"indices":[0],"offset":%d}`, offset))
		output, err := tool.Execute(context.Background(), input)
		if err != nil || !utf8.ValidString(output) || len(output) > maxToolResultBytes {
			t.Fatalf("invalid page: %v, bytes=%d", err, len(output))
		}
		header, body, ok := strings.Cut(output, "\n")
		if !ok {
			recovered.WriteString(output)
			break
		}
		recovered.WriteString(body)
		_, next, ok := strings.Cut(header, "next_offset=")
		if !ok {
			t.Fatal("missing continuation offset")
		}
		if next == "complete" {
			break
		}
		if _, err := fmt.Sscanf(next, "%d", &offset); err != nil {
			t.Fatal(err)
		}
	}
	var entries []struct {
		Index int            `json:"index"`
		Risk  ReflectionRisk `json:"risk"`
	}
	if err := json.Unmarshal([]byte(recovered.String()), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Risk.Evidence[0] != risk.Evidence[0] {
		t.Fatal("paginated evidence lost bytes")
	}
}

func TestRiskBatchBudgetIncludesJSONEscaping(t *testing.T) {
	huge := strings.Repeat("\x00", 20000)
	r := &Result{ReflectionRisks: []ReflectionRisk{{Type: huge, Location: huge, Package: huge, Symbol: huge, Evidence: []string{huge}}}}
	for _, batch := range verificationRiskBatches(r, "") {
		data, _ := json.Marshal(batch)
		if len(data) > maxRiskBatchBytes {
			t.Fatalf("escaped risk exceeds budget: %d", len(data))
		}
	}
}

func TestAIUsageCosts(t *testing.T) {
	read, write := int64(600), int64(300)
	inputRate, outputRate, readRate, writeRate := 3.0, 15.0, 0.3, 3.75
	pricing := &AIPricing{Input: &inputRate, Output: &outputRate, CacheRead: &readRate, CacheWrite: &writeRate}
	for _, tt := range []struct {
		name                                    string
		missingUsage, missingCache, missingRate bool
	}{
		{name: "complete"}, {name: "missing usage", missingUsage: true}, {name: "missing cache", missingCache: true}, {name: "missing rate", missingRate: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first := verificationUsageLog{requests: 1}
			first.record(&verificationTokenUsage{Input: 1000, Output: 20, CacheRead: &read, CacheWrite: &write})
			second := verificationUsageLog{requests: 1}
			if tt.missingUsage {
				second.record(nil)
			} else if tt.missingCache {
				second.record(&verificationTokenUsage{Input: 1000, Output: 20})
			} else {
				second.record(&verificationTokenUsage{Input: 1000, Output: 20, CacheRead: &read, CacheWrite: &write})
			}
			first.merge(&second)
			rates := *pricing
			if tt.missingRate {
				rates.Input = nil
			}
			out := first.output(&rates)
			if out.Requests != 2 || out.Input == nil || *out.Input != int64(1000*out.Reports) {
				t.Fatalf("bad usage: %+v", out)
			}
			if tt.missingUsage || tt.missingCache || tt.missingRate {
				if out.Cost.Total != nil {
					t.Fatal("incomplete cost reported as total")
				}
			} else {
				if !out.Complete || out.Cost.Total == nil || math.Abs(*out.Cost.Total-0.00381) > 1e-12 {
					t.Fatalf("bad costs: %+v", out.Cost)
				}
				if math.Abs(*out.Cost.Input-0.0006) > 1e-12 {
					t.Fatal("cached input charged twice")
				}
			}
			data, err := json.Marshal(out)
			if err != nil || !strings.Contains(string(data), `"input_tokens":`) || !strings.Contains(string(data), `"cost_usd":`) {
				t.Fatalf("bad JSON: %s / %v", data, err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != 5 {
				t.Fatalf("usage must have five fields: %s", data)
			}
			for _, name := range []string{"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "cost_usd"} {
				if _, ok := fields[name]; !ok {
					t.Fatalf("missing %s: %s", name, data)
				}
			}
			if out.CostUSD != out.Cost.Total {
				t.Fatal("JSON cost differs from calculated total")
			}
		})
	}
	empty := (&verificationUsageLog{requests: 1}).output(nil)
	if empty.Input != nil || empty.Output != nil || empty.Cost.Total != nil || empty.Complete {
		t.Fatal("missing usage treated as zero")
	}
	zero := int64(0)
	tracker := verificationUsageLog{requests: 1}
	tracker.record(&verificationTokenUsage{CacheRead: &zero, CacheWrite: &zero})
	if out := tracker.output(pricing); out.Cost.Total == nil || *out.Cost.Total != 0 {
		t.Fatal("reported zero lost")
	}
}

func TestAIUsageJSONOnFailedAssessment(t *testing.T) {
	for _, provider := range []string{"anthropic-vertex", "openai-compatible"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if provider == "anthropic-vertex" {
					json.NewEncoder(w).Encode(map[string]any{"id": "msg_final", "type": "message", "role": "assistant", "model": "test-model", "stop_reason": "end_turn", "content": []any{map[string]string{"type": "text", "text": "invalid JSON"}}, "usage": map[string]int{"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 600, "cache_creation_input_tokens": 300}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": "invalid JSON"}}}, "usage": map[string]any{"prompt_tokens": 1000, "completion_tokens": 20, "prompt_tokens_details": map[string]int{"cached_tokens": 600, "cache_write_tokens": 300}}})
				}
			}))
			defer server.Close()
			repo := t.TempDir()
			if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("Assess"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GVS_SKILLS_DIR", repo)
			agent := backendForTest(provider, server.URL, 1)
			result := &Result{}
			verifyWithAgent(context.Background(), result, repo, aiConfig{Provider: provider, Model: "test-model"}, agent)
			if result.AIVerification == nil || result.AIVerification.Usage == nil {
				t.Fatalf("usage lost: %+v", result)
			}
			usage := result.AIVerification.Usage
			// The malformed draft gets one correction; retain usage from both.
			if usage.Input == nil || usage.Output == nil || usage.CacheRead == nil || usage.CacheWrite == nil || usage.Requests != 2 || *usage.Input != 2000 || *usage.Output != 40 || *usage.CacheRead != 1200 || *usage.CacheWrite != 600 || len(result.Errors) == 0 || result.AIVerification.IsVulnerable != "unknown" {
				t.Fatalf("bad failure usage: %+v / %+v", usage, result.Errors)
			}
			// A second investigation adds to the same provider totals.
			if _, err := agent.Run(context.Background(), "Assess", nil); err != nil {
				t.Fatal(err)
			}
			totals := agent.(interface{ usageTotals() *verificationUsageLog }).usageTotals().output(nil)
			if totals.Requests != 3 || *totals.Input != 3000 {
				t.Fatalf("batch totals lost: %+v", totals)
			}
		})
	}
}

func TestAIUsageWithoutWriteBillingCategory(t *testing.T) {
	for _, tt := range []struct {
		name                           string
		requests, reports, readReports int
		writeRate                      *float64
		wantCost                       bool
	}{
		{"zero write rate", 2, 2, 2, new(float64), true},
		{"missing usage", 3, 2, 2, new(float64), false},
		{"missing reads", 2, 2, 1, new(float64), false},
		{"missing rate", 2, 2, 2, nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			read := int64(16768)
			inputRate, outputRate, readRate := 2.0, 8.0, 0.5
			tracker := verificationUsageLog{requests: tt.requests, reports: tt.reports, readReports: tt.readReports,
				total: verificationTokenUsage{Input: 35172, Output: 1000, CacheRead: &read}}
			out := tracker.output(&AIPricing{Input: &inputRate, Output: &outputRate, CacheRead: &readRate, CacheWrite: tt.writeRate})
			if out.CacheWrite != nil || out.WriteReports != 0 || out.Complete {
				t.Fatal("unreported write counter was invented")
			}
			if !tt.wantCost {
				if out.Cost.Total != nil {
					t.Fatal("incomplete usage produced total")
				}
				return
			}
			if out.Cost.Input == nil || math.Abs(*out.Cost.Input-0.036808) > 1e-12 || out.Cost.CacheWrite == nil || *out.Cost.CacheWrite != 0 || out.Cost.Total == nil || math.Abs(*out.Cost.Total-0.053192) > 1e-12 {
				t.Fatalf("wrong cost: %+v", out.Cost)
			}
		})
	}
}

func TestCompatibleEndpointErrorDetails(t *testing.T) {
	for _, tt := range []struct{ name, body, want string }{
		{"rejected parameter", `{"error":{"message":"Unsupported parameter: max_completion_tokens","param":"max_completion_tokens"}}`, "Unsupported parameter: max_completion_tokens"},
		{"key redaction", `{"error":{"message":"Invalid key secret-test-key"}}`, "Invalid key [redacted]"},
		{"non JSON", "<html>Bad request</html>", "AI endpoint returned HTTP 400"},
		{"missing message", `{"error":{}}`, "AI endpoint returned HTTP 400"},
		{"long message", `{"error":{"message":"` + strings.Repeat("x", 3000) + `"}}`, "[truncated]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, tt.body)
			}))
			defer server.Close()
			agent := &compatibleAgent{client: server.Client(), cfg: aiConfig{BaseURL: server.URL, APIKey: "secret-test-key", Model: "test-model", MaxIterations: 1}}
			_, err := agent.Run(context.Background(), "Assess", nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "secret-test-key") || len(err.Error()) > 2100 {
				t.Fatalf("bad endpoint error: %v", err)
			}
			if agent.usage.requests != 1 || agent.usage.reports != 0 {
				t.Fatalf("bad failure usage: %+v", agent.usage)
			}
		})
	}
}

func TestVerificationToolObjectSchemas(t *testing.T) {
	repo := t.TempDir()
	result := &Result{ReflectionRisks: []ReflectionRisk{{Type: "value_of"}}, ssaBuilds: map[string]*ssaBuild{repo: {cg: callgraph.New(nil)}}}
	tools := verificationTools(result, repo)
	tools = append(tools, &findImplementationsTool{})
	for _, tool := range tools {
		t.Run(tool.Name(), func(t *testing.T) {
			data, err := json.Marshal(tool.InputSchema())
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatal(err)
			}
			if schema["type"] != "object" {
				t.Fatalf("function parameters must be an object schema: %s", data)
			}
			props, ok := schema["properties"].(map[string]any)
			if !ok {
				t.Fatalf("properties must be an object: %s", data)
			}
			for _, name := range tool.InputSchema().Required {
				if _, ok := props[name]; !ok {
					t.Fatalf("required property %s is undefined", name)
				}
			}
			for name, value := range props {
				property, ok := value.(map[string]any)
				if !ok || property["type"] == nil || property["type"] == "" {
					t.Fatalf("property %s has no valid type", name)
				}
				if property["type"] == "array" {
					items, ok := property["items"].(map[string]any)
					if !ok || items["type"] == nil || items["type"] == "" {
						t.Fatalf("array %s has no item type", name)
					}
				}
			}
		})
	}
}

func TestVerificationPromptRequiresConcreteGaps(t *testing.T) {
	repo := t.TempDir()
	result := &Result{ScanConfig: ScanConfig{Directory: repo}, IsVulnerable: "false", Reflect: true, ssaBuilds: map[string]*ssaBuild{repo: {cg: callgraph.New(nil)}}}
	prompt, err := buildVerificationPrompt(result, "Assess {{.scan_result_json}}", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"graph_modules":{".":"available"}`, `"reflection_risks":null`,
		"An empty reflection_risks list is not a reason for unknown and is not proof of safety",
		"check_module/check_transitive_deps", "list_entry_points", "concrete verdict-changing question",
		"attempted check or why it could not be attempted", "do not automatically copy the scanner verdict",
		"Missing or truncated text is NOT evidence of absence",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("missing instruction %q", want)
		}
	}
	for _, want := range []string{"Stop using tools", "concrete verdict-changing question", "hypothetical hidden reflection", "not evidence that the repository is safe"} {
		if !strings.Contains(finalAssessmentPrompt, want) {
			t.Errorf("final prompt missing %q", want)
		}
	}
}

func TestCompactAIVerificationJSON(t *testing.T) {
	a := auditFixture(t)
	a.Provider, a.Model = "provider", "model"
	a.Coverage = &AIAuditCoverage{TotalRisks: 2, ReviewedRisks: 2}
	a.Uncertainties = []string{"Deployment configuration is unavailable"}
	a.DynamicAnalysis.Findings[0].Uncertainties = []string{"Deployment configuration is unavailable", "Callback registration depends on runtime input"}
	a.Usage = &AIUsage{}
	data, err := json.Marshal(&Result{AIVerification: a})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		AI map[string]json.RawMessage `json:"AIVerification"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.AI) != 5 {
		t.Fatalf("expected five public fields: %s", data)
	}
	for _, field := range []string{"IsVulnerable", "confidence", "evidence", "reasoning", "usage"} {
		if _, ok := result.AI[field]; !ok {
			t.Fatalf("missing %s", field)
		}
	}
	var reasoning string
	json.Unmarshal(result.AI["reasoning"], &reasoning)
	if !strings.Contains(reasoning, a.Reasoning) || strings.Count(reasoning, "Deployment configuration is unavailable") != 1 || !strings.Contains(reasoning, "Callback registration depends on runtime input") {
		t.Fatalf("missing or repeated gaps: %s", reasoning)
	}
	var evidence []string
	json.Unmarshal(result.AI["evidence"], &evidence)
	if !oneOf("main.go:8: reflect.Call invokes Run", evidence...) || len(evidence) != 4 {
		t.Fatalf("lost or duplicated finding evidence: %v", evidence)
	}
	if a.Reasoning != "Only tests call the symbol." || len(a.Evidence) != 1 {
		t.Fatal("serialization mutated audit")
	}
}

func TestCompactAIVerificationPreservesFailedCoverage(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("Assess"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	result := &Result{ReflectionRisks: []ReflectionRisk{{Type: "value_of"}}}
	verifyWithAgent(context.Background(), result, repo, aiConfig{}, fakeAgent(func(context.Context, string, []verificationTool) (string, error) {
		return "", errors.New("provider unavailable")
	}))
	data, err := json.Marshal(result.AIVerification)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"IsVulnerable":"unknown"`, `"confidence":"low"`, "provider unavailable", "1 of 1 reflection risk candidates remain unreviewed", `"usage":null`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "coverage.pending_risk_indices") {
		t.Fatal("public reason refers to hidden field")
	}
}

func TestCompactAIVerificationDeduplicatesValidationDetails(t *testing.T) {
	a := &AIVerification{
		IsVulnerable: "unknown", Confidence: "low",
		Reasoning: "The AI proposed IsVulnerable=false, but the verifier could not validate it.",
		Evidence:  []string{"Verifier: AI proposed IsVulnerable=false; required graph/source evidence was incomplete", "main.go:68: stopCh := signals.SetupSignalHandler(cancelFunc)"},
	}
	for _, symbol := range []string{"Server.Serve", "Server.handleStream", "Server.ServeHTTP"} {
		target := "google.golang.org/grpc." + symbol
		path := []string{"example.com/controller.main", "example.com/controller.SetupSignalHandler", "example.com/controller.SetupSignalHandler$1", target + "$1"}
		gap := "Graph evidence validation for " + target + ": no dispatch step is refuted with checked source citations for all matching call sites; step 3: " + strings.Join(path, " -> ") + " [dynamic function call; call site /tmp/scan/pkg/signals/signals.go:32]"
		// Simulate the long inventory accompanying the reflection path in real output.
		gap += strings.Repeat("; step 10: (reflect.Value).Call -> (net/http.Handler).ServeHTTP$bound [synthetic call]", 12)
		a.GraphAnalysis.Findings = append(a.GraphAnalysis.Findings, AIGraphFinding{Kind: "inconclusive", Module: ".", Package: "google.golang.org/grpc", Symbol: symbol, GraphPath: path, Reasoning: gap, Evidence: []string{gap}, Uncertainties: []string{gap}})
		a.Evidence = append(a.Evidence, "Unreviewed scanner candidate: module=.; target="+target+"; path="+strings.Join(path, " -> "))
		a.Uncertainties = append(a.Uncertainties, gap)
	}
	a.Uncertainties = append(a.Uncertainties, "3 scanner candidate paths remain unreviewed or inconclusive; see evidence for affected targets", "Callback registration depends on runtime input")
	before, err := marshalAuditResponseForTest(a)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var public struct {
		Evidence  []string `json:"evidence"`
		Reasoning string   `json:"reasoning"`
	}
	if err := json.Unmarshal(data, &public); err != nil {
		t.Fatal(err)
	}
	if len(data) > 2000 || len(public.Evidence) != 5 {
		t.Fatalf("validation report remains verbose (%d bytes, %d evidence entries): %s", len(data), len(public.Evidence), data)
	}
	for _, symbol := range []string{"Server.Serve", "Server.handleStream", "Server.ServeHTTP"} {
		if strings.Count(string(data), "target=google.golang.org/grpc."+symbol+";") != 1 {
			t.Errorf("target repeated or lost: %s", symbol)
		}
	}
	if strings.Contains(string(data), " -> ") || strings.Contains(string(data), "synthetic call") || strings.Contains(string(data), "Unreviewed scanner candidate:") {
		t.Fatalf("detailed route or redundant candidate leaked: %s", data)
	}
	if strings.Contains(public.Reasoning, "no dispatch step") || strings.Count(string(data), "no dispatch step") != 3 {
		t.Fatalf("failure explanation duplicated outside findings: %s", data)
	}
	for _, want := range []string{"main.go:68", "Callback registration depends on runtime input", "3 scanner candidate paths", `"IsVulnerable":"unknown"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("important evidence or gap lost: %s", want)
		}
	}
	after, err := marshalAuditResponseForTest(a)
	if err != nil || string(before) != string(after) {
		t.Fatal("public formatting changed internal audit or validation feedback")
	}
	t.Logf("Public JSON: %d bytes; internal audit JSON: %d bytes", len(data), len(before))
}

func TestMergedAssessmentReasoning(t *testing.T) {
	first, err := parseAssessment(testAssessment)
	if err != nil {
		t.Fatal(err)
	}
	second := *first
	second.Reasoning = "Registry entries resolve to an unaffected method."
	merged := mergeVerificationAssessments([]*AIVerification{first, &second, first}, nil)
	if strings.Count(merged.Reasoning, first.Reasoning) != 1 || !strings.Contains(merged.Reasoning, second.Reasoning) {
		t.Fatalf("lost or repeated reasoning: %s", merged.Reasoning)
	}
}

func TestVerificationPromptWithholdsScannerVerdict(t *testing.T) {
	r := &Result{IsVulnerable: "true", GraphPaths: []string{"https://example.invalid/scanner-true.svg"}}
	template := "Verdict: {{.is_vulnerable}}\n{{.scan_result_json}}\n{{.call_traces}}"
	positive, err := buildVerificationPrompt(r, template, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.IsVulnerable = "false"
	r.GraphPaths = nil
	negative, err := buildVerificationPrompt(r, template, nil)
	if err != nil {
		t.Fatal(err)
	}
	if positive != negative {
		t.Fatal("scanner verdict or rendered graph URLs changed the evidence prompt")
	}
	if !strings.Contains(positive, "Verdict: withheld") || strings.Contains(positive, "scanner-true.svg") {
		t.Fatalf("verdict was not withheld: %s", positive)
	}
}

func TestGrepCodeSearchFailures(t *testing.T) {
	for _, tc := range []struct {
		name, pattern string
		missingDir    bool
		want          string
	}{
		{"invalid regex", "[", false, "Search failed"},
		{"missing directory", "anything", true, "Search failed"},
		{"option-like pattern", "-needle", false, "-needle"},
		{"no match", "absent", false, "No matches found"},
		{"alternation", "absent|needle", false, "-needle"},
		{"grouping", "(needle|absent)$", false, "-needle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "source.go"), []byte("// -needle\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if tc.missingDir {
				dir = filepath.Join(dir, "missing")
			}
			input, _ := json.Marshal(map[string]string{"pattern": tc.pattern, "glob": "*.go"})
			got, err := (&grepCodeTool{repoDir: dir}).Execute(context.Background(), input)
			if err != nil || !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestInspectDispatchOrigins(t *testing.T) {
	repo, dependency := t.TempDir(), t.TempDir()
	mainSource := `package main
import (
 "context"
 dep "example.com/dependency"
)
func main() {
 _, cancel := context.WithCancel(context.Background())
 dep.Start(cancel)
 dep.Invoke(dep.Safe{})
}
func many() {
` + strings.Repeat(" dep.Many(func() {})\n", 60) + "}\n"
	dependencySource := `package dependency
import "context"
func Start(cancel context.CancelFunc) { go func() { cancel() }() }
func Serve() { go func() { println("server") }() }
type Runner interface { Run() }
type Safe struct{}
type Server struct{}
func (Safe) Run() {}
func (Server) Run() {}
func Invoke(r Runner) { r.Run() }
func Many(f func()) { f() }
`
	for path, content := range map[string]string{
		filepath.Join(repo, "go.mod"):       "module example.com/app\n\ngo 1.21\nrequire example.com/dependency v0.0.0\nreplace example.com/dependency => " + filepath.ToSlash(dependency) + "\n",
		filepath.Join(repo, "main.go"):      mainSource,
		filepath.Join(dependency, "go.mod"): "module example.com/dependency\n\ngo 1.21\n",
		filepath.Join(dependency, "dep.go"): dependencySource,
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ALGO", "cha")
	scan := &Result{ScanConfig: ScanConfig{Directory: repo}}
	build := scan.getSSABuild(repo)
	if build == nil || build.cg == nil {
		t.Fatalf("fixture build failed: %v", scan.Errors)
	}
	var inspector verificationTool
	for _, tool := range verificationTools(scan, repo) {
		if tool.Name() == "inspect_dispatch" {
			inspector = tool
		}
	}
	if inspector == nil {
		t.Fatal("dispatch tool not registered")
	}
	for _, tc := range []struct {
		name, caller, callee string
		want                 []string
	}{
		{"captured cancellation", "example.com/dependency.Start$1", "example.com/dependency.Serve$1", []string{"captured binding", "Argument supplied by example.com/app.main", "context.WithCancel", filepath.Join(repo, "main.go") + ":7", filepath.Join(dependency, "dep.go") + ":3"}},
		{"interface receiver", "example.com/dependency.Invoke", "(example.com/dependency.Server).Run", []string{"*ssa.MakeInterface", "Safe", "Argument supplied by example.com/app.main", filepath.Join(dependency, "dep.go") + ":10"}},
		{"bounded callers", "example.com/dependency.Many", "example.com/dependency.Serve$1", []string{"truncated"}},
		{"missing caller", "unknown", "example.com/dependency.Serve$1", []string{"Caller not found", "does not rule out"}},
		{"exact names required", "example.com/dependency.Start", "Serve", []string{"No matching edge", "does not rule out"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, _ := json.Marshal(map[string]string{"caller": tc.caller, "callee": tc.callee, "module": "."})
			output, err := executeTool(context.Background(), []verificationTool{inspector}, "inspect_dispatch", input, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(output, want) {
					t.Errorf("missing %q in %s", want, output)
				}
			}
			if len(output) > maxToolResultBytes {
				t.Errorf("output exceeds tool budget: %d", len(output))
			}
		})
	}
	// Inspection supplies actual source, including the indexed dependency, without
	// another read_file call. Merely having the source on disk is insufficient.
	evidence := newVerificationEvidence(repo, nil)
	evidence.sourceFiles = verificationSourceFiles(scan)
	citation := AISourceCitation{File: filepath.Join(dependency, "dep.go"), Line: 3, Quote: "func Start(cancel context.CancelFunc) { go func() { cancel() }() }"}
	if evidence.check(citation) == nil {
		t.Fatal("unread source accepted as evidence")
	}
	checkedInspector := &verificationEvidenceTool{verificationTool: inspector, evidence: evidence}
	input := json.RawMessage(`{"module":".","caller":"example.com/dependency.Start$1","callee":"example.com/dependency.Serve$1"}`)
	output, err := checkedInspector.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	origins := []AISourceCitation{
		{File: filepath.Join(repo, "main.go"), Line: 7, Quote: " _, cancel := context.WithCancel(context.Background())"},
		{File: filepath.Join(repo, "main.go"), Line: 8, Quote: " dep.Start(cancel)"},
	}
	for _, quote := range append([]AISourceCitation{citation}, origins...) {
		if err := evidence.check(quote); err != nil || !strings.Contains(output, verificationSourceQuote(quote)) {
			t.Fatalf("dispatch source not supplied and registered: %+v: %v\n%s", quote, err, output)
		}
	}
	t.Run("module prefix truncation", func(t *testing.T) {
		module := strings.Repeat("m", maxToolResultBytes)
		prefixed := &moduleGraphTool{tools: map[string]verificationTool{module: inspector.(*moduleGraphTool).tools["."]}}
		evidence := newVerificationEvidence(repo, nil)
		evidence.sourceFiles = verificationSourceFiles(scan)
		input, _ := json.Marshal(map[string]string{"module": module, "caller": "example.com/dependency.Start$1", "callee": "example.com/dependency.Serve$1"})
		output, err := (&verificationEvidenceTool{verificationTool: prefixed, evidence: evidence}).Execute(context.Background(), input)
		if err != nil || len(output) > maxToolResultBytes || evidence.check(citation) == nil {
			t.Fatalf("hidden source must not become evidence: %v, %d bytes", err, len(output))
		}
	})
	t.Run("cancellation assessment", func(t *testing.T) {
		// Omit initial excerpts to exercise source delivery through the tool alone.
		if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("Assess {{.call_traces}}"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GVS_SKILLS_DIR", repo)
		path := []string{"example.com/app.main", "example.com/dependency.Start", "example.com/dependency.Start$1", "example.com/dependency.Serve$1"}
		var nodes []*callgraph.Node
		for _, name := range path {
			for fn, node := range build.cg.Nodes {
				if fn != nil && fn.String() == name {
					nodes = append(nodes, node)
					break
				}
			}
		}
		if len(nodes) != len(path) {
			t.Fatal("fixture path missing")
		}
		for _, tc := range []struct {
			name, want string
		}{
			{"checked cancellation origin", "false"},
			{"unread source", "unknown"},
			{"fabricated origin", "unknown"},
			{"missing alternate review", "unknown"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				result := &Result{ScanConfig: ScanConfig{Directory: repo}, IsVulnerable: "true",
					AffectedImports: map[string]AffectedImportsDetails{"example.com/dependency": {Symbols: []string{"Serve"}}},
					UsedImports:     map[string]map[string]UsedImportsDetails{".": {"example.com/dependency": {Symbols: []string{"Serve"}, Paths: [][]*callgraph.Node{nodes}}}},
					ssaBuilds:       scan.ssaBuilds,
				}
				agent := fakeAgent(func(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
					if tc.name != "unread source" {
						if _, err := executeTool(ctx, tools, "inspect_dispatch", input, nil); err != nil {
							return "", err
						}
					}
					review := AIEdgeReview{Step: 3, Status: "ruled_out", CallSite: citation, ValueOrigin: append([]AISourceCitation(nil), origins...), Reasoning: "main passes the context.WithCancel result into Start; its captured cancel cannot be Serve's closure."}
					if tc.name == "fabricated origin" {
						review.ValueOrigin[0].Quote = "cancel := somethingElse()"
					}
					alternate := "Reviewed main, the fixture's only entry, and its callback argument; no path supplies Serve's closure."
					if tc.name == "missing alternate review" {
						alternate = ""
					}
					a := &AIVerification{IsVulnerable: "false", Confidence: "high", Reasoning: review.Reasoning, Evidence: []string{review.Reasoning},
						GraphAnalysis: AIGraphAnalysis{Summary: "Cancellation callback is overapproximated", AlternativePaths: alternate, ScopeEvidence: origins, Findings: []AIGraphFinding{{
							Kind: "suspected_false_positive", Module: ".", Package: "example.com/dependency", Symbol: "Serve", GraphPath: path,
							SourcePath: []string{citation.File + ":3"}, EdgeReviews: []AIEdgeReview{review}, Confidence: "high", Reasoning: review.Reasoning,
							Evidence: []string{review.Reasoning}, Uncertainties: []string{},
						}}}, DynamicAnalysis: AIDynamicAnalysis{Summary: "No further dynamic usage found in the fixture", Findings: []AIDynamicFinding{}}, Uncertainties: []string{},
					}
					raw, err := marshalAuditResponseForTest(a)
					return string(raw), err
				})
				verifyWithAgent(context.Background(), result, repo, aiConfig{}, agent)
				if result.IsVulnerable != "true" || result.AIVerification == nil || result.AIVerification.IsVulnerable != tc.want {
					t.Fatalf("want AI=%s with scanner unchanged, got %+v; errors %v", tc.want, result.AIVerification, result.Errors)
				}
			})
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executeTool(ctx, []verificationTool{inspector}, "inspect_dispatch", []byte(`{}`), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled inspection: %v", err)
	}
}

func TestInspectDispatchSourceQuoteBounds(t *testing.T) {
	repo, dependency := t.TempDir(), t.TempDir()
	local, external := filepath.Join(repo, "main.go"), filepath.Join(dependency, "dep.go")
	for _, path := range []string{local, external} {
		if err := os.WriteFile(path, []byte("package fixture\n"+strings.Repeat("x", maxToolResultBytes)+"\nfunc target() {}\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name      string
		path      string
		line      int
		indexed   bool
		wantQuote bool
	}{
		{"repository source", "main.go", 1, false, true},
		{"indexed dependency", external, 1, true, true},
		{"unindexed dependency", external, 1, false, false},
		{"missing file", "missing.go", 1, false, false},
		{"oversized source line", "main.go", 2, false, false},
		{"missing line", "main.go", 99, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool := &inspectDispatchTool{repoDir: repo, sourceFiles: map[string]bool{external: tc.indexed}}
			output, citations := tool.sourceQuotes(context.Background(), []token.Position{{Filename: tc.path, Line: tc.line}, {Filename: "main.go", Line: 3}})
			wantCount := 1
			if tc.wantQuote {
				wantCount++
			}
			if len(citations) != wantCount || len(output) > maxToolResultBytes || strings.Contains(output, "omitted") == tc.wantQuote {
				t.Fatalf("unexpected source availability: %+v, %q", citations, output)
			}
			// A missing or oversized row must not prevent later usable source.
			last := citations[len(citations)-1]
			if last.File != local || last.Line != 3 || last.Quote != "func target() {}" {
				t.Fatalf("lost later source: %+v", citations)
			}
			for _, citation := range citations {
				if !strings.Contains(output, verificationSourceQuote(citation)) {
					t.Fatalf("metadata quote not shown in output: %+v", citation)
				}
			}
		})
	}
}

func TestCheckModuleVendorMethodDeclarations(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken=%v", broken), func(t *testing.T) {
			dir := t.TempDir()
			vendor := filepath.Join(dir, "vendor", "example.com", "grpc")
			if err := os.MkdirAll(vendor, 0755); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"go.mod": "module example.com/app\n\ngo 1.21\n",
				"vendor/example.com/grpc/server.go": `package grpc
 type Server struct{}
 type Other struct{}
 type Generic[T any] struct{}
 func (*Server) Serve() {}
 func (Server) ServeHTTP() {}
 func (*Server) handleStream() {}
 func (Other) Missing() {}
 func (*Generic[T]) Call() {}
 func NewServer() {}
 `,
			}
			if broken {
				files["vendor/example.com/grpc/broken.go"] = "package grpc\nfunc ("
			}
			for name, source := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := (&checkModuleTool{repoDir: dir}).Execute(context.Background(), []byte(`{"package":"example.com/grpc","symbols":["Server.Serve","Server.ServeHTTP","Server.handleStream","Server.Missing","Generic.Call","NewServer"]}`))
			if err != nil {
				t.Fatal(err)
			}
			for _, symbol := range []string{"Server.Serve", "Server.ServeHTTP", "Server.handleStream", "Generic.Call", "NewServer"} {
				if !strings.Contains(got, symbol+": server.go:") {
					t.Errorf("missing declaration %s: %s", symbol, got)
				}
			}
			missing := "Server.Missing: no declaration"
			if broken {
				missing = "Server.Missing: unknown; declaration search incomplete"
			}
			if !strings.Contains(got, missing) {
				t.Fatalf("incorrect absence evidence: %s", got)
			}
		})
	}
}

func TestCheckTransitiveDepsPackageSubpath(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":            "module example.com/app\n\ngo 1.21\nrequire example.com/dependency v0.0.0\nreplace example.com/dependency => ./dep\n",
		"main.go":           "package main\nimport _ \"example.com/dependency/subpkg\"\nfunc main() {}\n",
		"dep/go.mod":        "module example.com/dependency\n\ngo 1.21\n",
		"dep/subpkg/pkg.go": "package subpkg\n",
	}
	for name, source := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := (&checkTransitiveDepsTool{repoDir: dir}).Execute(context.Background(), []byte(`{"package":"example.com/dependency/subpkg"}`))
	if err != nil || !strings.Contains(got, "  example.com/app\n  example.com/dependency/subpkg") {
		t.Fatalf("expected package import chain, got %s, %v", got, err)
	}
	if strings.Contains(got, "does not need") {
		t.Fatalf("used package incorrectly reported unused: %s", got)
	}
}

func TestAIGraphDispatchEvidence(t *testing.T) {
	repo := t.TempDir()
	code := `package main
 import "context"
 func WithCancel() context.CancelFunc { _, cancel := context.WithCancel(context.Background()); return cancel }
 func shutdown(cancel context.CancelFunc) { cancel() }
 func Serve() { go func() { println("server") }() }
 func main() { cancel := WithCancel(); shutdown(cancel) }
 `
	filePath := filepath.Join(repo, "main.go")
	if err := os.WriteFile(filePath, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.com/test\n\ngo 1.21\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ALGO", "cha")
	scan := &Result{ScanConfig: ScanConfig{Directory: repo}}
	build := scan.getSSABuild(repo)
	if build == nil {
		t.Fatalf("fixture build failed: %v", scan.Errors)
	}
	var pkg *ssa.Package
	for _, candidate := range build.prog.AllPackages() {
		if candidate.Pkg.Path() == "example.com/test" {
			pkg = candidate
		}
	}
	if pkg == nil {
		t.Fatal("fixture package missing")
	}
	graph := build.cg
	caller := graph.Nodes[pkg.Func("shutdown")]
	phantom := graph.Nodes[pkg.Func("Serve").AnonFuncs[0]]
	var edge *callgraph.Edge
	for _, candidate := range caller.Out {
		if candidate.Callee == phantom {
			edge = candidate
		}
	}
	if edge == nil {
		t.Fatal("fixture must reproduce CHA's CancelFunc to unrelated closure edge")
	}
	path := []string{caller.Func.String(), phantom.Func.String()}
	result := &Result{ScanConfig: ScanConfig{Directory: repo}, AffectedImports: map[string]AffectedImportsDetails{"example.com/test": {Symbols: []string{"Serve"}}}, UsedImports: map[string]map[string]UsedImportsDetails{".": {"example.com/test": {Symbols: []string{"Serve"}, Paths: [][]*callgraph.Node{{caller, phantom}}}}}, ssaBuilds: map[string]*ssaBuild{repo: {cg: graph, prog: pkg.Prog}}}
	snippets := map[string]string{"main.go": "3| func WithCancel() context.CancelFunc { _, cancel := context.WithCancel(context.Background()); return cancel }\n4| func shutdown(cancel context.CancelFunc) { cancel() }\n6| func main() { cancel := WithCancel(); shutdown(cancel) }\n"}
	origin := AISourceCitation{File: "main.go", Line: 6, Quote: "func main() { cancel := WithCancel(); shutdown(cancel) }"}
	review := AIEdgeReview{Step: 1, Status: "ruled_out", CallSite: AISourceCitation{File: "main.go", Line: 4, Quote: "func shutdown(cancel context.CancelFunc) { cancel() }"}, ValueOrigin: []AISourceCitation{origin}, Reasoning: "cancel originates from WithCancel, not Serve's closure."}
	for _, tc := range []struct {
		name    string
		verdict string
		kind    string
		reviews []AIEdgeReview
		want    string
	}{
		{"graph alone", "true", "supported_path", nil, "unknown"},
		{"unreviewed path", "false", "", nil, "unknown"},
		{"source refutation", "false", "suspected_false_positive", []AIEdgeReview{review}, "false"},
		{"missing origin", "false", "suspected_false_positive", []AIEdgeReview{{Step: 1, Status: "ruled_out", CallSite: review.CallSite, Reasoning: "CHA phantom"}}, "unknown"},
		{"fabricated quotation", "false", "suspected_false_positive", []AIEdgeReview{{Step: 1, Status: "ruled_out", CallSite: review.CallSite, ValueOrigin: []AISourceCitation{{File: "main.go", Line: 6, Quote: "not the actual source"}}, Reasoning: "CHA phantom"}}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &AIVerification{IsVulnerable: tc.verdict, Confidence: "high", Reasoning: "Model conclusion", Evidence: []string{"Model evidence"}, GraphAnalysis: AIGraphAnalysis{AlternativePaths: "Checked alternate callers in the graph and the callback origin in source.", ScopeEvidence: []AISourceCitation{origin}}}
			if tc.kind != "" {
				a.GraphAnalysis.Findings = []AIGraphFinding{{Kind: tc.kind, Module: ".", Package: "example.com/test", Symbol: "Serve", GraphPath: path, SourcePath: []string{"main.go:4"}, EdgeReviews: tc.reviews}}
			}
			validateGraphEvidence(result, repo, a, newVerificationEvidence(repo, snippets))
			if a.IsVulnerable != tc.want {
				t.Fatalf("verdict=%s, want %s: %+v", a.IsVulnerable, tc.want, a)
			}
			if tc.want == "unknown" && (a.Confidence != "low" || len(a.Uncertainties) == 0) {
				t.Fatalf("missing validation gap: %+v", a)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("{{.source_snippets}}\n{{.call_traces}}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	result.IsVulnerable = "true"
	agent := fakeAgent(func(context.Context, string, []verificationTool) (string, error) {
		a := &AIVerification{IsVulnerable: "true", Confidence: "high", Reasoning: "The scanner graph proves vulnerability", Evidence: []string{"Graph exists"}, GraphAnalysis: AIGraphAnalysis{Summary: "Candidate accepted", Findings: []AIGraphFinding{{Kind: "supported_path", Module: ".", Package: "example.com/test", Symbol: "Serve", GraphPath: path, SourcePath: []string{"main.go:4: cancel()"}, Confidence: "high", Reasoning: "Matching signature", Evidence: []string{"Graph exists"}, Uncertainties: []string{}}}}, DynamicAnalysis: AIDynamicAnalysis{Summary: "No risks supplied", Findings: []AIDynamicFinding{}}, Uncertainties: []string{}}
		raw, err := marshalAuditResponseForTest(a)
		return string(raw), err
	})
	verifyWithAgent(context.Background(), result, repo, aiConfig{}, agent)
	if result.IsVulnerable != "true" || result.AIVerification == nil || result.AIVerification.IsVulnerable != "unknown" {
		t.Fatalf("batch did not preserve scanner verdict and reject unsupported AI claim: %+v", result)
	}
	raw, err := json.Marshal(result.AIVerification)
	if err != nil || strings.Contains(string(raw), "The scanner graph proves vulnerability") || strings.Contains(string(raw), "edge_reviews") {
		t.Fatalf("unsupported claim or internal fields leaked: %s, %v", raw, err)
	}

}

func TestAIGraphSupportedAndAlternatePaths(t *testing.T) {
	repo := t.TempDir()
	code := `package main
func target() {}
func invoke(f func()) { f() }
func main() { invoke(target) }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(repo, "main.go"), code, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage("example.com/test", "main"), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	graph := cha.CallGraph(pkg.Prog)
	main, invoke, target := graph.Nodes[pkg.Func("main")], graph.Nodes[pkg.Func("invoke")], graph.Nodes[pkg.Func("target")]
	path := []*callgraph.Node{main, invoke, target}
	names := []string{main.Func.String(), invoke.Func.String(), target.Func.String()}
	r := &Result{ScanConfig: ScanConfig{Directory: repo}, UsedImports: map[string]map[string]UsedImportsDetails{".": {"example.com/test": {Symbols: []string{"target"}, Paths: [][]*callgraph.Node{path}}}}, ssaBuilds: map[string]*ssaBuild{repo: {cg: graph}}}
	snippets := map[string]string{"main.go": "3|func invoke(f func()) { f() }\n4|func main() { invoke(target) }\n"}
	origin := AISourceCitation{File: "main.go", Line: 4, Quote: "func main() { invoke(target) }"}
	review := AIEdgeReview{Step: 2, Status: "supported", CallSite: AISourceCitation{File: "main.go", Line: 3, Quote: "func invoke(f func()) { f() }"}, ValueOrigin: []AISourceCitation{origin}, Reasoning: "main passes target to invoke"}
	for _, tc := range []struct {
		name   string
		mutate func(*AIVerification)
		want   string
	}{
		{"supported dispatch", func(a *AIVerification) {}, "true"},
		{"missing dispatch evidence", func(a *AIVerification) { a.GraphAnalysis.Findings[0].EdgeReviews = nil }, "unknown"},
		{"wrong callsite", func(a *AIVerification) { a.GraphAnalysis.Findings[0].EdgeReviews[0].CallSite = origin }, "unknown"},
		{"invented edge", func(a *AIVerification) {
			a.GraphAnalysis.Findings[0].GraphPath = []string{main.Func.String(), target.Func.String()}
		}, "unknown"},
		{"unresolved dispatch", func(a *AIVerification) { a.GraphAnalysis.Findings[0].EdgeReviews[0].Status = "unresolved" }, "unknown"},
		{"another valid path preserves positive", func(a *AIVerification) {
			a.GraphAnalysis.Findings = append(a.GraphAnalysis.Findings, AIGraphFinding{Kind: "inconclusive", Uncertainties: []string{"another callback unresolved"}})
		}, "true"},
		{"negative missing alternate review", func(a *AIVerification) { a.IsVulnerable = "false" }, "unknown"},
		{"negative with version exclusion and scope", func(a *AIVerification) {
			a.IsVulnerable = "false"
			a.Reasoning = "Resolved dependency version is fixed"
			a.GraphAnalysis.AlternativePaths = "Reviewed entry and all reported paths; version excludes vulnerability"
			a.GraphAnalysis.ScopeEvidence = []AISourceCitation{origin}
		}, "false"},
		{"negative with string scope citation", func(a *AIVerification) {
			a.IsVulnerable = "false"
			a.GraphAnalysis.AlternativePaths = "Reviewed entry and all reported paths; version excludes vulnerability"
			if err := json.Unmarshal([]byte(`["main.go:4: func main() { invoke(target) }"]`), &a.GraphAnalysis.ScopeEvidence); err != nil {
				t.Fatal(err)
			}
		}, "false"},
		{"negative required prose citation", func(a *AIVerification) {
			a.IsVulnerable = "false"
			a.GraphAnalysis.AlternativePaths = "Checked"
			if err := json.Unmarshal([]byte(`["grep_code: no other callers found"]`), &a.GraphAnalysis.ScopeEvidence); err != nil {
				t.Fatal(err)
			}
		}, "unknown"},
		{"negative unresolved reflection", func(a *AIVerification) {
			a.IsVulnerable = "false"
			a.GraphAnalysis.AlternativePaths = "Checked"
			a.GraphAnalysis.ScopeEvidence = []AISourceCitation{origin}
			a.DynamicAnalysis.Findings = []AIDynamicFinding{{Status: "unresolved", Uncertainties: []string{"runtime reflection target unresolved"}}}
		}, "unknown"},
		{"negative leaves another path unreviewed", func(a *AIVerification) {
			a.IsVulnerable = "false"
			a.GraphAnalysis.AlternativePaths = "Checked"
			a.GraphAnalysis.ScopeEvidence = []AISourceCitation{origin}
			a.GraphAnalysis.Findings[0].GraphPath = names[1:]
			a.GraphAnalysis.Findings[0].EdgeReviews[0].Step = 1
		}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &AIVerification{IsVulnerable: "true", Confidence: "high", GraphAnalysis: AIGraphAnalysis{Findings: []AIGraphFinding{{Kind: "supported_path", Module: ".", Package: "example.com/test", Symbol: "target", GraphPath: append([]string(nil), names...), EdgeReviews: []AIEdgeReview{review}}}}}
			tc.mutate(a)
			validateGraphEvidence(r, repo, a, newVerificationEvidence(repo, snippets))
			if a.IsVulnerable != tc.want {
				t.Fatalf("want %s; got %+v", tc.want, a)
			}
		})
	}
}

func TestVerificationEvidenceRetrieval(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\nfunc target() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := newVerificationEvidence(repo, map[string]string{"main.go": "1|package main\n"})
	citation := AISourceCitation{File: "main.go", Line: 2, Quote: "func target() {}"}
	if e.check(citation) == nil {
		t.Fatal("unread source accepted")
	}
	tool := &verificationEvidenceTool{verificationTool: &readFileTool{repoDir: repo}, evidence: e}
	if _, err := tool.Execute(context.Background(), []byte(`{"path":"main.go","start_line":2,"end_line":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := e.check(citation); err != nil {
		t.Fatal(err)
	}
	citation.File = filepath.Join(repo, "main.go")
	if err := e.check(citation); err != nil {
		t.Fatal(err)
	}
	citation.File = "../main.go"
	if e.check(citation) == nil {
		t.Fatal("outside source accepted")
	}
	e.add("partial.go", "2|truncated without newline")
	if e.check(AISourceCitation{File: "partial.go", Line: 2, Quote: "truncated without newline"}) == nil {
		t.Fatal("partial line accepted")
	}
}

func TestVerificationDependencySourceAccess(t *testing.T) {
	repo, dependency := t.TempDir(), t.TempDir()
	path := filepath.Join(dependency, "target.go")
	if err := os.WriteFile(path, []byte("package dependency\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	fset.AddFile(path, -1, 19)
	r := &Result{ssaBuilds: map[string]*ssaBuild{repo: {prog: ssa.NewProgram(fset, 0)}}}
	e := newVerificationEvidence(repo, nil)
	e.sourceFiles = verificationSourceFiles(r)
	tool := &verificationEvidenceTool{verificationTool: &readFileTool{repoDir: repo, sourceFiles: e.sourceFiles}, evidence: e}
	input, _ := json.Marshal(map[string]any{"path": path})
	if _, err := tool.Execute(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if err := e.check(AISourceCitation{File: path, Line: 1, Quote: "package dependency"}); err != nil {
		t.Fatal(err)
	}
	unlisted := filepath.Join(dependency, "unlisted.go")
	if err := os.WriteFile(unlisted, []byte("package secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input, _ = json.Marshal(map[string]any{"path": unlisted})
	output, err := tool.Execute(context.Background(), input)
	if err != nil || strings.Contains(output, "package secret") || !strings.Contains(output, "escapes repository") {
		t.Fatalf("unindexed external file was accessible: %q, %v", output, err)
	}
}

func TestAIGraphInterfaceDispatch(t *testing.T) {
	repo := t.TempDir()
	code := `package main
 type Runner interface { Run() }
 type service struct{}
 func (service) Run() {}
 func invoke(r Runner) { r.Run() }
 func main() { invoke(service{}) }
 `
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(repo, "main.go"), code, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage("example.com/test", "main"), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	graph := cha.CallGraph(pkg.Prog)
	caller := graph.Nodes[pkg.Func("invoke")]
	var callee *callgraph.Node
	for _, edge := range caller.Out {
		if symbolForObject(edge.Callee.Func.Object()) == "service.Run" {
			callee = edge.Callee
		}
	}
	if callee == nil {
		t.Fatal("interface dispatch edge missing")
	}
	r := &Result{ssaBuilds: map[string]*ssaBuild{repo: {cg: graph}}}
	e := newVerificationEvidence(repo, map[string]string{"main.go": "5| func invoke(r Runner) { r.Run() }\n6| func main() { invoke(service{}) }\n"})
	for _, supported := range []bool{false, true} {
		t.Run(fmt.Sprintf("review=%v", supported), func(t *testing.T) {
			f := AIGraphFinding{Kind: "supported_path", Module: ".", Package: "example.com/test", Symbol: "service.Run", GraphPath: []string{caller.Func.String(), callee.Func.String()}}
			if supported {
				f.EdgeReviews = []AIEdgeReview{{Step: 1, Status: "supported", CallSite: AISourceCitation{File: "main.go", Line: 5, Quote: "func invoke(r Runner) { r.Run() }"}, ValueOrigin: []AISourceCitation{{File: "main.go", Line: 6, Quote: "func main() { invoke(service{}) }"}}, Reasoning: "The receiver passed by main is service{}"}}
			}
			err := validateGraphFinding(r, repo, &f, e)
			if (err == nil) != supported {
				t.Fatalf("supported=%v, error=%v", supported, err)
			}
		})
	}
}

func TestSourceCitationJSONCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, input, file, quote string
		line                     int
		parseError               bool
	}{
		{name: "object", input: `{"file":"main.go","line":4,"quote":"func main() {}"}`, file: "main.go", line: 4, quote: "func main() {}"},
		{name: "string", input: `"main.go:4: func main() {}"`, file: "main.go", line: 4, quote: "func main() {}"},
		{name: "string with column", input: `"main.go:4:7: func main() {}"`, file: "main.go", line: 4, quote: "func main() {}"},
		{name: "absolute path and colon in source", input: `"/tmp/repo/main.go:4: x := \"a:b\""`, file: "/tmp/repo/main.go", line: 4, quote: `x := "a:b"`},
		{name: "Windows path", input: `"C:\\repo\\main.go:4: func main() {}"`, file: `C:\repo\main.go`, line: 4, quote: "func main() {}"},
		{name: "prose remains unverified", input: `"grep_code: no server calls found"`},
		{name: "location alone remains unverified", input: `"main.go:4"`},
		{name: "zero line remains unverified", input: `"main.go:0: func main() {}"`},
		{name: "overflow remains unverified", input: `"main.go:999999999999999999999999: func main() {}"`},
		{name: "missing quote", input: `"main.go:4: "`, file: "main.go", line: 4},
		{name: "invalid object type", input: `{"file":"main.go","line":"4","quote":"func main() {}"}`, parseError: true},
		{name: "number", input: `42`, parseError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var citation AISourceCitation
			err := json.Unmarshal([]byte(tc.input), &citation)
			if (err != nil) != tc.parseError {
				t.Fatalf("parse error=%v, want error=%v", err, tc.parseError)
			}
			if err != nil {
				return
			}
			if citation.File != tc.file || citation.Line != tc.line || citation.Quote != tc.quote {
				t.Fatalf("citation=%+v", citation)
			}
			e := newVerificationEvidence(t.TempDir(), map[string]string{"main.go": "4|func main() {}\n"})
			if tc.file == "" || tc.quote == "" {
				if e.check(citation) == nil {
					t.Fatal("unstructured or incomplete citation accepted as verified source")
				}
			} else if tc.file == "main.go" {
				if err := e.check(citation); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAssessmentStringSourceCitations(t *testing.T) {
	var response map[string]any
	if err := json.Unmarshal([]byte(testAssessment), &response); err != nil {
		t.Fatal(err)
	}
	graph := response["graph_analysis"].(map[string]any)
	graph["scope_evidence"] = []any{"main.go:4: func main() {}", "grep_code: no production server calls found", map[string]any{"file": "main.go", "line": 4, "quote": "func main() {}"}}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	a, err := parseAssessment(string(data))
	if err != nil {
		t.Fatalf("string citation discarded the assessment: %v", err)
	}
	if len(a.GraphAnalysis.ScopeEvidence) != 3 {
		t.Fatal("citation entries were dropped")
	}
	repo := t.TempDir()
	e := newVerificationEvidence(repo, map[string]string{"main.go": "4|func main() {}\n"})
	if err := e.check(a.GraphAnalysis.ScopeEvidence[0]); err != nil {
		t.Fatal(err)
	}
	if e.check(a.GraphAnalysis.ScopeEvidence[1]) == nil {
		t.Fatal("prose upgraded to source evidence")
	}
	// No reported paths: optional scope citation formatting must not fail the audit.
	validateGraphEvidence(&Result{}, repo, a, e)
	if a.IsVulnerable != "false" {
		t.Fatalf("optional scope evidence changed verdict: %+v", a)
	}
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("Assess"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	result := &Result{IsVulnerable: "false"}
	verifyWithAgent(context.Background(), result, repo, aiConfig{}, fakeAgent(func(context.Context, string, []verificationTool) (string, error) { return string(data), nil }))
	if len(result.Errors) != 0 || result.AIVerification == nil || result.AIVerification.IsVulnerable != "false" {
		t.Fatalf("optional citation formatting failed the investigation: errors=%v assessment=%+v", result.Errors, result.AIVerification)
	}
	// Edge citation fields use the same decoder and retain exact quote validation.
	var edge AIEdgeReview
	if err := json.Unmarshal([]byte(`{"step":1,"status":"supported","call_site":"main.go:4: func main() {}","value_origin":["main.go:4: fabricated source"],"reasoning":"source flow"}`), &edge); err != nil {
		t.Fatal(err)
	}
	if err := e.check(edge.CallSite); err != nil {
		t.Fatal(err)
	}
	if e.check(edge.ValueOrigin[0]) == nil {
		t.Fatal("fabricated quote accepted")
	}
}

func TestAssessmentStructuredSourcePaths(t *testing.T) {
	for _, section := range []string{"graph_analysis", "dynamic_analysis"} {
		for _, tc := range []struct {
			name, path, location string
			valid                bool
		}{
			{"string", `["main.go:8: main -> Run"]`, "main.go:8", true},
			{"file and line", `[{"file":"main.go","line":8,"function":"main -> Run"}]`, "main.go:8", true},
			{"location", `[{"location":"main.go:8:3","caller":"main","callee":"Run"}]`, "main.go:8:3", true},
			{"path alias and string line", `[{"path":"main.go","line":"8","description":"main -> Run"}]`, "main.go:8", true},
			{"mixed steps", `["main.go:8: main",{"file":"worker.go","line":12,"function":"Run","details":{"receiver":"service"}}]`, "worker.go:12", true},
			{"empty object", `[{}]`, "", false},
			{"no location", `[{"function":"Run"}]`, "", false},
			{"missing line", `[{"file":"main.go"}]`, "", false},
			{"zero line", `[{"file":"main.go","line":0}]`, "", false},
			{"invalid line", `[{"file":"main.go","line":"eight"}]`, "", false},
			{"fractional line", `[{"file":"main.go","line":8.5}]`, "", false},
			{"overflow line", `[{"file":"main.go","line":"999999999999999999999999"}]`, "", false},
			{"invalid location", `[{"location":"main.go:0","function":"Run"}]`, "", false},
			{"empty string", `[""]`, "", false},
			{"null step", `[null]`, "", false},
			{"number step", `[123]`, "", false},
			{"non-array", `{"file":"main.go","line":8}`, "", false},
			{"missing required path", `null`, "", false},
			{"empty required path", `[]`, "", false},
		} {
			t.Run(section+"/"+tc.name, func(t *testing.T) {
				raw, err := marshalAuditResponseForTest(auditFixture(t))
				if err != nil {
					t.Fatal(err)
				}
				var response map[string]any
				if err := json.Unmarshal(raw, &response); err != nil {
					t.Fatal(err)
				}
				finding := response[section].(map[string]any)["findings"].([]any)[0].(map[string]any)
				finding["source_path"] = json.RawMessage(tc.path)
				raw, err = json.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				a, err := parseAssessment(string(raw))
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%v, err=%v", tc.valid, err)
				}
				if err != nil {
					return
				}
				path := a.GraphAnalysis.Findings[0].SourcePath
				if section == "dynamic_analysis" {
					path = a.DynamicAnalysis.Findings[0].SourcePath
				}
				if !strings.Contains(strings.Join(path, "\n"), tc.location) {
					t.Fatalf("location lost: %v", path)
				}
				if tc.name == "mixed steps" && !strings.Contains(path[1], `"receiver":"service"`) {
					t.Fatalf("source details lost: %v", path)
				}
				if tc.name == "string" && path[0] != "main.go:8: main -> Run" {
					t.Fatalf("string step changed: %v", path)
				}
				encoded, err := json.Marshal(path)
				if err != nil {
					t.Fatal(err)
				}
				var canonical []string
				if err := json.Unmarshal(encoded, &canonical); err != nil {
					t.Fatalf("normalized path is not strings: %v", err)
				}
				result := &Result{AffectedImports: map[string]AffectedImportsDetails{"example.com/p": {Symbols: []string{"Run"}}}, ReflectionRisks: make([]ReflectionRisk, 2)}
				if err := validateAuditTargets(result, a); err != nil {
					t.Fatal(err)
				}
				a.GraphAnalysis.Findings[0].Symbol = "invented"
				if validateAuditTargets(result, a) == nil {
					t.Fatal("normalization bypassed affected-symbol validation")
				}
			})
		}
	}
}

func TestStructuredSourcePathStillRequiresGraphEvidence(t *testing.T) {
	a := auditFixture(t)
	a.IsVulnerable = "true"
	a.GraphAnalysis.Findings[0].Kind = "supported_path"
	a.GraphAnalysis.Findings[0].GraphPath = []string{"example.com/p.main", "example.com/p.Run"}
	a.DynamicAnalysis.Findings = []AIDynamicFinding{}
	raw, err := marshalAuditResponseForTest(a)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	finding := response["graph_analysis"].(map[string]any)["findings"].([]any)[0].(map[string]any)
	finding["source_path"] = []any{map[string]any{"file": "main.go", "line": 8, "function": "main -> Run"}}
	raw, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("Assess"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	result := &Result{IsVulnerable: "true", AffectedImports: map[string]AffectedImportsDetails{"example.com/p": {Symbols: []string{"Run"}}}}
	verifyWithAgent(context.Background(), result, repo, aiConfig{}, fakeAgent(func(context.Context, string, []verificationTool) (string, error) { return string(raw), nil }))
	if len(result.Errors) != 0 || result.AIVerification == nil {
		t.Fatalf("structured source step failed parsing: errors=%v assessment=%+v", result.Errors, result.AIVerification)
	}
	if result.IsVulnerable != "true" || result.AIVerification.IsVulnerable != "unknown" || result.AIVerification.GraphAnalysis.Findings[0].Kind != "inconclusive" {
		t.Fatalf("normalization bypassed graph checks or changed scanner verdict: %+v", result)
	}
	public, err := json.Marshal(result.AIVerification)
	if err != nil || strings.Contains(string(public), `"source_path"`) {
		t.Fatalf("internal path leaked into public output: %s, %v", public, err)
	}
}

func TestIncompleteGraphAuditDiagnostics(t *testing.T) {
	repo := t.TempDir()
	code := "package main\nfunc one() {}\nfunc two() {}\nfunc main() { one(); two() }\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(repo, "main.go"), code, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage("example.com/test", "main"), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	graph := cha.CallGraph(pkg.Prog)
	main, one, two := graph.Nodes[pkg.Func("main")], graph.Nodes[pkg.Func("one")], graph.Nodes[pkg.Func("two")]
	r := &Result{ScanConfig: ScanConfig{Directory: repo}, UsedImports: map[string]map[string]UsedImportsDetails{".": {"example.com/test": {Symbols: []string{"one", "two", "one"}, Paths: [][]*callgraph.Node{{main, one}, {main, two}, {main, one}}}}}}
	a := &AIVerification{IsVulnerable: "false", Confidence: "high", Reasoning: "Unsupported model conclusion", Evidence: []string{"Unsupported model claim"}, GraphAnalysis: AIGraphAnalysis{ScopeEvidence: []AISourceCitation{{File: "main.go", Line: 4, Quote: "func main() { one(); two() }"}}}}
	validateGraphEvidence(r, repo, a, newVerificationEvidence(repo, map[string]string{"main.go": "4|func main() { one(); two() }\n"}))
	if a.IsVulnerable != "unknown" || a.Confidence != "low" {
		t.Fatalf("missing coverage accepted: %+v", a)
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var public struct {
		Evidence  []string `json:"evidence"`
		Reasoning string   `json:"reasoning"`
	}
	if err := json.Unmarshal(data, &public); err != nil {
		t.Fatal(err)
	}
	for _, gap := range a.Uncertainties {
		if strings.Count(public.Reasoning, gap) != 1 {
			t.Errorf("gap repeated or lost: %q in %q", gap, public.Reasoning)
		}
	}
	if !strings.Contains(public.Reasoning, "2 scanner candidate paths") {
		t.Errorf("missing unique-path count: %s", public.Reasoning)
	}
	joined := strings.Join(public.Evidence, "\n")
	for _, want := range []string{"example.com/test.one", "example.com/test.two", "main.go:4", "AI proposed IsVulnerable=false"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostic missing %q: %s", want, joined)
		}
	}
	if strings.Contains(string(data), "Unsupported model") {
		t.Fatal("unvalidated model conclusion leaked")
	}
	if strings.Count(joined, "target=example.com/test.one") != 1 {
		t.Fatalf("duplicate path diagnostic: %s", joined)
	}
}

func TestUnknownAuditKeepsItsExplanation(t *testing.T) {
	a := &AIVerification{IsVulnerable: "unknown", Confidence: "low", Reasoning: "Receiver type depends on the plugin configuration.", Evidence: []string{"registry.go:12: receiver is provided by plugin"}, Uncertainties: []string{"Plugin receiver not resolved"}, DynamicAnalysis: AIDynamicAnalysis{Findings: []AIDynamicFinding{{Status: "unresolved", Uncertainties: []string{"Plugin receiver not resolved"}}}}}
	validateGraphEvidence(&Result{}, t.TempDir(), a, newVerificationEvidence(t.TempDir(), nil))
	if a.Reasoning != "Receiver type depends on the plugin configuration." || len(a.Uncertainties) != 1 {
		t.Fatalf("useful uncertainty explanation lost or duplicated: %+v", a)
	}
}

func TestBackendsBoundedAssessmentCorrection(t *testing.T) {
	for _, provider := range []string{"anthropic-vertex", "openai-compatible"} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure=%v", provider, failure), func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					var request map[string]json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
					}
					if calls == 2 {
						for _, want := range []string{"original evidence", "draft assessment", "step 3 needs value origin"} {
							if !strings.Contains(string(request["messages"]), want) {
								t.Errorf("correction lost %q: %s", want, request["messages"])
							}
						}
						if !strings.Contains(string(request["tool_choice"]), "none") {
							t.Errorf("correction must disable tools: %s", request["tool_choice"])
						}
						if failure {
							w.WriteHeader(500)
							return
						}
					}
					text := "draft assessment"
					if calls > 1 {
						text = "corrected assessment"
					}
					w.Header().Set("Content-Type", "application/json")
					if provider == "anthropic-vertex" {
						json.NewEncoder(w).Encode(map[string]any{"id": "reply", "type": "message", "role": "assistant", "model": "test-model", "stop_reason": "end_turn", "content": []any{map[string]string{"type": "text", "text": text}}, "usage": map[string]int{"input_tokens": 100, "output_tokens": 10, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}})
					} else {
						json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": text}}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 10}})
					}
				}))
				defer server.Close()
				agent := backendForTest(provider, server.URL, 0)
				reviewer := agent.(reviewingVerificationAgent)
				reviews := 0
				output, err := reviewer.RunReviewed(context.Background(), "original evidence", nil, func(string) string { reviews++; return "step 3 needs value origin" })
				want := "corrected assessment"
				if failure {
					want = "draft assessment"
				}
				if err != nil || output != want || calls != 2 || reviews != 1 {
					t.Fatalf("output=%q err=%v calls=%d reviews=%d", output, err, calls, reviews)
				}
				usage := agent.(interface{ usageTotals() *verificationUsageLog }).usageTotals()
				if usage.requests != 2 || (!failure && usage.reports != 2) {
					t.Fatalf("correction usage missing: %+v", usage)
				}
			})
		}
	}
}

func TestValidatedPositiveSurvivesOtherBatchGaps(t *testing.T) {
	positive := &AIVerification{IsVulnerable: "true", Confidence: "high", Reasoning: "Verified affected invocation", Evidence: []string{"source-backed target call"}, validatedPositive: true}
	for _, others := range [][]*AIVerification{{{IsVulnerable: "unknown", Reasoning: "Other runtime value unresolved"}}, {{IsVulnerable: "false", Reasoning: "Other candidate was refuted"}}} {
		merged := mergeVerificationAssessments(append([]*AIVerification{positive}, others...), []string{"another batch timed out"})
		if merged.IsVulnerable != "true" || !merged.validatedPositive || !strings.Contains(merged.Reasoning, positive.Reasoning) {
			t.Fatalf("decisive positive lost: %+v", merged)
		}
	}
	unvalidated := &AIVerification{IsVulnerable: "true", Reasoning: "unverified model assertion"}
	merged := mergeVerificationAssessments([]*AIVerification{unvalidated, {IsVulnerable: "unknown"}}, nil)
	if merged.IsVulnerable != "unknown" {
		t.Fatalf("unvalidated positive accepted: %+v", merged)
	}
}

func TestSharedDispatchRefutation(t *testing.T) {
	repo := t.TempDir()
	code := `package main
func target() {}
func other() {}
func bridge() { target(); other() }
func invoke(f func()) { f() }
func safe() {}
func alternate() { invoke(bridge) }
func main() { invoke(safe) }
`
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(repo, "main.go"), code, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage("example.com/test", "main"), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	graph := cha.CallGraph(pkg.Prog)
	node := func(name string) *callgraph.Node { return graph.Nodes[pkg.Func(name)] }
	path := []*callgraph.Node{node("main"), node("invoke"), node("bridge"), node("target")}
	names := []string{path[0].Func.String(), path[1].Func.String(), path[2].Func.String(), path[3].Func.String()}
	origin := AISourceCitation{File: "main.go", Line: 8, Quote: "func main() { invoke(safe) }"}
	review := AIEdgeReview{Step: 2, Status: "ruled_out", CallSite: AISourceCitation{File: "main.go", Line: 5, Quote: "func invoke(f func()) { f() }"}, ValueOrigin: []AISourceCitation{origin}, Reasoning: "main passes safe; this invocation of f cannot call bridge"}
	evidence := newVerificationEvidence(repo, map[string]string{"main.go": "5|func invoke(f func()) { f() }\n8|func main() { invoke(safe) }\n"})
	for _, tc := range []struct{ name, module, caller, want string }{
		{"same prefix", ".", "main", "false"},
		{"different calling context", ".", "alternate", "unknown"},
		{"different module", "nested", "main", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			otherPath := []*callgraph.Node{node(tc.caller), node("invoke"), node("bridge"), node("other")}
			r := &Result{UsedImports: map[string]map[string]UsedImportsDetails{".": {"example.com/test": {Symbols: []string{"target"}, Paths: [][]*callgraph.Node{path}}}}, ssaBuilds: map[string]*ssaBuild{repo: {cg: graph}}}
			if tc.module == "." {
				d := r.UsedImports["."]["example.com/test"]
				d.Symbols = append(d.Symbols, "other")
				d.Paths = append(d.Paths, otherPath)
				r.UsedImports["."]["example.com/test"] = d
			} else {
				r.UsedImports[tc.module] = map[string]UsedImportsDetails{"example.com/test": {Symbols: []string{"other"}, Paths: [][]*callgraph.Node{otherPath}}}
			}
			a := &AIVerification{IsVulnerable: "false", Confidence: "high", GraphAnalysis: AIGraphAnalysis{AlternativePaths: "Checked alternate callers and callback assignments", ScopeEvidence: []AISourceCitation{origin}, Findings: []AIGraphFinding{{Kind: "suspected_false_positive", Module: ".", Package: "example.com/test", Symbol: "target", GraphPath: names, EdgeReviews: []AIEdgeReview{review}}}}}
			validateGraphEvidence(r, repo, a, evidence)
			if a.IsVulnerable != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, a)
			}
			if tc.want == "false" && !strings.Contains(strings.Join(a.Evidence, "\n"), "shared dispatch step 2") {
				t.Fatalf("missing reused evidence: %+v", a)
			}
		})
	}
	// Feedback identifies the exact source step, not just a generic missing proof.
	finding := AIGraphFinding{Kind: "suspected_false_positive", Module: ".", GraphPath: names}
	err = validateGraphFinding(&Result{ssaBuilds: map[string]*ssaBuild{repo: {cg: graph}}}, repo, &finding, evidence)
	if err == nil || !strings.Contains(err.Error(), "step 2") || !strings.Contains(err.Error(), "main.go:5") {
		t.Fatalf("unhelpful feedback: %v", err)
	}
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch correction/malformed=%v", malformed), func(t *testing.T) {
			r := &Result{AffectedImports: map[string]AffectedImportsDetails{"example.com/test": {Symbols: []string{"target"}}}, UsedImports: map[string]map[string]UsedImportsDetails{".": {"example.com/test": {Symbols: []string{"target"}, Paths: [][]*callgraph.Node{path}}}}, ssaBuilds: map[string]*ssaBuild{repo: {cg: graph}}}
			draft := &AIVerification{IsVulnerable: "false", Confidence: "high", Reasoning: "The callback invokes safe, not bridge", Evidence: []string{"main.go:8: main passes safe"}, GraphAnalysis: AIGraphAnalysis{Summary: "Checked callback dispatch", AlternativePaths: "Checked callers and entry point", ScopeEvidence: []AISourceCitation{origin}, Findings: []AIGraphFinding{{Kind: "suspected_false_positive", Module: ".", Package: "example.com/test", Symbol: "target", GraphPath: names, SourcePath: []string{}, Confidence: "high", Reasoning: "The passed function is safe", Evidence: []string{"main.go:8: main passes safe"}, Uncertainties: []string{}}}}, DynamicAnalysis: AIDynamicAnalysis{Summary: "No relevant dynamic candidates", Findings: []AIDynamicFinding{}}, Uncertainties: []string{}}
			first, err := marshalAuditResponseForTest(draft)
			if err != nil {
				t.Fatal(err)
			}
			draft.GraphAnalysis.Findings[0].EdgeReviews = []AIEdgeReview{review}
			corrected, err := marshalAuditResponseForTest(draft)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				calls++
				body, _ := io.ReadAll(request.Body)
				response := string(first)
				if calls > 1 {
					if !strings.Contains(string(body), "step 2") || !strings.Contains(string(body), "main.go:5") {
						t.Errorf("missing exact correction feedback: %s", body)
					}
					response = string(corrected)
					if malformed {
						response = "invalid JSON"
					}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": response}}}})
			}))
			defer server.Close()
			a, err := verifyRiskBatch(context.Background(), r, repo, aiConfig{}, backendForTest("openai-compatible", server.URL, 0), "{{.source_snippets}}\n{{.call_traces}}", nil, nil, true)
			want := "false"
			if malformed {
				want = "unknown"
			}
			if err != nil || a == nil || a.IsVulnerable != want || calls != 2 {
				t.Fatalf("verdict=%+v error=%v requests=%d", a, err, calls)
			}
			if malformed && !strings.Contains(strings.Join(a.Uncertainties, "\n"), "Assessment correction failed") {
				t.Fatalf("correction failure lost: %+v", a)
			}
		})
	}
}

func TestBackendsCorrectionRespectsBudgets(t *testing.T) {
	for _, provider := range []string{"anthropic-vertex", "openai-compatible"} {
		for _, limit := range []string{"context", "timeout", "accepted"} {
			t.Run(provider+"/"+limit, func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; replyAssessment(w, provider) }))
				defer server.Close()
				agent := backendForTest(provider, server.URL, 0)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				output, err := agent.(reviewingVerificationAgent).RunReviewed(ctx, "evidence", nil, func(string) string {
					if limit == "accepted" {
						return ""
					}
					if limit == "timeout" {
						cancel()
					} else {
						switch a := agent.(type) {
						case *anthropicAgent:
							a.cfg.ContextTokens = 1
						case *compatibleAgent:
							a.cfg.ContextTokens = 1
						}
					}
					return "repair needed"
				})
				if err != nil || output != testAssessment || calls != 1 {
					t.Fatalf("output=%q err=%v calls=%d", output, err, calls)
				}
			})
		}
	}
}

func TestPositiveBatchPreservesPendingCoverage(t *testing.T) {
	repo := t.TempDir()
	code := "package main\nfunc target() {}\nfunc main() { target() }\n"
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("{{.source_snippets}}\n{{.call_traces}}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(repo, "main.go"), code, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage("example.com/test", "main"), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	graph := cha.CallGraph(pkg.Prog)
	path := []*callgraph.Node{graph.Nodes[pkg.Func("main")], graph.Nodes[pkg.Func("target")]}
	r := &Result{ScanConfig: ScanConfig{Directory: repo}, AffectedImports: map[string]AffectedImportsDetails{"example.com/test": {Symbols: []string{"target"}}}, UsedImports: map[string]map[string]UsedImportsDetails{".": {"example.com/test": {Symbols: []string{"target"}, Paths: [][]*callgraph.Node{path}}}}, ReflectionRisks: make([]ReflectionRisk, 17), ssaBuilds: map[string]*ssaBuild{repo: {cg: graph}}}
	calls := 0
	agent := fakeAgent(func(context.Context, string, []verificationTool) (string, error) {
		calls++
		if calls > 1 {
			return "", fmt.Errorf("another batch unavailable")
		}
		a := &AIVerification{IsVulnerable: "true", Confidence: "high", Reasoning: "An affected invocation is reachable", Evidence: []string{"main calls target"}, GraphAnalysis: AIGraphAnalysis{Summary: "Source and graph establish invocation", Findings: []AIGraphFinding{{Kind: "supported_path", Module: ".", Package: "example.com/test", Symbol: "target", GraphPath: []string{path[0].Func.String(), path[1].Func.String()}, SourcePath: []string{"main.go:3: main calls target"}, Confidence: "high", Reasoning: "direct invocation", Evidence: []string{"main.go:3: main calls target"}, Uncertainties: []string{}}}}, DynamicAnalysis: AIDynamicAnalysis{Summary: "One unrelated candidate reviewed", Findings: []AIDynamicFinding{{Module: ".", Mechanism: "callback", Status: "unresolved", GraphStatus: "unknown", RiskIndices: []int{0}, SourcePath: []string{}, Confidence: "low", Reasoning: "Another callback unknown", Evidence: []string{"candidate 0"}, Uncertainties: []string{"callback identity unknown"}}}}, Uncertainties: []string{}}
		raw, err := marshalAuditResponseForTest(a)
		return string(raw), err
	})
	verifyWithAgent(context.Background(), r, repo, aiConfig{}, agent)
	a := r.AIVerification
	if a == nil || a.IsVulnerable != "true" || a.Confidence != "high" || a.Coverage.ReviewedRisks != 1 || len(a.Coverage.PendingRiskIndices) != 16 || calls != 2 {
		t.Fatalf("positive or coverage lost: calls=%d, assessment=%+v", calls, a)
	}
	if len(r.Errors) != 1 || !strings.Contains(strings.Join(a.Uncertainties, "\n"), "16 of 17") {
		t.Fatalf("gaps lost: %+v", a)
	}
}

func TestSourceOnlyPositiveRequiresReadEvidence(t *testing.T) {
	repo := t.TempDir()
	citation := AISourceCitation{File: "main.go", Line: 3, Quote: "func main() { reflect.ValueOf(target).Call(nil) }"}
	evidence := newVerificationEvidence(repo, map[string]string{"main.go": "3|func main() { reflect.ValueOf(target).Call(nil) }\n"})
	for _, kind := range []string{"dynamic", "false_negative"} {
		for _, checked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/checked=%v", kind, checked), func(t *testing.T) {
				var citations []AISourceCitation
				if checked {
					citations = []AISourceCitation{citation}
				}
				a := &AIVerification{IsVulnerable: "true", Confidence: "high"}
				if kind == "dynamic" {
					a.DynamicAnalysis.Findings = []AIDynamicFinding{{Status: "supported", SourcePath: []string{"main -> target"}, SourceEvidence: citations}}
				} else {
					a.GraphAnalysis.Findings = []AIGraphFinding{{Kind: "suspected_false_negative", SourcePath: []string{"main -> target"}, SourceEvidence: citations}}
				}
				validateGraphEvidence(&Result{}, repo, a, evidence)
				if (a.IsVulnerable == "true") != checked || a.validatedPositive != checked {
					t.Fatalf("unsupported source claim accepted or evidence discarded: %+v", a)
				}
			})
		}
	}
}

func TestVerificationAuditsGraphOnceAcrossDynamicBatches(t *testing.T) {
	for _, tc := range []struct {
		name, want                                    string
		omitReview, failGraph, unresolved, missedCall bool
	}{
		{name: "refuted CHA path", want: "false"},
		{name: "unreviewed graph remains unknown", omitReview: true, want: "unknown"},
		{name: "failed graph audit remains unknown", failGraph: true, want: "unknown"},
		{name: "runtime target unresolved", unresolved: true, want: "unknown"},
		{name: "missed reflection survives graph failure", failGraph: true, missedCall: true, want: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			code := "package main\nfunc target() {}\nfunc safe() {}\nfunc invoke(f func()) { f() }\nfunc main() { invoke(safe) }\n"
			dynamicCode := "package main\nimport \"reflect\"\nfunc init() { reflect.ValueOf(safe).Call(nil) }\n"
			if tc.missedCall {
				dynamicCode = strings.ReplaceAll(dynamicCode, "ValueOf(safe)", "ValueOf(target)")
			}
			for name, contents := range map[string]string{
				"main.go":        code,
				"dynamic.go":     dynamicCode,
				"verify-scan.md": "{{.source_snippets}}\n{{.call_traces}}\nBATCH_JSON:{{.scan_result_json}}",
			} {
				if err := os.WriteFile(filepath.Join(repo, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("GVS_SKILLS_DIR", repo)
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Join(repo, "main.go"), code, 0)
			if err != nil {
				t.Fatal(err)
			}
			pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage("example.com/test", "main"), []*ast.File{file}, ssa.SanityCheckFunctions)
			if err != nil {
				t.Fatal(err)
			}
			graph := cha.CallGraph(pkg.Prog)
			path := []*callgraph.Node{graph.Nodes[pkg.Func("main")], graph.Nodes[pkg.Func("invoke")], graph.Nodes[pkg.Func("target")]}
			r := &Result{ScanConfig: ScanConfig{Directory: repo}, IsVulnerable: "true", AffectedImports: map[string]AffectedImportsDetails{"example.com/test": {Symbols: []string{"target"}}}, UsedImports: map[string]map[string]UsedImportsDetails{".": {"example.com/test": {Symbols: []string{"target"}, Paths: [][]*callgraph.Node{path}}}}, ssaBuilds: map[string]*ssaBuild{repo: {cg: graph}}}
			for i := 0; i < 17; i++ {
				r.ReflectionRisks = append(r.ReflectionRisks, ReflectionRisk{Type: "reflection_call", Association: "unresolved", Location: "dynamic.go:3"})
			}
			calls, graphPrompts := 0, 0
			agent := fakeAgent(func(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
				calls++
				if strings.Contains(prompt, "Trace in module") {
					graphPrompts++
				}
				var scan struct {
					Scope string             `json:"investigation_scope"`
					Risks []verificationRisk `json:"reflection_risks"`
				}
				if err := json.Unmarshal([]byte(strings.SplitN(prompt, "BATCH_JSON:", 2)[1]), &scan); err != nil {
					t.Fatal(err)
				}
				wantScope := "dynamic_batch"
				if calls == 1 {
					wantScope = "graph_and_dynamic"
				}
				if scan.Scope != wantScope {
					t.Errorf("scope = %q, want %q", scan.Scope, wantScope)
				}
				if calls == 1 && tc.failGraph {
					return "", errors.New("graph investigation unavailable")
				}
				a, err := parseAssessment(testAssessment)
				if err != nil {
					t.Fatal(err)
				}
				a.Reasoning = "No affected invocation in this investigation's scope."
				if calls == 1 && !tc.omitReview {
					origin := AISourceCitation{File: "main.go", Line: 5, Quote: "func main() { invoke(safe) }"}
					a.GraphAnalysis = AIGraphAnalysis{Summary: "CHA candidate refuted", AlternativePaths: "Checked main and the callback origin", ScopeEvidence: []AISourceCitation{origin}, Findings: []AIGraphFinding{{Kind: "suspected_false_positive", Module: ".", Package: "example.com/test", Symbol: "target", GraphPath: []string{path[0].Func.String(), path[1].Func.String(), path[2].Func.String()}, SourcePath: []string{}, Confidence: "high", Reasoning: "main passes safe, so this callback cannot invoke target", Evidence: []string{"main.go:5: invoke receives safe"}, Uncertainties: []string{}, EdgeReviews: []AIEdgeReview{{Step: 2, Status: "ruled_out", CallSite: AISourceCitation{File: "main.go", Line: 4, Quote: "func invoke(f func()) { f() }"}, ValueOrigin: []AISourceCitation{origin}, Reasoning: "actual function value is safe"}}}}}
				}
				for _, risk := range scan.Risks {
					finding := AIDynamicFinding{Module: ".", Package: "example.com/test", Symbol: "target", Mechanism: "reflection", Status: "ruled_out", GraphStatus: "unknown", RiskIndices: risk.Indices, SourcePath: []string{}, Confidence: "high", Reasoning: "Candidate excluded in the investigated scope", Evidence: []string{"dynamic.go:3: checked reflected value"}, Uncertainties: []string{}}
					if calls == 2 && tc.unresolved {
						finding.Status = "unresolved"
						finding.Uncertainties = []string{"Runtime method name is unavailable"}
						a.IsVulnerable = "unknown"
						a.Uncertainties = append(a.Uncertainties, finding.Uncertainties...)
					}
					if calls == 2 && tc.missedCall {
						finding.Status, finding.GraphStatus = "supported", "missing"
						finding.SourcePath = []string{"dynamic.go:3: init reflects target"}
						finding.SourceEvidence = []AISourceCitation{{File: "dynamic.go", Line: 3, Quote: "func init() { reflect.ValueOf(target).Call(nil) }"}}
						finding.Reasoning = "init invokes the affected target through reflection"
						a.IsVulnerable = "true"
						a.GraphAnalysis.Findings = append(a.GraphAnalysis.Findings, AIGraphFinding{Kind: "suspected_false_negative", Module: ".", Package: finding.Package, Symbol: finding.Symbol, GraphPath: []string{}, SourcePath: finding.SourcePath, SourceEvidence: finding.SourceEvidence, Confidence: "high", Reasoning: "The available graph omits the reflected invocation", Evidence: finding.Evidence, Uncertainties: []string{}})
					}
					a.DynamicAnalysis.Findings = append(a.DynamicAnalysis.Findings, finding)
				}
				raw, err := marshalAuditResponseForTest(a)
				return string(raw), err
			})
			verifyWithAgent(context.Background(), r, repo, aiConfig{}, agent)
			if calls != 2 || graphPrompts != 1 {
				t.Fatalf("investigations=%d, graph prompts=%d; want 2, 1", calls, graphPrompts)
			}
			if r.AIVerification == nil || r.AIVerification.IsVulnerable != tc.want {
				t.Fatalf("want %s, got %+v (errors=%v)", tc.want, r.AIVerification, r.Errors)
			}
			if r.IsVulnerable != "true" || len(r.UsedImports["."]["example.com/test"].Paths) != 1 {
				t.Fatal("scanner result was mutated")
			}
			if tc.failGraph && len(r.AIVerification.Coverage.PendingRiskIndices) != 16 {
				t.Fatalf("failed batch coverage lost: %+v", r.AIVerification.Coverage)
			}
			if tc.unresolved {
				data, err := json.Marshal(r.AIVerification)
				if err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{"Suspected false-positive path", "main passes safe", "Runtime method name"} {
					if !strings.Contains(string(data), want) {
						t.Errorf("missing finding %q from public assessment: %s", want, data)
					}
				}
			}
		})
	}
}

func TestVerificationDiscoversReflectionWithoutScannerCandidates(t *testing.T) {
	repo := t.TempDir()
	code := "package main\nimport r \"reflect\"\nfunc target() {}\nfunc init() { r.ValueOf(target).Call(nil) }\n"
	for name, contents := range map[string]string{"helper.go": code, "verify-scan.md": "{{.source_snippets}}\n{{.scan_result_json}}"} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GVS_SKILLS_DIR", repo)
	r := &Result{ScanConfig: ScanConfig{Directory: repo}, IsVulnerable: "false", AffectedImports: map[string]AffectedImportsDetails{"example.com/test": {Symbols: []string{"target"}}}, ssaBuilds: map[string]*ssaBuild{repo: {cg: callgraph.New(nil)}}}
	calls := 0
	agent := fakeAgent(func(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
		calls++
		for _, want := range []string{"4|func init()", "focused independent source search", `"investigation_scope":"graph_and_dynamic"`} {
			if !strings.Contains(prompt, want) {
				t.Errorf("missing discovery context %q", want)
			}
		}
		a, err := parseAssessment(testAssessment)
		if err != nil {
			t.Fatal(err)
		}
		a.IsVulnerable, a.Reasoning = "true", "init reflects the affected target, which the available graph omits"
		citation := AISourceCitation{File: "helper.go", Line: 4, Quote: "func init() { r.ValueOf(target).Call(nil) }"}
		path := AISourcePath{"helper.go:4: init invokes target through reflect.Value.Call"}
		a.GraphAnalysis.Findings = []AIGraphFinding{{Kind: "suspected_false_negative", Module: ".", Package: "example.com/test", Symbol: "target", GraphPath: []string{}, SourcePath: path, SourceEvidence: []AISourceCitation{citation}, Confidence: "high", Reasoning: a.Reasoning, Evidence: []string{"helper.go:4: target is reflected and called"}, Uncertainties: []string{}}}
		a.DynamicAnalysis.Findings = []AIDynamicFinding{{Module: ".", Package: "example.com/test", Symbol: "target", Mechanism: "reflection", Status: "supported", GraphStatus: "missing", RiskIndices: []int{}, SourcePath: path, SourceEvidence: []AISourceCitation{citation}, Confidence: "high", Reasoning: a.Reasoning, Evidence: a.GraphAnalysis.Findings[0].Evidence, Uncertainties: []string{}}}
		raw, err := marshalAuditResponseForTest(a)
		return string(raw), err
	})
	verifyWithAgent(context.Background(), r, repo, aiConfig{}, agent)
	if calls != 1 || len(r.Errors) != 0 || r.AIVerification == nil || r.AIVerification.IsVulnerable != "true" {
		t.Fatalf("missed reflection finding lost: calls=%d, errors=%v, assessment=%+v", calls, r.Errors, r.AIVerification)
	}
	if r.IsVulnerable != "false" || len(r.ReflectionRisks) != 0 || r.Reflect {
		t.Fatal("scanner state changed")
	}
	data, err := json.Marshal(r.AIVerification)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Suspected missed invocation", "Dynamic usage (reflection, supported, graph=missing)", "helper.go:4"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing public finding %q: %s", want, data)
		}
	}
}
