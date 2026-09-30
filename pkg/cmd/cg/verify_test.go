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
	if !contains(prompt, "false") {
		t.Error("expected 'false' in prompt for IsVulnerable")
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
	for _, name := range []string{"GVS_AI", "GVS_AI_PROVIDER", "GVS_AI_MODEL", "GVS_AI_API_KEY", "GVS_AI_BASE_URL", "GVS_AI_PROJECT_ID", "GVS_AI_LOCATION", "GVS_AI_MAX_ITERATIONS", "GVS_AI_MAX_TOKENS", "GVS_AI_CONTEXT_TOKENS", "GVS_AI_TIMEOUT"} {
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

func TestParseAssessment(t *testing.T) {
	for _, tt := range []struct {
		name, response string
		valid          bool
	}{
		{"valid", testAssessment, true},
		{"boolean", strings.Replace(testAssessment, `"false"`, `false`, 1), true},
		{"unknown", strings.Replace(strings.Replace(testAssessment, `"false"`, `"unknown"`, 1), `"uncertainties":[]`, `"uncertainties":["Runtime configuration unavailable"]`, 1), true},
		{"fenced", "```json\n" + testAssessment + "\n```", true},
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
				if !strings.Contains(prompt, "Assess true") || len(tools) != 9 {
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
			data, err := json.Marshal(a)
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
	for _, want := range []string{`"reflection_risks":[`, `"unsafe":true`, `"reflect":true`, `"nested":"unavailable`, "suspected_false_positive", "suspected_false_negative", "risk_indices", "RuntimeTypes", "SVG rendering itself is not being visually inspected"} {
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
	if err := os.WriteFile(filepath.Join(repo, "verify-scan.md"), []byte("{{.scan_result_json}}"), 0600); err != nil {
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
		if err := json.Unmarshal([]byte(prompt[strings.Index(prompt, "{"):]), &scan); err != nil {
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
		data, _ := json.Marshal(a)
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
