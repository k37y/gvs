package cg

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func TestLoadClaudeConfig(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantFound bool
		wantCfg   claudeConfig
	}{
		{
			name:      "missing file",
			content:   "",
			wantFound: false,
		},
		{
			name:      "vertex not enabled",
			content:   "ANTHROPIC_VERTEX_PROJECT_ID=my-project\nCLOUD_ML_REGION=us-east1\n",
			wantFound: false,
		},
		{
			name:      "missing project ID",
			content:   "CLAUDE_CODE_USE_VERTEX=1\nCLOUD_ML_REGION=us-east1\n",
			wantFound: false,
		},
		{
			name:      "valid config with all fields",
			content:   "CLAUDE_CODE_USE_VERTEX=1\nANTHROPIC_VERTEX_PROJECT_ID=my-project\nCLOUD_ML_REGION=us-east1\nVERTEX_MODEL=claude-opus-4-20250514\n",
			wantFound: true,
			wantCfg: claudeConfig{
				ProjectID: "my-project",
				Location:  "us-east1",
				Model:     "claude-opus-4-20250514",
			},
		},
		{
			name:      "valid config with defaults",
			content:   "CLAUDE_CODE_USE_VERTEX=1\nANTHROPIC_VERTEX_PROJECT_ID=my-project\n",
			wantFound: true,
			wantCfg: claudeConfig{
				ProjectID: "my-project",
				Location:  "global",
				Model:     "claude-sonnet-4-20250514",
			},
		},
		{
			name:      "config with comments and blank lines",
			content:   "# Claude config\nCLAUDE_CODE_USE_VERTEX=1\n\nANTHROPIC_VERTEX_PROJECT_ID=test-proj\n# location override\nCLOUD_ML_REGION=eu\n",
			wantFound: true,
			wantCfg: claudeConfig{
				ProjectID: "test-proj",
				Location:  "eu",
				Model:     "claude-sonnet-4-20250514",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			origHome := os.Getenv("HOME")
			t.Setenv("HOME", tmpDir)
			defer os.Setenv("HOME", origHome)

			if tt.content != "" {
				confPath := filepath.Join(tmpDir, ".claude.conf")
				if err := os.WriteFile(confPath, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			cfg, found := loadClaudeConfig()
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
			if tt.wantFound {
				if cfg.ProjectID != tt.wantCfg.ProjectID {
					t.Errorf("ProjectID = %q, want %q", cfg.ProjectID, tt.wantCfg.ProjectID)
				}
				if cfg.Location != tt.wantCfg.Location {
					t.Errorf("Location = %q, want %q", cfg.Location, tt.wantCfg.Location)
				}
				if cfg.Model != tt.wantCfg.Model {
					t.Errorf("Model = %q, want %q", cfg.Model, tt.wantCfg.Model)
				}
			}
		})
	}
}

func TestLoadSkillPrompt(t *testing.T) {
	t.Run("from GVS_SKILLS_DIR", func(t *testing.T) {
		tmpDir := t.TempDir()
		skillContent := "# Test Skill\n{{.scan_result_json}}"
		if err := os.WriteFile(filepath.Join(tmpDir, "verify-scan.md"), []byte(skillContent), 0644); err != nil {
			t.Fatal(err)
		}

		t.Setenv("GVS_SKILLS_DIR", tmpDir)

		content, found := loadSkillPrompt()
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
		_, found := loadSkillPrompt()
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
		IsVulnerable: "false",
		GoCVE:        "GO-2024-3333",
		CVE:          "CVE-2024-45338",
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
		Directory: tmpDir,
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
		Directory: tmpDir,
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

	result := &Result{Directory: tmpDir}

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
		UsedImports: map[string]UsedImportsDetails{
			"example.com/vuln": {
				Symbols: []string{"BadFunc"},
				Paths:   [][]*callgraph.Node{{node1, node2}},
			},
		},
	}

	got := FormatCallTraces(result)
	if !strings.Contains(got, "Trace for example.com/vuln.BadFunc") {
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
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
	text := result[0].OfText.Text
	if !strings.Contains(text, "No nodes matching") {
		t.Errorf("expected no-match message, got: %s", text)
	}

	// max_depth > 10 should be capped
	input, _ = json.Marshal(map[string]any{"symbol": "foo.Bar", "max_depth": 99})
	result, err = tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	text = result[0].OfText.Text
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
