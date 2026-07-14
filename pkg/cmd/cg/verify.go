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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/vertex"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

type claudeConfig struct {
	ProjectID     string
	Location      string
	Model         string
	MaxIterations int
}

type claudeResponse struct {
	AgreesWithScanner bool     `json:"agrees_with_scanner"`
	ClaudeAssessment  string   `json:"claude_assessment"`
	Confidence        string   `json:"confidence"`
	Reasoning         string   `json:"reasoning"`
	Evidence          []string `json:"evidence"`
}

func VerifyAndSummarizeWithClaude(result *Result, repoDir string) {
	cfg, found := loadClaudeConfig()
	if !found {
		return
	}

	skillPrompt, found := loadSkillPrompt()
	if !found {
		return
	}

	fmt.Fprintf(os.Stderr, "[claude] Collecting source code from repository...\n")
	sourceSnippets := collectRelevantSource(result, repoDir)
	fmt.Fprintf(os.Stderr, "[claude] Collected %d source files\n", len(sourceSnippets))

	prompt, err := buildVerificationPrompt(result, skillPrompt, sourceSnippets)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to build Claude verification prompt: %v", err))
		return
	}

	fmt.Fprintf(os.Stderr, "[claude] REQUEST >>>\n%s\n[claude] <<< REQUEST\n", prompt)
	fmt.Fprintf(os.Stderr, "[claude] Calling Vertex AI agentic loop (project=%s, location=%s, model=%s, max_iterations=%d)...\n",
		cfg.ProjectID, cfg.Location, cfg.Model, cfg.MaxIterations)

	ctx := context.Background()
	client := anthropic.NewClient(
		vertex.WithGoogleAuth(ctx, cfg.Location, cfg.ProjectID),
	)

	tools := []anthropic.BetaTool{
		&grepCodeTool{repoDir: repoDir},
		&readFileTool{repoDir: repoDir},
		&listFilesTool{repoDir: repoDir},
	}
	if result.SsaProg != nil {
		tools = append(tools, &findImplementationsTool{prog: result.SsaProg})
	}
	if result.CgGraph != nil {
		modPath := readModulePath(repoDir)
		tools = append(tools, &findCallersTool{graph: result.CgGraph, repoModulePath: modPath})
	}

	runner := client.Beta.Messages.NewToolRunner(tools, anthropic.BetaToolRunnerParams{
		BetaMessageNewParams: anthropic.BetaMessageNewParams{
			Model:     cfg.Model,
			MaxTokens: 16384,
			Messages: []anthropic.BetaMessageParam{
				anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt)),
			},
		},
		MaxIterations: cfg.MaxIterations,
	})

	start := time.Now()
	iteration := 0

	for message, err := range runner.All(ctx) {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Claude API call failed: %v", err))
			fmt.Fprintf(os.Stderr, "[claude] API call failed: %v\n", err)
			return
		}
		iteration++
		for _, block := range message.Content {
			switch block.Type {
			case "tool_use":
				fmt.Fprintf(os.Stderr, "[claude] Iteration %d: tool_call %s(%s)\n", iteration, block.Name, string(block.Input))
			case "text":
				if block.Text != "" {
					fmt.Fprintf(os.Stderr, "[claude] Iteration %d: text response (%d chars)\n", iteration, len(block.Text))
				}
			}
		}
	}

	elapsed := time.Since(start)
	fmt.Fprintf(os.Stderr, "[claude] Agentic loop completed in %d iterations (%.1fs)\n", iteration, elapsed.Seconds())

	lastMsg := runner.LastMessage()
	if lastMsg == nil {
		result.Errors = append(result.Errors, "Claude returned no response")
		return
	}

	// If the loop ended while Claude still wanted to use tools (hit MaxIterations),
	// make one final call forcing it to produce the JSON answer.
	if lastMsg.StopReason == anthropic.BetaStopReasonToolUse {
		fmt.Fprintf(os.Stderr, "[claude] Loop ended mid-tool-use (iteration limit). Requesting final answer...\n")
		finalMessages := append(runner.Params.Messages,
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(
				"You have reached the investigation limit. Stop using tools. Based on everything you have found so far, respond with your final JSON assessment now.",
			)),
		)
		finalMsg, err := client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
			Model:     cfg.Model,
			MaxTokens: 4096,
			Messages:  finalMessages,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[claude] Final answer call failed: %v\n", err)
			result.Errors = append(result.Errors, fmt.Sprintf("Claude final answer call failed: %v", err))
			return
		}
		lastMsg = finalMsg
		fmt.Fprintf(os.Stderr, "[claude] Final answer received (stop_reason=%s)\n", lastMsg.StopReason)
	}

	if lastMsg.StopReason == anthropic.BetaStopReasonMaxTokens {
		fmt.Fprintf(os.Stderr, "[claude] WARNING: response truncated (max_tokens reached)\n")
	}

	var responseText string
	for _, block := range lastMsg.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	fmt.Fprintf(os.Stderr, "[claude] RESPONSE (stop_reason=%s) >>>\n%s\n[claude] <<< RESPONSE\n", lastMsg.StopReason, responseText)

	var resp claudeResponse
	cleaned := cleanJSONResponse(responseText)
	if err := json.Unmarshal([]byte(cleaned), &resp); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse Claude response: %v", err))
		fmt.Fprintf(os.Stderr, "[claude] Failed to parse response JSON: %v\n", err)
		return
	}

	result.ClaudeVerification = &ClaudeVerification{
		AgreesWithScanner: resp.AgreesWithScanner,
		ClaudeAssessment:  resp.ClaudeAssessment,
		Confidence:        resp.Confidence,
		Reasoning:         resp.Reasoning,
		Evidence:          resp.Evidence,
	}

	if resp.AgreesWithScanner {
		fmt.Fprintf(os.Stderr, "[claude] Result: agrees with scanner (confidence: %s)\n", resp.Confidence)
	} else {
		fmt.Fprintf(os.Stderr, "[claude] Result: disagrees with scanner (confidence: %s, claude=%s)\n",
			resp.Confidence, resp.ClaudeAssessment)
	}
}

func cleanJSONResponse(s string) string {
	s = strings.TrimSpace(s)

	// Strip markdown code fences
	if strings.HasPrefix(s, "```json") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	} else if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}

	// If already valid JSON object with nothing after the closing brace, return as-is
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		var js json.RawMessage
		if json.Unmarshal([]byte(s), &js) == nil {
			return s
		}
	}

	// Extract JSON from markdown fenced block anywhere in text
	if idx := strings.Index(s, "```json"); idx >= 0 {
		after := s[idx+7:]
		if end := strings.Index(after, "```"); end >= 0 {
			return strings.TrimSpace(after[:end])
		}
	}
	if idx := strings.Index(s, "```\n{"); idx >= 0 {
		after := s[idx+3:]
		if end := strings.Index(after, "```"); end >= 0 {
			return strings.TrimSpace(after[:end])
		}
	}

	// Find the LAST balanced { ... } object (Claude's final JSON is at the end)
	end := strings.LastIndexByte(s, '}')
	if end < 0 {
		return s
	}
	depth := 0
	inString := false
	escaped := false
	for i := end; i >= 0; i-- {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if i > 0 && s[i-1] == '\\' && inString {
			escaped = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if c == '}' {
			depth++
		} else if c == '{' {
			depth--
			if depth == 0 {
				return s[i : end+1]
			}
		}
	}

	return s
}

// formatCallTraces converts call graph paths into readable text with edge-type annotations.
func FormatCallTraces(result *Result) string {
	if len(result.UsedImports) == 0 {
		return "No call graph traces found (scanner did not find a path to vulnerable symbols).\n"
	}

	var b strings.Builder
	for pkg, details := range result.UsedImports {
		for i, sym := range details.Symbols {
			if i >= len(details.Paths) {
				continue
			}
			path := details.Paths[i]
			if len(path) == 0 {
				continue
			}
			b.WriteString(fmt.Sprintf("Trace for %s.%s:\n", pkg, sym))
			for j, node := range path {
				funcName := "unknown"
				location := "unknown"
				if node.Func != nil {
					func() {
						defer func() { recover() }()
						funcName = node.Func.String()
					}()
					if node.Func.Prog != nil {
						pos := node.Func.Prog.Fset.Position(node.Func.Pos())
						if pos.IsValid() {
							location = fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
						}
					}
				}
				b.WriteString(fmt.Sprintf("  %d. %s at %s\n", j+1, funcName, location))

				if j < len(path)-1 {
					edgeDesc := findEdgeDescription(path[j], path[j+1])
					b.WriteString(fmt.Sprintf("     -> [%s]\n", edgeDesc))
				}
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func findEdgeDescription(caller, callee *callgraph.Node) string {
	for _, edge := range caller.Out {
		if edge.Callee == callee {
			desc := edge.Description()
			if edge.Site != nil && edge.Site.Common().IsInvoke() {
				ifaceType := edge.Site.Common().Value.Type().String()
				methodName := edge.Site.Common().Method.Name()
				return fmt.Sprintf("%s via interface %s.%s", desc, ifaceType, methodName)
			}
			return desc
		}
	}
	return "unknown dispatch"
}

// --- Agentic tools for Claude ---

func safePath(repoDir, relPath string) (string, error) {
	cleaned := filepath.Clean(relPath)
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("path %q escapes repository root", relPath)
	}
	return filepath.Join(repoDir, cleaned), nil
}

func textResult(text string) ([]anthropic.BetaToolResultBlockParamContentUnion, error) {
	return []anthropic.BetaToolResultBlockParamContentUnion{
		{OfText: &anthropic.BetaTextBlockParam{Text: text}},
	}, nil
}

// grep_code tool
type grepCodeTool struct{ repoDir string }

func (t *grepCodeTool) Name() string        { return "grep_code" }
func (t *grepCodeTool) Description() string  { return "Search for a regex pattern in the repository. Returns matching lines with file paths and line numbers." }
func (t *grepCodeTool) InputSchema() anthropic.BetaToolInputSchemaParam {
	return anthropic.BetaToolInputSchemaParam{
		Properties: map[string]any{
			"pattern": map[string]any{"type": "string", "description": "Regex pattern to search for"},
			"glob":    map[string]any{"type": "string", "description": "File glob filter, e.g. *.go"},
		},
		Required: []string{"pattern"},
	}
}

func (t *grepCodeTool) Execute(ctx context.Context, input json.RawMessage) ([]anthropic.BetaToolResultBlockParamContentUnion, error) {
	var params struct {
		Pattern string `json:"pattern"`
		Glob    string `json:"glob"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}
	args := []string{"-rn", "--max-count=100"}
	if params.Glob != "" {
		args = append(args, "--include="+params.Glob)
	}
	args = append(args, params.Pattern, ".")
	cmd := exec.CommandContext(ctx, "grep", args...)
	cmd.Dir = t.repoDir
	out, _ := cmd.Output()
	result := string(out)
	if result == "" {
		result = "No matches found."
	}
	lines := strings.Split(result, "\n")
	if len(lines) > 100 {
		result = strings.Join(lines[:100], "\n") + "\n... (truncated)"
	}
	fmt.Fprintf(os.Stderr, "[claude] grep_code result: %d lines\n", len(lines))
	return textResult(result)
}

// read_file tool
type readFileTool struct{ repoDir string }

func (t *readFileTool) Name() string        { return "read_file" }
func (t *readFileTool) Description() string  { return "Read a file from the repository. Optionally specify start and end line numbers." }
func (t *readFileTool) InputSchema() anthropic.BetaToolInputSchemaParam {
	return anthropic.BetaToolInputSchemaParam{
		Properties: map[string]any{
			"path":       map[string]any{"type": "string", "description": "File path relative to repo root"},
			"start_line": map[string]any{"type": "integer", "description": "Start line (1-based, optional)"},
			"end_line":   map[string]any{"type": "integer", "description": "End line (1-based, optional)"},
		},
		Required: []string{"path"},
	}
}

func (t *readFileTool) Execute(ctx context.Context, input json.RawMessage) ([]anthropic.BetaToolResultBlockParamContentUnion, error) {
	var params struct {
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}
	fullPath, err := safePath(t.repoDir, params.Path)
	if err != nil {
		return textResult(err.Error())
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}
	lines := strings.Split(string(data), "\n")
	start, end := 0, len(lines)
	if params.StartLine > 0 {
		start = params.StartLine - 1
	}
	if params.EndLine > 0 && params.EndLine < end {
		end = params.EndLine
	}
	if start > end {
		start = end
	}
	if end-start > 500 {
		end = start + 500
	}
	var b strings.Builder
	for i := start; i < end && i < len(lines); i++ {
		b.WriteString(fmt.Sprintf("%d|%s\n", i+1, lines[i]))
	}
	fmt.Fprintf(os.Stderr, "[claude] read_file result: %s (%d lines)\n", params.Path, end-start)
	return textResult(b.String())
}

// list_files tool
type listFilesTool struct{ repoDir string }

func (t *listFilesTool) Name() string        { return "list_files" }
func (t *listFilesTool) Description() string  { return "List files in a directory of the repository. Skips vendor/ and .git/." }
func (t *listFilesTool) InputSchema() anthropic.BetaToolInputSchemaParam {
	return anthropic.BetaToolInputSchemaParam{
		Properties: map[string]any{
			"path": map[string]any{"type": "string", "description": "Directory path relative to repo root (default: root)"},
			"glob": map[string]any{"type": "string", "description": "Glob pattern to filter files, e.g. **/*.go"},
		},
	}
}

func (t *listFilesTool) Execute(ctx context.Context, input json.RawMessage) ([]anthropic.BetaToolResultBlockParamContentUnion, error) {
	var params struct {
		Path string `json:"path"`
		Glob string `json:"glob"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}
	dir := t.repoDir
	if params.Path != "" {
		d, err := safePath(t.repoDir, params.Path)
		if err != nil {
			return textResult(err.Error())
		}
		dir = d
	}
	var files []string
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if len(files) >= 200 {
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(t.repoDir, path)
		if params.Glob != "" {
			if matched, _ := filepath.Match(params.Glob, filepath.Base(path)); !matched {
				return nil
			}
		}
		files = append(files, rel)
		return nil
	})
	result := strings.Join(files, "\n")
	if result == "" {
		result = "No files found."
	}
	fmt.Fprintf(os.Stderr, "[claude] list_files result: %d files\n", len(files))
	return textResult(result)
}

// find_implementations tool
type findImplementationsTool struct {
	prog *ssa.Program
}

func (t *findImplementationsTool) Name() string { return "find_implementations" }
func (t *findImplementationsTool) Description() string {
	return "Given an interface type name (e.g. \"io.Writer\"), find all concrete types in the program that implement it and report whether each is instantiated (used as an interface value). Helps detect CHA false positives where a type implements an interface but is never allocated."
}
func (t *findImplementationsTool) InputSchema() anthropic.BetaToolInputSchemaParam {
	return anthropic.BetaToolInputSchemaParam{
		Properties: map[string]any{
			"interface_type": map[string]any{"type": "string", "description": "Full interface type name, e.g. \"io.Writer\" or \"golang.org/x/net/idna.Transformer\""},
		},
		Required: []string{"interface_type"},
	}
}

func (t *findImplementationsTool) Execute(ctx context.Context, input json.RawMessage) ([]anthropic.BetaToolResultBlockParamContentUnion, error) {
	var params struct {
		InterfaceType string `json:"interface_type"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}
	if t.prog == nil {
		return textResult("error: SSA program not available")
	}

	pkgPath, typeName := splitTypeName(params.InterfaceType)
	if pkgPath == "" || typeName == "" {
		return textResult(fmt.Sprintf("error: cannot parse interface type %q (expected \"pkg.TypeName\")", params.InterfaceType))
	}

	var ifaceType *types.Interface
	for _, pkg := range t.prog.AllPackages() {
		if pkg.Pkg.Path() == pkgPath {
			obj := pkg.Pkg.Scope().Lookup(typeName)
			if obj == nil {
				continue
			}
			if named, ok := obj.Type().(*types.Named); ok {
				if iface, ok := named.Underlying().(*types.Interface); ok {
					ifaceType = iface
					break
				}
			}
		}
	}
	if ifaceType == nil {
		return textResult(fmt.Sprintf("interface %q not found in loaded packages", params.InterfaceType))
	}

	runtimeTypes := make(map[string]bool)
	for _, rt := range t.prog.RuntimeTypes() {
		runtimeTypes[rt.String()] = true
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Concrete types implementing %s:\n\n", params.InterfaceType))
	found := 0
	for _, pkg := range t.prog.AllPackages() {
		scope := pkg.Pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil {
				continue
			}
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			if _, isIface := named.Underlying().(*types.Interface); isIface {
				continue
			}

			T := named
			ptrT := types.NewPointer(T)
			implements := types.Implements(T, ifaceType) || types.Implements(ptrT, ifaceType)
			if !implements {
				continue
			}

			found++
			instantiated := runtimeTypes[T.String()] || runtimeTypes[ptrT.String()]
			status := "instantiated: NO"
			if instantiated {
				status = "instantiated: yes"
			}

			loc := "unknown"
			if pos := obj.Pos(); pos.IsValid() {
				position := pkg.Prog.Fset.Position(pos)
				if position.IsValid() {
					loc = fmt.Sprintf("%s:%d", position.Filename, position.Line)
				}
			}
			b.WriteString(fmt.Sprintf("  - %s (%s) at %s\n", T.String(), status, loc))
			if found >= 50 {
				b.WriteString("  ... (truncated at 50 types)\n")
				break
			}
		}
		if found >= 50 {
			break
		}
	}

	if found == 0 {
		b.WriteString("  (no concrete types found implementing this interface)\n")
	}

	fmt.Fprintf(os.Stderr, "[claude] find_implementations result: %d types for %s\n", found, params.InterfaceType)
	return textResult(b.String())
}

// splitTypeName splits "io.Writer" into ("io", "Writer") and
// "golang.org/x/net/idna.Transformer" into ("golang.org/x/net/idna", "Transformer")
func splitTypeName(fullName string) (pkgPath, typeName string) {
	idx := strings.LastIndex(fullName, ".")
	if idx < 0 {
		return "", ""
	}
	return fullName[:idx], fullName[idx+1:]
}

// find_callers tool
type findCallersTool struct {
	graph          *callgraph.Graph
	repoModulePath string
}

func (t *findCallersTool) Name() string { return "find_callers" }
func (t *findCallersTool) Description() string {
	return "Given a function or method name, find all callers in the call graph using reverse traversal (up to N hops). Returns the chain of callers from the target back toward entry points. Useful for detecting false negatives when the scanner found no forward path."
}
func (t *findCallersTool) InputSchema() anthropic.BetaToolInputSchemaParam {
	return anthropic.BetaToolInputSchemaParam{
		Properties: map[string]any{
			"symbol":    map[string]any{"type": "string", "description": "Function/method name to search for, e.g. \"golang.org/x/net/html.Parse\" or \"(*net/http.Client).Do\""},
			"max_depth": map[string]any{"type": "integer", "description": "Max hops backward (default: 5)"},
		},
		Required: []string{"symbol"},
	}
}

func (t *findCallersTool) Execute(ctx context.Context, input json.RawMessage) ([]anthropic.BetaToolResultBlockParamContentUnion, error) {
	var params struct {
		Symbol   string `json:"symbol"`
		MaxDepth int    `json:"max_depth"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}
	if t.graph == nil {
		return textResult("error: call graph not available")
	}
	if params.MaxDepth <= 0 {
		params.MaxDepth = 5
	}
	if params.MaxDepth > 10 {
		params.MaxDepth = 10
	}

	var targets []*callgraph.Node
	for _, node := range t.graph.Nodes {
		if node.Func == nil {
			continue
		}
		funcStr := ""
		func() {
			defer func() { recover() }()
			funcStr = node.Func.String()
		}()
		if funcStr != "" && strings.Contains(funcStr, params.Symbol) {
			targets = append(targets, node)
		}
	}

	if len(targets) == 0 {
		return textResult(fmt.Sprintf("No nodes matching %q found in the call graph.", params.Symbol))
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Callers of %q (reverse BFS, max_depth=%d):\n\n", params.Symbol, params.MaxDepth))

	totalCallers := 0
	for _, target := range targets {
		if len(targets) > 1 {
			targetName := "unknown"
			func() {
				defer func() { recover() }()
				targetName = target.Func.String()
			}()
			b.WriteString(fmt.Sprintf("--- Target: %s ---\n", targetName))
		}

		type bfsEntry struct {
			node  *callgraph.Node
			depth int
		}
		visited := map[*callgraph.Node]bool{target: true}
		queue := []bfsEntry{}

		for _, inEdge := range target.In {
			if !visited[inEdge.Caller] {
				visited[inEdge.Caller] = true
				queue = append(queue, bfsEntry{inEdge.Caller, 1})
			}
		}

		for len(queue) > 0 && totalCallers < 50 {
			entry := queue[0]
			queue = queue[1:]

			node := entry.node
			depth := entry.depth

			funcName := "unknown"
			location := "unknown"
			if node.Func != nil {
				func() {
					defer func() { recover() }()
					funcName = node.Func.String()
				}()
				if node.Func.Prog != nil {
					pos := node.Func.Prog.Fset.Position(node.Func.Pos())
					if pos.IsValid() {
						location = fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
					}
				}
			}

			edgeDesc := ""
			for _, outEdge := range node.Out {
				if visited[outEdge.Callee] {
					edgeDesc = outEdge.Description()
					break
				}
			}

			isEntry := isEntryPointLike(node, t.repoModulePath)
			entryMarker := ""
			if isEntry {
				entryMarker = " ** ENTRY POINT **"
			}

			b.WriteString(fmt.Sprintf("  Depth %d: %s at %s [%s]%s\n", depth, funcName, location, edgeDesc, entryMarker))
			totalCallers++

			if depth < params.MaxDepth {
				for _, inEdge := range node.In {
					if !visited[inEdge.Caller] {
						visited[inEdge.Caller] = true
						queue = append(queue, bfsEntry{inEdge.Caller, depth + 1})
					}
				}
			}
		}
		b.WriteString("\n")

		if totalCallers >= 50 {
			b.WriteString("  ... (truncated at 50 callers)\n")
			break
		}
	}

	fmt.Fprintf(os.Stderr, "[claude] find_callers result: %d callers for %s\n", totalCallers, params.Symbol)
	return textResult(b.String())
}

func isEntryPointLike(node *callgraph.Node, repoModulePath string) bool {
	if node.Func == nil || node.Func.Pkg == nil {
		return false
	}
	name := node.Func.Name()
	if name == "main" || name == "init" {
		return true
	}
	if isHTTPHandler(node.Func.Signature) {
		return true
	}
	if node.Func.Pkg.Pkg.Name() == "main" && ast.IsExported(name) {
		return true
	}
	return false
}

func LogClaudeStatus() {
	cfg, found := loadClaudeConfig()
	if !found {
		fmt.Fprintf(os.Stderr, "Claude verification: disabled (missing ~/.claude.conf or CLAUDE_CODE_USE_VERTEX!=1)\n")
		return
	}
	fmt.Fprintf(os.Stderr, "Claude verification: enabled (project=%s, region=%s, model=%s, max_iterations=%d)\n",
		cfg.ProjectID, cfg.Location, cfg.Model, cfg.MaxIterations)

	if _, ok := loadSkillPrompt(); ok {
		fmt.Fprintf(os.Stderr, "Claude skill file: loaded\n")
	} else {
		fmt.Fprintf(os.Stderr, "Claude skill file: not found\n")
	}
}

func loadClaudeConfig() (claudeConfig, bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return claudeConfig{}, false
	}

	confPath := filepath.Join(homeDir, ".claude.conf")
	file, err := os.Open(confPath)
	if err != nil {
		return claudeConfig{}, false
	}
	defer file.Close()

	cfg := claudeConfig{
		Location:      "global",
		Model:         "claude-sonnet-4-20250514",
		MaxIterations: 20,
	}

	var useVertex bool

	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "CLAUDE_CODE_USE_VERTEX=") {
			useVertex = strings.TrimPrefix(line, "CLAUDE_CODE_USE_VERTEX=") == "1"
		} else if strings.HasPrefix(line, "ANTHROPIC_VERTEX_PROJECT_ID=") {
			cfg.ProjectID = strings.TrimPrefix(line, "ANTHROPIC_VERTEX_PROJECT_ID=")
		} else if strings.HasPrefix(line, "CLOUD_ML_REGION=") {
			cfg.Location = strings.TrimPrefix(line, "CLOUD_ML_REGION=")
		} else if strings.HasPrefix(line, "VERTEX_MODEL=") {
			cfg.Model = strings.TrimPrefix(line, "VERTEX_MODEL=")
		} else if strings.HasPrefix(line, "MAX_ITERATIONS=") {
			if v, err := strconv.Atoi(strings.TrimPrefix(line, "MAX_ITERATIONS=")); err == nil && v > 0 {
				cfg.MaxIterations = v
			}
		}
	}
	if err := sc.Err(); err != nil {
		return claudeConfig{}, false
	}

	if !useVertex || cfg.ProjectID == "" {
		return claudeConfig{}, false
	}

	return cfg, true
}

func loadSkillPrompt() (string, bool) {
	// 1. Environment variable override
	if dir := os.Getenv("GVS_SKILLS_DIR"); dir != "" {
		path := filepath.Join(dir, "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			fmt.Fprintf(os.Stderr, "[claude] Loading skill: %s\n", path)
			return string(data), true
		}
	}

	// 2. Relative to the binary location
	if exe, err := os.Executable(); err == nil {
		binDir := filepath.Dir(exe)
		path := filepath.Join(binDir, "..", "skills", "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			fmt.Fprintf(os.Stderr, "[claude] Loading skill: %s\n", path)
			return string(data), true
		}
		// Also check same directory as binary (container layout)
		path = filepath.Join(binDir, "skills", "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			fmt.Fprintf(os.Stderr, "[claude] Loading skill: %s\n", path)
			return string(data), true
		}
	}

	// 3. User install location
	if homeDir, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(homeDir, ".local", "share", "gvs", "skills", "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			fmt.Fprintf(os.Stderr, "[claude] Loading skill: %s\n", path)
			return string(data), true
		}
	}

	// 4. Current working directory (development)
	path := filepath.Join("skills", "verify-scan.md")
	if data, err := os.ReadFile(path); err == nil {
		fmt.Fprintf(os.Stderr, "[claude] Loading skill: %s\n", path)
		return string(data), true
	}

	return "", false
}

func buildVerificationPrompt(result *Result, skillTemplate string, sourceSnippets map[string]string) (string, error) {
	promptResult := struct {
		IsVulnerable    string                            `json:"IsVulnerable"`
		UsedImports     map[string]UsedImportsDetails     `json:"UsedImports,omitempty"`
		AffectedImports map[string]AffectedImportsDetails `json:"AffectedImports,omitempty"`
		GoCVE           string                            `json:"GoCVE"`
		CVE             string                            `json:"CVE"`
		Repository      string                            `json:"Repository"`
		Branch          string                            `json:"Branch"`
		ReflectionRisks []ReflectionRisk                  `json:"ReflectionRisks,omitempty"`
		Errors          []string                          `json:"Errors,omitempty"`
	}{
		IsVulnerable:    result.IsVulnerable,
		UsedImports:     result.UsedImports,
		AffectedImports: result.AffectedImports,
		GoCVE:           result.GoCVE,
		CVE:             result.CVE,
		Repository:      result.Repository,
		Branch:          result.Branch,
		ReflectionRisks: result.ReflectionRisks,
		Errors:          result.Errors,
	}

	resultJSON, err := json.MarshalIndent(promptResult, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal scan result: %w", err)
	}

	var snippetBuilder strings.Builder
	for path, content := range sourceSnippets {
		snippetBuilder.WriteString(fmt.Sprintf("### %s\n\n```go\n%s\n```\n\n", path, content))
	}

	algo := os.Getenv("ALGO")
	if algo == "" {
		algo = "rta"
	}

	callTraces := FormatCallTraces(result)

	prompt := skillTemplate
	prompt = strings.ReplaceAll(prompt, "{{.scan_result_json}}", string(resultJSON))
	prompt = strings.ReplaceAll(prompt, "{{.source_snippets}}", snippetBuilder.String())
	prompt = strings.ReplaceAll(prompt, "{{.algorithm}}", algo)
	prompt = strings.ReplaceAll(prompt, "{{.is_vulnerable}}", result.IsVulnerable)
	prompt = strings.ReplaceAll(prompt, "{{.call_traces}}", callTraces)

	return prompt, nil
}

const maxSourceBytes = 200 * 1024

func collectRelevantSource(result *Result, repoDir string) map[string]string {
	snippets := make(map[string]string)
	totalBytes := 0

	addFile := func(relPath string) {
		if _, exists := snippets[relPath]; exists {
			return
		}
		if totalBytes >= maxSourceBytes {
			return
		}
		fullPath := filepath.Join(repoDir, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return
		}
		if totalBytes+len(data) < maxSourceBytes {
			snippets[relPath] = string(data)
			totalBytes += len(data)
		}
	}

	// 1. go.mod for version context
	addFile("go.mod")

	// 2. Files along call graph paths (highest signal -- actual vulnerability paths)
	for _, details := range result.UsedImports {
		for _, path := range details.Paths {
			for _, node := range path {
				if node.Func == nil || node.Func.Prog == nil {
					continue
				}
				pos := node.Func.Prog.Fset.Position(node.Func.Pos())
				if !pos.IsValid() || pos.Filename == "" {
					continue
				}
				relPath, err := filepath.Rel(repoDir, pos.Filename)
				if err != nil || strings.HasPrefix(relPath, "..") {
					continue
				}
				addFile(relPath)
			}
		}
	}

	// 3. Files that directly import vulnerable packages + build reverse import index
	var vulnPkgs []string
	for pkg := range result.AffectedImports {
		vulnPkgs = append(vulnPkgs, pkg)
	}

	modulePath := readModulePath(repoDir)

	// reverseImports: Go import path -> list of repo-relative files importing it
	reverseImports := make(map[string][]string)
	// directImporterImportPaths: Go import paths of packages that directly import the vulnerable package
	var directImporterImportPaths []string

	if len(vulnPkgs) > 0 {
		filepath.WalkDir(repoDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				if d != nil && d.IsDir() {
					name := d.Name()
					if name == "vendor" || name == ".git" || strings.HasPrefix(name, ".") {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relPath, _ := filepath.Rel(repoDir, path)
			if relPath == "" {
				relPath = path
			}

			fset := token.NewFileSet()
			f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return nil
			}

			isDirectImporter := false

			for _, imp := range f.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				reverseImports[importPath] = append(reverseImports[importPath], relPath)
				for _, pkg := range vulnPkgs {
					if importPath == pkg || strings.HasPrefix(importPath, pkg+"/") {
						isDirectImporter = true
					}
				}
			}

			if isDirectImporter {
				addFile(relPath)
				if modulePath != "" {
					dirRel := filepath.Dir(relPath)
					var pkgImportPath string
					if dirRel == "." {
						pkgImportPath = modulePath
					} else {
						pkgImportPath = modulePath + "/" + filepath.ToSlash(dirRel)
					}
					directImporterImportPaths = append(directImporterImportPaths, pkgImportPath)
				}
			}
			return nil
		})
	}

	// 4. 2-hop importers: files that import a package which directly imports the vulnerable package
	seen := make(map[string]bool)
	for _, importPath := range directImporterImportPaths {
		if seen[importPath] {
			continue
		}
		seen[importPath] = true
		for _, relPath := range reverseImports[importPath] {
			addFile(relPath)
		}
	}

	// 5. Entry point files (main packages)
	for _, sets := range result.Files {
		for _, fileSet := range sets {
			for _, f := range fileSet {
				addFile(f)
			}
		}
	}

	// 6. Files from ReflectionRisks locations
	for _, risk := range result.ReflectionRisks {
		parts := strings.SplitN(risk.Location, ":", 2)
		if len(parts) == 0 {
			continue
		}
		addFile(parts[0])
	}

	return snippets
}

func readModulePath(repoDir string) string {
	data, err := os.ReadFile(filepath.Join(repoDir, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module"))
		}
	}
	return ""
}

func importsAnyPackage(filePath string, packages []string) bool {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
	if err != nil {
		return false
	}
	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		for _, pkg := range packages {
			if importPath == pkg || strings.HasPrefix(importPath, pkg+"/") {
				return true
			}
		}
	}
	return false
}
