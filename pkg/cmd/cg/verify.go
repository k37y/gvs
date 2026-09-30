package cg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/vertex"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

type AIVerification struct {
	Coverage        *AIAuditCoverage  `json:"coverage,omitempty"`
	Provider        string            `json:"provider"`
	Model           string            `json:"model"`
	IsVulnerable    string            `json:"IsVulnerable"`
	Confidence      string            `json:"confidence"`
	Reasoning       string            `json:"reasoning"`
	Evidence        []string          `json:"evidence"`
	GraphAnalysis   AIGraphAnalysis   `json:"graph_analysis"`
	DynamicAnalysis AIDynamicAnalysis `json:"dynamic_analysis"`
	Uncertainties   []string          `json:"uncertainties"`
}

type AIGraphAnalysis struct {
	Summary  string           `json:"summary"`
	Findings []AIGraphFinding `json:"findings"`
}

type AIGraphFinding struct {
	Kind          string   `json:"kind"`
	Module        string   `json:"module"`
	Package       string   `json:"package"`
	Symbol        string   `json:"symbol"`
	GraphPath     []string `json:"graph_path"`
	SourcePath    []string `json:"source_path"`
	Confidence    string   `json:"confidence"`
	Reasoning     string   `json:"reasoning"`
	Evidence      []string `json:"evidence"`
	Uncertainties []string `json:"uncertainties"`
}

type AIDynamicAnalysis struct {
	Summary  string             `json:"summary"`
	Findings []AIDynamicFinding `json:"findings"`
}

type AIDynamicFinding struct {
	Module        string   `json:"module"`
	Package       string   `json:"package"`
	Symbol        string   `json:"symbol"`
	Mechanism     string   `json:"mechanism"`
	Status        string   `json:"status"`
	GraphStatus   string   `json:"graph_status"`
	RiskIndices   []int    `json:"risk_indices"`
	SourcePath    []string `json:"source_path"`
	Confidence    string   `json:"confidence"`
	Reasoning     string   `json:"reasoning"`
	Evidence      []string `json:"evidence"`
	Uncertainties []string `json:"uncertainties"`
}

type verificationResponse struct {
	IsVulnerableRaw json.RawMessage    `json:"IsVulnerable"`
	Confidence      string             `json:"confidence"`
	Reasoning       string             `json:"reasoning"`
	Evidence        []string           `json:"evidence"`
	GraphAnalysis   *AIGraphAnalysis   `json:"graph_analysis"`
	DynamicAnalysis *AIDynamicAnalysis `json:"dynamic_analysis"`
	Uncertainties   []string           `json:"uncertainties"`
}

func (r *verificationResponse) GetIsVulnerable() string {
	raw := strings.TrimSpace(string(r.IsVulnerableRaw))
	raw = strings.Trim(raw, `"`)
	switch strings.ToLower(raw) {
	case "true":
		return "true"
	case "false":
		return "false"
	default:
		return "unknown"
	}
}

func VerifyAndSummarize(result *Result, repoDir string) {
	cfg, enabled, err := loadAIConfig()
	logAIStatus(cfg, enabled, err, result.ProgressFunc)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("AI configuration: %v", err))
		return
	}
	if !enabled {
		return
	}
	ctx, cancel := context.WithTimeout(result.ctx(), cfg.Timeout)
	defer cancel()
	agent := newAgent(ctx, cfg, result.ProgressFunc)
	verifyWithAgent(ctx, result, repoDir, cfg, agent)
}

// verificationRisk is a compact view, retaining indices into the original scan.
// Details stay available through read_reflection_risks; they are never discarded.
type verificationRisk struct {
	Indices     []int  `json:"indices"`
	Association string `json:"association,omitempty"`
	Type        string `json:"type"`
	Location    string `json:"location"`
	Package     string `json:"package,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Evidence    string `json:"evidence"`
}
type AIAuditCoverage struct {
	TotalRisks         int   `json:"total_risks"`
	ReviewedRisks      int   `json:"reviewed_risks"`
	PendingRiskIndices []int `json:"pending_risk_indices"`
}

const maxRiskBatchBytes = 6 * 1024
const maxRiskBatchEntries = 16

func verificationRiskBatches(result *Result, repoDir string) [][]verificationRisk {
	var groups []verificationRisk
	byKey := make(map[string]int)
	for i, risk := range result.ReflectionRisks {
		location := risk.Location
		if rel, err := filepath.Rel(repoDir, location); err == nil && !strings.HasPrefix(rel, "..") {
			location = filepath.ToSlash(rel)
		}
		key := risk.Type + "\x00" + risk.Location + "\x00" + risk.Package + "\x00" + risk.Symbol + "\x00" + risk.Association + "\x00" + strings.Join(risk.Evidence, "\x00")
		if index, ok := byKey[key]; ok && len(groups[index].Indices) < maxRiskBatchEntries {
			groups[index].Indices = append(groups[index].Indices, i)
			continue
		}
		byKey[key] = len(groups)
		groups = append(groups, verificationRisk{Indices: []int{i}, Association: boundedVerificationText(risk.Association, 32, "..."), Type: boundedVerificationText(risk.Type, 128, "..."), Location: boundedVerificationText(location, 512, " [truncated; read_reflection_risks]"), Package: boundedVerificationText(risk.Package, 256, " [truncated]"), Symbol: boundedVerificationText(risk.Symbol, 128, " [truncated]"), Evidence: boundedVerificationText(strings.Join(risk.Evidence, "; "), 512, " [truncated; read_reflection_risks]")})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].Association == "target_linked" && groups[j].Association != "target_linked"
	})
	batches := [][]verificationRisk{{}}
	for _, group := range groups {
		// JSON escaping can expand a byte sixfold; bound the serialized group too.
		if encoded, _ := json.Marshal(group); len(encoded) > maxRiskBatchBytes-64 {
			group.Association = boundedVerificationText(group.Association, 32, "...")
			group.Type = boundedVerificationText(group.Type, 64, "...")
			group.Location = boundedVerificationText(group.Location, 128, " [truncated]")
			group.Package = boundedVerificationText(group.Package, 128, " [truncated]")
			group.Symbol = boundedVerificationText(group.Symbol, 64, " [truncated]")
			group.Evidence = boundedVerificationText(group.Evidence, 128, " [truncated; read_reflection_risks]")
		}
		last := len(batches) - 1
		candidate := append(append([]verificationRisk(nil), batches[last]...), group)
		encoded, _ := json.Marshal(candidate)
		indices := 0
		for _, g := range candidate {
			indices += len(g.Indices)
		}
		if len(batches[last]) > 0 && (len(encoded) > maxRiskBatchBytes || indices > maxRiskBatchEntries) {
			batches = append(batches, []verificationRisk{group})
		} else {
			batches[last] = candidate
		}
	}
	return batches
}

func verifyWithAgent(ctx context.Context, result *Result, repoDir string, cfg aiConfig, agent verificationAgent) {
	skillPrompt, found := loadSkillPrompt(result)
	if !found {
		result.Errors = append(result.Errors, "AI verification: verify-scan.md not found (set GVS_SKILLS_DIR)")
		return
	}
	batches := verificationRiskBatches(result, repoDir)
	var parts []*AIVerification
	reviewed := make(map[int]bool)
	var gaps []string
	for number, batch := range batches {
		if ctx.Err() != nil {
			gaps = append(gaps, ctx.Err().Error())
			break
		}
		var indices []int
		for _, group := range batch {
			indices = append(indices, group.Indices...)
		}
		result.progress(fmt.Sprintf("[ai] Investigation %d/%d: %d reflection risks", number+1, len(batches), len(indices)))
		part, err := verifyRiskBatch(ctx, result, repoDir, cfg, agent, skillPrompt, batch, indices)
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			gaps = append(gaps, err.Error())
			continue
		}
		parts = append(parts, part)
		for _, index := range indices {
			reviewed[index] = true
		}
	}
	if len(parts) == 0 && len(result.ReflectionRisks) == 0 {
		return
	}
	assessment := mergeVerificationAssessments(parts, gaps)
	assessment.Provider, assessment.Model = cfg.Provider, cfg.Model
	assessment.Coverage = &AIAuditCoverage{TotalRisks: len(result.ReflectionRisks), ReviewedRisks: len(reviewed), PendingRiskIndices: []int{}}
	for index := range result.ReflectionRisks {
		if !reviewed[index] {
			assessment.Coverage.PendingRiskIndices = append(assessment.Coverage.PendingRiskIndices, index)
		}
	}
	if len(assessment.Coverage.PendingRiskIndices) > 0 {
		assessment.IsVulnerable = "unknown"
		assessment.Confidence = "low"
		assessment.Uncertainties = append(assessment.Uncertainties, fmt.Sprintf("%d reflection risk candidates remain unreviewed; see coverage.pending_risk_indices", len(assessment.Coverage.PendingRiskIndices)))
	}
	result.AIVerification = assessment
	result.progress(fmt.Sprintf("[ai] Result: scanner=%s ai=%s reviewed_risks=%d/%d", result.IsVulnerable, assessment.IsVulnerable, len(reviewed), len(result.ReflectionRisks)))
}

func verifyRiskBatch(ctx context.Context, result *Result, repoDir string, cfg aiConfig, agent verificationAgent, template string, batch []verificationRisk, indices []int) (*AIVerification, error) {
	// Copy only source-selection inputs; never copy Result's mutex.
	scope := &Result{ScanConfig: result.ScanConfig, UsedImports: result.UsedImports, AffectedImports: result.AffectedImports}
	for _, index := range indices {
		scope.ReflectionRisks = append(scope.ReflectionRisks, result.ReflectionRisks[index])
	}
	snippets := collectRelevantSource(scope, repoDir)
	prompt, err := buildVerificationPromptForRisks(result, template, snippets, batch)
	if err != nil {
		return nil, fmt.Errorf("Failed to build AI verification prompt: %w", err)
	}
	result.progress(fmt.Sprintf("[ai] Initial prompt: %d bytes (source excerpts: %d bytes; tool schemas excluded)", len(prompt), sourceBytes(snippets)))
	response, err := agent.Run(ctx, prompt, verificationTools(result, repoDir))
	if err != nil {
		return nil, fmt.Errorf("AI verification failed: %w", err)
	}
	assessment, err := parseAssessment(response)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse AI assessment: %w", err)
	}
	if err := validateAuditBatch(result, assessment, indices); err != nil {
		return nil, fmt.Errorf("Invalid AI audit: %w", err)
	}
	return assessment, nil
}

func mergeVerificationAssessments(parts []*AIVerification, gaps []string) *AIVerification {
	if len(parts) == 1 && len(gaps) == 0 {
		return parts[0]
	}
	a := &AIVerification{IsVulnerable: "unknown", Confidence: "low", Reasoning: fmt.Sprintf("Combined %d bounded investigations; consult findings and coverage for scope.", len(parts)), Evidence: []string{}, GraphAnalysis: AIGraphAnalysis{Summary: "Graph findings from bounded investigations.", Findings: []AIGraphFinding{}}, DynamicAnalysis: AIDynamicAnalysis{Summary: "Dynamic findings from bounded investigations.", Findings: []AIDynamicFinding{}}, Uncertainties: append([]string{}, gaps...)}
	verdict := ""
	consistent := len(parts) > 0 && len(gaps) == 0
	for _, part := range parts {
		if verdict == "" {
			verdict = part.IsVulnerable
		} else if verdict != part.IsVulnerable {
			consistent = false
		}
		a.Evidence = append(a.Evidence, part.Evidence...)
		a.GraphAnalysis.Findings = append(a.GraphAnalysis.Findings, part.GraphAnalysis.Findings...)
		a.DynamicAnalysis.Findings = append(a.DynamicAnalysis.Findings, part.DynamicAnalysis.Findings...)
		a.Uncertainties = append(a.Uncertainties, part.Uncertainties...)
	}
	if consistent {
		a.IsVulnerable = verdict
	}
	if a.IsVulnerable == "unknown" && len(a.Uncertainties) == 0 {
		a.Uncertainties = append(a.Uncertainties, "Investigations disagree or did not establish a complete verdict")
	}
	if len(a.Evidence) == 0 {
		a.Evidence = append(a.Evidence, "Verifier: no complete validated AI investigation available")
	}
	return a
}

type reflectionRisksTool struct{ risks []ReflectionRisk }

func (t *reflectionRisksTool) Name() string { return "read_reflection_risks" }
func (t *reflectionRisksTool) Description() string {
	return "Read original reflection risk evidence by scan index. Request at most 8 indices. Compact prompt summaries may omit evidence; indices refer to the original scan, not positions in the current batch. Large results are paginated as JSON text; pass the returned next_offset to continue."
}
func (t *reflectionRisksTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{Properties: map[string]any{"indices": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "maxItems": 8}, "offset": map[string]any{"type": "integer", "minimum": 0, "description": "Byte offset into original JSON, from next_offset"}}, Required: []string{"indices"}}
}
func (t *reflectionRisksTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var params struct {
		Indices []int `json:"indices"`
		Offset  int   `json:"offset"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return "", err
	}
	if len(params.Indices) == 0 || len(params.Indices) > 8 {
		return "", fmt.Errorf("request 1 to 8 risk indices")
	}
	type entry struct {
		Index int            `json:"index"`
		Risk  ReflectionRisk `json:"risk"`
	}
	values := make([]entry, 0, len(params.Indices))
	for _, index := range params.Indices {
		if index < 0 || index >= len(t.risks) {
			return "", fmt.Errorf("invalid risk index %d", index)
		}
		values = append(values, entry{index, t.risks[index]})
	}
	data, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	if params.Offset < 0 || params.Offset > len(data) {
		return "", fmt.Errorf("invalid evidence offset")
	}
	start := params.Offset
	for start < len(data) && !utf8.RuneStart(data[start]) {
		start++
	}
	end := min(start+6*1024, len(data))
	for end < len(data) && end > start && !utf8.RuneStart(data[end]) {
		end--
	}
	if start == 0 && end == len(data) {
		return string(data), nil
	}
	next := "complete"
	if end < len(data) {
		next = strconv.Itoa(end)
	}
	return fmt.Sprintf("Original risk JSON bytes %d:%d of %d; next_offset=%s\n%s", start, end, len(data), next, data[start:end]), nil
}

func verificationTools(result *Result, repoDir string) []verificationTool {
	pf := result.ProgressFunc
	tools := []verificationTool{
		&grepCodeTool{repoDir: repoDir, progressFunc: pf},
		&readFileTool{repoDir: repoDir, progressFunc: pf},
		&listFilesTool{repoDir: repoDir, progressFunc: pf},
		&checkModuleTool{repoDir: repoDir, progressFunc: pf},
		&checkGoVersionTool{repoDir: repoDir, result: result, progressFunc: pf},
		&isTestOnlyTool{repoDir: repoDir, progressFunc: pf},
		&checkBuildTagsTool{repoDir: repoDir, progressFunc: pf},
		&listEntryPointsTool{repoDir: repoDir, progressFunc: pf},
		&checkTransitiveDepsTool{repoDir: repoDir, progressFunc: pf},
	}
	if len(result.ReflectionRisks) > 0 {
		tools = append(tools, &reflectionRisksTool{risks: result.ReflectionRisks})
	}
	implementations, callers := make(map[string]verificationTool), make(map[string]verificationTool)
	for _, dir := range verificationKeys(result.ssaBuilds) {
		build := result.ssaBuilds[dir]
		if build == nil || build.err != nil {
			continue
		}
		module := verificationModule(repoDir, dir)
		if build.prog != nil {
			implementations[module] = &findImplementationsTool{prog: build.prog, progressFunc: pf}
		}
		if build.cg != nil {
			callers[module] = &findCallersTool{graph: build.cg, repoModulePath: readModulePath(dir), progressFunc: pf}
		}
	}
	if len(implementations) > 0 {
		tools = append(tools, &moduleGraphTool{tools: implementations})
	}
	if len(callers) > 0 {
		tools = append(tools, &moduleGraphTool{tools: callers})
	}
	return tools
}

func verificationModule(repoDir, dir string) string {
	if filepath.IsAbs(dir) {
		root, err := filepath.Abs(repoDir)
		if err == nil {
			if rel, err := filepath.Rel(root, dir); err == nil {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.ToSlash(filepath.Clean(dir))
}

// Graph tools must query the selected module, not an arbitrary cached build.
type moduleGraphTool struct{ tools map[string]verificationTool }

func (t *moduleGraphTool) first() verificationTool { return t.tools[verificationKeys(t.tools)[0]] }
func (t *moduleGraphTool) Name() string            { return t.first().Name() }
func (t *moduleGraphTool) Description() string {
	return t.first().Description() + " Select the repository-relative module directory with module. Missing graph evidence does not rule out a dynamic call."
}
func (t *moduleGraphTool) InputSchema() verificationToolSchema {
	schema := t.first().InputSchema()
	schema.Properties["module"] = map[string]any{"type": "string", "enum": verificationKeys(t.tools), "description": "Repository-relative module directory; required when multiple module graphs are available"}
	if len(t.tools) > 1 {
		schema.Required = append(schema.Required, "module")
	}
	return schema
}
func (t *moduleGraphTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var params struct {
		Module string `json:"module"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return "", err
	}
	if params.Module == "" && len(t.tools) == 1 {
		params.Module = verificationKeys(t.tools)[0]
	}
	tool, ok := t.tools[params.Module]
	if !ok {
		return "", fmt.Errorf("select module from %v; an unavailable module graph is not evidence of unreachability", verificationKeys(t.tools))
	}
	output, err := tool.Execute(ctx, input)
	return "Module: " + params.Module + "\n" + output, err
}

func parseAssessment(text string) (*AIVerification, error) {
	var resp verificationResponse
	if err := json.Unmarshal([]byte(cleanJSONResponse(text)), &resp); err != nil {
		return nil, err
	}
	verdict := strings.TrimSpace(string(resp.IsVulnerableRaw))
	if verdict != "true" && verdict != "false" && verdict != `"true"` && verdict != `"false"` && verdict != `"unknown"` {
		return nil, fmt.Errorf("IsVulnerable must be true, false, or unknown")
	}
	if resp.Confidence != "high" && resp.Confidence != "medium" && resp.Confidence != "low" {
		return nil, fmt.Errorf("confidence must be high, medium, or low")
	}
	if strings.TrimSpace(resp.Reasoning) == "" || len(resp.Evidence) == 0 {
		return nil, fmt.Errorf("reasoning and evidence are required")
	}
	for _, evidence := range resp.Evidence {
		if strings.TrimSpace(evidence) == "" {
			return nil, fmt.Errorf("evidence entries must not be empty")
		}
	}
	if resp.GraphAnalysis == nil || resp.DynamicAnalysis == nil || resp.Uncertainties == nil {
		return nil, fmt.Errorf("graph_analysis, dynamic_analysis, and uncertainties are required")
	}
	if strings.TrimSpace(resp.GraphAnalysis.Summary) == "" || resp.GraphAnalysis.Findings == nil ||
		strings.TrimSpace(resp.DynamicAnalysis.Summary) == "" || resp.DynamicAnalysis.Findings == nil {
		return nil, fmt.Errorf("each analysis requires a summary and a findings array")
	}
	for _, finding := range resp.GraphAnalysis.Findings {
		if !oneOf(finding.Kind, "supported_path", "suspected_false_positive", "suspected_false_negative", "inconclusive") {
			return nil, fmt.Errorf("invalid graph finding kind %q", finding.Kind)
		}
		if err := validateFinding(finding.Module, finding.Package, finding.Symbol, finding.Confidence, finding.Reasoning, finding.Evidence, finding.Uncertainties); err != nil {
			return nil, err
		}
		if finding.GraphPath == nil || finding.SourcePath == nil {
			return nil, fmt.Errorf("graph findings require graph_path and source_path arrays")
		}
		if oneOf(finding.Kind, "supported_path", "suspected_false_positive") && len(finding.GraphPath) == 0 {
			return nil, fmt.Errorf("%s requires the graph path being reviewed", finding.Kind)
		}
		if oneOf(finding.Kind, "supported_path", "suspected_false_negative") && len(finding.SourcePath) == 0 {
			return nil, fmt.Errorf("%s requires a source-backed path", finding.Kind)
		}
		if finding.Kind == "inconclusive" && len(finding.Uncertainties) == 0 {
			return nil, fmt.Errorf("inconclusive graph finding requires uncertainties")
		}
	}
	for _, finding := range resp.DynamicAnalysis.Findings {
		if !oneOf(finding.Status, "supported", "ruled_out", "unresolved") || !oneOf(finding.GraphStatus, "present", "missing", "unknown") {
			return nil, fmt.Errorf("invalid dynamic finding status")
		}
		if !oneOf(finding.Mechanism, "reflection", "unsafe", "function_value", "callback", "registration", "other") {
			return nil, fmt.Errorf("invalid dynamic mechanism %q", finding.Mechanism)
		}
		pkg, symbol := finding.Package, finding.Symbol
		if pkg == "" && symbol == "" && finding.Status == "unresolved" && finding.GraphStatus == "unknown" && len(finding.RiskIndices) > 0 {
			pkg, symbol = "unresolved", "unresolved"
		}
		if err := validateFinding(finding.Module, pkg, symbol, finding.Confidence, finding.Reasoning, finding.Evidence, finding.Uncertainties); err != nil {
			return nil, err
		}
		if finding.RiskIndices == nil || finding.SourcePath == nil {
			return nil, fmt.Errorf("dynamic findings require risk_indices and source_path arrays")
		}
		if finding.Status == "supported" && len(finding.SourcePath) == 0 {
			return nil, fmt.Errorf("supported dynamic usage requires a source-backed path")
		}
		if finding.Status == "unresolved" && len(finding.Uncertainties) == 0 {
			return nil, fmt.Errorf("unresolved dynamic finding requires uncertainties")
		}
	}
	if resp.GetIsVulnerable() == "unknown" && len(resp.Uncertainties) == 0 {
		return nil, fmt.Errorf("unknown verdict requires uncertainties")
	}
	return &AIVerification{IsVulnerable: resp.GetIsVulnerable(), Confidence: resp.Confidence,
		Reasoning: resp.Reasoning, Evidence: resp.Evidence, GraphAnalysis: *resp.GraphAnalysis,
		DynamicAnalysis: *resp.DynamicAnalysis, Uncertainties: resp.Uncertainties}, nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validateFinding(module, pkg, symbol, confidence, reasoning string, evidence, uncertainties []string) error {
	if strings.TrimSpace(module) == "" || strings.TrimSpace(pkg) == "" || strings.TrimSpace(symbol) == "" || strings.TrimSpace(reasoning) == "" {
		return fmt.Errorf("findings require module, package, symbol, and reasoning")
	}
	if !oneOf(confidence, "high", "medium", "low") || len(evidence) == 0 || uncertainties == nil {
		return fmt.Errorf("findings require valid confidence, evidence, and uncertainties")
	}
	for _, item := range append(append([]string(nil), evidence...), uncertainties...) {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("finding evidence/uncertainties must not contain empty entries")
		}
	}
	return nil
}

func validateAuditTargets(result *Result, assessment *AIVerification) error {
	indices := make([]int, len(result.ReflectionRisks))
	for i := range indices {
		indices[i] = i
	}
	return validateAuditBatch(result, assessment, indices)
}
func validateAuditBatch(result *Result, assessment *AIVerification, indices []int) error {
	allowed := make(map[int]bool, len(indices))
	for _, index := range indices {
		allowed[index] = true
	}

	checkSymbol := func(pkg, symbol string) error {
		affected, ok := result.AffectedImports[pkg]
		if !ok || !oneOf(symbol, affected.Symbols...) {
			return fmt.Errorf("finding refers to an unlisted affected symbol %s.%s", pkg, symbol)
		}
		return nil
	}
	for _, finding := range assessment.GraphAnalysis.Findings {
		if err := checkSymbol(finding.Package, finding.Symbol); err != nil {
			return err
		}
	}
	covered := make(map[int]bool)
	for _, finding := range assessment.DynamicAnalysis.Findings {
		if finding.Package != "" || finding.Symbol != "" || finding.Status != "unresolved" {
			if err := checkSymbol(finding.Package, finding.Symbol); err != nil {
				return err
			}
		}
		for _, index := range finding.RiskIndices {
			if !allowed[index] {
				return fmt.Errorf("invalid reflection risk index %d", index)
			}
			covered[index] = true
		}
	}
	for _, index := range indices {
		if !covered[index] {
			return fmt.Errorf("reflection risk %d has no supported, ruled_out, or unresolved disposition", index)
		}
	}
	return nil
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

	// Find the LAST balanced { ... } object (the final JSON is at the end)
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
	for _, dir := range verificationKeys(result.UsedImports) {
		pkgs := result.UsedImports[dir]
		for _, pkg := range verificationKeys(pkgs) {
			details := pkgs[pkg]
			for i, sym := range details.Symbols {
				if i >= len(details.Paths) {
					continue
				}
				path := details.Paths[i]
				if len(path) == 0 {
					continue
				}
				b.WriteString(fmt.Sprintf("Trace in module %s for %s.%s:\n", dir, pkg, sym))
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
	}
	return b.String()
}

func findEdgeDescription(caller, callee *callgraph.Node) string {
	if caller == nil || callee == nil {
		return "unavailable edge"
	}
	var descriptions []string
	for _, edge := range caller.Out {
		if edge.Callee != callee {
			continue
		}
		desc := edge.Description()
		if edge.Site != nil {
			if edge.Site.Common().IsInvoke() {
				ifaceType := edge.Site.Common().Value.Type().String()
				methodName := edge.Site.Common().Method.Name()
				desc += fmt.Sprintf(" via interface %s.%s", ifaceType, methodName)
			}
			if caller.Func != nil && caller.Func.Prog != nil && caller.Func.Prog.Fset != nil {
				if pos := caller.Func.Prog.Fset.Position(edge.Site.Pos()); pos.IsValid() {
					desc += fmt.Sprintf("; call site %s:%d", pos.Filename, pos.Line)
				}
			}
		}
		descriptions = append(descriptions, desc)
	}
	if len(descriptions) == 0 {
		return "unknown dispatch"
	}
	sort.Strings(descriptions)
	return boundedVerificationText(strings.Join(descriptions, "; alternative edge: "), 2048, " [additional call sites omitted]")
}

func loadSkillPrompt(result *Result) (string, bool) {
	// 1. Environment variable override
	if dir := os.Getenv("GVS_SKILLS_DIR"); dir != "" {
		path := filepath.Join(dir, "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			result.progress(fmt.Sprintf("[ai] Loading skill: %s", path))
			return string(data), true
		}
	}

	// 2. Relative to the binary location
	if exe, err := os.Executable(); err == nil {
		binDir := filepath.Dir(exe)
		path := filepath.Join(binDir, "..", "skills", "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			result.progress(fmt.Sprintf("[ai] Loading skill: %s", path))
			return string(data), true
		}
		// Also check same directory as binary (container layout)
		path = filepath.Join(binDir, "skills", "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			result.progress(fmt.Sprintf("[ai] Loading skill: %s", path))
			return string(data), true
		}
	}

	// 3. User install location
	if homeDir, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(homeDir, ".local", "share", "gvs", "skills", "verify-scan.md")
		if data, err := os.ReadFile(path); err == nil {
			result.progress(fmt.Sprintf("[ai] Loading skill: %s", path))
			return string(data), true
		}
	}

	// 4. Current working directory (development)
	path := filepath.Join("skills", "verify-scan.md")
	if data, err := os.ReadFile(path); err == nil {
		result.progress(fmt.Sprintf("[ai] Loading skill: %s", path))
		return string(data), true
	}

	return "", false
}

func buildVerificationPrompt(result *Result, skillTemplate string, sourceSnippets map[string]string) (string, error) {
	var risks []verificationRisk
	for _, batch := range verificationRiskBatches(result, result.Directory) {
		risks = append(risks, batch...)
	}
	return buildVerificationPromptForRisks(result, skillTemplate, sourceSnippets, risks)
}
func buildVerificationPromptForRisks(result *Result, skillTemplate string, sourceSnippets map[string]string, risks []verificationRisk) (string, error) {
	type sanitizedUsedImports struct {
		CurrentVersion string `json:"CurrentVersion,omitempty"`
		ReplaceModule  string `json:"ReplaceModule,omitempty"`
		ReplaceVersion string `json:"ReplaceVersion,omitempty"`
	}
	sanitized := make(map[string]map[string]sanitizedUsedImports)
	for dir, pkgs := range result.UsedImports {
		sanitized[dir] = make(map[string]sanitizedUsedImports)
		for pkg, details := range pkgs {
			sanitized[dir][pkg] = sanitizedUsedImports{
				CurrentVersion: details.CurrentVersion,
				ReplaceModule:  details.ReplaceModule,
				ReplaceVersion: details.ReplaceVersion,
			}
		}
	}

	promptResult := struct {
		UsedImports     map[string]map[string]sanitizedUsedImports `json:"UsedImports,omitempty"`
		AffectedImports map[string]AffectedImportsDetails          `json:"AffectedImports,omitempty"`
		GoCVE           string                                     `json:"GoCVE"`
		CVE             string                                     `json:"CVE"`
		Repository      string                                     `json:"Repository"`
		Branch          string                                     `json:"Branch"`
		ReflectionRisks []verificationRisk                         `json:"reflection_risks"`
		Unsafe          bool                                       `json:"unsafe"`
		Reflect         bool                                       `json:"reflect"`
		GraphModules    map[string]string                          `json:"graph_modules"`
		GraphPaths      []string                                   `json:"GraphPaths,omitempty"`
		Errors          []string                                   `json:"Errors,omitempty"`
	}{
		UsedImports:     sanitized,
		AffectedImports: result.AffectedImports,
		GoCVE:           result.GoCVE,
		CVE:             result.CVE,
		Repository:      result.Repository,
		Branch:          result.Branch,
		ReflectionRisks: risks,
		Unsafe:          result.Unsafe,
		Reflect:         result.Reflect,
		GraphPaths:      result.GraphPaths,
		GraphModules:    make(map[string]string),
		Errors:          result.Errors,
	}
	for dir, build := range result.ssaBuilds {
		status := "available"
		if build == nil || build.err != nil || build.cg == nil {
			status = "unavailable or incomplete; do not infer unreachability"
		}
		promptResult.GraphModules[verificationModule(result.Directory, dir)] = status
	}

	resultJSON, err := json.Marshal(promptResult)
	if err != nil {
		return "", fmt.Errorf("failed to marshal scan result: %w", err)
	}

	var snippetBuilder strings.Builder
	for _, path := range verificationKeys(sourceSnippets) {
		content := sourceSnippets[path]
		snippetBuilder.WriteString(fmt.Sprintf("### %s\n\n```go\n%s\n```\n\n", path, content))
	}

	algo := os.Getenv("ALGO")
	if algo == "" {
		algo = "rta"
	}

	callTraces := boundedVerificationText(FormatCallTraces(result), 16*1024, "\n[Graph traces truncated. Query find_callers by affected symbol and module. Unreviewed paths remain uncertain.]\n")

	prompt := skillTemplate
	prompt = strings.ReplaceAll(prompt, "{{.scan_result_json}}", string(resultJSON))
	prompt = strings.ReplaceAll(prompt, "{{.source_snippets}}", snippetBuilder.String())
	prompt = strings.ReplaceAll(prompt, "{{.algorithm}}", algo)
	prompt = strings.ReplaceAll(prompt, "{{.is_vulnerable}}", result.IsVulnerable)
	prompt = strings.ReplaceAll(prompt, "{{.call_traces}}", callTraces)

	return verificationEvidenceInstructions + "\n\n" + prompt, nil
}

const (
	maxSourceBytes     = 32 * 1024
	maxSourceFileBytes = 4 * 1024
	maxToolResultBytes = 8 * 1024
)

const verificationEvidenceInstructions = `Evidence handling rules:
Source context contains selected line-numbered excerpts, not complete files. Missing or truncated text is NOT evidence of absence. Use read_file with narrow line ranges to recover needed context, and specialize searches rather than repeating broad queries. Before requesting a tool, identify the unresolved question that could change the verdict. A call-graph edge is a candidate path, not proof of exploitability: check versions, replacements, production reachability, dispatch, and advisory preconditions. If critical evidence is unavailable or the investigation limit is reached without resolving it, return IsVulnerable="unknown" and explain the gap. Cite concrete file:line or tool evidence. Stop when sufficient evidence establishes the assessment.`

func verificationKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sourceBytes(snippets map[string]string) int {
	total := 0
	for _, snippet := range snippets {
		total += len(snippet)
	}
	return total
}

func collectRelevantSource(result *Result, repoDir string) map[string]string {
	// Keep all anchors for a file before rendering it. In particular, a call far
	// below its function declaration must not disappear behind a file-size cap.
	anchors := make(map[string][]int)
	var files []string
	addFile := func(path string, lines ...int) {
		if filepath.IsAbs(path) {
			var err error
			path, err = filepath.Rel(repoDir, path)
			if err != nil {
				return
			}
		}
		path = filepath.Clean(path)
		if _, err := safePath(repoDir, path); err != nil {
			return
		}
		if _, exists := anchors[path]; !exists {
			files = append(files, path)
		}
		anchors[path] = append(anchors[path], lines...)
	}
	addFile("go.mod")
	for _, dir := range verificationKeys(result.UsedImports) {
		for _, pkg := range verificationKeys(result.UsedImports[dir]) {
			for _, path := range result.UsedImports[dir][pkg].Paths {
				for i, node := range path {
					if node == nil || node.Func == nil || node.Func.Prog == nil || node.Func.Prog.Fset == nil {
						continue
					}
					fset := node.Func.Prog.Fset
					if i+1 < len(path) {
						for _, edge := range node.Out {
							if edge.Callee == path[i+1] && edge.Site != nil {
								pos := fset.Position(edge.Site.Pos())
								if pos.IsValid() {
									addFile(pos.Filename, pos.Line)
								}
							}
						}
					}
					pos := fset.Position(node.Func.Pos())
					if pos.IsValid() {
						addFile(pos.Filename, pos.Line)
					}
				}
			}
		}
	}
	for _, risk := range result.ReflectionRisks {
		parts := strings.SplitN(risk.Location, ":", 3)
		line := 0
		if len(parts) > 1 {
			line, _ = strconv.Atoi(parts[1])
		}
		addFile(parts[0], line)
	}

	vulnPkgs := verificationKeys(result.AffectedImports)
	modulePath := readModulePath(repoDir)
	reverseImports := make(map[string][]string)
	directImporters := make(map[string]bool)
	if len(vulnPkgs) > 0 {
		filepath.WalkDir(repoDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if path != repoDir && (name == "vendor" || name == ".git" || strings.HasPrefix(name, ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(repoDir, path)
			if err != nil {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return nil
			}
			for _, imp := range f.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				reverseImports[importPath] = append(reverseImports[importPath], rel)
				for _, pkg := range vulnPkgs {
					if importPath == pkg || strings.HasPrefix(importPath, pkg+"/") {
						addFile(rel)
						if modulePath != "" {
							pkgPath := modulePath
							if dir := filepath.Dir(rel); dir != "." {
								pkgPath += "/" + filepath.ToSlash(dir)
							}
							directImporters[pkgPath] = true
						}
					}
				}
			}
			return nil
		})
	}
	for _, pkg := range verificationKeys(directImporters) {
		for _, path := range reverseImports[pkg] {
			addFile(path)
		}
	}
	for _, dir := range verificationKeys(result.Files) {
		for _, set := range result.Files[dir] {
			paths := append([]string(nil), set...)
			sort.Strings(paths)
			for _, path := range paths {
				addFile(path)
			}
		}
	}

	symbols := make(map[string]bool)
	for _, affected := range result.AffectedImports {
		for _, symbol := range affected.Symbols {
			parts := strings.Split(symbol, ".")
			symbols[parts[len(parts)-1]] = true
		}
	}
	snippets := make(map[string]string)
	total := 0
	for _, path := range files {
		if maxSourceBytes-total < maxSourceFileBytes {
			break
		}
		data, err := os.ReadFile(filepath.Join(repoDir, path))
		if err != nil {
			continue
		}
		points := append([]int(nil), anchors[path]...)
		var fallback []int
		if strings.HasSuffix(path, ".go") {
			fset := token.NewFileSet()
			if f, err := parser.ParseFile(fset, path, data, 0); err == nil {
				ast.Inspect(f, func(node ast.Node) bool {
					switch n := node.(type) {
					case *ast.Ident:
						if symbols[n.Name] {
							points = append(points, fset.Position(n.Pos()).Line)
						}
					case *ast.FuncDecl:
						if n.Name.Name == "main" || n.Name.Name == "init" {
							fallback = append(fallback, fset.Position(n.Pos()).Line)
						}
					}
					return true
				})
				for _, imp := range f.Imports {
					fallback = append(fallback, fset.Position(imp.Pos()).Line)
				}
			}
		}
		points = append(points, fallback...)
		// Include module metadata or the package/build-tag header after the
		// vulnerability anchors, so large file headers cannot crowd those out.
		points = append(points, 1)
		snippet := sourceExcerpt(string(data), points, path == "go.mod")
		snippets[path] = snippet
		total += len(snippet)
	}
	return snippets
}

func sourceExcerpt(source string, anchors []int, module bool) string {
	lines := strings.Split(source, "\n")
	const header = "[Selected source lines; omitted text may contain relevant evidence. Use read_file for additional ranges.]\n"
	const footer = "[Other lines omitted; absence from these excerpts is not evidence of absence.]\n"
	selected := make(map[int]string)
	size := len(header) + len(footer)
	addLine := func(line int) {
		if line < 1 || line > len(lines) {
			return
		}
		if _, exists := selected[line]; exists {
			return
		}
		row := fmt.Sprintf("%d|%s\n", line, boundedVerificationText(lines[line-1], 512, " ... [line truncated; use read_file]"))
		if size+len(row) > maxSourceFileBytes {
			return
		}
		selected[line] = row
		size += len(row)
	}
	// Reserve the exact call/definition lines before adding surrounding context.
	for _, center := range anchors {
		addLine(center)
	}
	for _, center := range anchors {
		if center < 1 || center > len(lines) {
			continue
		}
		start, end := max(1, center-8), min(len(lines), center+8)
		if module {
			start, end = 1, len(lines)
		}
		for line := start; line <= end; line++ {
			addLine(line)
		}
	}
	order := make([]int, 0, len(selected))
	for line := range selected {
		order = append(order, line)
	}
	sort.Ints(order)
	var b strings.Builder
	b.WriteString(header)
	for _, line := range order {
		b.WriteString(selected[line])
	}
	if len(selected) < len(lines) {
		b.WriteString(footer)
	}
	return b.String()
}

func boundedVerificationText(text string, limit int, notice string) string {
	if len(text) <= limit {
		return text
	}
	end := max(0, limit-len(notice))
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	if newline := strings.LastIndexByte(text[:end], '\n'); newline >= end/2 {
		end = newline + 1
	}
	return text[:end] + notice
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

type verificationToolSchema struct {
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
	Required   []string       `json:"required,omitempty"`
}

// verificationTool exposes repository investigation without depending on a provider SDK.
type verificationTool interface {
	Name() string
	Description() string
	InputSchema() verificationToolSchema
	Execute(context.Context, json.RawMessage) (string, error)
}

// verificationAgent owns the provider's tool conversation and returns the final assessment text.
type verificationAgent interface {
	Run(context.Context, string, []verificationTool) (string, error)
}

type aiConfig struct {
	Provider      string
	Model         string
	BaseURL       string
	APIKey        string
	ProjectID     string
	Location      string
	MaxIterations int
	MaxTokens     int
	ContextTokens int
	Timeout       time.Duration
}

// Input includes cache reads and writes for both protocols. Pointers preserve
// the distinction between an unreported cache counter and a reported zero.
type verificationTokenUsage struct {
	Input, Output         int64
	CacheRead, CacheWrite *int64
}

type verificationUsageLog struct {
	progress                                     func(string)
	requests, reports, readReports, writeReports int
	total                                        verificationTokenUsage
}

func tokenCount(value *int64) string {
	if value == nil {
		return "unreported"
	}
	return strconv.FormatInt(*value, 10)
}

func (u *verificationUsageLog) record(usage *verificationTokenUsage) {
	if usage == nil {
		toolProgress(u.progress, fmt.Sprintf("[ai] Usage request=%d: unavailable (provider did not report complete usage)", u.requests))
		return
	}
	u.reports++
	u.total.Input += usage.Input
	u.total.Output += usage.Output
	if usage.CacheRead != nil {
		u.readReports++
		if u.total.CacheRead == nil {
			u.total.CacheRead = new(int64)
		}
		*u.total.CacheRead += *usage.CacheRead
	}
	if usage.CacheWrite != nil {
		u.writeReports++
		if u.total.CacheWrite == nil {
			u.total.CacheWrite = new(int64)
		}
		*u.total.CacheWrite += *usage.CacheWrite
	}
	uncached := "unreported"
	if usage.CacheRead != nil && usage.CacheWrite != nil {
		uncached = strconv.FormatInt(usage.Input-*usage.CacheRead-*usage.CacheWrite, 10)
	}
	toolProgress(u.progress, fmt.Sprintf("[ai] Usage request=%d: input=%d output=%d cache_read=%s cache_write=%s uncached=%s",
		u.requests, usage.Input, usage.Output, tokenCount(usage.CacheRead), tokenCount(usage.CacheWrite), uncached))
}

func (u *verificationUsageLog) summary() {
	if u.reports == 0 {
		toolProgress(u.progress, fmt.Sprintf("[ai] Usage total: unavailable (requests=%d usage_reports=0)", u.requests))
		return
	}
	toolProgress(u.progress, fmt.Sprintf("[ai] Usage reported totals: input=%d output=%d cache_read=%s cache_write=%s requests=%d usage_reports=%d cache_read_reports=%d cache_write_reports=%d",
		u.total.Input, u.total.Output, tokenCount(u.total.CacheRead), tokenCount(u.total.CacheWrite), u.requests, u.reports, u.readReports, u.writeReports))
}

func anthropicTokenUsage(usage anthropic.BetaUsage) *verificationTokenUsage {
	// Anthropic input_tokens excludes both cache categories, so all three
	// input counters are needed before reporting a comparable input total.
	if !usage.JSON.InputTokens.Valid() || !usage.JSON.OutputTokens.Valid() ||
		!usage.JSON.CacheReadInputTokens.Valid() || !usage.JSON.CacheCreationInputTokens.Valid() {
		return nil
	}
	result := &verificationTokenUsage{Input: usage.InputTokens + usage.CacheReadInputTokens + usage.CacheCreationInputTokens, Output: usage.OutputTokens}
	if usage.JSON.CacheReadInputTokens.Valid() {
		result.CacheRead = &usage.CacheReadInputTokens
	}
	if usage.JSON.CacheCreationInputTokens.Valid() {
		result.CacheWrite = &usage.CacheCreationInputTokens
	}
	return result
}

type compatibleUsage struct {
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	PromptDetails    struct {
		CachedTokens     *int64 `json:"cached_tokens"`
		CacheWriteTokens *int64 `json:"cache_write_tokens"`
	} `json:"prompt_tokens_details"`
}

func (usage *compatibleUsage) normalized() *verificationTokenUsage {
	if usage == nil || usage.PromptTokens == nil || usage.CompletionTokens == nil {
		return nil
	}
	return &verificationTokenUsage{Input: *usage.PromptTokens, Output: *usage.CompletionTokens, CacheRead: usage.PromptDetails.CachedTokens, CacheWrite: usage.PromptDetails.CacheWriteTokens}
}

func loadAIConfig() (aiConfig, bool, error) {
	cfg := aiConfig{MaxIterations: 20, MaxTokens: 16384, ContextTokens: 131072, Timeout: 10 * time.Minute}
	if os.Getenv("GVS_AI") != "1" {
		return cfg, false, nil
	}
	cfg.Provider = strings.ToLower(strings.TrimSpace(os.Getenv("GVS_AI_PROVIDER")))
	cfg.Model = strings.TrimSpace(os.Getenv("GVS_AI_MODEL"))
	cfg.APIKey = os.Getenv("GVS_AI_API_KEY")
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("GVS_AI_BASE_URL")), "/")
	cfg.ProjectID = strings.TrimSpace(os.Getenv("GVS_AI_PROJECT_ID"))
	cfg.Location = strings.TrimSpace(os.Getenv("GVS_AI_LOCATION"))
	for name, target := range map[string]*int{
		"GVS_AI_MAX_ITERATIONS": &cfg.MaxIterations,
		"GVS_AI_MAX_TOKENS":     &cfg.MaxTokens,
		"GVS_AI_CONTEXT_TOKENS": &cfg.ContextTokens,
	} {
		if value := os.Getenv(name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return cfg, true, fmt.Errorf("%s must be a positive integer", name)
			}
			*target = n
		}
	}
	if cfg.ContextTokens <= cfg.MaxTokens+8192 {
		return cfg, true, fmt.Errorf("GVS_AI_CONTEXT_TOKENS must exceed GVS_AI_MAX_TOKENS by more than 8192")
	}
	if value := os.Getenv("GVS_AI_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return cfg, true, fmt.Errorf("GVS_AI_TIMEOUT must be a positive duration, e.g. 10m")
		}
		cfg.Timeout = timeout
	}
	if cfg.Model == "" {
		return cfg, true, fmt.Errorf("GVS_AI_MODEL is required")
	}
	switch cfg.Provider {
	case "anthropic-vertex":
		if cfg.ProjectID == "" {
			return cfg, true, fmt.Errorf("GVS_AI_PROJECT_ID is required for anthropic-vertex")
		}
		if cfg.Location == "" {
			cfg.Location = "global"
		}
	case "openai-compatible":
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://api.openai.com/v1"
		}
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return cfg, true, fmt.Errorf("GVS_AI_BASE_URL must be an HTTP(S) base URL without credentials, query, or fragment")
		}
		if u.Hostname() == "api.openai.com" && cfg.APIKey == "" {
			return cfg, true, fmt.Errorf("GVS_AI_API_KEY is required for api.openai.com")
		}
	default:
		return cfg, true, fmt.Errorf("GVS_AI_PROVIDER must be anthropic-vertex or openai-compatible")
	}
	return cfg, true, nil
}

func newAgent(ctx context.Context, cfg aiConfig, progress func(string)) verificationAgent {
	if cfg.Provider == "anthropic-vertex" {
		return newAnthropicAgent(ctx, cfg, progress)
	}
	return &compatibleAgent{client: &http.Client{Timeout: cfg.Timeout}, cfg: cfg, progress: progress}
}

func logAIStatus(cfg aiConfig, enabled bool, err error, progress func(string)) {
	if err != nil {
		toolProgress(progress, fmt.Sprintf("AI verification: configuration error: %v", err))
		return
	}
	if !enabled {
		toolProgress(progress, "AI verification: disabled (set GVS_AI=1 to enable)")
		return
	}
	toolProgress(progress, fmt.Sprintf("AI verification: enabled (provider=%s, model=%s, max_iterations=%d)", cfg.Provider, cfg.Model, cfg.MaxIterations))
}

const finalAssessmentPrompt = "You have reached the investigation limit. Stop using tools and respond with your final JSON assessment, including graph_analysis, dynamic_analysis, and uncertainties. Give every supplied reflection risk an explicit supported, ruled_out, or unresolved disposition. If critical evidence is missing or truncated, return IsVulnerable=unknown and explain what could not be established. The investigation limit is not evidence that the repository is safe."

func executeTool(ctx context.Context, tools []verificationTool, name string, input json.RawMessage, progress func(string)) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	toolProgress(progress, fmt.Sprintf("[ai] tool_call %s(%s)", name, input))
	if !json.Valid(input) {
		return "", fmt.Errorf("invalid JSON arguments for tool %q", name)
	}
	for _, tool := range tools {
		if tool.Name() == name {
			output, err := tool.Execute(ctx, input)
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if err != nil {
				err = fmt.Errorf("%s", boundedVerificationText(err.Error(), maxToolResultBytes-7, "\n[Tool error truncated.]"))
			}
			bounded := boundedVerificationText(output, maxToolResultBytes, "\n[Tool output truncated. Narrow the query or use read_file with a later start_line; omitted evidence may change the verdict.]\n")
			if len(bounded) != len(output) {
				toolProgress(progress, fmt.Sprintf("[ai] %s output bounded: %d -> %d bytes", name, len(output), len(bounded)))
			}
			return bounded, err
		}
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

type anthropicAgent struct {
	client   anthropic.Client
	cfg      aiConfig
	progress func(string)
}

func newAnthropicAgent(ctx context.Context, cfg aiConfig, progress func(string)) verificationAgent {
	client := anthropic.NewClient(vertex.WithGoogleAuth(ctx, cfg.Location, cfg.ProjectID))
	return &anthropicAgent{client: client, cfg: cfg, progress: progress}
}

// Serialized request bytes provide a conservative input-token estimate for the
// supported protocols. This includes schemas and every history message. Reserve
// output tokens and framing margin; configure the actual model context limit.
func checkVerificationContext(cfg aiConfig, request any, headroom int) error {
	limit := cfg.ContextTokens
	if limit == 0 {
		limit = 131072
	}
	output := cfg.MaxTokens
	if output == 0 {
		output = 16384
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	budget := limit - output - 4096 - headroom
	if len(data) > budget {
		return fmt.Errorf("AI context budget reached: request=%d bytes, conservative input budget=%d; investigation remains incomplete", len(data), budget)
	}
	return nil
}

func (a *anthropicAgent) Run(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
	usageLog := verificationUsageLog{progress: a.progress}
	defer usageLog.summary()
	params := anthropic.BetaMessageNewParams{
		Model:     a.cfg.Model,
		MaxTokens: int64(a.cfg.MaxTokens),
		Messages:  []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt))},
	}
	for _, tool := range tools {
		schema := tool.InputSchema()
		params.Tools = append(params.Tools, anthropic.BetaToolUnionParam{OfTool: &anthropic.BetaToolParam{
			Name: tool.Name(), Description: anthropic.String(tool.Description()),
			InputSchema: anthropic.BetaToolInputSchemaParam{Properties: schema.Properties, Required: schema.Required},
		}})
	}
	// Each investigation turn may call several tools. One additional turn is
	// reserved for the final assessment, with tool use disabled.
	for iteration := 0; iteration <= a.cfg.MaxIterations; iteration++ {
		final := iteration == a.cfg.MaxIterations || checkVerificationContext(a.cfg, params, maxToolResultBytes) != nil
		if final {
			params.Messages = append(params.Messages, anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(finalAssessmentPrompt)))
			params.ToolChoice = anthropic.BetaToolChoiceUnionParam{OfNone: &anthropic.BetaToolChoiceNoneParam{}}
		}
		toolProgress(a.progress, fmt.Sprintf("[ai] Iteration %d", iteration+1))
		if err := checkVerificationContext(a.cfg, params, 0); err != nil {
			return "", err
		}
		usageLog.requests++
		message, err := a.client.Beta.Messages.New(ctx, params)
		if err != nil {
			return "", err
		}
		usageLog.record(anthropicTokenUsage(message.Usage))
		if message.StopReason == anthropic.BetaStopReasonMaxTokens {
			return "", fmt.Errorf("AI response truncated (max_tokens reached)")
		}
		params.Messages = append(params.Messages, message.ToParam())
		var text strings.Builder
		var results []anthropic.BetaContentBlockParamUnion
		for _, block := range message.Content {
			switch block.Type {
			case "text":
				text.WriteString(block.Text)
			case "tool_use":
				if final {
					return "", fmt.Errorf("AI requested tools after the investigation limit")
				}
				output, err := executeTool(ctx, tools, block.Name, block.Input, a.progress)
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				if err != nil {
					output = "error: " + err.Error()
				}
				results = append(results, anthropic.NewBetaToolResultBlock(block.ID, output, err != nil))
			}
		}
		if len(results) == 0 {
			if message.StopReason != anthropic.BetaStopReasonEndTurn || strings.TrimSpace(text.String()) == "" {
				return "", fmt.Errorf("AI returned no complete assessment (stop_reason=%s)", message.StopReason)
			}
			return text.String(), nil
		}
		params.Messages = append(params.Messages, anthropic.NewBetaUserMessage(results...))
	}
	return "", fmt.Errorf("AI investigation limit reached without an assessment")
}

// compatibleAgent uses the Chat Completions function-calling protocol.
// https://developers.openai.com/api/docs/guides/function-calling
type compatibleAgent struct {
	client   *http.Client
	cfg      aiConfig
	progress func(string)
}

type compatibleFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  verificationToolSchema `json:"parameters"`
}

type compatibleTool struct {
	Type     string             `json:"type"`
	Function compatibleFunction `json:"function"`
}

type compatibleRequest struct {
	Model               string           `json:"model"`
	Messages            []any            `json:"messages"`
	Tools               []compatibleTool `json:"tools,omitempty"`
	ToolChoice          string           `json:"tool_choice,omitempty"`
	MaxCompletionTokens int              `json:"max_completion_tokens"`
}

type compatibleMessage struct {
	Role      string `json:"role"`
	Content   string `json:"content"`
	Refusal   string `json:"refusal"`
	ToolCalls []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

func (a *compatibleAgent) Run(ctx context.Context, prompt string, tools []verificationTool) (string, error) {
	usageLog := verificationUsageLog{progress: a.progress}
	defer usageLog.summary()
	request := compatibleRequest{
		Model: a.cfg.Model, MaxCompletionTokens: a.cfg.MaxTokens,
		Messages: []any{map[string]string{"role": "user", "content": prompt}},
	}
	for _, tool := range tools {
		request.Tools = append(request.Tools, compatibleTool{Type: "function", Function: compatibleFunction{
			Name: tool.Name(), Description: tool.Description(), Parameters: tool.InputSchema(),
		}})
	}
	for iteration := 0; iteration <= a.cfg.MaxIterations; iteration++ {
		final := iteration == a.cfg.MaxIterations || checkVerificationContext(a.cfg, request, maxToolResultBytes) != nil
		if final {
			request.ToolChoice = "none"
			request.Messages = append(request.Messages, map[string]string{"role": "user", "content": finalAssessmentPrompt})
		}
		toolProgress(a.progress, fmt.Sprintf("[ai] Iteration %d", iteration+1))
		if err := checkVerificationContext(a.cfg, request, 0); err != nil {
			return "", err
		}
		usageLog.requests++
		raw, reason, usage, err := a.complete(ctx, request)
		if usage != nil {
			usageLog.record(usage)
		}
		if err != nil {
			return "", err
		}
		if usage == nil {
			usageLog.record(nil)
		}
		if reason != "stop" && reason != "tool_calls" {
			return "", fmt.Errorf("AI returned no complete assessment (finish_reason=%s)", reason)
		}
		var message compatibleMessage
		if err := json.Unmarshal(raw, &message); err != nil {
			return "", fmt.Errorf("invalid AI message: %w", err)
		}
		if message.Role != "assistant" || message.Refusal != "" {
			return "", fmt.Errorf("AI returned an invalid message or refused verification")
		}
		if len(message.ToolCalls) == 0 {
			if reason != "stop" || strings.TrimSpace(message.Content) == "" {
				return "", fmt.Errorf("AI returned an empty assessment")
			}
			return message.Content, nil
		}
		if final {
			return "", fmt.Errorf("AI requested tools after the investigation limit")
		}
		// Keep the original assistant message, including provider-specific state.
		request.Messages = append(request.Messages, raw)
		for _, call := range message.ToolCalls {
			if call.ID == "" || call.Type != "function" {
				return "", fmt.Errorf("AI returned an invalid function call")
			}
			output, err := executeTool(ctx, tools, call.Function.Name, json.RawMessage(call.Function.Arguments), a.progress)
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if err != nil {
				output = "error: " + err.Error()
			}
			request.Messages = append(request.Messages, map[string]string{
				"role": "tool", "tool_call_id": call.ID, "content": output,
			})
		}
	}
	return "", fmt.Errorf("AI investigation limit reached without an assessment")
}

func (a *compatibleAgent) complete(ctx context.Context, request compatibleRequest) (json.RawMessage, string, *verificationTokenUsage, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
	response, err := a.client.Do(req)
	if err != nil {
		return nil, "", nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "", nil, fmt.Errorf("AI endpoint returned HTTP %d", response.StatusCode)
	}
	var result struct {
		Usage   *compatibleUsage `json:"usage"`
		Choices []struct {
			Message      json.RawMessage `json:"message"`
			FinishReason string          `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&result); err != nil {
		return nil, "", nil, fmt.Errorf("invalid AI response: %w", err)
	}
	if len(result.Choices) != 1 {
		return nil, "", result.Usage.normalized(), fmt.Errorf("AI endpoint must return one response choice")
	}
	return result.Choices[0].Message, result.Choices[0].FinishReason, result.Usage.normalized(), nil
}

// --- Repository tools ---

func safePath(repoDir, relPath string) (string, error) {
	cleaned := filepath.Clean(relPath)
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("path %q escapes repository root", relPath)
	}
	return filepath.Join(repoDir, cleaned), nil
}

func textResult(text string) (string, error) {
	return text, nil
}

func toolProgress(pf func(string), msg string) {
	if pf != nil {
		pf(msg)
	}
}

// grep_code tool
type grepCodeTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *grepCodeTool) Name() string { return "grep_code" }
func (t *grepCodeTool) Description() string {
	return "Search for a regex pattern in the repository. Returns matching lines with file paths and line numbers."
}
func (t *grepCodeTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"pattern": map[string]any{"type": "string", "description": "Regex pattern to search for"},
			"glob":    map[string]any{"type": "string", "description": "File glob filter, e.g. *.go"},
		},
		Required: []string{"pattern"},
	}
}

func (t *grepCodeTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
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
	toolProgress(t.progressFunc, fmt.Sprintf("[ai] grep_code result: %d lines", len(lines)))
	return textResult(result)
}

// read_file tool
type readFileTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *readFileTool) Name() string { return "read_file" }
func (t *readFileTool) Description() string {
	return "Read a file from the repository. Optionally specify start and end line numbers."
}
func (t *readFileTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"path":       map[string]any{"type": "string", "description": "File path relative to repo root"},
			"start_line": map[string]any{"type": "integer", "description": "Start line (1-based, optional)"},
			"end_line":   map[string]any{"type": "integer", "description": "End line (1-based, optional)"},
		},
		Required: []string{"path"},
	}
}

func (t *readFileTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
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
	toolProgress(t.progressFunc, fmt.Sprintf("[ai] read_file result: %s (%d lines)", params.Path, end-start))
	return textResult(b.String())
}

// list_files tool
type listFilesTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *listFilesTool) Name() string { return "list_files" }
func (t *listFilesTool) Description() string {
	return "List files in a directory of the repository. Skips vendor/ and .git/."
}
func (t *listFilesTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"path": map[string]any{"type": "string", "description": "Directory path relative to repo root (default: root)"},
			"glob": map[string]any{"type": "string", "description": "Glob pattern to filter files, e.g. **/*.go"},
		},
	}
}

func (t *listFilesTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
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
	toolProgress(t.progressFunc, fmt.Sprintf("[ai] list_files result: %d files", len(files)))
	return textResult(result)
}

// find_implementations tool
type findImplementationsTool struct {
	prog         *ssa.Program
	progressFunc func(string)
}

func (t *findImplementationsTool) Name() string { return "find_implementations" }
func (t *findImplementationsTool) Description() string {
	return "Given an interface type name (e.g. \"io.Writer\"), find all concrete types in the program that implement it and report whether each is present in SSA RuntimeTypes. Presence does not prove allocation or reachability; absence does not exclude reflection or unsafe usage. Use source evidence to investigate possible spurious interface edges."
}
func (t *findImplementationsTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"interface_type": map[string]any{"type": "string", "description": "Full interface type name, e.g. \"io.Writer\" or \"golang.org/x/net/idna.Transformer\""},
		},
		Required: []string{"interface_type"},
	}
}

func (t *findImplementationsTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
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
			status := "runtime_type: absent (not proof of unreachability)"
			if instantiated {
				status = "runtime_type: present (not proof of allocation or reachability)"
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

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] find_implementations result: %d types for %s", found, params.InterfaceType))
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
	progressFunc   func(string)
}

func (t *findCallersTool) Name() string { return "find_callers" }
func (t *findCallersTool) Description() string {
	return "Given a function or method name, find all callers in the call graph using reverse traversal (up to N hops). Returns the chain of callers from the target back toward entry points. Queries only existing graph edges; use source inspection to discover omitted reflection or unsafe edges. Name matching is substring-based; confirm the exact affected package and symbol."
}
func (t *findCallersTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"symbol":    map[string]any{"type": "string", "description": "Function/method name to search for, e.g. \"golang.org/x/net/html.Parse\" or \"(*net/http.Client).Do\""},
			"max_depth": map[string]any{"type": "integer", "description": "Max hops backward (default: 5)"},
		},
		Required: []string{"symbol"},
	}
}

func (t *findCallersTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
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
		return textResult(fmt.Sprintf("No nodes matching %q found in this module graph. This does not rule out a source-level dynamic call.", params.Symbol))
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

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] find_callers result: %d callers for %s", totalCallers, params.Symbol))
	return textResult(b.String())
}

// check_module tool
type checkModuleTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *checkModuleTool) Name() string { return "check_module" }
func (t *checkModuleTool) Description() string {
	return "Check how a Go package is resolved (go.mod replace directives, vendor), verify symbol definitions in vendor, and find actual symbol calls in repo code. Use instead of grep_code for checking vulnerable symbol usage."
}
func (t *checkModuleTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"package": map[string]any{"type": "string", "description": "Full package import path, e.g. golang.org/x/net/html"},
			"symbols": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Vulnerable symbol names to check, e.g. [\"Parse\", \"ParseFragment\"]"},
		},
		Required: []string{"package", "symbols"},
	}
}

func (t *checkModuleTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var params struct {
		Package string   `json:"package"`
		Symbols []string `json:"symbols"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}

	var b strings.Builder

	// 1. Parse go.mod for replace directives
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-json")
	cmd.Dir = t.repoDir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	out, err := cmd.Output()

	b.WriteString("## Module Resolution\n\n")
	if err != nil {
		b.WriteString(fmt.Sprintf("Failed to parse go.mod: %v\n", err))
	} else {
		var goMod GoModEdit
		json.Unmarshal(out, &goMod)

		replaced := false
		for _, r := range goMod.Replace {
			if r.Old.Path == params.Package || strings.HasPrefix(params.Package, r.Old.Path+"/") {
				b.WriteString(fmt.Sprintf("Replace: %s %s => %s %s\n", r.Old.Path, r.Old.Version, r.New.Path, r.New.Version))
				replaced = true
			}
		}
		if !replaced {
			b.WriteString("Replace: none\n")
		}

		// Find version in Require
		for _, req := range goMod.Require {
			if req.Path == params.Package || strings.HasPrefix(params.Package, req.Path+"/") {
				dep := "direct"
				if req.Indirect {
					dep = "indirect"
				}
				b.WriteString(fmt.Sprintf("Require: %s %s (%s)\n", req.Path, req.Version, dep))
			}
		}
	}

	// 2. Check vendor directory
	b.WriteString("\n## Vendor Status\n\n")
	vendorPath := filepath.Join(t.repoDir, "vendor", params.Package)
	if info, err := os.Stat(vendorPath); err == nil && info.IsDir() {
		b.WriteString(fmt.Sprintf("Vendored: yes (%s)\n", filepath.Join("vendor", params.Package)))

		entries, _ := os.ReadDir(vendorPath)
		var goFiles []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				goFiles = append(goFiles, e.Name())
			}
		}
		if len(goFiles) > 50 {
			b.WriteString(fmt.Sprintf("Files: %d .go files (showing first 50)\n", len(goFiles)))
			goFiles = goFiles[:50]
		} else {
			b.WriteString(fmt.Sprintf("Files: %s\n", strings.Join(goFiles, ", ")))
		}

		// 3. Check symbol definitions in vendor
		b.WriteString("\n## Symbol Definitions in Vendor\n\n")
		for _, sym := range params.Symbols {
			pattern := fmt.Sprintf("func %s(\\||func .* %s(", sym, sym)
			grepCmd := exec.CommandContext(ctx, "grep", "-rn", "-E", pattern)
			grepCmd.Dir = vendorPath
			grepOut, _ := grepCmd.Output()
			if len(grepOut) > 0 {
				lines := strings.Split(strings.TrimSpace(string(grepOut)), "\n")
				if len(lines) > 5 {
					lines = lines[:5]
				}
				for _, l := range lines {
					b.WriteString(fmt.Sprintf("  %s: %s\n", sym, l))
				}
			} else {
				b.WriteString(fmt.Sprintf("  %s: not defined in vendor\n", sym))
			}
		}
	} else {
		b.WriteString("Vendored: no\n")
	}

	// 4. Find imports of the package in repo code (exclude vendor)
	b.WriteString("\n## Symbol Usage in Repo Code\n\n")
	importPattern := fmt.Sprintf(`"%s"`, params.Package)
	importCmd := exec.CommandContext(ctx, "grep", "-rn", "--include=*.go", importPattern, ".")
	importCmd.Dir = t.repoDir
	importOut, _ := importCmd.Output()

	var importingFiles []string
	for _, line := range strings.Split(strings.TrimSpace(string(importOut)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 1 {
			continue
		}
		file := parts[0]
		if strings.Contains(file, "/vendor/") {
			continue
		}
		found := false
		for _, f := range importingFiles {
			if f == file {
				found = true
				break
			}
		}
		if !found {
			importingFiles = append(importingFiles, file)
		}
	}

	if len(importingFiles) == 0 {
		b.WriteString("No repo code imports this package.\n")
	} else {
		b.WriteString(fmt.Sprintf("Files importing %s:\n", params.Package))
		for _, f := range importingFiles {
			b.WriteString(fmt.Sprintf("  %s\n", f))
		}

		// 5. For each symbol, grep importing files for calls
		lastSegment := params.Package[strings.LastIndex(params.Package, "/")+1:]
		for _, sym := range params.Symbols {
			b.WriteString(fmt.Sprintf("\nCalls to %s:\n", sym))
			callPattern := fmt.Sprintf(`\.%s(`, sym)
			found := 0
			for _, file := range importingFiles {
				fullPath := filepath.Join(t.repoDir, file)
				callCmd := exec.CommandContext(ctx, "grep", "-n", callPattern, fullPath)
				callOut, _ := callCmd.Output()
				for _, l := range strings.Split(strings.TrimSpace(string(callOut)), "\n") {
					if l == "" {
						continue
					}
					b.WriteString(fmt.Sprintf("  %s:%s\n", file, l))
					found++
					if found >= 20 {
						b.WriteString("  ... (truncated at 20 matches)\n")
						break
					}
				}
				if found >= 20 {
					break
				}
			}
			if found == 0 {
				b.WriteString(fmt.Sprintf("  %s.%s() not called in repo code\n", lastSegment, sym))
			}
		}
	}

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] check_module result: pkg=%s symbols=%v imports=%d", params.Package, params.Symbols, len(importingFiles)))
	return textResult(b.String())
}

// check_go_version tool
type checkGoVersionTool struct {
	repoDir      string
	result       *Result
	progressFunc func(string)
}

func (t *checkGoVersionTool) Name() string { return "check_go_version" }
func (t *checkGoVersionTool) Description() string {
	return "Check the Go toolchain version from go.mod and compare against fixed versions for stdlib CVE packages. For stdlib CVEs, this may be the complete answer."
}
func (t *checkGoVersionTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type:       "object",
		Properties: map[string]any{},
	}
}

func (t *checkGoVersionTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-json")
	cmd.Dir = t.repoDir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return textResult(fmt.Sprintf("error reading go.mod: %v", err))
	}

	var goMod GoModEdit
	if err := json.Unmarshal(out, &goMod); err != nil {
		return textResult(fmt.Sprintf("error parsing go.mod: %v", err))
	}

	goVersion := goMod.Go
	if !strings.HasPrefix(goVersion, "v") {
		goVersion = "v" + goVersion
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Go version: %s\n\n", goMod.Go))

	stdlibCount := 0
	for pkg, details := range t.result.AffectedImports {
		if details.Type != "stdlib" {
			continue
		}
		stdlibCount++
		fixVer := findAppropriateFixVersion(goVersion, details.FixedVersion)
		if fixVer == "" {
			b.WriteString(fmt.Sprintf("  %s: no matching fix version for Go %s branch\n", pkg, goMod.Go))
			continue
		}
		b.WriteString(fmt.Sprintf("  %s: current=%s, fix=%s\n", pkg, goMod.Go, fixVer))
	}

	if stdlibCount == 0 {
		b.WriteString("No stdlib packages in AffectedImports.\n")
	}

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] check_go_version result: Go %s, %d stdlib packages checked", goMod.Go, stdlibCount))
	return textResult(b.String())
}

// is_test_only tool
type isTestOnlyTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *isTestOnlyTool) Name() string { return "is_test_only" }
func (t *isTestOnlyTool) Description() string {
	return "Check if a Go file is test-only (test file or test package). Vulnerable code only in tests does not affect production."
}
func (t *isTestOnlyTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"file": map[string]any{"type": "string", "description": "File path relative to repo root"},
		},
		Required: []string{"file"},
	}
}

func (t *isTestOnlyTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var params struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}

	fullPath, err := safePath(t.repoDir, params.File)
	if err != nil {
		return textResult(err.Error())
	}

	baseName := filepath.Base(params.File)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("File: %s\n", params.File))

	if strings.HasSuffix(baseName, "_test.go") {
		b.WriteString("Test-only: YES (filename ends with _test.go)\n")
		toolProgress(t.progressFunc, fmt.Sprintf("[ai] is_test_only result: %s -> yes (test file)", params.File))
		return textResult(b.String())
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fullPath, nil, parser.PackageClauseOnly)
	if err != nil {
		b.WriteString(fmt.Sprintf("Test-only: UNKNOWN (parse error: %v)\n", err))
		toolProgress(t.progressFunc, fmt.Sprintf("[ai] is_test_only result: %s -> unknown", params.File))
		return textResult(b.String())
	}

	pkgName := f.Name.Name
	b.WriteString(fmt.Sprintf("Package: %s\n", pkgName))

	if strings.HasSuffix(pkgName, "_test") {
		b.WriteString("Test-only: YES (external test package)\n")
		toolProgress(t.progressFunc, fmt.Sprintf("[ai] is_test_only result: %s -> yes (test package)", params.File))
		return textResult(b.String())
	}

	// Check if the directory has any non-test .go files
	dir := filepath.Dir(fullPath)
	entries, _ := os.ReadDir(dir)
	hasNonTest := false
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			hasNonTest = true
			break
		}
	}
	if !hasNonTest {
		b.WriteString("Test-only: YES (directory contains only test files)\n")
	} else {
		b.WriteString("Test-only: NO (production code)\n")
	}

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] is_test_only result: %s -> %v", params.File, !hasNonTest))
	return textResult(b.String())
}

// check_build_tags tool
type checkBuildTagsTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *checkBuildTagsTool) Name() string { return "check_build_tags" }
func (t *checkBuildTagsTool) Description() string {
	return "Check for build constraints (//go:build and // +build tags) in a Go file. Helps determine if vulnerable code is conditionally compiled for specific platforms."
}
func (t *checkBuildTagsTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"file": map[string]any{"type": "string", "description": "File path relative to repo root"},
		},
		Required: []string{"file"},
	}
}

func (t *checkBuildTagsTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var params struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}

	fullPath, err := safePath(t.repoDir, params.File)
	if err != nil {
		return textResult(err.Error())
	}

	file, err := os.Open(fullPath)
	if err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}
	defer file.Close()

	var constraints []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "package ") {
			break
		}
		if strings.HasPrefix(line, "//go:build ") {
			constraints = append(constraints, line)
		} else if strings.HasPrefix(line, "// +build ") {
			constraints = append(constraints, line)
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("File: %s\n", params.File))
	if len(constraints) == 0 {
		b.WriteString("Build constraints: none\n")
	} else {
		b.WriteString("Build constraints:\n")
		for _, c := range constraints {
			b.WriteString(fmt.Sprintf("  %s\n", c))
		}
	}

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] check_build_tags result: %s -> %d constraints", params.File, len(constraints)))
	return textResult(b.String())
}

// list_entry_points tool
type listEntryPointsTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *listEntryPointsTool) Name() string { return "list_entry_points" }
func (t *listEntryPointsTool) Description() string {
	return "List all entry points: main() and init() functions across the repository. Helps verify which code paths are reachable at runtime."
}
func (t *listEntryPointsTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type:       "object",
		Properties: map[string]any{},
	}
}

func (t *listEntryPointsTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var b strings.Builder
	totalEntries := 0

	// Find main packages
	cmd := exec.CommandContext(ctx, "go", "list", "-f", `{{if eq .Name "main"}}{{.Dir}}{{end}}`, "./...")
	cmd.Dir = t.repoDir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	out, _ := cmd.Output()

	var mainDirs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			mainDirs = append(mainDirs, line)
		}
	}

	b.WriteString("## Main Packages\n\n")
	for _, dir := range mainDirs {
		if totalEntries >= 50 {
			b.WriteString("... (truncated at 50 entry points)\n")
			break
		}
		relDir, _ := filepath.Rel(t.repoDir, dir)
		b.WriteString(fmt.Sprintf("%s:\n", relDir))

		entries, _ := os.ReadDir(dir)
		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			filePath := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(fset, filePath, nil, 0)
			if err != nil {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil {
					continue
				}
				if fn.Name.Name == "main" || fn.Name.Name == "init" {
					pos := fset.Position(fn.Pos())
					relFile, _ := filepath.Rel(t.repoDir, pos.Filename)
					b.WriteString(fmt.Sprintf("  %s() at %s:%d\n", fn.Name.Name, relFile, pos.Line))
					totalEntries++
				}
			}
		}
	}

	// Find init() in non-main packages
	b.WriteString("\n## init() in Non-Main Packages\n\n")
	initCount := 0
	filepath.WalkDir(t.repoDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		if initCount >= 100 {
			return nil
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil || f.Name.Name == "main" {
			return nil
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != "init" {
				continue
			}
			pos := fset.Position(fn.Pos())
			relFile, _ := filepath.Rel(t.repoDir, pos.Filename)
			b.WriteString(fmt.Sprintf("  init() at %s:%d (package %s)\n", relFile, pos.Line, f.Name.Name))
			initCount++
			totalEntries++
		}
		return nil
	})

	if initCount == 0 {
		b.WriteString("  (none)\n")
	}

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] list_entry_points result: %d main dirs, %d total entries", len(mainDirs), totalEntries))
	return textResult(b.String())
}

// check_transitive_deps tool
type checkTransitiveDepsTool struct {
	repoDir      string
	progressFunc func(string)
}

func (t *checkTransitiveDepsTool) Name() string { return "check_transitive_deps" }
func (t *checkTransitiveDepsTool) Description() string {
	return "Check if a package is a direct or transitive dependency, show its version, and trace the import chain that brings it in."
}
func (t *checkTransitiveDepsTool) InputSchema() verificationToolSchema {
	return verificationToolSchema{
		Type: "object",
		Properties: map[string]any{
			"package": map[string]any{"type": "string", "description": "Package or module path, e.g. golang.org/x/net/html"},
		},
		Required: []string{"package"},
	}
}

func (t *checkTransitiveDepsTool) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var params struct {
		Package string `json:"package"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return textResult(fmt.Sprintf("error: %v", err))
	}

	var b strings.Builder

	// 1. Check go.mod for direct/indirect status
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-json")
	cmd.Dir = t.repoDir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	out, err := cmd.Output()

	b.WriteString("## Dependency Status\n\n")
	if err != nil {
		b.WriteString(fmt.Sprintf("Failed to parse go.mod: %v\n", err))
	} else {
		var goMod GoModEdit
		json.Unmarshal(out, &goMod)

		found := false
		for _, req := range goMod.Require {
			if req.Path == params.Package || strings.HasPrefix(params.Package, req.Path+"/") {
				dep := "DIRECT"
				if req.Indirect {
					dep = "INDIRECT (transitive)"
				}
				b.WriteString(fmt.Sprintf("Package: %s\nModule: %s\nVersion: %s\nType: %s\n", params.Package, req.Path, req.Version, dep))
				found = true

				// Check for replace
				for _, r := range goMod.Replace {
					if r.Old.Path == req.Path {
						b.WriteString(fmt.Sprintf("Replaced: %s %s => %s %s\n", r.Old.Path, r.Old.Version, r.New.Path, r.New.Version))
					}
				}
				break
			}
		}
		if !found {
			b.WriteString(fmt.Sprintf("Package %s not found in go.mod require directives.\n", params.Package))
		}
	}

	// 2. Check vendor/modules.txt if vendor exists
	modulesPath := filepath.Join(t.repoDir, "vendor", "modules.txt")
	if data, err := os.ReadFile(modulesPath); err == nil {
		b.WriteString("\n## Vendor Info\n\n")
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, params.Package) {
				b.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}
	}

	// 3. Run go mod why to get the import chain
	b.WriteString("\n## Import Chain (go mod why)\n\n")
	modPath := params.Package
	// Try to find the module path for the package
	listCmd := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Path}}", params.Package)
	listCmd.Dir = t.repoDir
	listCmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	if listOut, err := listCmd.Output(); err == nil {
		modPath = strings.TrimSpace(string(listOut))
	}

	whyCmd := exec.CommandContext(ctx, "go", "mod", "why", "-m", modPath)
	whyCmd.Dir = t.repoDir
	whyCmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	whyOut, err := whyCmd.Output()
	if err != nil {
		b.WriteString(fmt.Sprintf("go mod why failed: %v\n", err))
	} else {
		lines := strings.Split(strings.TrimSpace(string(whyOut)), "\n")
		if len(lines) > 50 {
			lines = lines[:50]
			lines = append(lines, "... (truncated)")
		}
		for _, l := range lines {
			b.WriteString(fmt.Sprintf("  %s\n", l))
		}
	}

	toolProgress(t.progressFunc, fmt.Sprintf("[ai] check_transitive_deps result: %s", params.Package))
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
