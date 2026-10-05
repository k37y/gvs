package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/k37y/gvs/internal/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type scanInput struct {
	Repo      string `json:"repo"`
	Branch    string `json:"branch"`
	CVE       string `json:"cve"`
	Algo      string `json:"algo"`
	RequestID string `json:"requestId,omitempty"`
}

type manualInput struct {
	Repo         string `json:"repo"`
	Branch       string `json:"branch"`
	Library      string `json:"library"`
	Symbol       string `json:"symbol"`
	FixedVersion string `json:"fixedVersion"`
	Algo         string `json:"algo"`
	RequestID    string `json:"requestId,omitempty"`
}

type taskInput struct {
	TaskID string `json:"taskId"`
}
type readInput struct {
	TaskID string `json:"taskId"`
	Cursor string `json:"cursor,omitempty"`
}

var vulnerabilityID = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,}|GO-[0-9]{4}-[0-9]{4,})$`)

func (a *adapter) addTools(server *sdk.Server) {
	addTool(server, &sdk.Tool{Name: "gvs_scan", Description: "Start a CVE or Go vulnerability call-graph scan of a Git repository. Returns immediately; scans may take several minutes. Wait pollAfterSeconds, then call gvs_status until completed, failed, or cancelled. Reuse requestId only for retries of the same submission. All four arguments, including algo, are required.", InputSchema: scanSchema(false), OutputSchema: outputSchema("submission"), Annotations: annotations(false, false, false, true)}, func(ctx context.Context, in scanInput) (*sdk.CallToolResult, error) {
		if !vulnerabilityID.MatchString(in.CVE) {
			return nil, invalidArgument("cve must be a CVE-YYYY-NNNN or GO-YYYY-NNNN identifier")
		}
		return a.start(ctx, api.CallgraphRequest{Repo: in.Repo, BranchOrCommit: in.Branch, CVE: in.CVE, Algo: in.Algo, RequestID: in.RequestID})
	})
	addTool(server, &sdk.Tool{Name: "gvs_manual_scan", Description: "Start a manual call-graph scan with the affected library, comma-separated symbol names, fixedVersion, and algo. Returns immediately. Wait pollAfterSeconds and call gvs_status until completed, failed, or cancelled. Reuse requestId only for retries of the same submission.", InputSchema: scanSchema(true), OutputSchema: outputSchema("submission"), Annotations: annotations(false, false, false, true)}, func(ctx context.Context, in manualInput) (*sdk.CallToolResult, error) {
		return a.start(ctx, api.CallgraphRequest{Repo: in.Repo, BranchOrCommit: in.Branch, Library: in.Library, Symbol: in.Symbol, FixVersion: in.FixedVersion, Algo: in.Algo, RequestID: in.RequestID})
	})
	addTool(server, &sdk.Tool{Name: "gvs_status", Description: "Get a scan task's status, separate scanner/AI assessments, and complete result when it fits. While pending/running, wait pollAfterSeconds before calling again; stop on completed/failed/cancelled. If result.available is true and result.inline is false, call gvs_read_result to retrieve all output, errors, and logs. Failed tasks are normal status results.", InputSchema: taskSchema(false), OutputSchema: outputSchema("status"), Annotations: annotations(true, false, true, false)}, func(_ context.Context, in taskInput) (*sdk.CallToolResult, error) {
		if err := validateTaskID(in.TaskID); err != nil {
			return nil, err
		}
		task, err := a.backend.GetTask(in.TaskID)
		if err != nil {
			return nil, err
		}
		return a.statusResult(task)
	})
	addTool(server, &sdk.Tool{Name: "gvs_cancel", Description: "Request cancellation of an active scan. Continue polling gvs_status until the worker finishes collecting output and reports cancelled. Repeated cancellation requests are harmless; an already completed or failed task cannot be cancelled.", InputSchema: taskSchema(false), OutputSchema: outputSchema("submission"), Annotations: annotations(false, true, true, false)}, func(_ context.Context, in taskInput) (*sdk.CallToolResult, error) {
		if err := validateTaskID(in.TaskID); err != nil {
			return nil, err
		}
		task, err := a.backend.CancelTask(in.TaskID)
		if err != nil {
			return nil, err
		}
		out := submission(task)
		if active(task.Status) {
			out.Message = "Cancellation requested. Call gvs_status after 5 seconds until the worker reports cancelled."
		}
		return encodeResult(out, false)
	})
	addTool(server, &sdk.Tool{Name: "gvs_read_result", Description: "Read the complete immutable JSON artifact of a terminal task, containing available output, error, and logs. Begin without cursor; append content from each response and follow nextCursor until eof=true. Cursor replay returns the same chunk. Task/result expiry or a server restart invalidates cursors.", InputSchema: taskSchema(true), OutputSchema: outputSchema("chunk"), Annotations: annotations(true, false, true, false)}, func(_ context.Context, in readInput) (*sdk.CallToolResult, error) {
		if err := validateTaskID(in.TaskID); err != nil {
			return nil, err
		}
		return a.readResult(in.TaskID, in.Cursor)
	})
}

func addTool[In any](server *sdk.Server, tool *sdk.Tool, fn func(context.Context, In) (*sdk.CallToolResult, error)) {
	sdk.AddTool(server, tool, func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
		result, err := fn(ctx, in)
		if err != nil {
			result = errorResult(err)
		}
		// Build both content representations ourselves to preserve JSON numbers and
		// enforce the bound on the complete result, including the text fallback.
		return result, nil, nil
	})
}

func (a *adapter) start(ctx context.Context, in api.CallgraphRequest) (*sdk.CallToolResult, error) {
	for name, value := range map[string]string{"repo": in.Repo, "branch": in.BranchOrCommit, "algo": in.Algo} {
		if strings.TrimSpace(value) == "" {
			return nil, invalidArgument(name + " must not be empty")
		}
	}
	if _, err := parseHTTPURL(in.Repo); err != nil {
		return nil, invalidArgument("repo must be an HTTP(S) Git repository URL")
	}
	switch in.Algo {
	case "rta", "vta", "cha", "static":
	default:
		return nil, invalidArgument("algo must be rta, vta, cha, or static")
	}
	if in.CVE == "" {
		for name, value := range map[string]string{"library": in.Library, "symbol": in.Symbol, "fixedVersion": in.FixVersion} {
			if strings.TrimSpace(value) == "" {
				return nil, invalidArgument(name + " must not be empty")
			}
		}
	}
	if utf8.RuneCountInString(in.RequestID) > 128 || (in.RequestID != "" && strings.TrimSpace(in.RequestID) == "") {
		return nil, invalidArgument("requestId must contain 1 to 128 characters when supplied")
	}
	baseURL, _ := ctx.Value(baseURLKey{}).(string)
	task, err := a.backend.StartCallgraph(in, baseURL)
	if err != nil {
		return nil, err
	}
	return encodeResult(submission(task), false)
}

func validateTaskID(id string) error {
	if strings.TrimSpace(id) == "" {
		return invalidArgument("taskId must not be empty")
	}
	return nil
}

func invalidArgument(message string) error {
	return &api.TaskError{Code: "invalid_argument", Message: message}
}

func errorResult(err error) *sdk.CallToolResult {
	code := "internal_error"
	var taskError *api.TaskError
	if errors.As(err, &taskError) {
		code = taskError.Code
	}
	result, marshalErr := encodeResult(map[string]any{"error": map[string]any{"code": code, "message": err.Error(), "retryable": code == "scan_busy" || code == "task_not_ready" || code == "server_stopping"}}, true)
	if marshalErr != nil {
		result = &sdk.CallToolResult{}
		result.SetError(fmt.Errorf("encode MCP error: %w", marshalErr))
	}
	if !fitsResult(result) {
		return oversizedErrorResult()
	}
	return result
}

func oversizedErrorResult() *sdk.CallToolResult {
	result, _ := encodeResult(map[string]any{"error": map[string]any{
		"code":      "error_too_large",
		"message":   "The tool error diagnostic exceeds the 64 KiB response limit. The original diagnostic was not included; no scan result or evidence was truncated.",
		"retryable": false,
	}}, true)
	return result
}

func annotations(readOnly, destructive, idempotent, openWorld bool) *sdk.ToolAnnotations {
	return &sdk.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &destructive, IdempotentHint: idempotent, OpenWorldHint: &openWorld}
}

func stringSchema(description string) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "description": description}
}
func objectSchema(properties map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

func scanSchema(manual bool) map[string]any {
	properties := map[string]any{
		"repo":      stringSchema("HTTP(S) Git repository URL."),
		"branch":    stringSchema("Explicit branch name or commit hash."),
		"algo":      map[string]any{"type": "string", "enum": []string{"rta", "vta", "cha", "static"}},
		"requestId": map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "description": "Optional idempotency key; reuse only when retrying the same scan arguments."},
	}
	if manual {
		properties["library"] = stringSchema("Affected Go import path.")
		properties["symbol"] = stringSchema("Affected symbol, or comma-separated symbols.")
		properties["fixedVersion"] = stringSchema("Fixed version or fixed-version range accepted by cg.")
		return objectSchema(properties, "repo", "branch", "library", "symbol", "fixedVersion", "algo")
	}
	properties["cve"] = map[string]any{"type": "string", "pattern": vulnerabilityID.String(), "description": "CVE or Go vulnerability identifier."}
	return objectSchema(properties, "repo", "branch", "cve", "algo")
}

func taskSchema(cursor bool) map[string]any {
	properties := map[string]any{"taskId": stringSchema("Task ID returned by a scan tool.")}
	if cursor {
		properties["cursor"] = map[string]any{"type": "string", "description": "Opaque nextCursor from the previous chunk; omit for the first chunk."}
	}
	return objectSchema(properties, "taskId")
}

func outputSchema(kind string) map[string]any {
	properties := map[string]any{"taskId": map[string]any{"type": "string"}, "status": map[string]any{"type": "string", "enum": []string{"pending", "running", "completed", "failed", "cancelled"}}, "pollAfterSeconds": map[string]any{"type": "integer", "const": 5}, "message": map[string]any{"type": "string"}}
	required := []string{"taskId", "status"}
	if kind == "status" {
		for _, field := range []string{"createdAt", "updatedAt", "completedAt", "expiresAt"} {
			properties[field] = map[string]any{"type": "string", "format": "date-time"}
		}
		properties["cached"] = map[string]any{"type": "boolean"}
		properties["output"] = map[string]any{}
		properties["error"] = map[string]any{"type": "string"}
		properties["logs"] = map[string]any{"type": "string"}
		verdict := map[string]any{"enum": []any{"true", "false", "unknown", nil}}
		properties["summary"] = objectSchema(map[string]any{"scannerVerdict": verdict, "aiVerdict": verdict, "aiConfidence": map[string]any{"enum": []any{"high", "medium", "low", nil}}, "verdictsDisagree": map[string]any{"type": []string{"boolean", "null"}}}, "scannerVerdict", "aiVerdict", "aiConfidence", "verdictsDisagree")
		properties["result"] = objectSchema(map[string]any{"available": map[string]any{"type": "boolean"}, "inline": map[string]any{"type": "boolean"}, "totalBytes": map[string]any{"type": "integer", "minimum": 0}, "externalFields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "message": map[string]any{"type": "string"}}, "available", "inline")
		required = append(required, "createdAt", "updatedAt", "cached", "result")
	} else if kind == "chunk" {
		properties = map[string]any{"taskId": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}, "nextCursor": map[string]any{"type": []string{"string", "null"}}, "eof": map[string]any{"type": "boolean"}}
		required = []string{"taskId", "content", "nextCursor", "eof"}
	}
	success := objectSchema(properties, required...)
	failure := objectSchema(map[string]any{"error": objectSchema(map[string]any{"code": map[string]any{"type": "string"}, "message": map[string]any{"type": "string"}, "retryable": map[string]any{"type": "boolean"}}, "code", "message", "retryable")}, "error")
	return map[string]any{"type": "object", "anyOf": []any{success, failure}}
}
