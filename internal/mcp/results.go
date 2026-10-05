package mcpserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/k37y/gvs/internal/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxResultBytes  = 64 << 10
	maxChunkBytes   = 16 << 10
	maxRequestBytes = 1 << 20
)

type Submission struct {
	TaskID           string         `json:"taskId"`
	Status           api.TaskStatus `json:"status"`
	PollAfterSeconds int            `json:"pollAfterSeconds,omitempty"`
	Message          string         `json:"message,omitempty"`
}

type Summary struct {
	ScannerVerdict   *string `json:"scannerVerdict"`
	AIVerdict        *string `json:"aiVerdict"`
	AIConfidence     *string `json:"aiConfidence"`
	VerdictsDisagree *bool   `json:"verdictsDisagree"`
}

type ResultDelivery struct {
	Available      bool     `json:"available"`
	Inline         bool     `json:"inline"`
	TotalBytes     *int     `json:"totalBytes,omitempty"`
	ExternalFields []string `json:"externalFields,omitempty"`
	Message        string   `json:"message,omitempty"`
}

type StatusResult struct {
	Submission
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
	CompletedAt *time.Time      `json:"completedAt,omitempty"`
	ExpiresAt   *time.Time      `json:"expiresAt,omitempty"`
	Cached      bool            `json:"cached"`
	Summary     *Summary        `json:"summary,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`
	Error       string          `json:"error,omitempty"`
	Logs        string          `json:"logs,omitempty"`
	Result      ResultDelivery  `json:"result"`
}

type ResultChunk struct {
	TaskID     string  `json:"taskId"`
	Content    string  `json:"content"`
	NextCursor *string `json:"nextCursor"`
	EOF        bool    `json:"eof"`
}

func active(status api.TaskStatus) bool {
	return status == api.StatusPending || status == api.StatusRunning
}

func submission(task api.TaskSnapshot) Submission {
	out := Submission{TaskID: task.TaskID, Status: task.Status}
	if active(task.Status) {
		out.PollAfterSeconds = 5
		out.Message = "Scan accepted and still processing; it may take several minutes. Call gvs_status after 5 seconds."
	}
	return out
}

func (a *adapter) statusResult(task api.TaskSnapshot) (*sdk.CallToolResult, error) {
	out := StatusResult{
		Submission: submission(task), CreatedAt: task.CreatedAt.UTC(), UpdatedAt: task.UpdatedAt.UTC(), CompletedAt: utcTime(task.CompletedAt), ExpiresAt: utcTime(task.ExpiresAt), Cached: task.Cached,
		Summary: summarize(task.Output), Output: outputJSON(task.Output), Error: task.Error, Logs: task.Logs,
		Result: ResultDelivery{Available: task.ResultAvailable, Inline: task.ResultAvailable},
	}
	if task.ResultAvailable {
		artifact, err := a.backend.ReadTaskResult(task.TaskID)
		if err != nil {
			return nil, err
		}
		n := len(artifact)
		out.Result.TotalBytes = &n
	}
	result, err := encodeResult(out, false)
	if err != nil {
		return nil, err
	}
	if fitsResult(result) {
		return result, nil
	}
	if !task.ResultAvailable {
		return nil, &api.TaskError{Code: "task_not_ready", Message: "The current task output exceeds the MCP response limit. Poll gvs_status again after the task finishes to retrieve its complete result."}
	}
	if len(out.Output) > 0 {
		out.Result.ExternalFields = append(out.Result.ExternalFields, "output")
	}
	if out.Error != "" {
		out.Result.ExternalFields = append(out.Result.ExternalFields, "error")
	}
	if out.Logs != "" {
		out.Result.ExternalFields = append(out.Result.ExternalFields, "logs")
	}
	out.Output, out.Error, out.Logs = nil, "", ""
	out.Result.Inline = false
	out.Result.Message = "Call gvs_read_result with this taskId and follow nextCursor until eof; concatenate content to reconstruct the complete output, error, and logs JSON."
	result, err = encodeResult(out, false)
	if err == nil && !fitsResult(result) {
		return nil, fmt.Errorf("MCP status metadata exceeds the response limit")
	}
	return result, err
}

func utcTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	value := t.UTC()
	return &value
}

func outputJSON(output string) json.RawMessage {
	if output == "" {
		return nil
	}
	if json.Valid([]byte(output)) {
		return json.RawMessage(output)
	}
	encoded, _ := json.Marshal(output)
	return encoded
}

func summarize(output string) *Summary {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &fields); err != nil || fields == nil {
		return nil
	}
	if _, scanner := fields["IsVulnerable"]; !scanner {
		if _, ai := fields["AIVerification"]; !ai {
			return nil
		}
	}
	var ai map[string]json.RawMessage
	_ = json.Unmarshal(fields["AIVerification"], &ai)
	out := &Summary{ScannerVerdict: enumString(fields["IsVulnerable"], "true", "false", "unknown"), AIVerdict: enumString(ai["IsVulnerable"], "true", "false", "unknown"), AIConfidence: enumString(ai["confidence"], "high", "medium", "low")}
	if out.ScannerVerdict != nil && out.AIVerdict != nil && *out.ScannerVerdict != "unknown" && *out.AIVerdict != "unknown" {
		disagree := *out.ScannerVerdict != *out.AIVerdict
		out.VerdictsDisagree = &disagree
	}
	return out
}

func enumString(raw json.RawMessage, allowed ...string) *string {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	for _, candidate := range allowed {
		if value == candidate {
			return &value
		}
	}
	return nil
}

func encodeResult(output any, isError bool) (*sdk.CallToolResult, error) {
	data, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("encode MCP result: %w", err)
	}
	return &sdk.CallToolResult{StructuredContent: json.RawMessage(data), Content: []sdk.Content{&sdk.TextContent{Text: string(data)}}, IsError: isError}, nil
}

func fitsResult(result *sdk.CallToolResult) bool {
	data, err := json.Marshal(result)
	return err == nil && len(data) <= maxResultBytes
}

// SDK schema failures happen before our tool handlers. Bound the final result
// too, so echoed invalid input cannot bypass the response limit.
func boundToolResults(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
		result, err := next(ctx, method, req)
		if method == "tools/call" && err == nil {
			if toolResult, ok := result.(*sdk.CallToolResult); ok && !fitsResult(toolResult) {
				if toolResult.IsError {
					return oversizedErrorResult(), nil
				}
				return errorResult(&api.TaskError{Code: "result_too_large", Message: "The tool result exceeds the 64 KiB response limit. No result content was included; retrieve the task's complete result with gvs_read_result."}), nil
			}
		}
		return result, err
	}
}

type resultCursor struct {
	TaskID string `json:"t"`
	Digest string `json:"d"`
	Offset int    `json:"o"`
}

func (a *adapter) readResult(taskID, cursor string) (*sdk.CallToolResult, error) {
	var position resultCursor
	if cursor != "" {
		var err error
		position, err = a.decodeCursor(cursor)
		if err != nil || position.TaskID != taskID {
			return nil, cursorError("Invalid cursor or cursor belongs to a different task.")
		}
	}
	artifact, err := a.backend.ReadTaskResult(taskID)
	if err != nil {
		var taskErr *api.TaskError
		if cursor != "" && errors.As(err, &taskErr) && taskErr.Code == "task_not_found" {
			return nil, cursorError("Cursor expired: its task is no longer available.")
		}
		return nil, err
	}
	if !utf8.Valid(artifact) {
		return nil, fmt.Errorf("stored result is not valid UTF-8")
	}
	digest := sha256.Sum256(artifact)
	digestText := base64.RawURLEncoding.EncodeToString(digest[:])
	if cursor != "" && (position.Digest != digestText || position.Offset < 0 || position.Offset > len(artifact) || (position.Offset < len(artifact) && !utf8.RuneStart(artifact[position.Offset]))) {
		return nil, cursorError("Cursor no longer matches this task's complete result.")
	}
	start := position.Offset
	end := min(start+maxChunkBytes, len(artifact))
	for {
		for end < len(artifact) && end > start && !utf8.RuneStart(artifact[end]) {
			end--
		}
		chunk := ResultChunk{TaskID: taskID, Content: string(artifact[start:end]), EOF: end == len(artifact)}
		if !chunk.EOF {
			next, err := a.encodeCursor(resultCursor{TaskID: taskID, Digest: digestText, Offset: end})
			if err != nil {
				return nil, err
			}
			chunk.NextCursor = &next
		}
		result, err := encodeResult(chunk, false)
		if err != nil {
			return nil, err
		}
		if fitsResult(result) {
			return result, nil
		}
		if end <= start+utf8.UTFMax {
			return nil, fmt.Errorf("MCP result chunk metadata exceeds response limit")
		}
		end = start + (end-start)/2
	}
}

func cursorError(message string) error {
	return &api.TaskError{Code: "invalid_cursor", Message: message}
}

func (a *adapter) encodeCursor(position resultCursor) (string, error) {
	data, err := json.Marshal(position)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, a.cursorKey[:])
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (a *adapter) decodeCursor(cursor string) (resultCursor, error) {
	var out resultCursor
	if len(cursor) > 4096 {
		return out, fmt.Errorf("cursor is too long")
	}
	dataPart, signaturePart, ok := strings.Cut(cursor, ".")
	if !ok {
		return out, fmt.Errorf("invalid cursor")
	}
	data, err := base64.RawURLEncoding.DecodeString(dataPart)
	if err != nil {
		return out, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signaturePart)
	if err != nil {
		return out, err
	}
	mac := hmac.New(sha256.New, a.cursorKey[:])
	mac.Write(data)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return out, fmt.Errorf("invalid cursor signature")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}
