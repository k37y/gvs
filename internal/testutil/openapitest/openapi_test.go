package openapitest

import (
	"encoding/json"
	"strings"
	"testing"
)

// These cases guard the validator itself: dropping a reference, skipping raw JSON
// decoding, or weakening a required/nullable field must not silently pass CI.
func TestCheckContractBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, schema, input string
		valid               bool
	}{
		{"accepted task", "TaskAccepted", `{"taskId":"task-1"}`, true},
		{"missing task ID", "TaskAccepted", `{}`, false},
		{"wrong task ID type", "TaskAccepted", `{"taskId":1}`, false},
		{"failed partial output", "TaskStatusResponse", `{"status":"failed","output":{"partial":true},"error":"scan failed"}`, true},
		{"cancelled null output", "TaskStatusResponse", `{"status":"cancelled","output":null}`, true},
		{"unknown task state", "TaskStatusResponse", `{"status":"done"}`, false},
		{"AI nullable usage", "CGAIVerification", `{"IsVulnerable":"unknown","confidence":"low","evidence":[],"reasoning":"incomplete","usage":null}`, true},
		{"AI missing usage", "CGAIVerification", `{"IsVulnerable":"unknown","confidence":"low","evidence":[],"reasoning":"incomplete"}`, false},
		{"AI boolean verdict", "CGAIVerification", `{"IsVulnerable":false,"confidence":"low","evidence":[],"reasoning":"incomplete","usage":null}`, false},
		{"AI invalid confidence", "CGAIVerification", `{"IsVulnerable":"unknown","confidence":"certain","evidence":[],"reasoning":"incomplete","usage":null}`, false},
		{"AI null evidence", "CGAIVerification", `{"IsVulnerable":"unknown","confidence":"low","evidence":null,"reasoning":"incomplete","usage":null}`, false},
		{"AI internal field leak", "CGAIVerification", `{"IsVulnerable":"unknown","confidence":"low","evidence":[],"reasoning":"incomplete","usage":null,"graph_analysis":{}}`, false},
		{"nullable usage counters", "CGAIUsage", `{"input_tokens":0,"output_tokens":1,"cache_read_tokens":null,"cache_write_tokens":null,"cost_usd":0.25}`, true},
		{"fractional token count", "CGAIUsage", `{"input_tokens":0.5,"output_tokens":1,"cache_read_tokens":null,"cache_write_tokens":null,"cost_usd":null}`, false},
		{"reflection gap", "CGReflectionRisk", `{"association":"unresolved","type":"analysis_incomplete","confidence":"low","location":"main.go:1:1","evidence":null}`, true},
		{"unknown reflection category", "CGReflectionRisk", `{"association":"unresolved","type":"other","confidence":"low","location":"main.go:1:1","evidence":[]}`, false},
		{"EOF cursor", "MCPChunkOutput", `{"taskId":"task-1","content":"}","nextCursor":null,"eof":true}`, true},
		{"missing EOF cursor", "MCPChunkOutput", `{"taskId":"task-1","content":"}","eof":true}`, false},
		{"tool error", "MCPStatusOutput", `{"error":{"code":"task_not_found","message":"not found","retryable":false}}`, true},
		{"tool error retryability type", "MCPStatusOutput", `{"error":{"code":"task_not_found","message":"not found","retryable":"false"}}`, false},
		{"empty scan result", "ScanResult", `{"success":true,"exit_code":1,"output":null}`, true},
		{"scan exit code", "ScanResult", `{"success":true,"exit_code":2,"output":null}`, false},
		{"malformed JSON", "TaskAccepted", `{"taskId":`, false},
		{"unknown schema", "MissingSchema", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.schema, json.RawMessage(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, want %v: %v", err == nil, tc.valid, err)
			}
			if err != nil && !strings.Contains(err.Error(), tc.schema) {
				t.Fatalf("error lacks schema context: %v", err)
			}
		})
	}
}

func TestCheckNestedScannerFields(t *testing.T) {
	const result = `{"IsVulnerable":"true","UsedImports":{".":{"example.com/lib":{"Symbols":["Call"],"CurrentVersion":"v1.0.0","FixCommands":["go get example.com/lib@v1.1.0"]}}},"Files":null,"AffectedImports":null,"GoCVE":"MANUAL-SCAN","Repository":"","Branch":"main","Errors":null,"unsafe":false,"reflect":false}`
	Validate(t, "CGResult", json.RawMessage(result))
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"required verdict", func(v map[string]any) { delete(v, "IsVulnerable") }},
		{"additional field", func(v map[string]any) { v["internal_state"] = true }},
		{"wrong nested symbol type", func(v map[string]any) {
			v["UsedImports"].(map[string]any)["."].(map[string]any)["example.com/lib"].(map[string]any)["Symbols"] = "Call"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal([]byte(result), &value); err != nil {
				t.Fatal(err)
			}
			tc.mutate(value)
			if err := Check("CGResult", value); err == nil {
				t.Fatal("accepted incompatible scanner output")
			}
		})
	}
}
