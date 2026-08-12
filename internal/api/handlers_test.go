package api

import (
	"encoding/json"
	"testing"
)

func TestConvertGraphPathsToURLs(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]interface{}
		baseURL string
		check   func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "converts graph paths to URLs",
			input: map[string]interface{}{
				"IsVulnerable": "true",
				"GraphPaths":   []interface{}{"/tmp/gvs-cache/graph/CVE-2024-1234/repo/main/rta/lib-sym.svg"},
			},
			baseURL: "http://localhost:8082",
			check: func(t *testing.T, result map[string]interface{}) {
				paths, ok := result["GraphPaths"].([]interface{})
				if !ok {
					t.Fatal("GraphPaths not found or wrong type")
				}
				if len(paths) != 1 {
					t.Fatalf("expected 1 path, got %d", len(paths))
				}
				got := paths[0].(string)
				want := "http://localhost:8082/graph/CVE-2024-1234/repo/main/rta/lib-sym.svg"
				if got != want {
					t.Errorf("got %q, want %q", got, want)
				}
			},
		},
		{
			name: "no graph paths, returns unchanged",
			input: map[string]interface{}{
				"IsVulnerable": "false",
			},
			baseURL: "http://localhost:8082",
			check: func(t *testing.T, result map[string]interface{}) {
				if _, ok := result["GraphPaths"]; ok {
					t.Error("GraphPaths should not exist")
				}
			},
		},
		{
			name: "empty graph paths array",
			input: map[string]interface{}{
				"IsVulnerable": "false",
				"GraphPaths":   []interface{}{},
			},
			baseURL: "http://localhost:8082",
			check: func(t *testing.T, result map[string]interface{}) {
				// Should return unchanged since empty
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputJSON, _ := json.Marshal(tt.input)
			output := convertGraphPathsToURLs(inputJSON, tt.baseURL)

			var result map[string]interface{}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("failed to unmarshal output: %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestConvertGraphPathsToURLs_InvalidJSON(t *testing.T) {
	input := []byte("not json")
	output := convertGraphPathsToURLs(input, "http://localhost:8082")
	if string(output) != "not json" {
		t.Errorf("expected unchanged input for invalid JSON")
	}
}
