package utils

import "testing"

func TestValidateTools(t *testing.T) {
	// "go" should always be available in a Go test environment
	if !ValidateTools([]string{"go"}) {
		t.Error("expected 'go' tool to be available")
	}

	// nonexistent tool
	if ValidateTools([]string{"nonexistent_tool_abc123"}) {
		t.Error("expected nonexistent tool to fail validation")
	}

	// mixed: one valid, one invalid
	if ValidateTools([]string{"go", "nonexistent_tool_abc123"}) {
		t.Error("expected mixed tools to fail validation")
	}
}
