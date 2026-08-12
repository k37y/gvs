package utils

import (
	"io"
	"testing"
)

func TestValidateTools(t *testing.T) {
	if !ValidateTools([]string{"go"}, io.Discard) {
		t.Error("expected 'go' tool to be available")
	}

	if ValidateTools([]string{"nonexistent_tool_abc123"}, io.Discard) {
		t.Error("expected nonexistent tool to fail validation")
	}

	if ValidateTools([]string{"go", "nonexistent_tool_abc123"}, io.Discard) {
		t.Error("expected mixed tools to fail validation")
	}
}
