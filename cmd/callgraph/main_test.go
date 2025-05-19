package main

import (
	"os"
	"path/filepath"
	"testing"
)

// createTempModule sets up a go.mod file with a replace directive
func createTempModule(t *testing.T) string {
	tmpDir := t.TempDir()

	goMod := `
module testmod

go 1.20

require golang.org/x/net v0.0.0-20240115110440-ef1b5c325497

replace golang.org/x/net => golang.org/x/net v0.24.0
`

	err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	if err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	return tmpDir
}

func TestGetReplaceVersion(t *testing.T) {
	dir := createTempModule(t)

	version := getReplaceVersion("golang.org/x/net", dir)

	expected := "v0.24.0"
	if version != expected {
		t.Errorf("Expected version %s, got %s", expected, version)
	}
}
