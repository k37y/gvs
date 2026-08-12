package gvs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.input)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetDirSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files with known sizes
	os.WriteFile(filepath.Join(tmpDir, "a.txt"), make([]byte, 100), 0644)
	os.WriteFile(filepath.Join(tmpDir, "b.txt"), make([]byte, 200), 0644)
	os.MkdirAll(filepath.Join(tmpDir, "sub"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "sub", "c.txt"), make([]byte, 300), 0644)

	size, err := getDirSize(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if size != 600 {
		t.Errorf("getDirSize() = %d, want 600", size)
	}
}

func TestGetDirSize_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	size, err := getDirSize(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Errorf("getDirSize() = %d, want 0", size)
	}
}
