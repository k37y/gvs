package gvs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestCleanupOldDirectories(t *testing.T) {
	tempDir := t.TempDir()
	tests := []struct {
		name   string
		age    time.Duration
		active bool
		keep   bool
	}{
		{"cg-old", 2 * time.Hour, false, false},
		{"gvc-old", 2 * time.Hour, false, false},
		{"cg-active", 2 * time.Hour, true, true},
		{"gvc-active", 2 * time.Hour, true, true},
		{"cg-recent", time.Minute, false, true},
		{"unrelated-old", 2 * time.Hour, false, true},
	}
	active := make(map[string]bool)
	for _, tt := range tests {
		dir := filepath.Join(tempDir, tt.name)
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		modified := time.Now().Add(-tt.age)
		if err := os.Chtimes(dir, modified, modified); err != nil {
			t.Fatal(err)
		}
		active[dir] = tt.active
	}

	cleanupOldDirectoriesIn(context.Background(), tempDir, func(dir string) bool { return active[dir] })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := os.Stat(filepath.Join(tempDir, tt.name))
			if tt.keep && err != nil {
				t.Errorf("expected directory to be kept: %v", err)
			}
			if !tt.keep && !os.IsNotExist(err) {
				t.Errorf("expected directory to be removed, stat error: %v", err)
			}
		})
	}
}

func TestStartDirectoryCleanupWithContext(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)
	dir := filepath.Join(tempDir, "cg-active")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartDirectoryCleanupWithContext(ctx, func(path string) bool {
			select {
			case started <- struct{}{}:
			default:
			}
			return path == dir
		})
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not perform its initial pass")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not stop when its context was cancelled")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("active directory was not preserved: %v", err)
	}
}

func TestCleanupOldDirectoriesCancelled(t *testing.T) {
	tempDir := t.TempDir()
	dir := filepath.Join(tempDir, "cg-old")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cleanupOldDirectoriesIn(ctx, tempDir, nil)
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("cancelled cleanup removed a directory: %v", err)
	}
}
