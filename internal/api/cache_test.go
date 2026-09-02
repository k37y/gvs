package api

import (
	"os"
	"testing"
)

func TestKeyToFilename(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"repo@main:CVE-2024-1234", "repo@main_CVE-2024-1234.json"},
		{"https://github.com/foo/bar@main:CVE-2024-1234", "https___github.com_foo_bar@main_CVE-2024-1234.json"},
		{"simple", "simple.json"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := keyToFilename(tt.key)
			if got != tt.want {
				t.Errorf("keyToFilename(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestKeyToLogFilename(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"repo@main:CVE-2024-1234", "repo@main_CVE-2024-1234.log"},
		{"simple", "simple.log"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := keyToLogFilename(tt.key)
			if got != tt.want {
				t.Errorf("keyToLogFilename(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestCacheRoundtrip(t *testing.T) {
	origCacheDir := cacheDir
	cacheDir = t.TempDir()
	defer func() { cacheDir = origCacheDir }()

	key := "test-repo@main:CVE-2024-1234"
	data := []byte(`{"IsVulnerable":"true"}`)

	if err := SaveCacheToDisk(key, data); err != nil {
		t.Fatalf("SaveCacheToDisk failed: %v", err)
	}

	got, err := RetrieveCacheFromDisk(key)
	if err != nil {
		t.Fatalf("RetrieveCacheFromDisk failed: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", string(got), string(data))
	}
}

func TestCacheLogRoundtrip(t *testing.T) {
	origCacheDir := cacheDir
	cacheDir = t.TempDir()
	defer func() { cacheDir = origCacheDir }()

	key := "test-repo@main:CVE-2024-1234"
	data := []byte("scan log output here")

	if err := SaveCacheLogsToDisk(key, data); err != nil {
		t.Fatalf("SaveCacheLogsToDisk failed: %v", err)
	}

	got, err := RetrieveCacheLogFromDisk(key)
	if err != nil {
		t.Fatalf("RetrieveCacheLogFromDisk failed: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", string(got), string(data))
	}
}

func TestRetrieveCacheFromDisk_Missing(t *testing.T) {
	origCacheDir := cacheDir
	cacheDir = t.TempDir()
	defer func() { cacheDir = origCacheDir }()

	_, err := RetrieveCacheFromDisk("nonexistent")
	if !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}
