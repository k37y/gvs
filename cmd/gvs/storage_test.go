package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k37y/gvs/internal/api"
)

func preserveStorageEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"GVS_DATA_DIR", "GVS_GRAPH_CACHE", "GOCACHE", "GOMODCACHE", "GOPATH", "GOBIN", "TMPDIR", "TMP", "TEMP", "GOTMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "TEST_TELEMETRY_DIR"} {
		t.Setenv(key, os.Getenv(key))
	}
}

func TestConfigureStorage(t *testing.T) {
	preserveStorageEnv(t)
	root := filepath.Join(t.TempDir(), "runtime data")
	t.Setenv("GVS_DATA_DIR", root)
	// A single root must take precedence over inherited tool settings.
	t.Setenv("GOCACHE", "/unused/build")
	t.Setenv("GOMODCACHE", "/unused/mod")
	t.Setenv("GVS_GRAPH_CACHE", "/unused/graph")
	graphDir, err := configureStorage()
	if err != nil {
		t.Fatal(err)
	}
	if graphDir != filepath.Join(root, "graph") {
		t.Fatalf("graph directory = %q", graphDir)
	}
	for key, suffix := range map[string]string{
		"GOCACHE": "go-build", "GOPATH": "go", "GOMODCACHE": "go/pkg/mod", "GOBIN": "go/bin",
		"TMPDIR": "tmp", "TMP": "tmp", "TEMP": "tmp", "GOTMPDIR": "tmp",
		"XDG_CACHE_HOME": "cache", "XDG_CONFIG_HOME": "config", "TEST_TELEMETRY_DIR": "config/go/telemetry",
	} {
		want := filepath.Join(root, filepath.FromSlash(suffix))
		if got := os.Getenv(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
		if info, err := os.Stat(want); err != nil || !info.IsDir() {
			t.Errorf("%s directory missing: %v", key, err)
		}
	}
	clone, err := os.MkdirTemp("", "cg-test-")
	if err != nil || filepath.Dir(clone) != filepath.Join(root, "tmp") {
		t.Fatalf("temporary clone = %q, error %v", clone, err)
	}
	const key = "storage-test"
	for _, save := range []func(string, []byte) error{api.SaveCacheToDisk, api.SaveCacheLogsToDisk} {
		if err := save(key, []byte("result")); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{"json", "log"} {
		if _, err := os.Stat(filepath.Join(root, "cache", "gvs", key+"."+suffix)); err != nil {
			t.Fatal(err)
		}
	}
	for _, read := range []func(string) ([]byte, error){api.RetrieveCacheFromDisk, api.RetrieveCacheLogFromDisk} {
		if data, err := read(key); err != nil || string(data) != "result" {
			t.Fatalf("cache read = %q, error %v", data, err)
		}
	}
	// Exercise real Go subprocesses: includes telemetry and persisted Go defaults.
	t.Setenv("GOTOOLCHAIN", "local")
	out, err := exec.Command("go", "env", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR", "GOTELEMETRYDIR").CombinedOutput()
	if err != nil {
		t.Fatalf("go env: %v\n%s", err, out)
	}
	for _, path := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.HasPrefix(path, root+string(os.PathSeparator)) {
			t.Errorf("Go subprocess writes outside root: %q", path)
		}
	}
}

func TestConfigureStorageDefaults(t *testing.T) {
	preserveStorageEnv(t)
	t.Setenv("GVS_DATA_DIR", "")
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("GOCACHE", "")
	graphDir, err := configureStorage()
	if err != nil {
		t.Fatal(err)
	}
	if graphDir != filepath.Join(cache, "gvs", "graph") || os.Getenv("GOCACHE") != filepath.Join(cache, "go-build") {
		t.Fatalf("legacy cache layout changed: graph=%s GOCACHE=%s", graphDir, os.Getenv("GOCACHE"))
	}
	customGoCache := t.TempDir()
	t.Setenv("GOCACHE", customGoCache)
	if _, err := configureStorage(); err != nil || os.Getenv("GOCACHE") != customGoCache {
		t.Fatalf("explicit GOCACHE not preserved: %v", err)
	}
}

func TestConfigureStorageInvalid(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"relative/path", file, filepath.Join(file, "child")} {
		t.Run(root, func(t *testing.T) {
			preserveStorageEnv(t)
			t.Setenv("GVS_DATA_DIR", root)
			if _, err := configureStorage(); err == nil || !strings.Contains(err.Error(), "GVS_DATA_DIR") {
				t.Fatalf("expected actionable configuration error, got %v", err)
			}
		})
	}
}
