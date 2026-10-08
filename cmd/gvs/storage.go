package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// configureStorage runs before handlers or maintenance goroutines start, so
// temporary files and child processes inherit the same storage configuration.
func configureStorage() (string, error) {
	root := os.Getenv("GVS_DATA_DIR")
	if root == "" {
		cache := getCacheDir()
		goCache := filepath.Join(cache, "go-build")
		if os.Getenv("GOCACHE") == "" {
			if err := os.Setenv("GOCACHE", goCache); err != nil {
				return "", err
			}
		}
		graph := filepath.Join(cache, "gvs", "graph")
		for _, dir := range []string{goCache, graph} {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return "", fmt.Errorf("create cache directory %q: %w", dir, err)
			}
		}
		return graph, os.Setenv("GVS_GRAPH_CACHE", graph)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("GVS_DATA_DIR must be an absolute path: %q", root)
	}
	root = filepath.Clean(root)
	paths := []struct{ key, dir string }{
		{"GVS_GRAPH_CACHE", filepath.Join(root, "graph")},
		{"GOCACHE", filepath.Join(root, "go-build")},
		{"GOPATH", filepath.Join(root, "go")},
		{"GOMODCACHE", filepath.Join(root, "go", "pkg", "mod")},
		{"GOBIN", filepath.Join(root, "go", "bin")},
		{"TMPDIR", filepath.Join(root, "tmp")},
		{"TMP", filepath.Join(root, "tmp")},
		{"TEMP", filepath.Join(root, "tmp")},
		{"GOTMPDIR", filepath.Join(root, "tmp")},
		{"XDG_CACHE_HOME", filepath.Join(root, "cache")},
		{"XDG_CONFIG_HOME", filepath.Join(root, "config")},
		// Go's telemetry directory is not a settable GOTELEMETRYDIR variable.
		// This toolchain override also covers macOS, where XDG_CONFIG_HOME is ignored.
		{"TEST_TELEMETRY_DIR", filepath.Join(root, "config", "go", "telemetry")},
	}
	for _, path := range paths {
		if err := os.MkdirAll(path.dir, 0755); err != nil {
			return "", fmt.Errorf("GVS_DATA_DIR: create %q: %w", path.dir, err)
		}
	}
	for _, path := range paths {
		if err := os.Setenv(path.key, path.dir); err != nil {
			return "", fmt.Errorf("GVS_DATA_DIR: set %s: %w", path.key, err)
		}
	}
	return filepath.Join(root, "graph"), nil
}
