package api

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

var cacheDir = "/tmp/gvs-cache"

func getCacheDir() string {
	if root := os.Getenv("GVS_DATA_DIR"); root != "" {
		return filepath.Join(root, "cache", "gvs")
	}
	return cacheDir
}

func RetrieveCacheFromDisk(key string) ([]byte, error) {
	path := filepath.Join(getCacheDir(), keyToFilename(key))
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		return os.ReadFile(path)
	}
	return nil, os.ErrNotExist
}

func SaveCacheToDisk(key string, data []byte) error {
	cacheDir := getCacheDir()
	err := os.MkdirAll(cacheDir, 0755)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cacheDir, keyToFilename(key)), data, 0644)
}

func RetrieveCacheLogFromDisk(key string) ([]byte, error) {
	path := filepath.Join(getCacheDir(), keyToLogFilename(key))
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		return os.ReadFile(path)
	}
	return nil, os.ErrNotExist
}

func SaveCacheLogsToDisk(key string, data []byte) error {
	cacheDir := getCacheDir()
	err := os.MkdirAll(cacheDir, 0755)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cacheDir, keyToLogFilename(key)), data, 0644)
}

func keyToFilename(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "/", "_"), ":", "_") + ".json"
}

func keyToLogFilename(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "/", "_"), ":", "_") + ".log"
}
