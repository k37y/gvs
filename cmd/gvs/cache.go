package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func retrieveCacheFromDisk(key string) ([]byte, error) {
	path := filepath.Join(cacheDir, keyToFilename(key))
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		return os.ReadFile(path)
	}
	return nil, os.ErrNotExist
}

func saveCacheToDisk(key string, data []byte) error {
	err := os.MkdirAll(cacheDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}
	return os.WriteFile(filepath.Join(cacheDir, keyToFilename(key)), data, 0644)
}

func keyToFilename(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "/", "_"), ":", "_") + ".json"
}
