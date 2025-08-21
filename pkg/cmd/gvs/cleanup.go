package gvs

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func StartDirectoryCleanup() {
	log.Println("Starting directory cleanup routine")

	// Run cleanup immediately on startup
	cleanupOldDirectories()

	// Run cleanup every hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		cleanupOldDirectories()
	}
}

func cleanupOldDirectories() {
	tempDir := os.TempDir()
	cutoffTime := time.Now().Add(-1 * time.Hour)

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		log.Printf("Failed to read temp directory %s: %v", tempDir, err)
		return
	}

	var deletedCount int
	var totalSize int64

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Check if directory matches our patterns: cg-* or gvc-*
		if !strings.HasPrefix(name, "cg-") && !strings.HasPrefix(name, "gvc-") {
			continue
		}

		dirPath := filepath.Join(tempDir, name)
		info, err := entry.Info()
		if err != nil {
			log.Printf("Failed to get info for directory %s: %v", dirPath, err)
			continue
		}

		// Check if directory is older than 1 hour
		if info.ModTime().Before(cutoffTime) {
			// Calculate directory size before deletion
			if size, err := getDirSize(dirPath); err == nil {
				totalSize += size
			}

			// Remove the directory
			if err := os.RemoveAll(dirPath); err != nil {
				log.Printf("Failed to remove directory %s: %v", dirPath, err)
			} else {
				log.Printf("Cleaned up old directory: %s (age: %v)", dirPath, time.Since(info.ModTime()).Round(time.Hour))
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("Cleanup completed: removed %d directories, freed %s", deletedCount, formatBytes(totalSize))
	} else {
		log.Printf("Cleanup completed: no old directories found")
	}
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
