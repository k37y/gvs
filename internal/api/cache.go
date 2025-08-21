package api

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/k37y/gvs/internal/cli"
)

var cacheDir = "/tmp/gvs-cache"

func RetrieveCacheFromDisk(key string) ([]byte, error) {
	path := filepath.Join(cacheDir, keyToFilename(key))
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		return os.ReadFile(path)
	}
	return nil, os.ErrNotExist
}

func SaveCacheToDisk(key string, data []byte) error {
	err := os.MkdirAll(cacheDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}
	return os.WriteFile(filepath.Join(cacheDir, keyToFilename(key)), data, 0644)
}

func keyToFilename(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "/", "_"), ":", "_") + ".json"
}

// ConvertCacheForRunFix converts cached runFix=false data to runFix=true format
// by parsing fixCommands from cache and executing them in the cached directory
func ConvertCacheForRunFix(cachedData []byte) ([]byte, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(cachedData, &result); err != nil {
		return nil, err
	}

	// Get the cached directory
	cachedDir, ok := result["Directory"].(string)
	if !ok || cachedDir == "" {
		return nil, fmt.Errorf("no Directory field found in cached data")
	}

	// Check if the cached directory still exists
	if _, err := os.Stat(cachedDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("cached directory no longer exists: %s", cachedDir)
	}

	// Initialize fix-specific fields
	fixErrors := []string{}
	fixSuccess := []string{}
	result["FixErrors"] = &fixErrors
	result["FixSuccess"] = &fixSuccess

	// Add cursor command field using the cached directory
	cursorCmd := "cursor --remote ssh-remote+gvs-host " + cachedDir
	result["CursorCommand"] = &cursorCmd

	// If not vulnerable, return with empty fix results
	if result["IsVulnerable"] != "true" {
		return json.MarshalIndent(result, "", "  ")
	}

	// Create a temporary result structure to use the shared functions
	tempResult := &cli.Result{
		Directory:  cachedDir,
		FixErrors:  &fixErrors,
		FixSuccess: &fixSuccess,
	}

	// Execute fix commands if UsedImports contains them
	if usedImports, ok := result["UsedImports"].(map[string]interface{}); ok {
		for pkg, importDetails := range usedImports {
			if details, ok := importDetails.(map[string]interface{}); ok {
				if fixCommandsRaw, exists := details["FixCommands"]; exists {
					if fixCommands, ok := fixCommandsRaw.([]interface{}); ok {
						// Convert []interface{} to []string
						fixCmds := make([]string, len(fixCommands))
						for i, cmd := range fixCommands {
							if cmdStr, ok := cmd.(string); ok {
								fixCmds[i] = cmdStr
							}
						}

						if len(fixCmds) > 0 {
							// Use the shared runFixCommands function
							cli.RunFixCommands(pkg, cachedDir, fixCmds, tempResult)
						}
					}
				}
			}
		}
	}

	// Use the shared readFixResults function to populate success/error arrays
	cli.ReadFixResults(tempResult)

	// Update the result with populated fix results
	result["FixErrors"] = tempResult.FixErrors
	result["FixSuccess"] = tempResult.FixSuccess

	// Convert back to JSON
	return json.MarshalIndent(result, "", "  ")
}
