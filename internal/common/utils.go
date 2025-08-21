package common

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func FormatIntroducedFixed(events []interface{}) []string {
	var result []string
	var introduced string

	for _, e := range events {
		if event, ok := e.(map[string]interface{}); ok {
			if intro, exists := event["introduced"]; exists && intro != nil {
				if introStr, ok := intro.(string); ok {
					introduced = introStr
				}
			}
			if fixed, exists := event["fixed"]; exists && fixed != nil {
				if fixedStr, ok := fixed.(string); ok && introduced != "" {
					pair := fmt.Sprintf("Introduced in %s and fixed in %s", introduced, fixedStr)
					result = append(result, pair)
					introduced = ""
				}
			}
		}
	}

	if introduced != "" {
		result = append(result, fmt.Sprintf("Introdued in %s - ", introduced))
	}

	return result
}

func ExtractFormattedFixedVersions(inputs []string) []string {
	re := regexp.MustCompile(`fixed in ([0-9a-zA-Z.\-]+)`)

	var fixedVersions []string

	for _, input := range inputs {
		matches := re.FindAllStringSubmatch(input, -1)
		for _, match := range matches {
			if len(match) > 1 {
				fixedVersions = append(fixedVersions, match[1])
			}
		}
	}

	return fixedVersions
}

func SemVersion(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func UniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

func CloneRepo(repoURL, branch, cloneDir string) error {
	os.Setenv("GIT_TERMINAL_PROMPT", "0")

	checkCmd := exec.Command("git", "ls-remote", "--exit-code", repoURL)
	var checkStderr bytes.Buffer
	checkCmd.Stderr = &checkStderr

	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("repository is not publicly accessible: %s", checkStderr.String())
	}

	cmd := exec.Command("git", "clone", "--depth", "1", "--branch", branch, "--single-branch", repoURL, cloneDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("git clone failed: %v\n%s", err, stderr.String())
	}
	return nil
}

func FindGoModDirs(root string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "vendor" {
			return filepath.SkipDir
		}
		if d.Name() == "go.mod" {
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})
	return dirs, err
}

func RunGovulncheck(directory, target string) (string, int, error) {
	cmd := exec.Command("govulncheck", "-format", "sarif", "-C", directory, target)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	if err != nil && exitCode != 3 {
		log.Printf("govulncheck failed: %v\nSTDERR:\n%s", err, stderr.String())
		return stderr.String(), 1, fmt.Errorf("govulncheck failed: %v", err)
	}

	return out.String(), exitCode, nil
}
