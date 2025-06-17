package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func runCommand(dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return out, err
}

func validateTools(tools []string) bool {
	allAvailable := true
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			allAvailable = false
			fmt.Printf("Failed finding %s package: %s", tool, err)
		}
	}
	return allAvailable
}

func getGitBranch(result *Result) {
	cmd := "git"
	args := []string{"rev-parse", "--abbrev-ref", "HEAD"}
	out, err := runCommand(result.Directory, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), result.Directory, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
	}
	result.Branch = strings.TrimSpace(string(out))
}

func getGitURL(result *Result) {
	cmd := "git"
	args := []string{"remote", "get-url", "origin"}
	out, err := runCommand(result.Directory, cmd, args...)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to run %s %s in %s: %s", cmd, strings.Join(args, " "), result.Directory, strings.TrimSpace(string(out)))
		result.Errors = append(result.Errors, errMsg)
	}
	result.Repository = strings.TrimSpace(string(out))
}

func formatIntroducedFixed(events []Event) []string {
	var result []string
	var introduced string

	for _, e := range events {
		if e.Introduced != "" {
			introduced = e.Introduced
		}
		if e.Fixed != "" && introduced != "" {
			pair := fmt.Sprintf("Introduced in %s and fixed in %s", introduced, e.Fixed)
			result = append(result, pair)
			introduced = ""
		}
	}

	if introduced != "" {
		result = append(result, fmt.Sprintf("Introdued in %s - ", introduced))
	}

	return result
}

func extractFormattedFixedVersions(inputs []string) []string {
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

func semVersion(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}
