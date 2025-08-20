package fixtools

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func runCommand(dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return out, err
}

// RunFixCommands executes fix commands and writes results to gvs-output.txt
func RunFixCommands(pkg, dir string, fixCommands []string, result *Result) {
	outputFile := filepath.Join(dir, "gvs-output.txt")
	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		if result.FixErrors != nil {
			*result.FixErrors = append(*result.FixErrors, fmt.Sprintf("Failed to open output file %s: %v", outputFile, err))
		}
		return
	}
	defer f.Close()

	prompt := `Context / Background:
- Collected the command output and provided here [1].
- Scanned the repository and generated the vulnerability status JSON output [2].
- Executed the fixCommand if any present in the JSON output [2].
- If the fixCommand is not present, then no action is needed.

Goal / Objective:
- Fix the vulnerability of the repository.

Scope / Boundaries:
- Keep the Go version same as the original repository.
- Make minimal changes to the repository while fixing the vulnerability.
- Check the go.mod file and confirm if the package is indirect dependency. If yes, compare the fix version and current version to see if the change is major.

Format of Output:
- What was done.
- What is next.
- What is the status of vulnerability.

Tone & Style:
- Clear and concise.

Constraints / Requirements:
Keep the response under 250 words.

Special Instructions:
- Check the go.mod file and confirm if the package is indirect dependency and compare fix version and current version to see if the change is major.

[1]
`

	f.WriteString(prompt)
	f.WriteString(fmt.Sprintf("Package: %s\n", pkg))

	_, err = runCommand(dir, "go", "clean", "-modcache")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to run go clean -modcache: %v", err))
	}

	for _, fullCommand := range fixCommands {
		parts := strings.Fields(fullCommand)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		f.WriteString(fmt.Sprintf("Command: %s\n", fullCommand))

		out, err := runCommand(dir, cmd, args...)
		output := strings.TrimSpace(string(out))
		if output == "" {
			output = "nil"
		}
		f.WriteString(fmt.Sprintf("Output: %s\n", output))

		if err != nil {
			errMsg := fmt.Sprintf("Error: %v\n", err)
			f.WriteString(errMsg)
		} else {
			f.WriteString("Status: Success\n")
		}
		f.WriteString("---\n")
	}

	// Add CVE Assessment section with Result{} JSON after all fix commands
	if result != nil {
		f.WriteString("\n[2]\n")
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			f.WriteString(fmt.Sprintf("Error marshaling result to JSON: %v\n", err))
		} else {
			f.WriteString(string(jsonData))
			f.WriteString("\n")
		}
		f.WriteString("---\n")
	}
}

// ReadFixResults reads gvs-output.txt and populates fix results
func ReadFixResults(result *Result) {
	outputFile := filepath.Join(result.Directory, "gvs-output.txt")

	// Check if the file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read gvs-output.txt: %v", err))
		return
	}

	if len(content) == 0 {
		return
	}

	// Parse the content to extract success and error information
	lines := strings.Split(string(content), "\n")
	var currentPackage, currentCommand string
	var currentOutput []string
	var inOutputSection bool

	for _, line := range lines {
		originalLine := line
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Package: ") {
			currentPackage = strings.TrimPrefix(line, "Package: ")
			currentOutput = []string{}
			inOutputSection = false
		} else if strings.HasPrefix(line, "Command: ") {
			currentCommand = strings.TrimPrefix(line, "Command: ")
			currentOutput = []string{}
			inOutputSection = false
		} else if strings.HasPrefix(line, "Output: ") {
			outputContent := strings.TrimPrefix(line, "Output: ")
			currentOutput = []string{outputContent}
			inOutputSection = true
		} else if strings.HasPrefix(line, "Status: Success") {
			if result.FixSuccess != nil {
				outputStr := strings.Join(currentOutput, "\n")
				*result.FixSuccess = append(*result.FixSuccess,
					fmt.Sprintf("\nPackage: %s\nCommand: %s\nOutput: %s",
						currentPackage, currentCommand, outputStr))
			}
			inOutputSection = false
		} else if strings.HasPrefix(line, "Error: ") {
			errorMsg := strings.TrimPrefix(line, "Error: ")
			if result.FixErrors != nil {
				outputStr := strings.Join(currentOutput, "\n")
				*result.FixErrors = append(*result.FixErrors,
					fmt.Sprintf("\nPackage: %s\nCommand: %s\nError: %s\nOutput: %s",
						currentPackage, currentCommand, errorMsg, outputStr))
			}
			inOutputSection = false
		} else if line == "---" {
			// Reset for next command block
			currentOutput = []string{}
			inOutputSection = false
		} else if inOutputSection && line != "" &&
			!strings.HasPrefix(line, "Package:") &&
			!strings.HasPrefix(line, "Command:") &&
			!strings.HasPrefix(line, "Status:") &&
			!strings.HasPrefix(line, "Error:") {
			// Continue collecting output lines, preserve original formatting
			currentOutput = append(currentOutput, originalLine)
		}
	}
}
