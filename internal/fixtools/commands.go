package fixtools

import (
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

	prompt := `Prompt:
Assist as a Golang security expert to fix CVE vulnerabilities in a Golang repository.

Context:
	1.	The following commands are run in sequence:
    	•	go get
    	•	go mod tidy
    	•	go mod vendor
	3.	The command output is captured in the 'Command output:' section. It is provided to you for analysis.
	4.	If the commands succeed, make sure that the package bump version is appropriate for the codebase.
	5.	If the commands fail, need next step action plan with reasoning.
	6.	Be careful not to bump the Go version when bumping package versions.
	7.	The job is to:
    	•	Analyze 'Command output' section and check if it is appropriate.
    	•	Suggest the exact next action plan if any.
    	•	If there are multiple options, list them in priority order.
    	•	Keep the plan concise, actionable, and specific to Go modules.

Instruction:
Given the content of gvs-output.txt, provide a step-by-step action plan for resolving issues. If no issues are found, respond with "No further action needed."

Command output:
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
