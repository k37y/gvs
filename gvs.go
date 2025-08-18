package gvs

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

type ScanRequest struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
	CVE    string `json:"cve"`
}

type ScanResponse struct {
	Success  bool        `json:"success"`
	ExitCode int         `json:"exit_code"`
	Output   interface{} `json:"output,omitempty"`
	Error    string      `json:"error,omitempty"`
}

type Sarif struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		} `json:"results"`
	} `json:"runs"`
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

func RunCallgraphScript(repoDir, cveID string) (string, error) {
	scriptPath := "hack/callgraph.sh"

	cmd := exec.Command("bash", scriptPath, cveID, repoDir)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	return output.String(), err
}
