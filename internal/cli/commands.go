package cli

import (
	"os"
	"os/exec"
)

// RunCommand executes a command in the specified directory with Go-specific environment
func RunCommand(dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return out, err
}

// RunCommandStdout executes a command and returns only stdout (ignoring stderr)
func RunCommandStdout(dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	cmd.Dir = dir
	out, err := cmd.Output()
	return out, err
}
