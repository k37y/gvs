package cli

import (
	"context"
	"os"
	"os/exec"
)

type CommandRunner interface {
	RunCommand(ctx context.Context, dir string, command string, args ...string) ([]byte, error)
	RunCommandStdout(ctx context.Context, dir string, command string, args ...string) ([]byte, error)
	RunCommandWithEnv(ctx context.Context, dir string, env []string, command string, args ...string) ([]byte, error)
}

type DefaultRunner struct{}

func (DefaultRunner) RunCommand(ctx context.Context, dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return out, err
}

func (DefaultRunner) RunCommandStdout(ctx context.Context, dir string, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	cmd.Dir = dir
	out, err := cmd.Output()
	return out, err
}

func (DefaultRunner) RunCommandWithEnv(ctx context.Context, dir string, env []string, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = env
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return out, err
}

// RunCommand executes a command in the specified directory with Go-specific environment
func RunCommand(ctx context.Context, dir string, command string, args ...string) ([]byte, error) {
	return DefaultRunner{}.RunCommand(ctx, dir, command, args...)
}

// RunCommandStdout executes a command and returns only stdout (ignoring stderr)
func RunCommandStdout(ctx context.Context, dir string, command string, args ...string) ([]byte, error) {
	return DefaultRunner{}.RunCommandStdout(ctx, dir, command, args...)
}
