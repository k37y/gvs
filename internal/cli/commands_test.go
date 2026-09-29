package cli

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDefaultRunnerImplementsInterface(t *testing.T) {
	var _ CommandRunner = DefaultRunner{}
}

func TestRunCommand(t *testing.T) {
	out, err := RunCommand(context.Background(), "", "echo", "hello")
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}
	if got := string(out); got != "hello\n" {
		t.Errorf("RunCommand = %q, want %q", got, "hello\n")
	}
}

func TestRunCommandStdout(t *testing.T) {
	out, err := RunCommandStdout(context.Background(), "", "echo", "hello")
	if err != nil {
		t.Fatalf("RunCommandStdout failed: %v", err)
	}
	if got := string(out); got != "hello\n" {
		t.Errorf("RunCommandStdout = %q, want %q", got, "hello\n")
	}
}

func TestRunCommand_Error(t *testing.T) {
	_, err := RunCommand(context.Background(), "", "nonexistent_cmd_xyz")
	if err == nil {
		t.Error("expected error for nonexistent command")
	}
}

func TestRunCommand_Dir(t *testing.T) {
	dir := t.TempDir()
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RunCommand(context.Background(), dir, "pwd")
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}
	if got := string(out); got != want+"\n" {
		t.Errorf("RunCommand = %q, want %q", got, want+"\n")
	}
}
