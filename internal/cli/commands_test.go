package cli

import (
	"context"
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
	out, err := RunCommand(context.Background(), "/tmp", "pwd")
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}
	if got := string(out); got != "/tmp\n" {
		t.Errorf("RunCommand = %q, want %q", got, "/tmp\n")
	}
}
