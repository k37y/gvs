package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func cgProcessCommand(ctx context.Context, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCGProcessHelper$")
	cmd.Env = append(os.Environ(), "GVS_TEST_PROCESS_MODE="+mode, "GORACE=atexit_sleep_ms=0")
	return cmd
}

func TestCGProcessHelper(t *testing.T) {
	mode := os.Getenv("GVS_TEST_PROCESS_MODE")
	if mode == "" {
		return
	}
	fmt.Fprintln(os.Stderr, "gvs-process-test-start")
	switch mode {
	case "large":
		fmt.Fprint(os.Stdout, strings.Repeat("o", 128*1024)+"\nfinal output")
		fmt.Fprint(os.Stderr, strings.Repeat("e", 128*1024)+"\nnext\r\npartial")
	case "failure":
		fmt.Fprint(os.Stdout, "partial output")
		fmt.Fprint(os.Stderr, "scanner failed\n")
		os.Exit(7)
	case "inherited", "cancel":
		child := cgProcessCommand(context.Background(), "descendant")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "childPID=%d\n", child.Process.Pid)
		if mode == "cancel" {
			time.Sleep(30 * time.Second)
		}
	case "descendant":
		time.Sleep(30 * time.Second)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func capturedProcessLogs(t *testing.T, logs []byte) string {
	t.Helper()
	// Package initialization also logs to stderr in the helper subprocess.
	_, payload, found := strings.Cut(string(logs), "gvs-process-test-start\n")
	if !found {
		t.Fatalf("helper output marker missing: %q", logs)
	}
	return payload
}

func TestRunCgWithProgressCapture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var progress []string
	started := false
	output, logs, err := runCgWithProgressCapture(cgProcessCommand(ctx, "large"), func(line string) {
		if started {
			progress = append(progress, line)
		}
		if line == "gvs-process-test-start" {
			started = true
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("o", 128*1024) + "\nfinal output"; string(output) != want {
		t.Errorf("stdout was not preserved: got %d bytes, want %d", len(output), len(want))
	}
	if got, want := capturedProcessLogs(t, logs), strings.Repeat("e", 128*1024)+"\nnext\r\npartial"; got != want {
		t.Errorf("stderr was not preserved: got %d bytes, want %d", len(got), len(want))
	}
	if len(progress) != 3 {
		t.Fatalf("got %d progress messages, want 3", len(progress))
	}
	if progress[0] != strings.Repeat("e", 128*1024) || progress[1] != "next" || progress[2] != "partial" {
		t.Error("progress did not preserve long lines, strip CRLF, and flush the final partial line")
	}
}

func TestRunCgWithProgressCaptureFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, logs, err := runCgWithProgressCapture(cgProcessCommand(ctx, "failure"), nil)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("error = %v, want exit code 7", err)
	}
	if string(output) != "partial output" || capturedProcessLogs(t, logs) != "scanner failed\n" {
		t.Errorf("failed process output lost: stdout=%q, stderr=%q", output, logs)
	}
}

func TestRunCgWithProgressCaptureStartError(t *testing.T) {
	cmd := exec.Command("/nonexistent-gvs-test-scanner")
	output, logs, err := runCgWithProgressCapture(cmd, nil)
	if err == nil || len(output) != 0 || len(logs) != 0 {
		t.Errorf("start failure: stdout=%q, stderr=%q, error=%v", output, logs, err)
	}
}

func TestRunCgWithProgressCaptureInheritedPipes(t *testing.T) {
	for _, mode := range []string{"inherited", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := cgProcessCommand(ctx, mode)
			cmd.WaitDelay = 50 * time.Millisecond
			childPID := 0
			defer func() {
				if childPID != 0 {
					if process, err := os.FindProcess(childPID); err == nil {
						_ = process.Kill()
					}
				}
			}()
			start := time.Now()
			_, logs, err := runCgWithProgressCapture(cmd, func(line string) {
				if pid, parseErr := strconv.Atoi(strings.TrimPrefix(line, "childPID=")); parseErr == nil {
					childPID = pid
					if mode == "cancel" {
						cancel()
					}
				}
			})
			if elapsed := time.Since(start); elapsed >= 4*time.Second {
				t.Errorf("capture waited %v for inherited pipes despite WaitDelay", elapsed)
			}
			if childPID == 0 {
				t.Fatalf("helper did not start its descendant: logs=%q, error=%v", logs, err)
			}
			if mode == "inherited" && !errors.Is(err, exec.ErrWaitDelay) {
				t.Errorf("error = %v, want exec.ErrWaitDelay", err)
			}
			if mode == "cancel" && (err == nil || ctx.Err() != context.Canceled) {
				t.Errorf("cancellation error = %v, context error = %v", err, ctx.Err())
			}
		})
	}
}
