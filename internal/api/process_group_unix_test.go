//go:build linux || darwin

package api

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestScannerGroupHelper(t *testing.T) {
	if os.Getenv("GVS_TEST_SCANNER_GROUP") != "1" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	child := cgProcessCommand(context.Background(), "descendant")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "childPID=%d\n", child.Process.Pid)
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestScannerProcessGroupCleanup(t *testing.T) {
	for _, ignoresTERM := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignoresTERM=%t", ignoresTERM), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := cgProcessCommand(ctx, "inherited")
			if ignoresTERM {
				cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestScannerGroupHelper$")
				cmd.Env = append(os.Environ(), "GVS_TEST_SCANNER_GROUP=1", "GORACE=atexit_sleep_ms=0")
			}
			cleanup := configureScannerProcess(cmd)
			defer cleanup()
			cmd.WaitDelay = 50 * time.Millisecond
			childPID := 0
			start := time.Now()
			_, logs, err := runCgWithProgressCapture(cmd, func(line string) {
				if pid, parseErr := strconv.Atoi(strings.TrimPrefix(line, "childPID=")); parseErr == nil {
					childPID = pid
					if ignoresTERM {
						cancel()
					}
				}
			})
			cleanup()
			if err == nil {
				t.Error("expected cancellation or inherited-pipe error")
			}
			if elapsed := time.Since(start); elapsed > 4*time.Second {
				t.Errorf("scanner shutdown exceeded WaitDelay: %v", elapsed)
			}
			if childPID == 0 {
				t.Fatalf("scanner did not launch descendant: %s", logs)
			}
			deadline := time.Now().Add(time.Second)
			for !scannerDescendantTerminated(childPID) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !scannerDescendantTerminated(childPID) {
				t.Errorf("descendant %d survived scanner termination", childPID)
			}
		})
	}
}

func scannerDescendantTerminated(pid int) bool {
	if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
		return true
	}
	// Container PID 1 may not immediately reap an exited orphan.
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(data), ')')
	return i >= 0 && len(data) > i+2 && data[i+2] == 'Z'
}
