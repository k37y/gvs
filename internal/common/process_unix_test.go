//go:build linux || darwin

package common

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCommandGroupHelper(t *testing.T) {
	mode := os.Getenv("GVS_TEST_GROUP_MODE")
	if mode == "" {
		return
	}
	if mode == "child" {
		if err := os.WriteFile(os.Getenv("GVS_TEST_GROUP_PID_FILE"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestCommandGroupHelper$")
	child.Env = append(os.Environ(), "GVS_TEST_GROUP_MODE=child")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestCommandGroupCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCommandGroupHelper$")
	cmd.Env = append(os.Environ(), "GVS_TEST_GROUP_MODE=parent", "GVS_TEST_GROUP_PID_FILE="+pidFile, "GORACE=atexit_sleep_ms=0")
	cmd.WaitDelay = 3 * time.Second
	configureCommandCancellation(cmd)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	childPID := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			childPID, _ = strconv.Atoi(string(data))
			if childPID != 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		cancel()
		<-done
		t.Fatalf("descendant did not start: %s", output.String())
	}
	defer func() { _ = syscall.Kill(childPID, syscall.SIGKILL) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled command succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("descendant held inherited pipes open after cancellation")
	}
	deadline = time.Now().Add(time.Second)
	for !processTerminated(childPID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !processTerminated(childPID) {
		t.Errorf("descendant %d survived command cancellation", childPID)
	}
}

func processTerminated(pid int) bool {
	if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
		return true
	}
	// Container PID 1 may leave an exited orphan as a zombie until it reaps it.
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(data), ')')
	return i >= 0 && len(data) > i+2 && data[i+2] == 'Z'
}
