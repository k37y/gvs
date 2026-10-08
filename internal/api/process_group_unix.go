//go:build linux || darwin

package api

import (
	"errors"
	"log"
	"os/exec"
	"syscall"
)

func configureScannerProcess(cmd *exec.Cmd) func() {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	// The scanner first gets a chance to cancel and reap its own subprocesses.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	return func() {
		if cmd.Process == nil {
			return
		}
		// WaitDelay can kill an unresponsive scanner without killing descendants.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			log.Printf("Stop scanner process group: %v", err)
		}
	}
}
