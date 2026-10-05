//go:build !linux && !darwin

package api

import "os/exec"

func configureScannerProcess(cmd *exec.Cmd) func() { return func() {} }
