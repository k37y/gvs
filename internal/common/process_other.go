//go:build !linux && !darwin

package common

import "os/exec"

func configureCommandCancellation(cmd *exec.Cmd) {}
