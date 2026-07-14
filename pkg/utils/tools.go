package utils

import (
	"fmt"
	"os"
	"os/exec"
)

func ValidateTools(tools []string) bool {
	allAvailable := true
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			allAvailable = false
			fmt.Fprintf(os.Stderr, "Failed finding %s package: %s", tool, err)
		}
	}
	return allAvailable
}
