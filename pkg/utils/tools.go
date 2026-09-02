package utils

import (
	"fmt"
	"io"
	"os/exec"
)

func ValidateTools(tools []string, w io.Writer) bool {
	allAvailable := true
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			allAvailable = false
			fmt.Fprintf(w, "Failed finding %s package: %s", tool, err)
		}
	}
	return allAvailable
}
