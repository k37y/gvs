package main

import (
	"fmt"
	"os"

	"golang.org/x/mod/semver"
)

var version string

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  semver version")
		fmt.Println("  semver <current_version> <future_version>")
		return
	}

	switch os.Args[1] {
	case "version":
		if version == "" {
			fmt.Println("version: (not set)")
		} else {
			fmt.Println("version:", version)
		}
		return

	default:
		if len(os.Args) < 3 {
			fmt.Println("Usage:")
			fmt.Println("  semver version")
			fmt.Println("  semver <current_version> <future_version>")
			return
		}
		cmv := os.Args[1]
		fmv := os.Args[2]

		if semver.Compare(cmv, fmv) >= 0 {
			fmt.Println("yes")
		} else {
			fmt.Println("no")
		}
	}
}
