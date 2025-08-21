package common

import (
	"fmt"
	"regexp"
	"strings"
)

func FormatIntroducedFixed(events []interface{}) []string {
	var result []string
	var introduced string

	for _, e := range events {
		if event, ok := e.(map[string]interface{}); ok {
			if intro, exists := event["introduced"]; exists && intro != nil {
				if introStr, ok := intro.(string); ok {
					introduced = introStr
				}
			}
			if fixed, exists := event["fixed"]; exists && fixed != nil {
				if fixedStr, ok := fixed.(string); ok && introduced != "" {
					pair := fmt.Sprintf("Introduced in %s and fixed in %s", introduced, fixedStr)
					result = append(result, pair)
					introduced = ""
				}
			}
		}
	}

	if introduced != "" {
		result = append(result, fmt.Sprintf("Introdued in %s - ", introduced))
	}

	return result
}

func ExtractFormattedFixedVersions(inputs []string) []string {
	re := regexp.MustCompile(`fixed in ([0-9a-zA-Z.\-]+)`)

	var fixedVersions []string

	for _, input := range inputs {
		matches := re.FindAllStringSubmatch(input, -1)
		for _, match := range matches {
			if len(match) > 1 {
				fixedVersions = append(fixedVersions, match[1])
			}
		}
	}

	return fixedVersions
}

func SemVersion(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func UniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
