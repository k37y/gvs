package api

import "testing"

func TestKeyToFilename(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"repo@main:CVE-2024-1234", "repo@main_CVE-2024-1234.json"},
		{"https://github.com/foo/bar@main:CVE-2024-1234", "https___github.com_foo_bar@main_CVE-2024-1234.json"},
		{"simple", "simple.json"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := keyToFilename(tt.key)
			if got != tt.want {
				t.Errorf("keyToFilename(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestKeyToLogFilename(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"repo@main:CVE-2024-1234", "repo@main_CVE-2024-1234.log"},
		{"simple", "simple.log"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := keyToLogFilename(tt.key)
			if got != tt.want {
				t.Errorf("keyToLogFilename(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
