package cg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
)

type fakeRunner struct {
	stdout   map[string][]byte
	combined map[string][]byte
	err      map[string]error
}

func (f *fakeRunner) key(command string, args ...string) string {
	s := command
	for _, a := range args {
		s += " " + a
	}
	return s
}

func (f *fakeRunner) RunCommand(_ context.Context, dir string, command string, args ...string) ([]byte, error) {
	k := f.key(command, args...)
	if e, ok := f.err[k]; ok {
		return f.combined[k], e
	}
	return f.combined[k], nil
}

func (f *fakeRunner) RunCommandStdout(_ context.Context, dir string, command string, args ...string) ([]byte, error) {
	k := f.key(command, args...)
	if e, ok := f.err[k]; ok {
		return f.stdout[k], e
	}
	return f.stdout[k], nil
}

func (f *fakeRunner) RunCommandWithEnv(_ context.Context, dir string, env []string, command string, args ...string) ([]byte, error) {
	return f.RunCommand(context.Background(), dir, command, args...)
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		stdout:   make(map[string][]byte),
		combined: make(map[string][]byte),
		err:      make(map[string]error),
	}
}

func TestParseVersionRanges(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  [][2]string
	}{
		{
			name:  "single range with introduced/fixed",
			input: []string{"Introduced in 0 and fixed in 0.33.0"},
			want:  [][2]string{{"v0", "v0.33.0"}},
		},
		{
			name:  "multi range",
			input: []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			want:  [][2]string{{"v0", "v1.21.8"}, {"v1.22.0", "v1.22.2"}},
		},
		{
			name:  "plain version string",
			input: []string{"v0.33.0"},
			want:  [][2]string{{"v", "v0.33.0"}},
		},
		{
			name:  "empty input",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty string entry",
			input: []string{""},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVersionRanges(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d ranges, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("range[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsVersionInVulnerableRange(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		rawFixVer  []string
		wantVuln   bool
		wantFixVer string
	}{
		{
			name:       "version in single range",
			version:    "v0.23.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			wantVuln:   true,
			wantFixVer: "v0.33.0",
		},
		{
			name:      "version at fix boundary",
			version:   "v0.33.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.33.0"},
			wantVuln:  false,
		},
		{
			name:      "version above fix",
			version:   "v0.34.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.33.0"},
			wantVuln:  false,
		},
		{
			name:       "version in second range",
			version:    "v1.22.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 1.21.9", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantVuln:   true,
			wantFixVer: "v1.22.2",
		},
		{
			name:      "version between ranges (not vulnerable)",
			version:   "v1.21.9",
			rawFixVer: []string{"Introduced in 0 and fixed in 1.21.9", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantVuln:  false,
		},
		{
			name:       "version in first range of multi-range",
			version:    "v1.21.4",
			rawFixVer:  []string{"Introduced in 0 and fixed in 1.21.9", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantVuln:   true,
			wantFixVer: "v1.21.9",
		},
		{
			name:      "version above all ranges",
			version:   "v1.22.5",
			rawFixVer: []string{"Introduced in 0 and fixed in 1.21.9", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantVuln:  false,
		},
		{
			name:      "empty fix versions",
			version:   "v0.23.0",
			rawFixVer: nil,
			wantVuln:  false,
		},
		{name: "prerelease before final fix", version: "v1.2.0-rc.1", rawFixVer: []string{"v1.2.0"}, wantVuln: true, wantFixVer: "v1.2.0"},
		{name: "at prerelease fix", version: "v1.2.0-rc.2", rawFixVer: []string{"v1.2.0-rc.2"}},
		{name: "before prerelease introduction", version: "v1.2.0-beta.1", rawFixVer: []string{"Introduced in 1.2.0-rc.1 and fixed in 1.2.0"}},
		{name: "at prerelease introduction", version: "v1.2.0-rc.1", rawFixVer: []string{"Introduced in 1.2.0-rc.1 and fixed in 1.2.0"}, wantVuln: true, wantFixVer: "v1.2.0"},
		{name: "zero based pseudo version is included by introduced zero", version: "v0.0.0-20260101000000-abcdefabcdef", rawFixVer: []string{"Introduced in 0 and fixed in 1.0.0"}, wantVuln: true, wantFixVer: "v1.0.0"},
		{name: "zero based pseudo version in unfixed range", version: "v0.0.0-20260101000000-abcdefabcdef", rawFixVer: []string{"Introduced in 0 - "}, wantVuln: true},

		{name: "pseudo version before fix", version: "v1.0.1-0.20260101000000-abcdefabcdef", rawFixVer: []string{"v1.0.1-0.20260201000000-123456789abc"}, wantVuln: true, wantFixVer: "v1.0.1-0.20260201000000-123456789abc"},
		{name: "pseudo version at fix", version: "v1.0.1-0.20260201000000-123456789abc", rawFixVer: []string{"v1.0.1-0.20260201000000-123456789abc"}},
		{name: "open range before introduction", version: "v1.1.9", rawFixVer: []string{"Introduced in 1.2.0 - "}},
		{name: "open range at introduction", version: "v1.2.0", rawFixVer: []string{"Introduced in 1.2.0 - "}, wantVuln: true},
		{name: "open range after introduction", version: "v2.0.0", rawFixVer: []string{"Introduced in 1.2.0 - "}, wantVuln: true},

		{
			name:       "plain version format",
			version:    "v0.23.0",
			rawFixVer:  []string{"v0.33.0"},
			wantVuln:   true,
			wantFixVer: "v0.33.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVuln, gotFix := isVersionInVulnerableRange(tt.version, tt.rawFixVer)
			if gotVuln != tt.wantVuln {
				t.Errorf("vulnerable = %v, want %v", gotVuln, tt.wantVuln)
			}
			if gotFix != tt.wantFixVer {
				t.Errorf("fixVersion = %q, want %q", gotFix, tt.wantFixVer)
			}
		})
	}
}

func TestHasIntroducedInfo(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  bool
	}{
		{"with introduced info", []string{"Introduced in 0 and fixed in 1.21.8"}, true},
		{"plain version", []string{"v0.33.0"}, false},
		{"mixed", []string{"v0.33.0", "Introduced in 1.22.0 and fixed in 1.22.2"}, true},
		{"empty", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasIntroducedInfo(tt.input)
			if got != tt.want {
				t.Errorf("hasIntroducedInfo = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckDirVulnerability(t *testing.T) {
	tests := []struct {
		name               string
		curVer             string
		repVer             string
		used               bool
		unknown            bool
		isStdlib           bool
		goToolchainVersion string
		rawFixVer          []string
		wantDirVuln        bool
		wantStatus         string
		wantReplaceFix     bool
		wantFixVersion     string
	}{
		// --- Non-stdlib, symbol used ---
		{
			name:       "non-stdlib used, current below fix, no replace",
			curVer:     "v0.23.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantFixVersion: "v0.33.0",
		},
		{
			name:       "non-stdlib used, current equals fix, no replace",
			curVer:     "v0.33.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, current above fix, no replace",
			curVer:     "v0.34.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true, wantFixVersion: "v0.33.0",
		},
		{
			name:       "non-stdlib used, replace equals fix",
			curVer:     "v0.23.0",
			repVer:     "v0.33.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, replace above fix",
			curVer:     "v0.23.0",
			repVer:     "v0.34.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},

		// --- Non-stdlib, symbol not used ---
		{
			name:       "non-stdlib not used, current below fix",
			curVer:     "v0.23.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       false,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib not used, replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       false,
			wantStatus: "false", wantDirVuln: true, wantReplaceFix: true, wantFixVersion: "v0.33.0",
		},

		// --- Unknown reachability ---
		{
			name:       "unknown reachability",
			curVer:     "v0.23.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			unknown:    true,
			wantStatus: "unknown", wantDirVuln: true,
		},
		{
			name:       "unknown reachability with replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			unknown:    true,
			wantStatus: "unknown", wantDirVuln: true, wantReplaceFix: true, wantFixVersion: "v0.33.0",
		},

		// --- Stdlib, symbol used (multi-range) ---
		{
			name:               "stdlib used, toolchain below fix in first range",
			curVer:             "v1.21.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.21.4",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "true", wantDirVuln: true, wantFixVersion: "v1.21.8",
		},
		{
			name:               "stdlib used, toolchain at fix",
			curVer:             "v1.21.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.21.8",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},
		{
			name:               "stdlib used, toolchain in second range",
			curVer:             "v1.22.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.22.1",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "true", wantDirVuln: true, wantFixVersion: "v1.22.2",
		},
		{
			name:               "stdlib used, toolchain above all fixes",
			curVer:             "v1.21.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.22.5",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},
		{
			name:               "stdlib used, toolchain predates vulnerability (stdlib fallback)",
			curVer:             "v1.20.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.20.5",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "true", wantDirVuln: true,
		},
		{
			name:       "stdlib used, empty toolchain version",
			curVer:     "v1.21.0",
			used:       true,
			isStdlib:   true,
			rawFixVer:  []string{"Introduced in 0 and fixed in 1.21.8"},
			wantStatus: "unknown", wantDirVuln: true,
		},
		{
			name:       "stdlib used, no fix versions available",
			curVer:     "v1.21.0",
			used:       true,
			isStdlib:   true,
			wantStatus: "unknown", wantDirVuln: true,
		},
		{
			name:               "stdlib used, plain version format (implicit introduced=v0)",
			curVer:             "v1.20.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.20.5",
			rawFixVer:          []string{"1.21.8", "1.22.2"},
			wantStatus:         "true", wantDirVuln: true, wantFixVersion: "v1.21.8",
		},

		{
			name:               "stdlib used, toolchain above all fixes (fallback safe)",
			curVer:             "v1.22.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.25.0",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.9", "Introduced in 1.22.0-0 and fixed in 1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},

		{name: "open ended stdlib range", used: true, isStdlib: true, goToolchainVersion: "v1.23.0", rawFixVer: []string{"Introduced in 1.23.0 - "}, wantStatus: "true", wantDirVuln: true},
		{name: "stdlib before open ended introduction", used: true, isStdlib: true, goToolchainVersion: "v1.22.0", rawFixVer: []string{"Introduced in 1.23.0 - "}, wantStatus: "false"},

		// --- Real-world mod-dir scenarios ---
		{
			name:       "mod-dir root: require v0.23.0, replace v0.24.0, fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true, wantFixVersion: "v0.33.0",
		},
		{
			name:       "mod-dir bar: require v0.33.0, replace v0.24.0 (downgrade), fix v0.33.0",
			curVer:     "v0.33.0",
			repVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true, wantFixVersion: "v0.33.0",
		},
		{
			name:       "mod-dir foo: require v0.23.0, replace v0.33.0 (fixed), fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.33.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vr := checkDirVulnerability(tt.curVer, tt.repVer,
				tt.used, tt.unknown, tt.isStdlib, tt.goToolchainVersion, tt.rawFixVer)

			if vr.DirVulnerable != tt.wantDirVuln {
				t.Errorf("DirVulnerable = %v, want %v", vr.DirVulnerable, tt.wantDirVuln)
			}
			if vr.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", vr.Status, tt.wantStatus)
			}
			if vr.NeedsReplaceFix != tt.wantReplaceFix {
				t.Errorf("NeedsReplaceFix = %v, want %v", vr.NeedsReplaceFix, tt.wantReplaceFix)
			}
			if tt.wantFixVersion != "" && vr.FixVersion != tt.wantFixVersion {
				t.Errorf("FixVersion = %q, want %q", vr.FixVersion, tt.wantFixVersion)
			}
		})
	}
}

func TestExtractGoVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"go1.21.4", "v1.21.4"},
		{"1.21.4", "v1.21.4"},
		{"v1.21.4", "v1.21.4"},
		{"Introduced in 0 and fixed in 1.21.8", "v1.21.8"},
		{"Introduced in 0 and fixed in go1.22.2", "v1.22.2"},
		{"  go1.23.0  ", "v1.23.0"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractGoVersion(tt.input)
			if got != tt.want {
				t.Errorf("extractGoVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetMajorMinor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v1.23.8", "v1.23"},
		{"v1.21.0", "v1.21"},
		{"v2.0.0", "v2.0"},
		{"1.23.8", ""}, // missing v prefix
		{"v1", ""},     // too few parts
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := getMajorMinor(tt.input)
			if got != tt.want {
				t.Errorf("getMajorMinor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindAppropriateFixVersion(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		fixedVersions  []string
		want           string
	}{
		{
			name:           "same branch match",
			currentVersion: "v1.23.4",
			fixedVersions:  []string{"1.23.8", "1.24.2"},
			want:           "v1.23.8",
		},
		{
			name:           "different branch, nearest applicable",
			currentVersion: "v1.20.5",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "v1.21.8",
		},
		{
			name:           "already at fix version",
			currentVersion: "v1.23.8",
			fixedVersions:  []string{"1.23.8"},
			want:           "v1.23.8",
		},
		{
			name:           "empty current version",
			currentVersion: "",
			fixedVersions:  []string{"1.23.8"},
			want:           "",
		},
		{
			name:           "empty fix versions",
			currentVersion: "v1.23.4",
			fixedVersions:  nil,
			want:           "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findAppropriateFixVersion(tt.currentVersion, tt.fixedVersions)
			if got != tt.want {
				t.Errorf("findAppropriateFixVersion(%q, %v) = %q, want %q", tt.currentVersion, tt.fixedVersions, got, tt.want)
			}
		})
	}
}

func TestSelectFixVersionForCurrentGoVersion(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		fixedVersions  []string
		want           string
	}{
		{
			name:           "single fix version",
			currentVersion: "v1.21.4",
			fixedVersions:  []string{"1.21.8"},
			want:           "v1.21.8", // single version returns extractGoVersion result directly
		},
		{
			name:           "multiple fix versions, picks smallest greater",
			currentVersion: "v1.21.4",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "1.21.8",
		},
		{
			name:           "empty fix versions",
			currentVersion: "v1.21.4",
			fixedVersions:  nil,
			want:           "",
		},
		{
			name:           "current above all fixes",
			currentVersion: "v1.25.0",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "v1.22.2", // fallback returns extractGoVersion result directly
		},
		{
			name:           "empty current version",
			currentVersion: "",
			fixedVersions:  []string{"1.21.8", "1.22.2"},
			want:           "v1.21.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectFixVersionForCurrentGoVersion(tt.currentVersion, tt.fixedVersions)
			if got != tt.want {
				t.Errorf("selectFixVersionForCurrentGoVersion(%q, %v) = %q, want %q", tt.currentVersion, tt.fixedVersions, got, tt.want)
			}
		})
	}
}

func TestFormatIntroducedFixed(t *testing.T) {
	tests := []struct {
		name   string
		events []Event
		want   []string
	}{
		{
			name:   "empty",
			events: nil,
			want:   nil,
		},
		{
			name:   "single pair",
			events: []Event{{Introduced: "0"}, {Fixed: "1.21.8"}},
			want:   []string{"Introduced in 0 and fixed in 1.21.8"},
		},
		{
			name:   "introduced only",
			events: []Event{{Introduced: "0"}},
			want:   []string{"Introduced in 0 - "},
		},
		{
			name:   "multiple pairs",
			events: []Event{{Introduced: "0"}, {Fixed: "1.21.8"}, {Introduced: "1.22.0"}, {Fixed: "1.22.2"}},
			want:   []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatIntroducedFixed(tt.events)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d results, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("result[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMatchesSymbol_NilFunc(t *testing.T) {
	node := &callgraph.Node{Func: nil}
	if matchesSymbol(node, "pkg", "sym") {
		t.Error("expected false for nil Func")
	}
}

func TestIsRepoPackage(t *testing.T) {
	tests := []struct {
		pkgPath        string
		repoModulePath string
		want           bool
	}{
		{"github.com/foo/bar/pkg", "github.com/foo/bar", true},
		{"github.com/foo/bar", "github.com/foo/bar", true},
		{"github.com/other/pkg", "github.com/foo/bar", false},
		{"command-line-arguments", "github.com/foo/bar", true},
		{"golang.org/x/net/html", "github.com/foo/bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.pkgPath, func(t *testing.T) {
			got := isRepoPackage(tt.pkgPath, tt.repoModulePath)
			if got != tt.want {
				t.Errorf("isRepoPackage(%q, %q) = %v, want %v", tt.pkgPath, tt.repoModulePath, got, tt.want)
			}
		})
	}
}

func TestExtractEntryPoints(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "with main functions",
			input: "command-line-arguments.main command-line-arguments.init\ncommand-line-arguments.main pkg.Foo\n",
			want:  1,
		},
		{
			name:  "no main functions",
			input: "pkg.Foo pkg.Bar\n",
			want:  0,
		},
		{
			name:  "empty",
			input: "",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEntryPoints(tt.input)
			if len(got) != tt.want {
				t.Errorf("extractEntryPoints() returned %d entries, want %d: %v", len(got), tt.want, got)
			}
		})
	}
}

func TestReconstructPath(t *testing.T) {
	node1 := &callgraph.Node{ID: 1}
	node2 := &callgraph.Node{ID: 2}
	node3 := &callgraph.Node{ID: 3}

	parent := map[*callgraph.Node]*callgraph.Node{
		node1: nil,
		node2: node1,
		node3: node2,
	}

	path := reconstructPath(node3, parent)
	if len(path) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(path))
	}
	if path[0] != node1 || path[1] != node2 || path[2] != node3 {
		t.Error("path order is wrong")
	}
}

func TestGetCallGraphAlgorithm(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		setEnv bool
		want   string
	}{
		{"default", "", false, "rta"},
		{"vta", "VTA", true, "vta"},
		{"cha", "cha", true, "cha"},
		{"static", "STATIC", true, "static"},
		{"empty string", "", true, "rta"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("ALGO", tt.envVal)
			} else {
				os.Unsetenv("ALGO")
			}
			got := getCallGraphAlgorithm()
			if got != tt.want {
				t.Errorf("getCallGraphAlgorithm() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAnalyzeASTForPackages(t *testing.T) {
	tests := []struct {
		name        string
		src         string
		wantUnsafe  bool
		wantReflect bool
	}{
		{
			name:        "no imports",
			src:         `package main`,
			wantUnsafe:  false,
			wantReflect: false,
		},
		{
			name:        "unsafe import with usage",
			src:         `package main; import "unsafe"; var _ = unsafe.Sizeof(0)`,
			wantUnsafe:  true,
			wantReflect: false,
		},
		{
			name:        "reflect import with usage",
			src:         `package main; import "reflect"; var _ = reflect.TypeOf(0)`,
			wantUnsafe:  false,
			wantReflect: true,
		},
		{
			name:        "both imports",
			src:         `package main; import "unsafe"; import "reflect"; var _ = unsafe.Sizeof(0); var _ = reflect.TypeOf(0)`,
			wantUnsafe:  true,
			wantReflect: true,
		},
		{
			name:        "fmt import only",
			src:         `package main; import "fmt"; var _ = fmt.Println`,
			wantUnsafe:  false,
			wantReflect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, "test.go", tt.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			gotUnsafe, gotReflect := analyzeASTForPackages(node)
			if gotUnsafe != tt.wantUnsafe {
				t.Errorf("unsafe = %v, want %v", gotUnsafe, tt.wantUnsafe)
			}
			if gotReflect != tt.wantReflect {
				t.Errorf("reflect = %v, want %v", gotReflect, tt.wantReflect)
			}
		})
	}
}

func TestGetCurrentVersion_NonStdlib(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\ngo 1.22\nrequire golang.org/x/net v0.23.0\n"), 0644)

	r := &Result{}
	got := getCurrentVersion("golang.org/x/net", dir, ".", r)
	if got != "v0.23.0" {
		t.Errorf("getCurrentVersion = %q, want %q", got, "v0.23.0")
	}
}

func TestGetCurrentVersion_Stdlib(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\ngo 1.21.4\n"), 0644)

	r := &Result{
		ScanConfig: ScanConfig{Directory: dir},
		AffectedImports: map[string]AffectedImportsDetails{
			"net/http": {Type: "stdlib"},
		},
		GoToolchainVersions: map[string]string{
			".": "v1.21.4",
		},
	}
	got := getCurrentVersion("net/http", dir, ".", r)
	if got != "v1.21.4" {
		t.Errorf("getCurrentVersion = %q, want %q", got, "v1.21.4")
	}
}

func TestGetCurrentVersion_NotFound(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\ngo 1.22\n"), 0644)

	r := &Result{}
	got := getCurrentVersion("golang.org/x/net", dir, ".", r)
	if got != "" {
		t.Errorf("getCurrentVersion = %q, want empty", got)
	}
}

// --- getGoToolchainVersion tests ---

func TestGetGoToolchainVersion(t *testing.T) {
	tests := []struct {
		name    string
		gomod   string
		want    string
		wantErr bool
	}{
		{
			name:  "normal",
			gomod: "module example.com/foo\ngo 1.21.4\n",
			want:  "v1.21.4",
		},
		{
			name:  "with v prefix",
			gomod: "module example.com/foo\ngo 1.22.0\n",
			want:  "v1.22.0",
		},
		{
			name:  "no go directive",
			gomod: "module example.com/foo\n",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "go.mod"), []byte(tt.gomod), 0644)

			r := &Result{}
			got := getGoToolchainVersion(dir, r)
			if got != tt.want {
				t.Errorf("getGoToolchainVersion = %q, want %q", got, tt.want)
			}
			if tt.wantErr && len(r.Errors) == 0 {
				t.Error("expected errors")
			}
		})
	}
}

func TestGetGoToolchainVersion_CmdError(t *testing.T) {
	r := &Result{}
	got := getGoToolchainVersion("/nonexistent/dir", r)
	if got != "" {
		t.Errorf("getGoToolchainVersion = %q, want empty", got)
	}
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

// --- getReplaceVersion tests ---

func TestGetReplaceVersion(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/test
go 1.21

require golang.org/x/net v0.23.0

replace golang.org/x/net v0.23.0 => golang.org/x/net v0.33.0
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	r := &Result{}
	path, ver := getReplaceVersion("golang.org/x/net", dir, r)
	if path != "golang.org/x/net" || ver != "v0.33.0" {
		t.Errorf("getReplaceVersion = (%q, %q), want (%q, %q)", path, ver, "golang.org/x/net", "v0.33.0")
	}
}

func TestGetReplaceVersion_NoMatch(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/test
go 1.21

replace other/pkg => other/pkg v1.0.0
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	r := &Result{}
	path, ver := getReplaceVersion("golang.org/x/net", dir, r)
	if path != "" || ver != "" {
		t.Errorf("getReplaceVersion = (%q, %q), want empty", path, ver)
	}
}

func TestGetReplaceVersion_CmdError(t *testing.T) {
	r := &Result{}
	path, ver := getReplaceVersion("golang.org/x/net", "/nonexistent/dir", r)
	if path != "" || ver != "" {
		t.Errorf("getReplaceVersion = (%q, %q), want empty", path, ver)
	}
}

// --- getModPath tests ---

func TestGetModPath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\ngo 1.22\nrequire golang.org/x/net v0.23.0\n"), 0644)

	r := &Result{}
	got := getModPath("golang.org/x/net/html", dir, r)
	if got != "golang.org/x/net" {
		t.Errorf("getModPath = %q, want %q", got, "golang.org/x/net")
	}
}

func TestGetModPath_NotFound(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/foo\ngo 1.22\n"), 0644)

	r := &Result{}
	got := getModPath("golang.org/x/net", dir, r)
	if got != "" {
		t.Errorf("getModPath = %q, want empty", got)
	}
}

// --- checkIgnoredFiles tests ---

func TestCheckIgnoredFiles(t *testing.T) {
	dir := t.TempDir()

	// File that imports the vulnerable package
	vulnFile := filepath.Join(dir, "constrained.go")
	os.WriteFile(vulnFile, []byte("//go:build linux\n\npackage main\n\nimport \"golang.org/x/net/html\"\n\nvar _ = html.Parse\n"), 0644)

	// File that imports something else
	safeFile := filepath.Join(dir, "safe.go")
	os.WriteFile(safeFile, []byte("//go:build windows\n\npackage main\n\nimport \"fmt\"\n\nvar _ = fmt.Println\n"), 0644)

	pkgs := []*packages.Package{
		{IgnoredFiles: []string{vulnFile, safeFile}},
	}

	warnings := checkIgnoredFiles(pkgs, "golang.org/x/net/html")
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "constrained.go") {
		t.Errorf("warning should mention constrained.go: %s", warnings[0])
	}
	if !strings.Contains(warnings[0], "Need manual analysis") {
		t.Errorf("warning should say 'Need manual analysis': %s", warnings[0])
	}
}

func TestCheckIgnoredFiles_NoMatch(t *testing.T) {
	dir := t.TempDir()

	safeFile := filepath.Join(dir, "safe.go")
	os.WriteFile(safeFile, []byte("package main\n\nimport \"fmt\"\n\nvar _ = fmt.Println\n"), 0644)

	pkgs := []*packages.Package{
		{IgnoredFiles: []string{safeFile}},
	}

	warnings := checkIgnoredFiles(pkgs, "golang.org/x/net/html")
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d: %v", len(warnings), warnings)
	}
}

// --- getRepoModulePath tests ---

func TestGetRepoModulePath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/foo/bar\ngo 1.21\n"), 0644)

	r := &Result{}
	got := getRepoModulePath(dir, r)
	if got != "github.com/foo/bar" {
		t.Errorf("getRepoModulePath = %q, want %q", got, "github.com/foo/bar")
	}
}

func TestGetRepoModulePath_Error(t *testing.T) {
	r := &Result{}
	got := getRepoModulePath("/nonexistent/dir", r)
	if got != "" {
		t.Errorf("getRepoModulePath = %q, want empty", got)
	}
}

// --- isModuleInGoMod tests ---

func TestIsModuleInGoMod(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module github.com/foo/bar

go 1.22.0

require (
	golang.org/x/net v0.23.0
	golang.org/x/crypto v0.23.0
)

require golang.org/x/sys v0.20.0 // indirect
`), 0644)

	tests := []struct {
		pkg  string
		want bool
	}{
		{"golang.org/x/net/html", true},
		{"golang.org/x/net", true},
		{"golang.org/x/crypto/ssh", true},
		{"golang.org/x/sys", true},
		{"golang.org/x/text", false},
		{"net/http", false},
		{"github.com/other/pkg", false},
	}
	r := &Result{}
	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			if got := r.isModuleInGoMod(tt.pkg, dir); got != tt.want {
				t.Errorf("isModuleInGoMod(%q) = %v, want %v", tt.pkg, got, tt.want)
			}
		})
	}
}

func TestIsModuleInGoMod_NoGoMod(t *testing.T) {
	r := &Result{}
	if r.isModuleInGoMod("golang.org/x/net", "/nonexistent/dir") {
		t.Error("expected false for missing go.mod")
	}
}

// --- isModuleInGoModOrSum tests ---

func TestIsModuleInGoModOrSum(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module github.com/foo/bar

go 1.22.0

require golang.org/x/net v0.23.0
`), 0644)
	os.WriteFile(filepath.Join(dir, "go.sum"), []byte(`golang.org/x/net v0.23.0 h1:abc=
golang.org/x/net v0.23.0/go.mod h1:def=
golang.org/x/crypto v0.17.0 h1:ghi=
golang.org/x/crypto v0.17.0/go.mod h1:jkl=
`), 0644)

	tests := []struct {
		pkg  string
		want bool
	}{
		{"golang.org/x/net/html", true},
		{"golang.org/x/net", true},
		{"golang.org/x/crypto/ssh", true},
		{"golang.org/x/crypto", true},
		{"golang.org/x/text", false},
		{"github.com/other/pkg", false},
	}
	r := &Result{}
	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			if got := r.isModuleInGoModOrSum(tt.pkg, dir); got != tt.want {
				t.Errorf("isModuleInGoModOrSum(%q) = %v, want %v", tt.pkg, got, tt.want)
			}
		})
	}
}

func TestIsModuleInGoModOrSum_NoGoSum(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module github.com/foo/bar

go 1.22.0

require golang.org/x/net v0.23.0
`), 0644)

	r := &Result{}
	if !r.isModuleInGoModOrSum("golang.org/x/net", dir) {
		t.Error("expected true for module in go.mod even without go.sum")
	}
	if r.isModuleInGoModOrSum("golang.org/x/crypto", dir) {
		t.Error("expected false for module not in go.mod and no go.sum")
	}
}

// --- getGitBranch tests ---

func TestGetGitBranch(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git rev-parse --abbrev-ref HEAD"] = []byte("main\n")

	r := &Result{ScanConfig: ScanConfig{Runner: fr, Directory: "/repo"}}
	getGitBranch(r)
	if r.Branch != "main" {
		t.Errorf("Branch = %q, want %q", r.Branch, "main")
	}
}

func TestGetGitBranch_DetachedHEAD(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git rev-parse --abbrev-ref HEAD"] = []byte("HEAD\n")
	fr.stdout["git rev-parse HEAD"] = []byte("abc123def456\n")

	r := &Result{ScanConfig: ScanConfig{Runner: fr, Directory: "/repo"}}
	getGitBranch(r)
	if r.Branch != "abc123def456" {
		t.Errorf("Branch = %q, want %q", r.Branch, "abc123def456")
	}
}

func TestGetGitBranch_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.err["git rev-parse --abbrev-ref HEAD"] = fmt.Errorf("exit 1")

	r := &Result{ScanConfig: ScanConfig{Runner: fr, Directory: "/repo"}}
	getGitBranch(r)
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

func TestGetGitBranch_DetachedHEAD_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git rev-parse --abbrev-ref HEAD"] = []byte("HEAD\n")
	fr.err["git rev-parse HEAD"] = fmt.Errorf("exit 1")

	r := &Result{ScanConfig: ScanConfig{Runner: fr, Directory: "/repo"}}
	getGitBranch(r)
	if r.Branch != "HEAD" {
		t.Errorf("Branch = %q, want %q", r.Branch, "HEAD")
	}
}

// --- getGitURL tests ---

func TestGetGitURL(t *testing.T) {
	fr := newFakeRunner()
	fr.stdout["git remote get-url origin"] = []byte("https://github.com/foo/bar.git\n")

	r := &Result{ScanConfig: ScanConfig{Runner: fr, Directory: "/repo"}}
	getGitURL(r)
	if r.Repository != "https://github.com/foo/bar.git" {
		t.Errorf("Repository = %q, want %q", r.Repository, "https://github.com/foo/bar.git")
	}
}

func TestGetGitURL_Error(t *testing.T) {
	fr := newFakeRunner()
	fr.err["git remote get-url origin"] = fmt.Errorf("exit 1")

	r := &Result{ScanConfig: ScanConfig{Runner: fr, Directory: "/repo"}}
	getGitURL(r)
	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

// --- findMainGoFiles tests ---

func TestFindMainGoFiles(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0644)

	os.MkdirAll(filepath.Join(tmpDir, "cmd", "app"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "cmd", "app", "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	// Library package should not be found
	os.MkdirAll(filepath.Join(tmpDir, "pkg", "lib"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "pkg", "lib", "lib.go"), []byte("package lib\nfunc Hello() {}\n"), 0644)

	r := &Result{ScanConfig: ScanConfig{Directory: tmpDir}}
	findMainGoFiles(r)

	if r.Files == nil {
		t.Fatal("Files is nil")
	}
	if len(r.Errors) > 0 {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
	sets, ok := r.Files["."]
	if !ok {
		t.Fatal("Files missing root module entry '.'")
	}
	if len(sets) != 1 {
		t.Fatalf("expected 1 file set, got %d", len(sets))
	}
	if len(sets[0]) != 1 || sets[0][0] != filepath.Join("cmd", "app", "main.go") {
		t.Errorf("expected [cmd/app/main.go], got %v", sets[0])
	}
}

func TestFindMainGoFiles_MultipleAndConstrained(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0644)

	// Two separate main packages
	os.MkdirAll(filepath.Join(tmpDir, "cmd", "server"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "cmd", "server", "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	os.MkdirAll(filepath.Join(tmpDir, "cmd", "cli"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "cmd", "cli", "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	// Build-constrained main file should also be found
	os.WriteFile(filepath.Join(tmpDir, "cmd", "cli", "windows.go"), []byte("//go:build windows\n\npackage main\n\nfunc init() {}\n"), 0644)

	r := &Result{ScanConfig: ScanConfig{Directory: tmpDir}}
	findMainGoFiles(r)

	sets, ok := r.Files["."]
	if !ok {
		t.Fatal("Files missing root module entry '.'")
	}
	if len(sets) != 2 {
		t.Fatalf("expected 2 file sets, got %d: %v", len(sets), sets)
	}

	// Verify constrained file is included (not filtered out)
	foundConstrainedFile := false
	for _, set := range sets {
		for _, f := range set {
			if strings.Contains(f, "windows.go") {
				foundConstrainedFile = true
			}
		}
	}
	if !foundConstrainedFile {
		t.Error("build-constrained file windows.go should be included")
	}
}

func TestFindMainGoFiles_NoGoMod(t *testing.T) {
	tmpDir := t.TempDir()

	r := &Result{ScanConfig: ScanConfig{Directory: tmpDir}}
	findMainGoFiles(r)

	if len(r.Files) != 0 {
		t.Errorf("expected empty Files for dir without go.mod, got %d entries", len(r.Files))
	}
}

// --- HTTP function tests ---

func TestFetchGoVulnID(t *testing.T) {
	vulns := []VulnReport{
		{ID: "GO-2024-3333", Aliases: []string{"CVE-2024-45338"}},
		{ID: "GO-2024-1111", Aliases: []string{"CVE-2024-11111"}},
	}
	body, _ := json.Marshal(vulns)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		ScanConfig: ScanConfig{CVE: "CVE-2024-45338", HTTP: ts.Client()},
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchGoVulnID(r)
	if r.GoCVE != "GO-2024-3333" {
		t.Errorf("GoCVE = %q, want %q", r.GoCVE, "GO-2024-3333")
	}
}

func TestFetchGoVulnID_NoMatch(t *testing.T) {
	vulns := []VulnReport{
		{ID: "GO-2024-1111", Aliases: []string{"CVE-2024-11111"}},
	}
	body, _ := json.Marshal(vulns)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		ScanConfig: ScanConfig{CVE: "CVE-2024-99999", HTTP: ts.Client()},
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchGoVulnID(r)
	if r.GoCVE != "" {
		t.Errorf("GoCVE = %q, want empty", r.GoCVE)
	}
}

func TestFetchAffectedSymbols(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "golang.org/x/net", Ecosystem: "Go"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "0.33.0"}}},
				},
				EcosystemSpecific: EcosystemSpecific{
					Imports: []Import{
						{Path: "golang.org/x/net/html", Symbols: []string{"Parse", "ParseFragment"}},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		ScanConfig: ScanConfig{HTTP: ts.Client()},
		GoCVE:      "GO-2024-3333",
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchAffectedSymbols(r)
	if r.AffectedImports == nil {
		t.Fatal("AffectedImports is nil")
	}
	entry, ok := r.AffectedImports["golang.org/x/net/html"]
	if !ok {
		t.Fatal("expected golang.org/x/net/html in AffectedImports")
	}
	if len(entry.Symbols) != 2 {
		t.Errorf("expected 2 symbols, got %d", len(entry.Symbols))
	}
}

func TestFetchAffectedSymbols_EmptyAffected(t *testing.T) {
	report := VulnReport{ID: "GO-2024-3333"}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		ScanConfig: ScanConfig{HTTP: ts.Client()},
		GoCVE:      "GO-2024-3333",
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchAffectedSymbols(r)
	if len(r.Errors) == 0 {
		t.Error("expected error for empty affected list")
	}
}

func TestFetchAffectedSymbols_NoSymbols(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package:           Package{Name: "golang.org/x/net"},
				EcosystemSpecific: EcosystemSpecific{Imports: []Import{{Path: "golang.org/x/net/html"}}},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{
		ScanConfig: ScanConfig{HTTP: ts.Client()},
		GoCVE:      "GO-2024-3333",
	}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	fetchAffectedSymbols(r)
	if len(r.Errors) == 0 {
		t.Error("expected error when no symbols found")
	}
}

func TestGetFixedVersion(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "golang.org/x/net"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "0.33.0"}}},
				},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{ScanConfig: ScanConfig{HTTP: ts.Client()}}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	got := getFixedVersion("GO-2024-3333", "golang.org/x/net", r)
	if len(got) != 1 {
		t.Fatalf("expected 1 version, got %d", len(got))
	}
	if got[0] != "Introduced in 0 and fixed in 0.33.0" {
		t.Errorf("got %q", got[0])
	}
}

func TestGetFixedVersion_Stdlib(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "stdlib"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "1.21.8"}, {Introduced: "1.22.0"}, {Fixed: "1.22.2"}}},
				},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{ScanConfig: ScanConfig{HTTP: ts.Client()}}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	got := getFixedVersion("GO-2024-3333", "net/http", r)
	if len(got) != 2 {
		t.Fatalf("expected 2 versions, got %d: %v", len(got), got)
	}
}

func TestGetFixedVersion_NoMatch(t *testing.T) {
	report := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "other/pkg"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "1.0.0"}}}},
			},
		},
	}
	body, _ := json.Marshal(report)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	r := &Result{ScanConfig: ScanConfig{HTTP: ts.Client()}}

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	got := getFixedVersion("GO-2024-3333", "golang.org/x/net", r)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// --- SetupLibraryMode / SetupCVEMode / Prepare tests ---

func TestSetupCVEMode_InvalidFormat(t *testing.T) {
	r := &Result{ScanConfig: ScanConfig{CVE: "not-a-cve", Directory: t.TempDir()}, IsVulnerable: "unknown"}
	done := SetupCVEMode(r)
	if !done {
		t.Error("expected done=true for invalid CVE format")
	}
	if len(r.Errors) == 0 {
		t.Error("expected errors for invalid CVE format")
	}
}

func TestSetupLibraryMode_MissingFields(t *testing.T) {
	r := &Result{ScanConfig: ScanConfig{Directory: t.TempDir()}, IsVulnerable: "unknown"}
	done := SetupLibraryMode(r, "golang.org/x/net", "", "")
	if !done {
		t.Error("expected done=true for missing library mode fields")
	}
	if len(r.Errors) == 0 || r.Errors[0] != "When using library mode, all three flags are required: -library, -symbols, and -fixversion" {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}

func TestSetupLibraryMode_Whitespace(t *testing.T) {
	r := &Result{ScanConfig: ScanConfig{Directory: t.TempDir()}, IsVulnerable: "unknown"}
	done := SetupLibraryMode(r, "  ", "Parse", "v0.33.0")
	if !done {
		t.Error("expected done=true for whitespace library")
	}
	if len(r.Errors) == 0 || r.Errors[0] != "Library mode parameters cannot be empty or whitespace only" {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}

func TestSetupLibraryMode_EmptySymbols(t *testing.T) {
	r := &Result{ScanConfig: ScanConfig{Directory: t.TempDir()}, IsVulnerable: "unknown"}
	done := SetupLibraryMode(r, "golang.org/x/net", " , , ", "v0.33.0")
	if !done {
		t.Error("expected done=true for all-empty symbols")
	}
	if len(r.Errors) == 0 || r.Errors[0] != "At least one non-empty symbol is required" {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}

func TestSetupLibraryMode_Valid(t *testing.T) {
	r := &Result{ScanConfig: ScanConfig{Directory: t.TempDir()}, IsVulnerable: "unknown"}
	done := SetupLibraryMode(r, "golang.org/x/net/html", "Parse,ParseFragment", "v0.33.0")
	if done {
		t.Errorf("expected done=false for valid library mode, errors: %v", r.Errors)
	}
	if r.GoCVE != "MANUAL-SCAN" {
		t.Errorf("GoCVE = %q, want %q", r.GoCVE, "MANUAL-SCAN")
	}
	if _, ok := r.AffectedImports["golang.org/x/net/html"]; !ok {
		t.Error("expected golang.org/x/net/html in AffectedImports")
	}
	if len(r.AffectedImports["golang.org/x/net/html"].Symbols) != 2 {
		t.Errorf("expected 2 symbols, got %d", len(r.AffectedImports["golang.org/x/net/html"].Symbols))
	}
}

func TestSetupLibraryMode_Stdlib(t *testing.T) {
	r := &Result{ScanConfig: ScanConfig{Directory: t.TempDir()}, IsVulnerable: "unknown"}
	SetupLibraryMode(r, "net/http", "Get", "1.21.8")
	entry, ok := r.AffectedImports["net/http"]
	if !ok {
		t.Fatal("expected net/http in AffectedImports")
	}
	if entry.Type != "stdlib" {
		t.Errorf("Type = %q, want %q", entry.Type, "stdlib")
	}
}

func TestSetupCVEMode_GoCVEDirect(t *testing.T) {
	vulnReport := VulnReport{
		ID: "GO-2024-3333",
		Affected: []Affected{
			{
				Package: Package{Name: "golang.org/x/net"},
				EcosystemSpecific: EcosystemSpecific{
					Imports: []Import{
						{Path: "golang.org/x/net/html", Symbols: []string{"Parse"}},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(vulnReport)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	origURL := VulnsURL
	defer func() { VulnsURL = origURL }()
	VulnsURL = ts.URL

	r := &Result{ScanConfig: ScanConfig{CVE: "GO-2024-3333", Directory: t.TempDir()}, IsVulnerable: "unknown"}
	done := SetupCVEMode(r)
	if done {
		t.Errorf("expected done=false, errors: %v", r.Errors)
	}
	if r.GoCVE != "GO-2024-3333" {
		t.Errorf("GoCVE = %q, want %q", r.GoCVE, "GO-2024-3333")
	}
}

func TestPrepare_NoAffectedImports(t *testing.T) {
	r := &Result{IsVulnerable: "unknown"}
	done := Prepare(r)
	if !done {
		t.Error("expected done=true when no affected imports")
	}
	if r.IsVulnerable != "unknown" {
		t.Errorf("IsVulnerable = %q, want %q", r.IsVulnerable, "unknown")
	}
}

// --- DetectUnsafeReflectUsage tests ---

func TestDetectUnsafeReflectUsage_UnsafeOnly(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "unsafe"
var _ = unsafe.Sizeof(0)
func main() {}
`), 0644)

	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	DetectUnsafeReflectUsage(r, nil)

	if !r.Unsafe {
		t.Error("expected Unsafe=true")
	}
	if r.Reflect {
		t.Error("expected Reflect=false")
	}
}

func TestDetectUnsafeReflectUsage_ReflectOnly(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "reflect"
var _ = reflect.TypeOf(0)
func main() {}
`), 0644)

	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	DetectUnsafeReflectUsage(r, nil)

	if r.Unsafe {
		t.Error("expected Unsafe=false")
	}
	if !r.Reflect {
		t.Error("expected Reflect=true")
	}
}

func TestDetectUnsafeReflectUsage_Both(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte(`package main
import "unsafe"
var _ = unsafe.Sizeof(0)
`), 0644)
	os.WriteFile(filepath.Join(dir, "b.go"), []byte(`package main
import "reflect"
var _ = reflect.TypeOf(0)
`), 0644)

	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	DetectUnsafeReflectUsage(r, nil)

	if !r.Unsafe {
		t.Error("expected Unsafe=true")
	}
	if !r.Reflect {
		t.Error("expected Reflect=true")
	}
}

func TestDetectUnsafeReflectUsage_Neither(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "fmt"
func main() { fmt.Println("hello") }
`), 0644)

	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	DetectUnsafeReflectUsage(r, nil)

	if r.Unsafe {
		t.Error("expected Unsafe=false")
	}
	if r.Reflect {
		t.Error("expected Reflect=false")
	}
}

func TestDetectUnsafeReflectUsage_SkipsVendorAndTests(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vendor", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "vendor", "pkg", "v.go"), []byte(`package pkg
import "unsafe"
var _ = unsafe.Sizeof(0)
`), 0644)
	os.WriteFile(filepath.Join(dir, "main_test.go"), []byte(`package main
import "reflect"
var _ = reflect.TypeOf(0)
`), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
func main() {}
`), 0644)

	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	DetectUnsafeReflectUsage(r, nil)

	if r.Unsafe {
		t.Error("expected Unsafe=false (vendor should be skipped)")
	}
	if r.Reflect {
		t.Error("expected Reflect=false (test files should be skipped)")
	}
}

func TestDetectUnsafeReflectUsage_WithProgress(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "unsafe"
var _ = unsafe.Sizeof(0)
func main() {}
`), 0644)

	var messages []string
	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	DetectUnsafeReflectUsage(r, func(msg string) {
		messages = append(messages, msg)
	})

	if !r.Unsafe {
		t.Error("expected Unsafe=true")
	}
	if len(messages) == 0 {
		t.Error("expected progress messages")
	}
}

// Call graph integration tests using testdata fixtures

func TestGenerateCallGraphWithLibInternal_Simple(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}
	t.Setenv("ALGO", "rta")

	output, prog, cg, _, err := r.generateCallGraphWithLibInternal(dir, nil)
	if err != nil {
		t.Fatalf("generateCallGraphWithLibInternal failed: %v", err)
	}
	if output == "" {
		t.Error("expected non-empty call graph output")
	}
	if prog == nil {
		t.Error("expected non-nil SSA program")
	}
	if cg == nil {
		t.Error("expected non-nil call graph")
	}
}

func TestGenerateCallGraphObject_Simple(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}
	t.Setenv("ALGO", "static")

	graph, err := r.GenerateCallGraphObject(dir, nil)
	if err != nil {
		t.Fatalf("GenerateCallGraphObject failed: %v", err)
	}
	if graph == nil {
		t.Fatal("expected non-nil call graph")
	}
	if len(graph.Nodes) == 0 {
		t.Error("expected call graph nodes")
	}
}

func TestBuildCallGraph_AllAlgorithms(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}

	for _, algo := range []string{"vta", "rta", "cha", "static"} {
		t.Run(algo, func(t *testing.T) {
			t.Setenv("ALGO", algo)
			_, _, cg, _, err := r.generateCallGraphWithLibInternal(dir, nil)
			if err != nil {
				t.Fatalf("failed with algo %s: %v", algo, err)
			}
			if cg == nil {
				t.Errorf("expected non-nil call graph for algo %s", algo)
			}
		})
	}
}

func TestFindPathToSymbol_Found(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}
	t.Setenv("ALGO", "rta")

	_, _, graph, _, err := r.generateCallGraphWithLibInternal(dir, nil)
	if err != nil {
		t.Fatalf("failed to generate call graph: %v", err)
	}

	// Find an entry node (main function)
	var mainNode *callgraph.Node
	for _, node := range graph.Nodes {
		if node.Func != nil && node.Func.Name() == "main" && node.Func.Pkg != nil && node.Func.Pkg.Pkg.Name() == "main" {
			mainNode = node
			break
		}
	}
	if mainNode == nil {
		t.Fatal("could not find main node in call graph")
	}

	// Search for "helper" which is called from main
	path, found := findPathToSymbol(mainNode, "example.com/simple", "helper", false)
	if !found {
		t.Error("expected to find path to helper()")
	}
	if len(path) < 2 {
		t.Errorf("expected path with at least 2 nodes, got %d", len(path))
	}
}

func TestFindPathToSymbol_NotFound(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}
	t.Setenv("ALGO", "rta")

	_, _, graph, _, err := r.generateCallGraphWithLibInternal(dir, nil)
	if err != nil {
		t.Fatalf("failed to generate call graph: %v", err)
	}

	var mainNode *callgraph.Node
	for _, node := range graph.Nodes {
		if node.Func != nil && node.Func.Name() == "main" && node.Func.Pkg != nil && node.Func.Pkg.Pkg.Name() == "main" {
			mainNode = node
			break
		}
	}
	if mainNode == nil {
		t.Fatal("could not find main node in call graph")
	}

	_, found := findPathToSymbol(mainNode, "example.com/simple", "nonexistent", false)
	if found {
		t.Error("expected not to find nonexistent symbol")
	}
}

func TestCheckDirectUsage_Found(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	t.Setenv("ALGO", "rta")

	result := r.checkDirectUsage("fmt", dir, ".", []string{"fmt.Println"}, nil)
	if result != "true" {
		t.Errorf("expected 'true' for fmt.Println usage, got %q", result)
	}
}

func TestCheckDirectUsage_NotFound(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	t.Setenv("ALGO", "rta")

	result := r.checkDirectUsage("crypto/tls", dir, ".", []string{"crypto/tls.Dial"}, nil)
	if result == "true" {
		t.Error("expected non-true for unused symbol")
	}
}

func TestGenerateCallGraphWithLibInternal_NoMain(t *testing.T) {
	dir := filepath.Join("testdata", "libonly")
	r := &Result{}
	t.Setenv("ALGO", "rta")

	_, _, cg, _, err := r.generateCallGraphWithLibInternal(dir, nil)
	if err != nil {
		t.Fatalf("expected no error for lib-only, got: %v", err)
	}
	if cg == nil {
		t.Error("expected non-nil call graph even for lib-only")
	}
}

func TestMatchesSymbol_WithSSA(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}
	t.Setenv("ALGO", "static")

	_, _, graph, _, err := r.generateCallGraphWithLibInternal(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Find the helper node
	var helperNode *callgraph.Node
	for _, node := range graph.Nodes {
		if node.Func != nil && node.Func.Name() == "helper" {
			helperNode = node
			break
		}
	}
	if helperNode == nil {
		t.Fatal("could not find helper node")
	}

	if !matchesSymbol(helperNode, "example.com/simple", "helper") {
		t.Error("expected matchesSymbol to match helper")
	}
	if matchesSymbol(helperNode, "other/pkg", "helper") {
		t.Error("expected matchesSymbol to not match wrong package")
	}
}

func TestSetupLibraryMode_WithProgressFunc(t *testing.T) {
	var messages []string
	r := &Result{
		ScanConfig: ScanConfig{
			CVE:       "GO-2024-0001",
			Directory: "testdata/simple",
			ProgressFunc: func(msg string) {
				messages = append(messages, msg)
			},
		},
		IsVulnerable: "unknown",
	}
	SetupLibraryMode(r, "fmt", "Println", "v1.22.0")
	if len(messages) == 0 {
		t.Error("expected progress messages to be emitted")
	}
}

func TestGenerateCallGraphForVisualization(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}
	t.Setenv("ALGO", "static")

	output, err := r.GenerateCallGraphForVisualization(dir, nil)
	if err != nil {
		t.Fatalf("GenerateCallGraphForVisualization failed: %v", err)
	}
	if output == "" {
		t.Error("expected non-empty output")
	}
}

func TestFindPathToSymbolExported(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{}
	t.Setenv("ALGO", "rta")

	_, _, graph, _, err := r.generateCallGraphWithLibInternal(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	var mainNode *callgraph.Node
	for _, node := range graph.Nodes {
		if node.Func != nil && node.Func.Name() == "main" && node.Func.Pkg != nil && node.Func.Pkg.Pkg.Name() == "main" {
			mainNode = node
			break
		}
	}
	if mainNode == nil {
		t.Fatal("could not find main node")
	}

	path, found := FindPathToSymbolExported(mainNode, "example.com/simple", "helper", false)
	if !found {
		t.Error("expected to find path via exported wrapper")
	}
	if len(path) < 2 {
		t.Errorf("expected path with at least 2 nodes, got %d", len(path))
	}
}

func TestIsSymbolUsed(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{ScanConfig: ScanConfig{Directory: dir}}
	t.Setenv("ALGO", "rta")

	result := r.isSymbolUsed("fmt", dir, ".", []string{"Println"}, []string{"main.go"})
	if result != "true" {
		t.Errorf("expected 'true' for fmt.Println usage, got %q", result)
	}
}

func TestDetectReflectionVulnerabilities_WithReflection(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{ScanConfig: ScanConfig{Directory: dir}}

	risks := r.detectReflectionVulnerabilities("fmt", dir, []string{"Println"}, []string{"reflect.go"})
	if len(risks) == 0 {
		t.Error("expected reflection risks for file with reflect usage")
	}
}

func TestDetectReflectionVulnerabilities_NoReflection(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{ScanConfig: ScanConfig{Directory: dir}}

	risks := r.detectReflectionVulnerabilities("fmt", dir, []string{"Println"}, []string{"main.go"})
	if len(risks) != 0 {
		t.Errorf("expected no reflection risks for plain main.go, got %d", len(risks))
	}
}

func TestDetectReflectionVulnerabilities_BadFile(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	r := &Result{ScanConfig: ScanConfig{Directory: dir}}

	risks := r.detectReflectionVulnerabilities("fmt", dir, []string{"Println"}, []string{"nonexistent.go"})
	if len(risks) != 0 {
		t.Errorf("expected no risks for missing file, got %d", len(risks))
	}
}

func TestWorker(t *testing.T) {
	dir := filepath.Join("testdata", "simple")
	t.Setenv("ALGO", "rta")

	absDir, _ := filepath.Abs(dir)

	runner := newFakeRunner()
	runner.combined[absDir+"|go|list|-f|{{if .Module}}{{.Module.Version}}{{end}}|fmt"] = []byte("v1.21.0\n")
	runner.combined[absDir+"|go|list|-m|-f|{{.Path}}|fmt"] = []byte("fmt\n")
	runner.stdout[absDir+"|go|mod|edit|-json"] = []byte(`{"Module":{"Path":"example.com/simple"},"Go":"1.21","Require":[],"Replace":[]}`)

	result := &Result{
		ScanConfig: ScanConfig{
			Directory: absDir,
			Runner:    runner,
		},
		GoCVE: "GO-2024-0001",
		AffectedImports: map[string]AffectedImportsDetails{
			"fmt": {
				Symbols:      []string{"Println"},
				Type:         "stdlib",
				FixedVersion: []string{"v1.21.9"},
			},
		},
	}

	jobs := make(chan Job, 1)
	results := make(chan *Result, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go Worker(jobs, results, &wg, result)

	jobs <- Job{
		Package: "fmt",
		Symbols: []string{"Println"},
		Dir:     ".",
		Files:   []string{"main.go"},
	}
	close(jobs)

	wg.Wait()
	close(results)

	res := <-results
	if res == nil {
		t.Fatal("expected non-nil result from worker")
	}
}

func TestWorkerKeepsEachJobStatus(t *testing.T) {
	t.Setenv("ALGO", "static")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":  "module example.com/worker\n\ngo 1.22.0\n",
		"main.go": "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hello\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	result := &Result{
		ScanConfig: ScanConfig{Directory: dir},
		AffectedImports: map[string]AffectedImportsDetails{
			"fmt": {Type: "stdlib", FixedVersion: []string{"1.22.2"}},
		},
	}
	jobs := make(chan Job, 2)
	results := make(chan *Result, 2)
	jobs <- Job{Package: "fmt", Symbols: []string{"Println"}, Dir: "."}
	jobs <- Job{Package: "fmt", Symbols: []string{"Nonexistent"}, Dir: "."}
	close(jobs)
	var wg sync.WaitGroup
	wg.Add(1)
	go Worker(jobs, results, &wg, result)
	// Delay reading until both jobs have updated the shared scan result.
	wg.Wait()
	for _, want := range []string{"true", "false"} {
		if got := (<-results).IsVulnerable; got != want {
			t.Errorf("job status = %q, want %q", got, want)
		}
	}
}

type failingAdvisoryTransport func(*http.Request) (*http.Response, error)

func (f failingAdvisoryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type truncatedAdvisoryBody struct{}

func (truncatedAdvisoryBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (truncatedAdvisoryBody) Close() error             { return nil }

func TestAdvisoryFailures(t *testing.T) {
	for _, failure := range []string{"transport", "timeout", "http status", "malformed JSON", "trailing JSON data", "truncated body"} {
		for _, operation := range []string{"alias", "symbols", "versions", "scan setup"} {
			t.Run(failure+"/"+operation, func(t *testing.T) {
				client := &http.Client{Transport: failingAdvisoryTransport(func(req *http.Request) (*http.Response, error) {
					switch failure {
					case "transport":
						return nil, errors.New("connection unavailable")
					case "timeout":
						return nil, context.DeadlineExceeded
					case "truncated body":
						return &http.Response{StatusCode: 200, Body: io.NopCloser(io.MultiReader(strings.NewReader(`{}`), truncatedAdvisoryBody{})), Header: make(http.Header)}, nil
					case "trailing JSON data":
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{} trailing`)), Header: make(http.Header)}, nil
					case "http status":
						return &http.Response{StatusCode: 503, Status: "503 Service Unavailable", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
					default:
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"affected":`)), Header: make(http.Header)}, nil
					}
				})}
				r := &Result{ScanConfig: ScanConfig{CVE: "CVE-2024-12345", HTTP: client}}
				switch operation {
				case "alias":
					fetchGoVulnID(r)
				case "symbols":
					r.GoCVE = "GO-2024-1234"
					fetchAffectedSymbols(r)
				case "versions":
					if got := getFixedVersion("GO-2024-1234", "example.com/vulnerable", r); len(got) != 0 {
						t.Errorf("versions = %v", got)
					}
				case "scan setup":
					if !SetupCVEMode(r) && !Prepare(r) {
						t.Fatal("scan continued after advisory failure")
					}
					if r.IsVulnerable != "unknown" {
						t.Errorf("status = %q, want unknown", r.IsVulnerable)
					}
				}
				if len(r.Errors) == 0 {
					t.Fatal("advisory failure has no diagnostic")
				}
				if len(r.AffectedImports) != 0 {
					t.Errorf("failed advisory produced findings: %v", r.AffectedImports)
				}
			})
		}
	}
}

func TestAdvisoryRangePreserved(t *testing.T) {
	for _, tc := range []struct {
		name            string
		events          []Event
		version, status string
	}{
		{"unfixed vulnerability", []Event{{Introduced: "1.0.0"}}, "v1.2.0", "true"},
		{"before unfixed vulnerability", []Event{{Introduced: "1.0.0"}}, "v0.9.0", "false"},
		{"between affected ranges", []Event{{Introduced: "0"}, {Fixed: "1.0.0"}, {Introduced: "1.2.0"}, {Fixed: "1.3.0"}}, "v1.1.0", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := VulnReport{Affected: []Affected{{Package: Package{Name: "example.com/vulnerable"}, Ranges: []Range{{Type: "SEMVER", Events: tc.events}}, EcosystemSpecific: EcosystemSpecific{Imports: []Import{{Path: "example.com/vulnerable", Symbols: []string{"Danger"}}}}}}}
			body, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			r := &Result{ScanConfig: ScanConfig{HTTP: &http.Client{Transport: failingAdvisoryTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}}}
			fetchAffectedSymbols(r)
			if len(r.Errors) != 0 {
				t.Fatal(r.Errors)
			}
			details := r.AffectedImports["example.com/vulnerable"]
			verdict := checkDirVulnerability(tc.version, "", true, false, false, "", details.versionRanges)
			if verdict.Status != tc.status {
				t.Errorf("status = %s, want %s", verdict.Status, tc.status)
			}
			if tc.name == "unfixed vulnerability" && verdict.FixVersion != "" {
				t.Errorf("invented fix: %q", verdict.FixVersion)
			}
		})
	}
}

func TestCancelledWorkerCannotReportSafe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := &Result{ScanConfig: ScanConfig{Ctx: ctx}}
	jobs, results := make(chan Job, 1), make(chan *Result, 1)
	jobs <- Job{Package: "example.com/vulnerable", Symbols: []string{"Danger"}, Dir: "."}
	close(jobs)
	var workers sync.WaitGroup
	workers.Add(1)
	Worker(jobs, results, &workers, result)
	if got := (<-results).IsVulnerable; got != "unknown" {
		t.Errorf("cancelled scan status = %q, want unknown", got)
	}
}
