package cg

import "testing"

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
	}{
		// --- Non-stdlib, symbol used ---
		{
			name:       "non-stdlib used, current below fix, no replace",
			curVer:     "v0.23.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true,
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
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true,
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
			wantStatus: "false", wantDirVuln: true, wantReplaceFix: true,
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
			wantStatus: "unknown", wantDirVuln: true, wantReplaceFix: true,
		},

		// --- Stdlib, symbol used ---
		{
			name:               "stdlib used, toolchain below fix",
			curVer:             "v1.21.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.21.4",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "true", wantDirVuln: true,
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
			name:               "stdlib used, toolchain above fix",
			curVer:             "v1.21.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.22.5",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},
		{
			name:               "stdlib used, no matching fix for branch (fallback)",
			curVer:             "v1.20.0",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.20.5",
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			wantStatus:         "true", wantDirVuln: true,
		},
		{
			name:               "stdlib used, empty toolchain version",
			curVer:             "v1.21.0",
			used:               true,
			isStdlib:           true,
			rawFixVer:          []string{"Introduced in 0 and fixed in 1.21.8"},
			wantStatus:         "unknown", wantDirVuln: true,
		},
		{
			name:       "stdlib used, no fix versions available",
			curVer:     "v1.21.0",
			used:       true,
			isStdlib:   true,
			wantStatus: "unknown", wantDirVuln: true,
		},

		// --- Real-world mod-dir scenarios ---
		{
			name:       "mod-dir root: require v0.23.0, replace v0.24.0, fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true,
		},
		{
			name:       "mod-dir bar: require v0.33.0, replace v0.24.0, fix v0.33.0",
			curVer:     "v0.33.0",
			repVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true,
		},
		{
			name:       "mod-dir foo: require v0.23.0, replace v0.33.0 (fixed), fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.33.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.33.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},

		// --- Multiple ranges (non-stdlib) ---
		{
			name:       "non-stdlib, multiple ranges, current in second range",
			curVer:     "v0.24.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.23.0 and fixed in 0.26.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true,
		},
		{
			name:       "non-stdlib, multiple ranges, current between ranges (safe)",
			curVer:     "v0.22.5",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.25.0 and fixed in 0.26.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib, multiple ranges, current above all fixes",
			curVer:     "v0.27.0",
			rawFixVer:  []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.23.0 and fixed in 0.26.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},

		// --- Plain version strings (no "Introduced in" format) ---
		{
			name:       "plain version string, current below fix",
			curVer:     "v0.23.0",
			rawFixVer:  []string{"v0.33.0"},
			used:       true,
			wantStatus: "true", wantDirVuln: true,
		},
		{
			name:       "plain version string, current above fix",
			curVer:     "v0.34.0",
			rawFixVer:  []string{"v0.33.0"},
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vr := checkDirVulnerability(tt.curVer, tt.repVer, tt.used,
				tt.unknown, tt.isStdlib, tt.goToolchainVersion, tt.rawFixVer)

			if vr.DirVulnerable != tt.wantDirVuln {
				t.Errorf("DirVulnerable = %v, want %v", vr.DirVulnerable, tt.wantDirVuln)
			}
			if vr.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", vr.Status, tt.wantStatus)
			}
			if vr.NeedsReplaceFix != tt.wantReplaceFix {
				t.Errorf("NeedsReplaceFix = %v, want %v", vr.NeedsReplaceFix, tt.wantReplaceFix)
			}
		})
	}
}

func TestParseVersionRanges(t *testing.T) {
	tests := []struct {
		name      string
		rawFixVer []string
		want      [][2]string
	}{
		{
			name:      "single introduced/fixed pair",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.33.0"},
			want:      [][2]string{{"v0", "v0.33.0"}},
		},
		{
			name:      "multiple pairs",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.23.0 and fixed in 0.26.0"},
			want:      [][2]string{{"v0", "v0.22.0"}, {"v0.23.0", "v0.26.0"}},
		},
		{
			name:      "plain version string",
			rawFixVer: []string{"v0.33.0"},
			want:      [][2]string{{"v", "v0.33.0"}},
		},
		{
			name:      "stdlib format",
			rawFixVer: []string{"Introduced in 0 and fixed in 1.25.10", "Introduced in 1.26.0-0 and fixed in 1.26.3"},
			want:      [][2]string{{"v0", "v1.25.10"}, {"v1.26.0-0", "v1.26.3"}},
		},
		{
			name:      "empty input",
			rawFixVer: []string{},
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVersionRanges(tt.rawFixVer)
			if len(got) != len(tt.want) {
				t.Fatalf("parseVersionRanges() returned %d ranges, want %d", len(got), len(tt.want))
			}
			for i, r := range got {
				if r[0] != tt.want[i][0] || r[1] != tt.want[i][1] {
					t.Errorf("range[%d] = {%q, %q}, want {%q, %q}", i, r[0], r[1], tt.want[i][0], tt.want[i][1])
				}
			}
		})
	}
}

func TestIsVersionInVulnerableRange(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		rawFixVer []string
		wantVuln  bool
		wantFix   string
	}{
		{
			name:      "below fix in single range",
			version:   "v0.23.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.33.0"},
			wantVuln:  true,
			wantFix:   "v0.33.0",
		},
		{
			name:      "at fix version (not vulnerable)",
			version:   "v0.33.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.33.0"},
			wantVuln:  false,
			wantFix:   "",
		},
		{
			name:      "above fix (patched)",
			version:   "v0.34.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.33.0"},
			wantVuln:  false,
			wantFix:   "",
		},
		{
			name:      "in second vulnerable range",
			version:   "v0.24.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.23.0 and fixed in 0.26.0"},
			wantVuln:  true,
			wantFix:   "v0.26.0",
		},
		{
			name:      "between ranges (safe window)",
			version:   "v0.22.5",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.25.0 and fixed in 0.26.0"},
			wantVuln:  false,
			wantFix:   "",
		},
		{
			name:      "above all ranges",
			version:   "v0.27.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.23.0 and fixed in 0.26.0"},
			wantVuln:  false,
			wantFix:   "",
		},
		{
			name:      "in first range of multiple",
			version:   "v0.15.0",
			rawFixVer: []string{"Introduced in 0 and fixed in 0.22.0", "Introduced in 0.23.0 and fixed in 0.26.0"},
			wantVuln:  true,
			wantFix:   "v0.22.0",
		},
		{
			name:      "stdlib in first range",
			version:   "v1.21.4",
			rawFixVer: []string{"Introduced in 0 and fixed in 1.25.10", "Introduced in 1.26.0-0 and fixed in 1.26.3"},
			wantVuln:  true,
			wantFix:   "v1.25.10",
		},
		{
			name:      "stdlib between ranges (patched)",
			version:   "v1.25.10",
			rawFixVer: []string{"Introduced in 0 and fixed in 1.25.10", "Introduced in 1.26.0-0 and fixed in 1.26.3"},
			wantVuln:  false,
			wantFix:   "",
		},
		{
			name:      "stdlib in second range",
			version:   "v1.26.1",
			rawFixVer: []string{"Introduced in 0 and fixed in 1.25.10", "Introduced in 1.26.0-0 and fixed in 1.26.3"},
			wantVuln:  true,
			wantFix:   "v1.26.3",
		},
		{
			name:      "empty fix versions",
			version:   "v0.23.0",
			rawFixVer: []string{},
			wantVuln:  false,
			wantFix:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVuln, gotFix := isVersionInVulnerableRange(tt.version, tt.rawFixVer)
			if gotVuln != tt.wantVuln {
				t.Errorf("isVersionInVulnerableRange() vuln = %v, want %v", gotVuln, tt.wantVuln)
			}
			if gotFix != tt.wantFix {
				t.Errorf("isVersionInVulnerableRange() fix = %q, want %q", gotFix, tt.wantFix)
			}
		})
	}
}
