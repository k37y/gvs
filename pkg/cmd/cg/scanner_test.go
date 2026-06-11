package cg

import "testing"

func TestCheckDirVulnerability(t *testing.T) {
	tests := []struct {
		name               string
		curVer             string
		repVer             string
		fv                 string
		used               bool
		unknown            bool
		isStdlib           bool
		goToolchainVersion string
		fixVer             []string
		wantDirVuln        bool
		wantStatus         string
		wantReplaceFix     bool
	}{
		// --- Non-stdlib, symbol used ---
		{
			name:       "non-stdlib used, current below fix, no replace",
			curVer:     "v0.23.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true,
		},
		{
			name:       "non-stdlib used, current equals fix, no replace",
			curVer:     "v0.33.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, current above fix, no replace",
			curVer:     "v0.34.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true,
		},
		{
			name:       "non-stdlib used, replace equals fix",
			curVer:     "v0.23.0",
			repVer:     "v0.33.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib used, replace above fix",
			curVer:     "v0.23.0",
			repVer:     "v0.34.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},

		// --- Non-stdlib, symbol not used ---
		{
			name:       "non-stdlib not used, current below fix",
			curVer:     "v0.23.0",
			fv:         "v0.33.0",
			used:       false,
			wantStatus: "false", wantDirVuln: false,
		},
		{
			name:       "non-stdlib not used, replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       false,
			wantStatus: "false", wantDirVuln: true, wantReplaceFix: true,
		},

		// --- Unknown reachability ---
		{
			name:       "unknown reachability",
			curVer:     "v0.23.0",
			fv:         "v0.33.0",
			unknown:    true,
			wantStatus: "unknown", wantDirVuln: true,
		},
		{
			name:       "unknown reachability with replace below fix",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			unknown:    true,
			wantStatus: "unknown", wantDirVuln: true, wantReplaceFix: true,
		},

		// --- Stdlib, symbol used ---
		{
			name:               "stdlib used, toolchain below fix",
			curVer:             "v1.21.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.21.4",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "true", wantDirVuln: true,
		},
		{
			name:               "stdlib used, toolchain at fix",
			curVer:             "v1.21.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.21.8",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},
		{
			name:               "stdlib used, toolchain above fix",
			curVer:             "v1.21.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.22.5",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "false", wantDirVuln: false,
		},
		{
			name:               "stdlib used, no matching fix for branch",
			curVer:             "v1.20.0",
			fv:                 "v1.21.8",
			used:               true,
			isStdlib:           true,
			goToolchainVersion: "v1.20.5",
			fixVer:             []string{"1.21.8", "1.22.2"},
			wantStatus:         "true", wantDirVuln: true,
		},
		{
			name:     "stdlib used, empty toolchain version",
			curVer:   "v1.21.0",
			fv:       "v1.21.8",
			used:     true,
			isStdlib: true,
			fixVer:   []string{"1.21.8"},
			wantStatus: "unknown", wantDirVuln: true,
		},
		{
			name:     "stdlib used, no fix versions available",
			curVer:   "v1.21.0",
			fv:       "",
			used:     true,
			isStdlib: true,
			wantStatus: "unknown", wantDirVuln: true,
		},

		// --- Real-world mod-dir scenarios ---
		{
			name:       "mod-dir root: require v0.23.0, replace v0.24.0, fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true, wantReplaceFix: true,
		},
		{
			name:       "mod-dir bar: require v0.33.0, replace v0.24.0, fix v0.33.0",
			curVer:     "v0.33.0",
			repVer:     "v0.24.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "true", wantDirVuln: true,
		},
		{
			name:       "mod-dir foo: require v0.23.0, replace v0.33.0 (fixed), fix v0.33.0",
			curVer:     "v0.23.0",
			repVer:     "v0.33.0",
			fv:         "v0.33.0",
			used:       true,
			wantStatus: "false", wantDirVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vr := checkDirVulnerability(tt.curVer, tt.repVer, tt.fv,
				tt.used, tt.unknown, tt.isStdlib, tt.goToolchainVersion, tt.fixVer)

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
