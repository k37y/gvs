package common

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormatIntroducedFixed(t *testing.T) {
	tests := []struct {
		name   string
		events []interface{}
		want   []string
	}{
		{
			name:   "empty events",
			events: nil,
			want:   nil,
		},
		{
			name: "single introduced-fixed pair",
			events: []interface{}{
				map[string]interface{}{"introduced": "0"},
				map[string]interface{}{"fixed": "1.21.8"},
			},
			want: []string{"Introduced in 0 and fixed in 1.21.8"},
		},
		{
			name: "multiple pairs",
			events: []interface{}{
				map[string]interface{}{"introduced": "0"},
				map[string]interface{}{"fixed": "1.21.8"},
				map[string]interface{}{"introduced": "1.22.0"},
				map[string]interface{}{"fixed": "1.22.2"},
			},
			want: []string{
				"Introduced in 0 and fixed in 1.21.8",
				"Introduced in 1.22.0 and fixed in 1.22.2",
			},
		},
		{
			name: "introduced only, no fix",
			events: []interface{}{
				map[string]interface{}{"introduced": "0"},
			},
			want: []string{"Introdued in 0 - "},
		},
		{
			name: "non-map event ignored",
			events: []interface{}{
				"not a map",
				map[string]interface{}{"introduced": "0"},
				map[string]interface{}{"fixed": "1.0.0"},
			},
			want: []string{"Introduced in 0 and fixed in 1.0.0"},
		},
		{
			name: "fixed without prior introduced ignored",
			events: []interface{}{
				map[string]interface{}{"fixed": "1.0.0"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatIntroducedFixed(tt.events)
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

func TestExtractFormattedFixedVersions(t *testing.T) {
	tests := []struct {
		name   string
		inputs []string
		want   []string
	}{
		{
			name:   "no matches",
			inputs: []string{"no version here"},
			want:   nil,
		},
		{
			name:   "single version",
			inputs: []string{"Introduced in 0 and fixed in 1.21.8"},
			want:   []string{"1.21.8"},
		},
		{
			name:   "multiple versions across inputs",
			inputs: []string{"Introduced in 0 and fixed in 1.21.8", "Introduced in 1.22.0 and fixed in 1.22.2"},
			want:   []string{"1.21.8", "1.22.2"},
		},
		{
			name:   "empty input",
			inputs: nil,
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFormattedFixedVersions(tt.inputs)
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

func TestSemVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.0.0", "v1.0.0"},
		{"v1.0.0", "v1.0.0"},
		{"0.33.0", "v0.33.0"},
		{"v0.33.0", "v0.33.0"},
		{"", "v"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SemVersion(tt.input)
			if got != tt.want {
				t.Errorf("SemVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"nil input", nil, nil},
		{"empty", []string{}, nil},
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"all same", []string{"x", "x", "x"}, []string{"x"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UniqueStrings(tt.input)
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

func TestIsGOCVEID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"GO-2024-3333", true},
		{"GO-2024-12345", true},
		{"GO-2024-333", false},   // too few digits
		{"CVE-2024-3333", false}, // wrong prefix
		{"go-2024-3333", false},  // lowercase
		{"", false},
		{"GO-ABCD-3333", false}, // non-digit year
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsGOCVEID(tt.input)
			if got != tt.want {
				t.Errorf("IsGOCVEID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCVEID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"CVE-2024-45338", true},
		{"CVE-2024-1234", true},
		{"CVE-2024-123", false},  // too few digits
		{"GO-2024-3333", false},  // wrong prefix
		{"cve-2024-1234", false}, // lowercase
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsCVEID(tt.input)
			if got != tt.want {
				t.Errorf("IsCVEID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCommitHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"full SHA-1", "c600016ab638aab33bf02be5414f4174033c744a", true},
		{"short hash 7 chars", "c600016", true},
		{"short hash 8 chars", "c600016a", true},
		{"too short", "c6000", false},
		{"branch name", "main", false},
		{"branch with slash", "feature/foo", false},
		{"branch with numbers", "release-1.0", false},
		{"too long", "c600016ab638aab33bf02be5414f4174033c744a1", false},
		{"uppercase hex", "C600016AB638", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCommitHash(tt.input)
			if got != tt.want {
				t.Errorf("isCommitHash(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindGoModDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested structure
	os.MkdirAll(filepath.Join(tmpDir, "submod"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "vendor", "dep"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module root\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "submod", "go.mod"), []byte("module submod\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "vendor", "dep", "go.mod"), []byte("module vendored\n"), 0644)

	dirs, err := FindGoModDirs(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// Should find root and submod but not vendor
	if len(dirs) != 2 {
		t.Fatalf("expected 2 dirs, got %d: %v", len(dirs), dirs)
	}

	foundRoot := false
	foundSubmod := false
	for _, d := range dirs {
		if d == tmpDir {
			foundRoot = true
		}
		if d == filepath.Join(tmpDir, "submod") {
			foundSubmod = true
		}
	}
	if !foundRoot {
		t.Error("expected root dir in results")
	}
	if !foundSubmod {
		t.Error("expected submod dir in results")
	}
}
