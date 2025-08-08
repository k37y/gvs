package main

import "sync"

const (
	vulnsURL = "https://vuln.go.dev"
)

type Job struct {
	Package string
	Symbols []string
	Dir     string
	Files   []string
}

type AffectedImportsDetails struct {
	Symbols      []string
	Type         string
	FixedVersion []string
}

type UsedImportsDetails struct {
	Symbols        []string `json:"Symbols,omitempty"`
	CurrentVersion string   `json:"CurrentVersion,omitempty"`
	ReplaceVersion string   `json:"ReplaceVersion,omitempty"`
	FixCommands    []string `json:"FixCommands,omitempty"`
}

type Result struct {
	IsVulnerable    string
	UsedImports     map[string]UsedImportsDetails
	Files           map[string][][]string
	AffectedImports map[string]AffectedImportsDetails
	GoCVE           string
	CVE             string
	Repository      string
	Branch          string
	Directory       string
	CursorCommand   string
	Errors          []string `json:"Errors"`
	FixErrors       []string `json:"FixErrors"`
	FixSuccess      []string `json:"FixSuccess"`
	mu              sync.Mutex
	Summary         string
}

type VulnReport struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases"`
	Affected []Affected `json:"affected"`
}

type Affected struct {
	Package           Package           `json:"package"`
	Ranges            []Range           `json:"ranges"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

type EcosystemSpecific struct {
	Imports []Import `json:"imports"`
}

type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type PathVersion struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
}

type Replace struct {
	Old PathVersion
	New PathVersion
}

type GoModEdit struct {
	Replace []Replace
}
