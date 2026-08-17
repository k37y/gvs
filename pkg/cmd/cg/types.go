package cg

import (
	"net/http"
	"sync"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/k37y/gvs/internal/cli"
)

type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

var VulnsURL = "https://vuln.go.dev"

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
	Symbols        []string            `json:"Symbols,omitempty"`
	CurrentVersion string              `json:"CurrentVersion,omitempty"`
	ReplaceModule  string              `json:"ReplaceModule,omitempty"`
	ReplaceVersion string              `json:"ReplaceVersion,omitempty"`
	FixCommands    []string            `json:"FixCommands,omitempty"`
	Paths          [][]*callgraph.Node `json:"-"`
}

// ReflectionRisk represents a potential vulnerability through reflection usage
type ReflectionRisk struct {
	Type       string   `json:"type"`       // "method_by_name", "value_of", "string_literal", "function_registry"
	Confidence string   `json:"confidence"` // "high", "medium", "low"
	Location   string   `json:"location"`   // file:line
	Evidence   []string `json:"evidence"`   // What was found
	Symbol     string   `json:"symbol"`     // The vulnerable symbol detected
	Package    string   `json:"package"`    // The package containing the symbol
}

// ScanConfig holds the input configuration for a scan.
type ScanConfig struct {
	CVE          string       `json:"CVE,omitempty"`
	Directory    string       `json:"Directory,omitempty"`
	ProgressFunc func(string) `json:"-"`
	Runner       cli.CommandRunner `json:"-"`
	HTTP         HTTPClient       `json:"-"`
}

type Result struct {
	ScanConfig
	IsVulnerable       string
	UsedImports        map[string]map[string]UsedImportsDetails
	Files              map[string][][]string
	AffectedImports    map[string]AffectedImportsDetails
	GoCVE              string
	Repository         string
	Branch             string
	Errors             []string            `json:"Errors"`
	Unsafe             bool                `json:"unsafe"`
	Reflect            bool                `json:"reflect"`
	ReflectionRisks    []ReflectionRisk    `json:"reflection_risks,omitempty"`
	GraphPaths         []string            `json:"GraphPaths,omitempty"`
	ClaudeVerification *ClaudeVerification `json:"ClaudeVerification,omitempty"`
	GoToolchainVersions map[string]string   `json:"-"`
	Mu                 sync.Mutex          `json:"-"`
	Progress           bool                `json:"-"`
	SsaProg            *ssa.Program        `json:"-"`
	CgGraph            *callgraph.Graph    `json:"-"`
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

type Require struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Indirect bool   `json:"Indirect"`
}

type GoModEdit struct {
	Module  struct{ Path string } `json:"Module"`
	Go      string               `json:"Go"`
	Require []Require            `json:"Require"`
	Replace []Replace            `json:"Replace"`
}
