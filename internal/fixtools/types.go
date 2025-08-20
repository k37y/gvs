package fixtools

type UsedImportsDetails struct {
	Symbols        []string `json:"Symbols,omitempty"`
	CurrentVersion string   `json:"CurrentVersion,omitempty"`
	ReplaceVersion string   `json:"ReplaceVersion,omitempty"`
	FixCommands    []string `json:"FixCommands,omitempty"`
}

type Result struct {
	IsVulnerable  string
	UsedImports   map[string]UsedImportsDetails
	Files         map[string][][]string
	GoCVE         string
	CVE           string
	Repository    string
	Branch        string
	Directory     string
	CursorCommand *string   `json:"CursorCommand,omitempty"`
	Errors        []string  `json:"Errors"`
	FixErrors     *[]string `json:"FixErrors,omitempty"`
	FixSuccess    *[]string `json:"FixSuccess,omitempty"`
	Summary       string
}
