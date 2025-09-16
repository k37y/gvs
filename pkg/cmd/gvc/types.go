package gvc

type ScanRequest struct {
	Repo           string `json:"repo"`
	BranchOrCommit string `json:"branchOrCommit"` // Branch name or commit hash (7+ hex characters for commit detection)
	CVE            string `json:"cve"`
}

type ScanResponse struct {
	Success  bool        `json:"success"`
	ExitCode int         `json:"exit_code"`
	Output   interface{} `json:"output,omitempty"`
	Error    string      `json:"error,omitempty"`
}

type Sarif struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		} `json:"results"`
	} `json:"runs"`
}
