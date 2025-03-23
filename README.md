### GVC

### Installation
```
make gvs
```

### Test
```
func runScan(scanRequest ScanRequest) ScanResponse {
	exitCode, err := installGovulncheck()
	if err != nil {
		return ScanResponse{Success: false, ExitCode: exitCode, Error: err.Error()}
	}

	cloneDir := "/tmp/repo_scan"
	target := "./..."

	_ = os.RemoveAll(cloneDir) // Clean temp directory

	err = cloneRepo(scanRequest.Repo, scanRequest.Branch, cloneDir)
	if err != nil {
		return ScanResponse{Success: false, Error: err.Error()}
	}

	output, exitCode, err := runGovulncheck(cloneDir, target)
	if err != nil && exitCode != 3 {
		return ScanResponse{Success: false, ExitCode: exitCode, Error: err.Error()}
	}

	var sarif Sarif
	err = json.Unmarshal([]byte(output), &sarif)
	if err != nil {
		return ScanResponse{Success: false, Error: "Failed to parse govulncheck output"}
	}

	var findings []map[string]interface{}
	for _, run := range sarif.Runs {
		for _, result := range run.Results {
			findings = append(findings, map[string]interface{}{
				"ruleId":    result.RuleID,
				"message":   result.Message.Text,
				"locations": result.Locations,
			})
		}
	}

	return ScanResponse{Success: true, ExitCode: exitCode, Output: findings}
}
```
```go
func main() {
    scanRequest := ScanRequest{Repo: "https://github.com/openshift/metallb.git", Branch: "release-4.18",}
    response := runScan(scanRequest)
    output, _ := json.MarshalIndent(response, "", "  ")
    fmt.Println(string(output))
}
```
