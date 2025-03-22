package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// ScanRequest represents the input JSON for scanning a repo
type ScanRequest struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

// ScanResponse represents the API response
type ScanResponse struct {
	Success  bool        `json:"success"`
	ExitCode int         `json:"exit_code"`
	Output   interface{} `json:"output,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// SARIF struct to parse govulncheck output
type Sarif struct {
	Runs []struct {
		Results []struct {
			RuleID    string `json:"ruleId"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func cloneRepo(repoURL, branch, cloneDir string) error {
	cmd := exec.Command("git", "clone", "--branch", branch, "--single-branch", repoURL, cloneDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("git clone failed: %v\n%s", err, stderr.String())
	}

	return nil
}

func runGovulncheck(directory, target string) (string, int, error) {
	cmd := exec.Command("govulncheck", "-format", "sarif", "-C", directory, target)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := cmd.ProcessState.ExitCode()

	if err != nil && exitCode != 3 {
		log.Printf("govulncheck failed: %v\nSTDERR:\n%s", err, stderr.String())
		return stderr.String(), exitCode, fmt.Errorf("govulncheck failed: %v", err)
	}

	return out.String(), exitCode, nil
}

func scanHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var scanRequest ScanRequest
	err := json.Unmarshal([]byte(request.Body), &scanRequest)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body:       `{"error": "Invalid JSON format"}`,
		}, nil
	}

	cloneDir := "/tmp/repo_scan"
	target := "./..."

	_ = os.RemoveAll(cloneDir) // Clean temp directory

	err = cloneRepo(scanRequest.Repo, scanRequest.Branch, cloneDir)
	if err != nil {
		response, _ := json.Marshal(ScanResponse{Success: false, Error: err.Error()})
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       string(response),
		}, nil
	}

	output, exitCode, err := runGovulncheck(cloneDir, target)
	if err != nil && exitCode != 3 {
		response, _ := json.Marshal(ScanResponse{Success: false, ExitCode: exitCode, Error: err.Error()})
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       string(response),
		}, nil
	}

	var sarif Sarif
	err = json.Unmarshal([]byte(output), &sarif)
	if err != nil {
		response, _ := json.Marshal(ScanResponse{Success: false, Error: "Failed to parse govulncheck output"})
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       string(response),
		}, nil
	}

	var findings []map[string]interface{}
	for _, run := range sarif.Runs {
		for _, result := range run.Results {
			finding := map[string]interface{}{
				"ruleId":    result.RuleID,
				"message":   result.Message.Text,
				"locations": result.Locations,
			}
			findings = append(findings, finding)
		}
	}

	response, _ := json.Marshal(ScanResponse{Success: true, ExitCode: exitCode, Output: findings})
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       string(response),
	}, nil
}

func runScan(scanRequest ScanRequest) ScanResponse {
	cloneDir := "/tmp/repo_scan"
	target := "./..."

	_ = os.RemoveAll(cloneDir) // Clean temp directory

	err := cloneRepo(scanRequest.Repo, scanRequest.Branch, cloneDir)
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

func main() {
	// scanRequest := ScanRequest{Repo: "https://github.com/openshift/metallb.git", Branch: "release-4.18",}
	// response := runScan(scanRequest)
	// output, _ := json.MarshalIndent(response, "", "  ")
	// fmt.Println(string(output))
	lambda.Start(scanHandler)
}
