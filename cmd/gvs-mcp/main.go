// Package main provides an MCP (Model Context Protocol) server for GVS vulnerability scanning.
// This allows AI assistants like Claude to directly check Go repositories for CVE vulnerabilities.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var version = "dev"

func main() {
	// Parse flags
	port := flag.String("port", getEnv("GVS_MCP_PORT", "8083"), "HTTP port to listen on")
	apiKey := flag.String("api-key", os.Getenv("GVS_MCP_API_KEY"), "API key for authentication (optional)")
	stateless := flag.Bool("stateless", getEnv("GVS_MCP_STATELESS", "true") == "true", "Run in stateless mode (no session persistence)")
	flag.Parse()

	// Create HTTP handler - creates a fresh server for each request in stateless mode
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return createServer()
	}, &mcp.StreamableHTTPOptions{
		JSONResponse: true,
		Stateless:    *stateless,
	})

	if *stateless {
		log.Printf("Running in stateless mode (recommended for reliability)")
	}

	// Wrap with auth middleware if API key is set
	var finalHandler http.Handler = handler
	if *apiKey != "" {
		finalHandler = authMiddleware(handler, *apiKey)
		log.Printf("API key authentication enabled")
	}

	// Start server
	log.Printf("Starting GVS MCP server version %s on :%s", version, *port)
	if err := http.ListenAndServe(":"+*port, finalHandler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// createServer creates and configures the MCP server with all tools
func createServer() *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "gvs",
			Version: version,
		},
		nil,
	)

	// Register all tools
	registerTools(server)

	return server
}

// registerTools registers all 7 MCP tools with the server
func registerTools(server *mcp.Server) {
	// Tool 1: scan_vulnerability - Deep CVE analysis with optional graph
	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_vulnerability",
		Description: "Check if a Go repository is vulnerable to a specific CVE. Performs deep call graph analysis to determine if vulnerable code is actually reachable. TIMING: This operation takes 1-5 minutes to complete (cloning: 10-30s, analysis: 30s-3min, summary: 2-5s). IMPORTANT: Wait for the complete result - do not timeout or assume failure during analysis. Progress notifications will indicate current step. Use 'static' or 'cha' algorithm for faster results on large repositories. Optionally generates SVG visualization. Supports 'algorithm' parameter: 'static' (fastest, ~30s), 'cha' (fast, ~1min), 'rta' (default, good for reflection, ~2-3min), 'vta' (slowest, highest precision, ~3-5min).",
	}, ScanVulnerability)

	// Tool 2: lookup_cve - CVE info without scanning
	mcp.AddTool(server, &mcp.Tool{
		Name:        "lookup_cve",
		Description: "Look up CVE details from the Go vulnerability database. Returns affected packages, vulnerable symbols, and fixed versions without scanning any repository. TIMING: Fast operation, completes in 1-3 seconds.",
	}, LookupCVE)

	// Tool 3: check_package_version - Package safety check
	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_package_version",
		Description: "Check if a specific Go package version has known vulnerabilities. Returns list of CVEs affecting this package@version with fix versions. TIMING: Takes 5-15 seconds to check first 20 vulnerabilities in the database.",
	}, CheckPackageVersion)

	// Tool 4: get_call_graph - SVG visualization
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_call_graph",
		Description: "Generate call graph visualization showing the path from entry points to a vulnerable symbol. Returns SVG image. TIMING: Takes 1-3 minutes to complete (clone + analysis + SVG generation). IMPORTANT: Wait for the full SVG result. Supports 'algorithm' parameter: 'static' (~30s), 'cha' (~1min), 'rta' (default, ~2min), 'vta' (~3min).",
	}, GetCallGraph)

	// Tool 5: scan_all_vulnerabilities - govulncheck full scan
	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_all_vulnerabilities",
		Description: "Scan a Go repository for ALL known vulnerabilities using govulncheck. Discovers all CVEs affecting the project without needing to specify a particular CVE. TIMING: This operation takes 1-10 minutes depending on repository size and number of modules. Multi-module repos take longer. IMPORTANT: Wait for the complete result - progress notifications will indicate modules being scanned.",
	}, ScanAllVulnerabilities)

	// Tool 6: analyze_reflection_risks - reflection analysis
	mcp.AddTool(server, &mcp.Tool{
		Name:        "analyze_reflection_risks",
		Description: "Analyze code for reflection patterns that could invoke vulnerable symbols at runtime. Detects patterns like reflect.ValueOf, MethodByName, function registries, etc. TIMING: Takes 1-3 minutes to complete (clone + analysis). Progress notifications will indicate current step. Supports 'algorithm' parameter: 'static' (~30s), 'cha' (~1min), 'rta' (default, best for reflection, ~2min), 'vta' (~3min).",
	}, AnalyzeReflectionRisks)

	// Tool 7: check_symbol_reachability - Manual symbol reachability check
	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_symbol_reachability",
		Description: "Check if a specific symbol from any Go package is reachable from entry points in a repository. Use this to manually verify if code can call a particular function without needing a CVE ID. TIMING: Takes 1-3 minutes to complete (clone + call graph analysis). IMPORTANT: Wait for the full result. Progress notifications will indicate current step. Supports 'algorithm' parameter: 'static' (~30s), 'cha' (~1min), 'rta' (default, ~2min), 'vta' (~3min). Returns the call path if reachable.",
	}, CheckSymbolReachability)
}

// authMiddleware adds Bearer token authentication
func authMiddleware(next http.Handler, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + apiKey

		if auth != expected {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getEnv returns the value of an environment variable or a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
