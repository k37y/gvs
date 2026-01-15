# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GVS (Go Vulnerability Scanner) is a vulnerability analysis tool that determines if a Git repository is vulnerable to specific CVEs by analyzing call graphs and symbol usage. It provides both CLI binaries (`cg` and `gvs`) and a web-based API service.

**Key Capabilities:**
- Call graph analysis to trace vulnerable symbol usage from entry points
- Support for both CVE IDs and GOCVE IDs (e.g., `CVE-2024-45338` or `GO-2024-3333`)
- Multiple call graph algorithms (vta, rta, cha, static) with different speed/precision trade-offs
- Automatic fix command generation and execution
- Reflection-based vulnerability detection (analyzes dynamic symbol invocation)
- Branch and commit hash support for repository scanning
- Web API with task-based async processing and progress streaming

## Build and Development Commands

### Local Development
```bash
# Build both binaries
make gvs cg

# Build individual binaries
make gvs          # Web server binary
make cg           # CLI scanner binary

# Run the web server locally
make run          # Builds and starts on port 8082
```

### Container Development
```bash
# Build container image with default settings
make image

# Build with custom settings
make image WORKER_COUNT=5 ALGO=rta PORT=8082

# Build and run container
make image-run

# Build and run with Gemini API (for AI summaries)
# Requires ~/.gemini.conf with API_URL and API_KEY
make image-run
```

### Testing
```bash
# Run all tests
go test ./...

# Test a specific package
go test ./pkg/cmd/cg
go test ./internal/api
```

### System Installation (Linux with systemd)
```bash
# Install binaries and systemd service
make install

# Uninstall
make uninstall
```

## Architecture

### Binary Structure

**Two main binaries:**
1. **`gvs`** (`cmd/gvs/main.go`): HTTP server providing web UI and REST API
   - Serves static site from `site/` directory
   - Provides `/scan` (govulncheck), `/callgraph` (call graph analysis), `/status`, `/progress` endpoints
   - Manages async task processing with progress streaming
   - Automatic cleanup of temporary directories every hour

2. **`cg`** (`cmd/cg/main.go`): CLI tool for direct call graph analysis
   - Accepts CVE ID or GOCVE ID as first argument, directory as second
   - Supports `-fix` flag to automatically run fix commands
   - Supports `-progress` flag for detailed progress reporting
   - Supports `-library` and `-symbol` flags to bypass CVE lookup and scan directly
   - Supports `-algo` flag to choose call graph algorithm
   - Outputs JSON results to stdout

### Code Organization

```
cmd/              # Binary entry points
  gvs/            # Web server
  cg/             # CLI scanner

pkg/              # Shared library code
  cmd/
    cg/           # Core scanning logic (scanner.go, types.go, summary.go)
    gvs/          # Cleanup utilities
    gvc/          # Legacy scan types
  utils/          # Tool validation

internal/         # Private application code
  api/            # HTTP handlers (handlers.go), caching (cache.go)
  cli/            # Command execution (commands.go)
  common/         # Shared utilities (utils.go)

site/             # Frontend assets (HTML, CSS, JS)
  config.js         # API backend URL configuration
  script.js         # Main frontend logic
  index.html        # Web UI
  styles.css        # Styling
```

### Frontend Configuration

The frontend can be configured to connect to a remote backend by editing `site/config.js`:

```javascript
window.GVS_CONFIG = {
  API_BASE_URL: 'http://192.168.1.100:8082'  // Remote backend URL
  // Or leave empty for same-host: API_BASE_URL: ''
};
```

**Use Cases:**
- **Same-host deployment**: Leave `API_BASE_URL` empty (default)
- **Remote backend**: Set full URL with protocol and port
- **CORS requirement**: When using remote backend, set `CORS_ALLOWED_ORIGINS` environment variable

Implementation: All fetch calls in `script.js` use `${API_BASE_URL}/endpoint` pattern

### Call Graph Analysis Flow

The scanner follows this workflow (see README.md flowchart):

1. **Initialize** (`InitResult` in `pkg/cmd/cg/scanner.go`):
   - Convert CVE ID to GOCVE ID if needed (or accept GOCVE directly)
   - Fetch affected symbols from vuln.go.dev
   - Find all `main` packages in repository
   - Detect unsafe/reflect package usage

2. **Worker Pool Processing** (`Worker` in scanner.go):
   - For each (endpoint, vulnerable symbol) combination:
     - Generate call graph using selected algorithm
     - Check if symbol is reachable from entry point
     - Compare current version vs fixed version
     - Generate fix commands if vulnerable

3. **Merge Results** (`cmd/cg/main.go`):
   - Deduplicate symbols across workers
   - Determine overall vulnerability status
   - Optionally execute fix commands

4. **Generate Summary** (`GenerateSummaryWithGemini` in summary.go):
   - Optional AI-powered summary using Gemini API
   - Requires `~/.gemini.conf` configuration

### Call Graph Algorithms

Configured via `ALGO` environment variable or `-algo` flag:

- **`vta`** (default): Variable Type Analysis - Most precise, slowest. Use for accuracy.
- **`rta`**: Rapid Type Analysis - Good balance. Includes panic recovery.
- **`cha`**: Class Hierarchy Analysis - Fast, less precise. Good for large codebases.
- **`static`**: Static analysis only - Fastest, only detects direct calls.

Implementation: `buildCallGraph` and related functions in `pkg/cmd/cg/scanner.go:652-703`

### Reflection Detection

The scanner includes advanced reflection analysis (`detectReflectionVulnerabilities` in scanner.go):

Detects 14 types of reflection-based symbol invocation:
- `reflect.ValueOf()`, `MethodByName()`, `CallSlice()`, etc.
- Function registries (maps containing vulnerable symbols)
- String literals containing symbol names
- Confidence levels: high/medium/low

Each detection includes location, evidence, and confidence score in `ReflectionRisks` field.

### API Architecture

**Async Task Processing:**
- Each scan/callgraph request returns a `taskId`
- Client polls `/status` endpoint with taskId to get results
- Server-Sent Events available at `/progress/{taskId}` for real-time updates
- Single concurrent request limit (`inProgress` mutex)

**Caching:**
- Disk-based caching in `/tmp/gvs-cache/`
- Cache key includes repo, branch/commit, CVE, library, symbol, and fix flag
- Smart cache reuse: fix=true requests can reuse fix=false cache

**Request Flow:**
1. `POST /callgraph` → returns `{"taskId": "..."}`
2. `POST /status {"taskId": "..."}` → returns status and output when complete
3. Optional: `GET /progress/{taskId}` → SSE stream of progress messages

**CORS Configuration:**
- All API endpoints support CORS via middleware (`internal/api/cors.go`)
- Controlled by `CORS_ALLOWED_ORIGINS` environment variable
- Default: Not set (same-origin only, no CORS headers - most secure)
- Set to `"*"` to allow all origins (development/testing)
- Set to comma-separated list for specific origins (e.g., `"http://localhost:3000,http://app.example.com"`)
- Handles preflight OPTIONS requests automatically when CORS is enabled

### Version Handling

**Non-stdlib packages:**
- Uses semantic versioning comparison (`semver.Compare`)
- Supports `replace` directives in go.mod
- Fix commands use `go get` or `go mod edit -replace`

**Stdlib packages:**
- Compares Go toolchain version (from `go.mod`)
- Matches fix version to same major.minor branch (`findAppropriateFixVersion`)
- Fix commands use `go mod edit -go=X.Y.Z`

Implementation: `Worker` function in scanner.go:167-292

### Branch vs Commit Detection

The scanner auto-detects branch names vs commit hashes:
- **Branch**: Contains non-hex characters → shallow clone (`--depth 1`)
- **Commit**: 7-40 hex characters → full clone then checkout

Implementation: `CloneRepo` in `internal/common/utils.go`

## Important Development Notes

### Cross-Binary Compatibility
- Code in `pkg/` and `internal/` is shared between `cg` and `gvs` binaries
- Changes to scanner logic affect both CLI and API
- Always test both binaries after modifying shared code

### Environment Variables
- `GVS_PORT`: Web server port (default: 8082)
- `WORKER_COUNT`: Worker pool size (default: CPU/2)
- `ALGO`: Call graph algorithm (default: vta)
- `GOCACHE`: Go build cache location (set to `/tmp/go-build` by gvs server)
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed CORS origins (default: not set)
  - Examples:
    - Not set - Same-origin only, no CORS headers (default, most secure)
    - `CORS_ALLOWED_ORIGINS="*"` - Allow all origins (use for development/testing)
    - `CORS_ALLOWED_ORIGINS="http://localhost:3000,http://192.168.1.100:8080"` - Allow specific origins
    - Required when frontend is hosted separately from backend

### Tool Dependencies
Required CLI tools (validated on startup):
- `go`: Go toolchain
- `git`: Repository cloning
- `digraph`: Call graph querying (installed via golang.org/x/tools/cmd/digraph)
- `jq`: JSON processing (container only)

### Cursor Rules Integration
The project has detailed development rules in `.cursorrules`:
- Minimal code changes philosophy
- Comprehensive testing requirements (table-driven tests)
- No premature optimization
- Cross-platform compatibility (Linux/macOS)
- Environment variable handling with sensible defaults

### Common Patterns

**Error Handling:**
- Errors appended to `result.Errors` slice (not fatal)
- JSON output always generated, even with errors
- Allows partial results with error context

**Progress Reporting:**
- Optional `ProgressCallback` function parameter
- Used in `-progress` mode and API progress streaming
- Write to stderr for CLI, channel for API

**Fix Command Execution:**
- Commands run in module directory context
- Output captured to `gvs-output.txt` file
- Success/errors tracked separately in result

## Testing Checklist

When making changes, verify:
1. Both `cg` and `gvs` binaries build successfully
2. Container builds with `make image`
3. All four algorithms work (vta, rta, cha, static)
4. API endpoints return valid JSON
5. Progress reporting works in CLI and API
6. Fix commands execute correctly
7. Both branch and commit cloning work
