# AGENTS.md

Shared development guidance for coding agents working in this repository. Directory-specific instructions, such as `data/AGENTS.md`, apply within their directories.

This guide is separate from the runtime AI audit prompt in `skills/verify-scan.md`. The verifier loads that prompt, not this file.

## Project Overview

GVS (Go Vulnerability Scanner) is a vulnerability analysis tool that determines if a Git repository is vulnerable to specific CVEs by analyzing call graphs and symbol usage. It provides both CLI binaries (`cg` and `gvs`) and a web-based API service.

**Key Capabilities:**
- Call graph analysis to trace vulnerable symbol usage from entry points
- Support for both CVE IDs and GOCVE IDs (e.g., `CVE-2024-45338` or `GO-2024-3333`)
- Multiple call graph algorithms (vta, rta, cha, static) with different speed/precision trade-offs
- Suggested fix command generation
- Typed reflection and unsafe usage candidates for further investigation
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

# Build with CORS enabled for all origins
make image CORS_ALLOWED_ORIGINS="*"

# Build with CORS for specific origins
make image CORS_ALLOWED_ORIGINS="http://localhost:3000,http://192.168.1.100:8080"

# Build with GVS_COUNTER_URL to track API call counts
make image GVS_COUNTER_URL="https://foo.com/bar"

# Build and run container
make image-run

# Build and run with optional AI verification
# Configure GVS_AI settings in ~/.config/gvs/gvs.env (see README.md)
make image-run
```

### Testing
```bash
# Run tests without the integration build tag
go test ./...

# Run the API/scanner integration suite, including race detection
make test-integration

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
   - Supports `-progress` flag for detailed progress reporting
   - Manual scans require `-library`, `-symbols`, and `-fixversion` together
   - Supports `-graph` to generate SVG call graph visualizations
   - Supports `-algo` flag to choose call graph algorithm
   - Outputs JSON results to stdout

### Code Organization

```
cmd/              # Binary entry points
  gvs/            # Web server
  cg/             # CLI scanner

pkg/              # Shared library code
  cmd/
    cg/           # Scanner, reflection.go, verify.go, types, and summaries
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
   - Include suggested fix commands and optionally generate graph SVGs

4. **AI Verification** (`VerifyAndSummarize` in verify.go):
   - Keep all production AI configuration, provider adapters, repository tools, batching, and validation in `pkg/cmd/cg/verify.go`
   - The scanner calls only `cg.VerifyAndSummarize(result, directory)`; tests live in `verify_test.go`
   - Audit source against the structured graph paths underlying SVGs for supported paths and suspected false positives/negatives; SVG rendering is not visually inspected
   - Investigate affected-symbol dynamic usage through reflection, unsafe operations, and callbacks, using `reflection_risks` as leads
   - Keep the scanner verdict separate from `AIVerification`, which contains `graph_analysis`, `dynamic_analysis`, `uncertainties`, and `coverage`
   - Select `anthropic-vertex` or `openai-compatible` using `GVS_AI_PROVIDER`; require `GVS_AI=1` and an explicit `GVS_AI_MODEL`
   - See [README.md](README.md) for provider setup and the complete configuration table

### AI Context and Coverage

- Group duplicate risk observations while preserving original scan indices. Each investigation receives at most 16 risk indices and 6 KiB of compact risk JSON.
- Full risk evidence is available through paginated `read_reflection_risks`. A fresh conversation handles each batch under the overall verification timeout.
- Initial source excerpts have a 32 KiB total budget and 4 KiB per file. Graph excerpts are capped at 16 KiB; tool responses at 8 KiB. Mark omissions and allow focused retrieval.
- Budget complete serialized requests, including tool schemas and conversation history, with output and framing reserves. `GVS_AI_CONTEXT_TOKENS` must match the selected model's context limit. The local estimate uses one token per serialized byte, not a provider-specific tokenizer.
- Track total, reviewed, and pending risks in Go. Reviewed risks may still be unresolved. The current implementation forces an `unknown` AI verdict when any risk remains pending.
- Missing graph edges, truncated evidence, and exhausted budgets do not establish safety. Findings must cite source or tool evidence and state specific remaining gaps.

### Call Graph Algorithms

The CLI's `-algo` flag defaults to `rta` and sets `ALGO`. The scanner library also defaults to `rta` when `ALGO` is unset. The Makefile's image-build setting defaults to `vta`; distinguish these entry points when checking configuration.

- **`rta`**: Rapid Type Analysis; falls back to static analysis on panic or missing roots.
- **`vta`**: Variable Type Analysis.
- **`cha`**: Class Hierarchy Analysis.
- **`static`**: Direct static call edges.

Implementation: `getCallGraphAlgorithm`, `buildCallGraph`, and `buildRTACallGraph` in `pkg/cmd/cg/scanner.go`. Treat graph edges as candidate calls, not proof of exploitability, and avoid unconditional algorithm accuracy rankings.

### Reflection and Unsafe Detection

`detectReflectionVulnerabilities` in `pkg/cmd/cg/reflection.go` reuses loaded Go type information and caches candidate extraction per module. Keep scanner detection here and AI investigation in `verify.go`.

- Resolve actual package, function, and receiver identities rather than matching symbol substrings or method names alone.
- Detect affected function references, reflected method lookups/calls, function maps, and unsafe memory operations. Registries and unsafe usage do not require a `reflect` import.
- Deduplicate observations while preserving evidence and distinct affected targets.
- Emit `reflection_risks` with `association: "target_linked"` for evidence connected to an exact affected symbol, or `association: "unresolved"` when the affected target is unknown. Unresolved candidates omit `package` and `symbol`.
- Candidate types include `value_of`, `method_lookup`, `reflection_call`, `function_registry`, `unsafe_pointer`, and `analysis_incomplete`.
- Retain explicit dynamic-analysis gaps for files importing `reflect` or `unsafe` without usable type information. Ordinary build/load failures belong in `Errors`, not in reflection risks. Candidate evidence does not prove runtime reachability and does not directly change the scanner's `IsVulnerable` verdict.

Regression fixtures in `reflection_test.go` cover unrelated names, aliases, receiver method sets, runtime-unknown targets, registries, unsafe operations, and incomplete types. Measure output reductions on fixtures or actual scans; do not imply a universal reduction or live-model accuracy improvement.

### API Architecture

**Async Task Processing:**
- Each scan/callgraph request returns a `taskId`
- Client polls `/status` endpoint with taskId to get results
- Server-Sent Events available at `/progress/{taskId}` for real-time updates
- Single concurrent request limit (`inProgress` mutex)

**Caching:**
- Disk-based caching in `/tmp/gvs-cache/`
- Callgraph cache keys include repository, branch/commit, CVE, library, symbol, fix version, and algorithm
- Disk cache entries expire after 24 hours

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
- Compares the resolved Go toolchain version for the scanned module
- Matches fix version to same major.minor branch (`findAppropriateFixVersion`)
- Fix commands use `go mod edit -go=X.Y.Z`

Implementation: `Worker`, `checkDirVulnerability`, and `findAppropriateFixVersion` in `pkg/cmd/cg/scanner.go`

### Branch vs Commit Detection

The scanner auto-detects branch names vs commit hashes:
- **Branch**: Does not match the commit-hash heuristic → shallow clone (`--depth 1`)
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
- `ALGO`: Scanner-library algorithm selection; see the entry-point defaults above
- `GOCACHE`: Go build cache location; the server sets an XDG-based cache path if unset
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed CORS origins (default: not set)
  - Examples:
    - Not set - Same-origin only, no CORS headers (default, most secure)
    - `CORS_ALLOWED_ORIGINS="*"` - Allow all origins (use for development/testing)
    - `CORS_ALLOWED_ORIGINS="http://localhost:3000,http://192.168.1.100:8080"` - Allow specific origins
    - Required when frontend is hosted separately from backend

### Tool Dependencies
The CLI validates `go` and `git` on startup, and `sfdp` when generating SVG graphs. Container and Makefile workflows also use tools such as `jq`; check those files for their specific dependencies.

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
- `Result.ProgressFunc` callback; some helpers accept `ProgressCallback`
- Used in `-progress` mode and API progress streaming
- Write to stderr for CLI, channel for API

**Suggested Fixes:**
- Scanner results include fix commands derived from affected versions and module replacements.
- The current CLI reports suggestions; it does not expose a `-fix` execution flag.

## Testing Checklist

For code changes, build both binaries and run the relevant tests. Use `go test -race ./... -timeout=120s` for shared scanner or concurrency changes. The separately tagged API/scanner integration tests require `make test-integration`; the untagged command does not run them. Run relevant integration cases when scanner output, CLI/API behavior, or concurrency changes. Verify the following when the corresponding behavior is affected; documentation-only edits need content/reference checks:
1. Both `cg` and `gvs` binaries build successfully
2. Container builds with `make image`
3. All four algorithms work (vta, rta, cha, static)
4. API endpoints return valid JSON
5. Progress reporting works in CLI and API
6. Suggested fix commands match the affected module and version
7. Both branch and commit cloning work
