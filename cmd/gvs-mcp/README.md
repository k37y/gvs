# GVS MCP Server

An MCP (Model Context Protocol) server that enables AI assistants like Claude to directly check Go repositories for CVE vulnerabilities.

## Installation

### Build from source

```bash
git clone https://github.com/k37y/gvs
cd gvs
make gvs-mcp
```

The binary will be available at `./bin/gvs-mcp`.

### Install globally

```bash
go install github.com/k37y/gvs/cmd/gvs-mcp@latest
```

## Running the Server

The server runs as an HTTP service on port 8083 by default.

### Basic usage

```bash
./bin/gvs-mcp
```

### Custom port

```bash
# Via environment variable
GVS_MCP_PORT=9000 ./bin/gvs-mcp

# Via command-line flag
./bin/gvs-mcp -port 9000
```

### With API key authentication

```bash
# Via environment variable
GVS_MCP_API_KEY=your-secret-key ./bin/gvs-mcp

# Via command-line flag
./bin/gvs-mcp -api-key your-secret-key
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GVS_MCP_PORT` | `8083` | HTTP port to listen on |
| `GVS_MCP_API_KEY` | (none) | API key for Bearer token authentication |

### Command-line Flags

| Flag | Description |
|------|-------------|
| `-port` | HTTP port to listen on |
| `-api-key` | API key for authentication |

## Claude Desktop Configuration

### Adding as a Remote Connector

1. Open Claude Desktop
2. Go to **Settings** > **Connectors**
3. Click **Add Connector**
4. Enter the server URL: `http://your-server:8083/`
5. If using API key auth, configure Bearer token authentication

### For Team/Enterprise Plans

1. Organization Owner adds the connector in **Admin Settings** > **Connectors**
2. Team members can then connect via **Settings** > **Connectors**

## Available Tools

### 1. `scan_vulnerability`

Check if a repository is vulnerable to a specific CVE with deep call graph analysis.

**Parameters:**
- `repo` (required): Git repository URL
- `branch` (optional): Branch or commit hash
- `cve` (required): CVE ID or GO-ID
- `generate_graph` (optional): Generate SVG call graph

**Example prompt:**
> "Is https://github.com/example/app vulnerable to CVE-2024-45338?"

### 2. `lookup_cve`

Look up CVE details from the Go vulnerability database.

**Parameters:**
- `cve` (required): CVE ID or GO-ID

**Example prompt:**
> "What is CVE-2024-45338?"

### 3. `check_package_version`

Check if a package version has known vulnerabilities.

**Parameters:**
- `package` (required): Go package path
- `version` (required): Package version

**Example prompt:**
> "Is golang.org/x/net v0.23.0 safe?"

### 4. `get_call_graph`

Generate SVG visualization of the call path to a vulnerable symbol.

**Parameters:**
- `repo` (required): Git repository URL
- `branch` (optional): Branch or commit
- `cve` (required): CVE ID
- `symbol` (optional): Specific symbol to trace

**Example prompt:**
> "Show me the call graph for CVE-2024-45338"

### 5. `scan_all_vulnerabilities`

Scan repository for ALL known vulnerabilities using govulncheck.

**Parameters:**
- `repo` (required): Git repository URL
- `branch` (optional): Branch or commit

**Example prompt:**
> "What vulnerabilities does my project have?"

### 6. `analyze_reflection_risks`

Analyze code for reflection patterns that could invoke vulnerable symbols.

**Parameters:**
- `repo` (required): Git repository URL
- `branch` (optional): Branch or commit
- `cve` (optional): CVE ID for targeted analysis

**Example prompt:**
> "Does my code use reflection that could call vulnerable functions?"

## Deployment Examples

### Docker

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o gvs-mcp ./cmd/gvs-mcp

FROM alpine:latest
RUN apk add --no-cache git
COPY --from=builder /app/gvs-mcp /usr/local/bin/
EXPOSE 8083
CMD ["gvs-mcp"]
```

### Systemd Service

```ini
[Unit]
Description=GVS MCP Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gvs-mcp
Environment=GVS_MCP_PORT=8083
Environment=GVS_MCP_API_KEY=your-secret-key
Restart=always

[Install]
WantedBy=multi-user.target
```

### Behind a Reverse Proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;

    location / {
        proxy_pass http://127.0.0.1:8083;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Requirements

- Go 1.23+
- git (for cloning repositories)
- govulncheck (for `scan_all_vulnerabilities`)
- graphviz/sfdp (optional, for SVG graph generation)

## Algorithm

The scanner uses RTA (Rapid Type Analysis) by default, which provides the best balance of:
- Precision for direct calls
- Reflection tracking capability
- Performance

## License

Apache 2.0 - See [LICENSE](../../LICENSE)
