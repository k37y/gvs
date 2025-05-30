![gvs](https://github.com/user-attachments/assets/e726bf74-5bc4-48de-8b89-bc57ee6d53e4)

Takes **repository**, **branch**, and **CVE ID** gives vulnerability status
## Demo
[![asciicast](https://asciinema.org/a/721319.svg)](https://asciinema.org/a/721319)
## Flowchart
```mermaid
flowchart TD
    A[Start: Input Parameters] --> B[Clone Repository]
    B --> C[Checkout Branch]
    C --> D[Find Project Endpoint Files]
    D --> E[Find Affected Symbols from CVE ID]
    E --> F[Generate Endpoint-Symbol Combinations]
    F --> G[Loop: For Each Combination]
    G --> H[Generate Callgraph Path]
    H --> I{Is Symbol Used in Endpoint?}
    I -- Yes --> J[Compare Used vs Fixed Version]
    J --> K{Used Version < Fixed?}
    K -- Yes --> L[Mark as Vulnerable]
    K -- No --> M[Mark as Not Vulnerable]
    L --> N[Add to Result]
    M --> N
    I -- No --> O[Skip Combination]
    O --> N
    N --> P{More Combinations?}
    P -- Yes --> G
    P -- No --> Q[Generate Summary Using AI]
    Q --> R[Return Result as JSON]
    R --> S[End]

    %% Style nodes
    style A fill:#d1e8ff,stroke:#333,stroke-width:1px
    style L fill:#ffcccc,stroke:#d33,stroke-width:1px
    style M fill:#ccffcc,stroke:#393,stroke-width:1px
    style S fill:#e2e2e2,stroke:#333,stroke-width:1px
```
## Prerequisites
* Gemini API credentials
  - Create a file named `~/.gemini.conf`
  - Use the below contents (Use your API key)
    ```bash
    API_URL=https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent
    API_KEY=<your-api-key>
    ```
* Podman
## Usage
### Build and run as a container image
```bash
$ git clone https://github.com/k37y/gvs && cd gvs
$ make image-run
```
### Sample API request and response of callgraph path
```bash
$ curl --request POST \
       --header "Content-Type: application/json" \
       --data '{"repo": "https://github.com/openshift/metallb", "branch": "release-4.18", "cve": "CVE-2024-45338"}' \
       http://10.0.0.10:8082/callgraph | jq .
```
```bash
{
  "taskId": "1748493013100462517"
}
```
```bash
$ curl --silent \
       --request POST \
       --header "Content-Type: application/json" \
       --data '{"taskId":"1748493013100462517"}' \
       http://localhost:8082/status | jq .output
```
```bash
{
  "AffectedImports": {
    "golang.org/x/net/html": {
      "FixedVersion": [
        "v0.33.0"
      ],
      "Symbols": [
        "Parse",
        "ParseFragment",
        "ParseFragmentWithOptions",
        "ParseWithOptions",
        "htmlIntegrationPoint",
        "inBodyIM",
        "inTableIM",
        "parseDoctype"
      ],
      "Type": "non-stdlib"
    }
  },
  "Branch": "release-4.18",
  "CVE": "CVE-2024-45338",
  "Directory": "/tmp/cg-metallb-1402140135",
  "Errors": null,
  "Files": {
    ".": [
      [
        "configmaptocrs/main.go",
        "configmaptocrs/types.go"
      ],
      [
        "controller/main.go",
        "controller/service.go"
      ],
      [
        "frr-tools/cp-tool/cp-tool.go"
      ],
      [
        "frr-tools/metrics/exporter.go"
      ],
      [
        "speaker/bgp_controller.go",
        "speaker/layer2_controller.go",
        "speaker/main.go"
      ]
    ],
    "e2etest": null,
    "website/themes/hugo-theme-relearn": null
  },
  "GoCVE": "GO-2024-3333",
  "IsVulnerable": "false",
  "Repository": "https://github.com/openshift/metallb",
  "Summary": "**Vulnerability Assessment Summary**\n\nNo vulnerability was detected in the scanned project (Repository: `https://github.com/openshift/metallb`, Branch: `release-4.18`, Directory: ``, GoCVE: `GO-2024-3333`, CVE: `CVE-2024-45338`). No errors were encountered during the scan.\n",
  "UsedImports": null
}
```
