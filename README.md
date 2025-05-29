# Golang Vulnerability Scanner (GVS)
Analyze your Golang-based repository for vulnerabilities
## Usage
### Build and run
```
$ make
```
### Build and run as a container image
```
$ make image-run
```
### Sample API request of govulncheck path
```
$ curl --silent \
       --location \
       --request "POST" \
       --header "Content-Type: application/json" \
       --data '{"repo": "https://github.com/openshift/metallb", "branch": "release-4.18"}' \
       "http://<URL>:8082/scan" | jq .
```
### Sample API requests of callgraph path
```
$ curl --silent \
       --location \
       --request POST \
       --header "Content-Type: application/json" \
       --data '{"repo": "https://github.com/openshift/metallb", "branch": "release-4.18", "cve": "CVE-2024-45338"}' \
       http://<URL>:8082/cg | jq .

$ curl --silent \
       --location \
       --request POST \
       --header "Content-Type: application/json" \
       --data '{"taskId":"<task-id>"}' \
       http://<URL>:8082/status | jq .
```
### Sample API response of govulncheck path
```
$ curl -X POST "http://10.74.129.37:8088/scan" -H "Content-Type: application/json" -d '{"repo": "https://github.com/openshift/metallb", "branch": "release-4.18", "cve": "CVE-2024-45338"}' | jq
[
  {
    "directory": "metallb/e2etest",
    "results": [
      {
        "message": "Your code imports 1 vulnerable package (golang.org/x/net/html), but doesn’t appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2024-3333"
      },
      {
        "message": "Your code calls vulnerable functions in 1 package (github.com/golang/glog).",
        "ruleId": "GO-2025-3372"
      },
      {
        "message": "Your code depends on 1 vulnerable module (golang.org/x/oauth2), but doesn't appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2025-3488"
      },
      {
        "message": "Your code imports 1 vulnerable package (golang.org/x/net/proxy), but doesn’t appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2025-3503"
      },
      {
        "message": "Your code calls vulnerable functions in 1 package (net/http/internal).",
        "ruleId": "GO-2025-3563"
      },
      {
        "message": "Your code imports 1 vulnerable package (golang.org/x/net/html), but doesn’t appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2025-3595"
      }
    ]
  },
  {
    "directory": "metallb",
    "results": [
      {
        "message": "Your code depends on 1 vulnerable module (golang.org/x/net), but doesn't appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2024-3333"
      },
      {
        "message": "Your code depends on 1 vulnerable module (golang.org/x/oauth2), but doesn't appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2025-3488"
      },
      {
        "message": "Your code depends on 1 vulnerable module (golang.org/x/net), but doesn't appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2025-3503"
      },
      {
        "message": "Your code calls vulnerable functions in 1 package (net/http/internal).",
        "ruleId": "GO-2025-3563"
      },
      {
        "message": "Your code depends on 1 vulnerable module (golang.org/x/net), but doesn't appear to call any of the vulnerable symbols.",
        "ruleId": "GO-2025-3595"
      }
    ]
  },
  {
    "directory": "metallb/website/themes/hugo-theme-relearn",
    "results": null
  }
]
```
### Sample API response of callgraph path
```
$ curl -X POST "http://10.74.129.37:8088/callgraph" -H "Content-Type: application/json" -d '{"repo": "https://github.com/openshift/metallb", "branch": "release-4.18", "cve": "CVE-2024-45338"}' | jq .
{
  "taskId": "1748493013100462517"
}
```
```
$ curl -s -X POST http://10.74.129.37:8088/status -H "Content-Type: application/json" -d '{"taskId":"1748493013100462517"}' | jq .output
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
