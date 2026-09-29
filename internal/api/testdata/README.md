# Expected advisory data

Scanner scenarios live in https://github.com/k37y/gvs-testdata, with one branch
per scenario. `integration_test.go` consumes those branches through the HTTP API.
It creates private temporary repositories only for lifecycle tests that need
controlled cache contents, process cancellation, and failed clone/checkout paths.

The JSON files in `advisories/` contain the expected affected package and symbol
sets from `https://vuln.go.dev/ID/<GO-ID>.json`, retrieved on 2026-09-29. They are
assertion data, not scanner input. A change upstream intentionally fails the
contract checks so it can be reviewed before updating these snapshots.

Run all integration tests with `make test-integration` (requires Go, Git, a C compiler for `-race`,
Graphviz's `sfdp`, and access to GitHub and vuln.go.dev). The harness builds the
real scanner with `-race`, disables optional AI verification, and serves the real API handlers
on an ephemeral port with isolated cache and clone directories.
The Makefile also enables `-race` for the API test process, so both processes
are checked by `make test-integration`.

To validate unpublished fixture branches in a local checkout:

```sh
GVS_TESTDATA_REPO=/absolute/path/to/gvs-testdata make test-integration
```

The `vuln-untidy-gomod` and `selected-dependency-version` cases check the actual
version selected by Go, including transitive upgrades. Additional branches cover
initialization, goroutines, deferred calls, generics, reflection in helpers,
broken packages, missing dependencies, replacement downgrades, forks, prereleases,
pseudo-versions, and matching each SVG to the reported symbol and call edge.
Concurrency checks run fresh scans with 1, 4, and 8 workers, using multiple
modules and multiple affected packages. Unit tests inject advisory transport,
timeout, HTTP status, malformed JSON, and truncated-body failures and check
version boundaries, including ranges without a fixed version.
