package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCallgraphArgs(t *testing.T) {
	for _, algo := range []string{"rta", "vta", "cha", "static"} {
		for _, mode := range []string{"cve", "go", "manual", "manual with cve"} {
			t.Run(algo+"/"+mode, func(t *testing.T) {
				req := CallgraphRequest{Algo: algo}
				want := []string{"-progress", "-algo=" + algo, "-graph=/graphs"}
				switch mode {
				case "cve":
					req.CVE = "CVE-2024-45338"
				case "go":
					req.CVE = "GO-2024-3333"
				case "manual", "manual with cve":
					req.Library = "golang.org/x/net/html"
					req.Symbol = "Parse,ParseFragment"
					req.FixVersion = "v0.33.0"
					want = append(want, "-library", "golang.org/x/net/html", "-symbols", "Parse,ParseFragment", "-fixversion", "v0.33.0")
					if mode == "manual with cve" {
						req.CVE = "CVE-2024-45338"
					}
				}
				want = append(want, "--")
				if req.CVE != "" {
					want = append(want, req.CVE)
				}
				want = append(want, "-checkout")
				if got := callgraphArgs(req, "-checkout", "/graphs"); !reflect.DeepEqual(got, want) {
					t.Errorf("arguments = %#v, want %#v", got, want)
				}
			})
		}
	}
}

func TestStartCallgraphValidation(t *testing.T) {
	prepareTaskTest(t)
	valid := CallgraphRequest{Repo: "https://github.com/example/repo", BranchOrCommit: "main", CVE: "CVE-2024-45338", Algo: "rta"}
	for _, tc := range []struct {
		name   string
		change func(*CallgraphRequest)
	}{
		{"missing repo", func(r *CallgraphRequest) { r.Repo = "" }},
		{"missing branch", func(r *CallgraphRequest) { r.BranchOrCommit = "" }},
		{"missing cve", func(r *CallgraphRequest) { r.CVE = "" }},
		{"unknown algorithm", func(r *CallgraphRequest) { r.Algo = "unknown" }},
		{"library only", func(r *CallgraphRequest) { r.Library = "golang.org/x/net/html" }},
		{"symbol only", func(r *CallgraphRequest) { r.Symbol = "Parse" }},
		{"fixed version only", func(r *CallgraphRequest) { r.FixVersion = "v0.33.0" }},
		{"missing manual version", func(r *CallgraphRequest) { r.Library, r.Symbol = "golang.org/x/net/html", "Parse" }},
		{"long request ID", func(r *CallgraphRequest) { r.RequestID = strings.Repeat("r", 129) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.change(&req)
			_, err := StartCallgraph(req, "http://gvs.example.com")
			requireTaskError(t, err, "invalid_argument")
		})
	}
}

func TestStartCallgraphCachedResults(t *testing.T) {
	for _, algo := range []string{"", "rta", "vta", "cha", "static"} {
		for _, manual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/manual=%t", algo, manual), func(t *testing.T) {
				oldCacheDir := cacheDir
				cacheDir = t.TempDir()
				t.Cleanup(func() { cacheDir = oldCacheDir })
				prepareTaskTest(t)
				graphDir := filepath.Join(cacheDir, "graph")
				t.Setenv("GVS_GRAPH_CACHE", graphDir)
				req := CallgraphRequest{Repo: "https://github.com/example/repo", BranchOrCommit: "release/1.0", CVE: "CVE-2024-45338", Algo: algo, RequestID: "cache-request"}
				if algo == "" {
					req.RequestID = strings.Repeat("雪", 128)
				}
				if manual {
					req.CVE, req.Library, req.Symbol, req.FixVersion = "", "golang.org/x/net/html", "Parse,ParseFragment", "v0.33.0"
				}
				normalized := req
				if normalized.Algo == "" {
					normalized.Algo = "rta"
				}
				key := callgraphCacheKey(normalized)
				const graphSuffix = "CVE-2024-45338/repo/release-1.0/rta/library-symbol.svg"
				output := fmt.Sprintf(`{"IsVulnerable":"true","GraphPaths":[%q,%q],"future":{"huge":9007199254740993123456789}}`, filepath.Join(graphDir, graphSuffix), "http://old-host:9099/graph/"+graphSuffix)
				if err := SaveCacheToDisk(key, []byte(output)); err != nil {
					t.Fatal(err)
				}
				const logs = "original cached analysis logs\n"
				if err := SaveCacheLogsToDisk(key, []byte(logs)); err != nil {
					t.Fatal(err)
				}
				task, err := StartCallgraph(req, "https://public.example.com/gvs/")
				if err != nil {
					t.Fatal(err)
				}
				waitTaskWorkers(t)
				result, err := GetTask(task.TaskID)
				if err != nil || result.Status != StatusCompleted || !result.Cached || result.Logs != logs {
					t.Fatalf("cached result = %+v, error %v", result, err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal([]byte(result.Output), &fields); err != nil {
					t.Fatal(err)
				}
				var paths []string
				if err := json.Unmarshal(fields["GraphPaths"], &paths); err != nil {
					t.Fatal(err)
				}
				wantPath := "https://public.example.com/gvs/graph/" + graphSuffix
				if !reflect.DeepEqual(paths, []string{wantPath, wantPath}) {
					t.Errorf("graph paths = %v, want current public base URL %q", paths, wantPath)
				}
				if string(fields["future"]) != `{"huge":9007199254740993123456789}` {
					t.Errorf("unknown fields or number precision lost: %s", fields["future"])
				}
				artifact, err := ReadTaskResult(task.TaskID)
				if err != nil || !strings.Contains(string(artifact), `original cached analysis logs\n`) {
					t.Errorf("cached artifact lost logs: %s, error %v", artifact, err)
				}
				again, err := StartCallgraph(normalized, "https://public.example.com/gvs/")
				if err != nil || again.TaskID != task.TaskID {
					t.Errorf("retry of normalized request = %+v, error %v", again, err)
				}
				cached, err := RetrieveCacheFromDisk(key)
				if err != nil || string(cached) != output {
					t.Error("reading a cached result rewrote the stored artifact")
				}
				otherAlgorithm := normalized
				otherAlgorithm.Algo = "different-algorithm"
				if _, err := RetrieveCacheFromDisk(callgraphCacheKey(otherAlgorithm)); !os.IsNotExist(err) {
					t.Errorf("algorithm-specific cache lookup = %v, want missing", err)
				}
			})
		}
	}
}
