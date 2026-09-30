package cg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const reflectionNoiseFixture = `package sample
import (
 "fmt"
 "reflect"
)
type unrelated struct{}
func (unrelated) Convert() {}
func (unrelated) Interface() {}
func (unrelated) PrintlnExtra() {}
func examine() {
 v := reflect.ValueOf(fmt.Println)
 v.Call(nil)
 other := unrelated{}
 other.Convert()
 other.Interface()
 other.PrintlnExtra()
 s := "Println is only mentioned in this message"
 _ = s
 x := reflect.ValueOf(123)
 _ = x.Interface()
 _ = reflect.TypeOf(123)
}
`

func TestReflectionOutputMeasurement(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/sample\n\ngo 1.27\n"), 0600)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(reflectionNoiseFixture), 0600)
	r := &Result{}
	risks := r.detectReflectionVulnerabilities("fmt", dir, []string{"Println"}, []string{"main.go"})
	if len(risks) != 2 {
		t.Fatalf("want value reference and invocation, got %+v", risks)
	}
	for _, risk := range risks {
		if risk.Symbol != "Println" || risk.Association != "target_linked" {
			t.Fatalf("unexpected risk: %+v", risk)
		}
	}
	data, _ := json.MarshalIndent(risks, "", "  ")
	t.Logf("reflection fixture: entries=%d bytes=%d lines=%d\n%s", len(risks), len(data), strings.Count(string(data), "\n")+1, data)
}

func TestTypedDynamicCandidates(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/dynamic\n\ngo 1.27\n",
		"target/target.go": `package target
 type Parser struct{}
 func (*Parser) Parse() {}
 func Parse() {}
 func ParseFragment() {}
 `,
		"other/other.go": `package other
 func Parse() {}
 type Parser struct{}
 func (Parser) Parse() {}
 func (Parser) MethodByName(string) {}
 func (Parser) Convert() {}
 `,
		"main.go": `package main
 import (r "reflect"; "example.com/dynamic/target"; "example.com/dynamic/other")
 func main() {
  p := &target.Parser{}
  const name = "Parse"
  r.ValueOf(p).MethodByName(name).Call(nil)
  r.ValueOf(target.Parse).Call(nil)
  r.ValueOf(other.Parse).Call(nil)
  r.ValueOf(target.ParseFragment).Call(nil)
  r.ValueOf(other.Parser{}).MethodByName("Parse").Call(nil)
  other.Parser{}.MethodByName("Parse")
  other.Parser{}.Convert()
 }
 func unknown(v r.Value, name string) {v.MethodByName(name).Call(nil)}
 func branch(v r.Value, name string) {
  var f r.Value
  if name=="x" {f=r.ValueOf(target.Parse)} else {f=v}
  f.Call(nil)
 }
 `,
		"registry.go": `package main
 import "example.com/dynamic/target"
 var callbacks = map[string]func(){"run": target.Parse}
 func register(){callbacks["other"]=target.Parse}
 `,
		"memory.go": `package main
 import "unsafe"
 func memory(p unsafe.Pointer) unsafe.Pointer {return unsafe.Add(p, 1)}
 `,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Result{}
	paths := []string{"main.go", "registry.go", "memory.go", "main.go"}
	risks := r.detectReflectionVulnerabilities("example.com/dynamic/target", dir, []string{"Parse", "Parser.Parse"}, paths)
	kinds := map[string]int{}
	for _, risk := range risks {
		kinds[risk.Type]++
		if risk.Association == "target_linked" && (risk.Package != "example.com/dynamic/target" || (risk.Symbol != "Parse" && risk.Symbol != "Parser.Parse")) {
			t.Errorf("invented target: %+v", risk)
		}
		if risk.Association == "unresolved" && (risk.Package != "" || risk.Symbol != "") {
			t.Errorf("unresolved target assigned: %+v", risk)
		}
		if strings.Contains(risk.Location, "main.go:8:") || strings.Contains(risk.Location, "main.go:9:") || strings.Contains(risk.Location, "main.go:10:") || strings.Contains(risk.Location, "main.go:11:") || strings.Contains(risk.Location, "main.go:12:") {
			t.Errorf("unrelated operation matched: %+v", risk)
		}
	}
	for _, kind := range []string{"method_lookup", "value_of", "reflection_call", "function_registry", "unsafe_pointer"} {
		if kinds[kind] == 0 {
			t.Errorf("missing %s in %+v", kind, risks)
		}
	}
	if kinds["function_registry"] != 2 {
		t.Errorf("registries missing/duplicated: %v", kinds)
	}
	unresolved := 0
	method := false
	for _, risk := range risks {
		if risk.Association == "unresolved" {
			unresolved++
		}
		if risk.Symbol == "Parser.Parse" && risk.Type == "reflection_call" {
			method = true
		}
	}
	if unresolved < 2 || !method {
		t.Fatalf("lost unresolved or typed receiver: %+v", risks)
	}
	// Reuse cached typed source across affected-package checks and deduplicate
	// generic operations without conflating different affected targets.
	cache := r.reflectionBuilds[dir]
	other := r.detectReflectionVulnerabilities("example.com/dynamic/other", dir, []string{"Parse"}, paths)
	if r.reflectionBuilds[dir] != cache {
		t.Fatal("source cache replaced")
	}
	combined := mergeReflectionRisks(risks, other)
	if len(mergeReflectionRisks(combined, combined)) != len(combined) {
		t.Fatal("duplicate risk accumulation")
	}
}

func TestReflectionAliasesAndIncompleteTypes(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/aliases\n\ngo 1.27\n",
		"main.go": `package aliases
 import (. "reflect"; f "fmt")
 func invoke(){ValueOf(f.Println).Call(nil)}
 func escaped(v Value){v.Interface().(func())()}
 `,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Result{}
	risks := r.detectReflectionVulnerabilities("fmt", dir, []string{"Println"}, []string{"main.go"})
	linked, unknown := 0, 0
	for _, risk := range risks {
		if risk.Association == "target_linked" {
			linked++
		}
		if risk.Association == "unresolved" {
			unknown++
		}
	}
	if linked != 2 || unknown != 1 {
		t.Fatalf("alias or interface escape lost: %+v", risks)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package aliases\nimport \"reflect\"\nfunc broken(){reflect.ValueOf(missing).Call(nil)}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r = &Result{}
	risks = r.detectReflectionVulnerabilities("fmt", dir, []string{"Println"}, []string{"broken.go"})
	incomplete := false
	for _, risk := range risks {
		if risk.Type == "analysis_incomplete" && risk.Association == "unresolved" {
			incomplete = true
		}
	}
	if !incomplete {
		t.Fatalf("type errors hidden: %+v", risks)
	}
}

func TestReflectionMethodSetAndEmptyName(t *testing.T) {
	dir := t.TempDir()
	code := `package sample
 import "reflect"
 type Parser struct{}
 func (*Parser) Parse(){}
 func cases(){
  reflect.ValueOf(Parser{}).MethodByName("Parse")
  reflect.ValueOf(&Parser{}).MethodByName("")
  reflect.ValueOf(&Parser{}).Elem().MethodByName("Parse")
  reflect.New(reflect.TypeOf(Parser{})).MethodByName("Parse").Call(nil)
 }
 `
	for name, content := range map[string]string{"go.mod": "module example.com/sample\n\ngo 1.27\n", "main.go": code} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Result{}
	risks := r.detectReflectionVulnerabilities("example.com/sample", dir, []string{"Parser.Parse"}, []string{"main.go"})
	if len(risks) != 2 {
		t.Fatalf("expected only New's method lookup and call: %+v", risks)
	}
	for _, risk := range risks {
		if !strings.Contains(risk.Location, "main.go:9:") {
			t.Fatalf("impossible reflected method matched: %+v", risk)
		}
	}
}

func TestReflectionGapsRequireDynamicSource(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		gap          bool
	}{
		{"ordinary type error", "package sample\nimport \"fmt\"\nfunc broken(){fmt.Println(missing)}\n", false},
		{"excluded ordinary file", "//go:build gvs_reflection_gap_fixture\n\npackage sample\nimport \"fmt\"\nfunc excluded(){fmt.Println(1)}\n", false},
		{"reflection type error", "package sample\nimport \"reflect\"\nfunc broken(){reflect.ValueOf(missing).Call(nil)}\n", true},
		{"excluded reflection file", "//go:build gvs_reflection_gap_fixture\n\npackage sample\nimport \"reflect\"\nfunc excluded(v reflect.Value){v.Call(nil)}\n", true},
		{"excluded unsafe file", "//go:build gvs_reflection_gap_fixture\n\npackage sample\nimport \"unsafe\"\nfunc excluded(p unsafe.Pointer){_ = unsafe.Add(p,1)}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range map[string]string{"go.mod": "module example.com/gap\n\ngo 1.27\n", "main.go": "package sample\n", "candidate.go": tc.source} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r := &Result{}
			risks := r.detectReflectionVulnerabilities("fmt", dir, []string{"Println"}, []string{"main.go", "candidate.go"})
			gap := false
			for _, risk := range risks {
				if risk.Type == "analysis_incomplete" {
					gap = true
					if !strings.Contains(risk.Location, "candidate.go:") {
						t.Errorf("gap attributed to unrelated source: %+v", risk)
					}
				}
			}
			if gap != tc.gap || (!tc.gap && len(risks) > 0) {
				t.Fatalf("gap=%v want=%v; risks=%+v", gap, tc.gap, risks)
			}
		})
	}
}
