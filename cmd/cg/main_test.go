package main

import (
	"encoding/hex"
	"github.com/k37y/gvs/pkg/cmd/cg"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func TestGenerateRandomFilename(t *testing.T) {
	name := generateRandomFilename()
	if len(name) != 8 {
		t.Errorf("expected 8-char hex string, got %q (len=%d)", name, len(name))
	}
	if _, err := hex.DecodeString(name); err != nil {
		t.Errorf("expected valid hex, got %q: %v", name, err)
	}
}

func TestGenerateRandomFilename_Unique(t *testing.T) {
	a := generateRandomFilename()
	b := generateRandomFilename()
	if a == b {
		t.Errorf("two calls returned same value: %q", a)
	}
}

func TestPathToDOT_Empty(t *testing.T) {
	dot := pathToDOT(nil)
	if !strings.Contains(dot, "digraph callgraph") {
		t.Errorf("expected digraph header, got: %s", dot)
	}
	if strings.Contains(dot, "->") {
		t.Error("expected no edges for nil path")
	}
}

func TestPathToDOT_SingleNode(t *testing.T) {
	node := &callgraph.Node{Func: nil}
	dot := pathToDOT([]*callgraph.Node{node})
	if strings.Contains(dot, "->") {
		t.Error("expected no edges for single node")
	}
}

func TestPathToDOT_TwoNodes(t *testing.T) {
	prog := &ssa.Program{}
	_ = prog
	n1 := &callgraph.Node{Func: nil}
	n2 := &callgraph.Node{Func: nil}
	dot := pathToDOT([]*callgraph.Node{n1, n2})
	if !strings.Contains(dot, `"unknown" -> "unknown"`) {
		t.Errorf("expected unknown->unknown edge, got: %s", dot)
	}
}

func TestIsFlagPassed(t *testing.T) {
	// isFlagPassed uses flag.Visit on the default FlagSet,
	// which only includes flags that were actually set via flag.Parse.
	// Since we don't call flag.Parse in tests, no flags are "passed".
	if isFlagPassed("nonexistent") {
		t.Error("expected false for unset flag")
	}
}

func TestNormalizeUsedImportsKeepsSymbolPaths(t *testing.T) {
	alpha, zed := &callgraph.Node{ID: 1}, &callgraph.Node{ID: 2}
	result := &cg.Result{UsedImports: map[string]map[string]cg.UsedImportsDetails{
		"a": {"example.com/lib": {Symbols: []string{"Zed", "example.com/lib.Alpha", "example.com/lib.Zed"}, Paths: [][]*callgraph.Node{{zed}, {alpha}, {zed}}}},
		"b": {"example.com/lib": {Symbols: []string{"Zed"}, Paths: [][]*callgraph.Node{{alpha, zed}}}},
	}}
	normalizeUsedImports(result)
	first := result.UsedImports["a"]["example.com/lib"]
	if !reflect.DeepEqual(first.Symbols, []string{"Alpha", "Zed"}) {
		t.Fatalf("symbols = %v", first.Symbols)
	}
	if !reflect.DeepEqual(first.Paths, [][]*callgraph.Node{{alpha}, {zed}}) {
		t.Errorf("sorting or deduplication changed symbol-path association: %v", first.Paths)
	}
	second := result.UsedImports["b"]["example.com/lib"]
	if !reflect.DeepEqual(second.Paths, [][]*callgraph.Node{{alpha, zed}}) {
		t.Errorf("module path overwritten: %v", second.Paths)
	}
}

func TestNormalizeUsedImportsKeepsPresentPackages(t *testing.T) {
	result := &cg.Result{UsedImports: map[string]map[string]cg.UsedImportsDetails{
		".": {"net": {}, "example.com/lib": {CurrentVersion: "v1.0.0"}},
	}}
	normalizeUsedImports(result)
	if len(result.UsedImports["."]) != 2 {
		t.Fatalf("present packages removed: %v", result.UsedImports)
	}
	for pkg, details := range result.UsedImports["."] {
		if len(details.Symbols) != 0 || len(details.Paths) != 0 || len(details.FixCommands) != 0 {
			t.Errorf("presence alone added usage for %s: %+v", pkg, details)
		}
	}
}
