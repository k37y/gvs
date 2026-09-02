package main

import (
	"encoding/hex"
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
