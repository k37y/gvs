package cg

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestMatchesSymbolIdentity(t *testing.T) {
	const source = `package main
func Danger() {}
func DangerExtra() {}
func Generic[T any](v T) {}
type Parser struct{}
func (Parser) Answer() {}
type Other struct{}
func (Other) Answer() {}
type Reader struct{}
func (*Reader) Read() {}
type Box[T any] struct{}
func (Box[T]) Answer() {}
type Embedded struct { Parser }
func invoke(v interface{ Answer() }) { v.Answer() }
func closure() func() { return func() {} }
func main() {
	Danger(); DangerExtra(); Generic(1)
	p := Parser{}; p.Answer(); Other{}.Answer(); Box[int]{}.Answer()
	new(Reader).Read()
	f := p.Answer; f()
	g := Parser.Answer; g(p)
	e := Embedded{}; invoke(&e)
	closure()()
}`
	for _, path := range []string{"example.com/lib", "vendor/example.com/lib", "example.com/libextra"} {
		t.Run(path, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "main.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			pkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, types.NewPackage(path, "main"), []*ast.File{file}, ssa.InstantiateGenerics)
			if err != nil {
				t.Fatal(err)
			}
			for _, algo := range []string{"rta", "vta", "cha", "static"} {
				t.Run(algo, func(t *testing.T) {
					graph := buildCallGraph(pkg.Prog, algo)
					entry := graph.Nodes[pkg.Func("main")]
					for _, tc := range []struct {
						pkg, symbol string
						want        bool
					}{
						{path, "Danger", true},
						{path, path + ".Danger", true},
						{path, "Dang", false},
						{path, "Parser.Answer", true},
						{path, "(" + path + ".Parser).Answer", true},
						{path, "(*" + path + ".Reader).Read", true},
						{path, "(" + path + ".Reader).Read", false},
						{path, "Missing.Answer", false},
						{path, "Answer", false},
						{path, "Generic", true},
						{path, "Box.Answer", true},
						{"example.com/lib", "Danger", path == "example.com/lib"},
						{"example.com/li", "Parser.Answer", false},
					} {
						_, got := findPathToSymbol(entry, tc.pkg, tc.symbol, false)
						if got != tc.want {
							t.Errorf("%s %s: reachable = %v, want %v", tc.pkg, tc.symbol, got, tc.want)
						}
					}
				})
			}
			if matchesSymbol(&callgraph.Node{Func: pkg.Func("DangerExtra")}, path, "Danger") {
				t.Error("function name prefix matched a different function")
			}
			seen := map[string]bool{}
			for fn := range ssautil.AllFunctions(pkg.Prog) {
				node := &callgraph.Node{Func: fn}
				if fn.Parent() != nil && matchesSymbol(node, path, fn.Parent().Name()) {
					t.Errorf("closure %s matched its parent's identity", fn)
				}
				obj, ok := fn.Object().(*types.Func)
				if !ok || obj.Name() != "Answer" {
					continue
				}
				if strings.HasSuffix(fn.Name(), "$bound") || strings.HasSuffix(fn.Name(), "$thunk") || strings.HasPrefix(fn.Synthetic, "wrapper") {
					want := obj.Type().(*types.Signature).Recv().Type().String() == path+".Parser"
					if want {
						seen[fn.Synthetic] = true
					}
					if matchesSymbol(node, path, "Parser.Answer") != want {
						t.Errorf("method wrapper %s has incorrect declaring method identity", fn)
					}
				}
				if strings.Contains(fn.String(), ".Other)") && matchesSymbol(node, path, "Parser.Answer") {
					t.Errorf("method %s matched a different receiver", fn)
				}
			}
			if len(seen) < 3 {
				t.Fatalf("fixture must exercise bound, thunk, and promoted wrappers: %v", seen)
			}
		})
	}
}
