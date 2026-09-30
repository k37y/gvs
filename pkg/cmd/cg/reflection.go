package cg

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
)

// Cache typed source and candidate extraction once per module, across affected
// packages. Candidates describe possible usage, never runtime reachability.
type reflectionBuild struct {
	once  sync.Once
	mu    sync.Mutex
	files map[string][]dynamicCandidate
}

type dynamicOrigin struct {
	objects   []types.Object
	types     []types.Type
	unknown   bool
	reflected bool
}
type dynamicCandidate struct {
	kind, location, evidence string
	origin                   dynamicOrigin
	keepUnknown              bool
}
type dynamicSource struct {
	info        *types.Info
	fset        *token.FileSet
	definitions map[types.Object][]ast.Expr
}

func (r *Result) detectReflectionVulnerabilities(pkg, dir string, symbols, files []string) []ReflectionRisk {
	r.Mu.Lock()
	if r.reflectionBuilds == nil {
		r.reflectionBuilds = make(map[string]*reflectionBuild)
	}
	cache := r.reflectionBuilds[dir]
	if cache == nil {
		cache = &reflectionBuild{}
		r.reflectionBuilds[dir] = cache
	}
	build := r.ssaBuilds[dir]
	r.Mu.Unlock()
	cache.once.Do(func() {
		cache.files = make(map[string][]dynamicCandidate)
		var loaded []*packages.Package
		if build != nil {
			loaded = build.loadedPkgs
		}
		if len(loaded) == 0 {
			loaded, _ = packages.Load(&packages.Config{Context: r.ctx(), Dir: dir, Mode: packages.LoadAllSyntax}, "./...")
		}
		root, _ := filepath.Abs(dir)
		packages.Visit(loaded, nil, func(p *packages.Package) {
			source := dynamicSource{info: p.TypesInfo, fset: p.Fset, definitions: make(map[types.Object][]ast.Expr)}
			if source.info == nil || source.fset == nil {
				return
			}
			var local []*ast.File
			for _, file := range p.Syntax {
				name := source.fset.Position(file.Pos()).Filename
				rel, err := filepath.Rel(root, name)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					continue
				}
				local = append(local, file)
			}
			for _, file := range local {
				source.collectDefinitions(file)
			}
			for _, file := range local {
				name := source.fset.Position(file.Pos()).Filename
				cache.files[filepath.Clean(name)] = source.candidates(file)
				if p.IllTyped && importsDynamicPackage(file) {
					cache.files[filepath.Clean(name)] = append(cache.files[filepath.Clean(name)], dynamicCandidate{kind: "analysis_incomplete", location: fmt.Sprintf("%s:1:1", name), evidence: "Package has type errors; dynamic targets may be missing", origin: dynamicOrigin{unknown: true}, keepUnknown: true})
				}
			}
		})
	})
	cache.mu.Lock()
	defer cache.mu.Unlock()
	var risks []ReflectionRisk
	for _, file := range files {
		name := file
		if !filepath.IsAbs(name) {
			name = filepath.Join(dir, name)
		}
		name, _ = filepath.Abs(name)
		candidates, ok := cache.files[name]
		if !ok {
			// General build/load failures belong in Result.Errors. Add a dynamic
			// coverage gap only for source importing reflect or unsafe.
			fs := token.NewFileSet()
			if parsed, err := parser.ParseFile(fs, name, nil, parser.ImportsOnly); err == nil {
				if importsDynamicPackage(parsed) {
					candidates = []dynamicCandidate{{kind: "analysis_incomplete", location: fmt.Sprintf("%s:1:1", name), evidence: "File is outside available typed source; check build constraints and dynamic usage", origin: dynamicOrigin{unknown: true}, keepUnknown: true}}
				}
			}
			cache.files[name] = candidates
		}
		for _, candidate := range candidates {
			matched := false
			for _, symbol := range symbols {
				if !candidate.origin.matches(pkg, symbol) {
					continue
				}
				matched = true
				evidence := candidate.evidence
				if candidate.origin.unknown {
					evidence += "; value flow includes unresolved alternatives"
				}
				risks = append(risks, ReflectionRisk{Type: candidate.kind, Confidence: "medium", Location: candidate.location, Evidence: []string{evidence}, Symbol: symbol, Package: pkg, Association: "target_linked"})
			}
			if !matched && candidate.keepUnknown && candidate.origin.unknown {
				risks = append(risks, ReflectionRisk{Type: candidate.kind, Confidence: "low", Location: candidate.location, Evidence: []string{candidate.evidence + "; affected target unresolved"}, Association: "unresolved"})
			}
		}
	}
	return mergeReflectionRisks(nil, risks)
}

func importsDynamicPackage(file *ast.File) bool {
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"`")
		if path == "reflect" || path == "unsafe" {
			return true
		}
	}
	return false
}

func (s *dynamicSource) collectDefinitions(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		var lhs, rhs []ast.Expr
		switch n := n.(type) {
		case *ast.AssignStmt:
			lhs, rhs = n.Lhs, n.Rhs
		case *ast.ValueSpec:
			rhs = n.Values
			for _, name := range n.Names {
				lhs = append(lhs, name)
			}
		}
		for i, left := range lhs {
			id, ok := left.(*ast.Ident)
			if !ok {
				continue
			}
			obj := s.info.ObjectOf(id)
			if obj == nil {
				continue
			}
			var value ast.Expr
			if len(lhs) == len(rhs) {
				value = rhs[i]
			}
			s.definitions[obj] = append(s.definitions[obj], value)
		}
		return true
	})
}

func (s *dynamicSource) object(expr ast.Expr) types.Object {
	switch expr := expr.(type) {
	case *ast.Ident:
		return s.info.ObjectOf(expr)
	case *ast.SelectorExpr:
		return s.info.ObjectOf(expr.Sel)
	case *ast.ParenExpr:
		return s.object(expr.X)
	case *ast.IndexExpr:
		return s.object(expr.X)
	case *ast.IndexListExpr:
		return s.object(expr.X)
	}
	return nil
}
func objectPackage(obj types.Object) string {
	if obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path()
	}
	return ""
}
func reflectedObject(obj types.Object) bool { return objectPackage(obj) == "reflect" }
func symbolForObject(obj types.Object) string {
	if obj == nil {
		return ""
	}
	name := obj.Name()
	if fn, ok := obj.(*types.Func); ok {
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			typ := types.Unalias(sig.Recv().Type())
			if ptr, ok := typ.(*types.Pointer); ok {
				typ = types.Unalias(ptr.Elem())
			}
			if named, ok := typ.(*types.Named); ok {
				name = named.Obj().Name() + "." + name
			}
		}
	}
	return name
}
func (o dynamicOrigin) matches(pkg, symbol string) bool {
	for _, obj := range o.objects {
		if objectPackage(obj) == pkg && symbolForObject(obj) == symbol {
			return true
		}
	}
	return false
}
func (o *dynamicOrigin) add(other dynamicOrigin) {
	o.objects = append(o.objects, other.objects...)
	o.types = append(o.types, other.types...)
	o.unknown = o.unknown || other.unknown
	o.reflected = o.reflected || other.reflected
}

func (s *dynamicSource) origin(expr ast.Expr, visiting map[types.Object]bool, depth int) dynamicOrigin {
	if expr == nil || depth > 20 {
		return dynamicOrigin{unknown: true}
	}
	out := dynamicOrigin{}
	typ := s.info.TypeOf(expr)
	out.reflected = isReflectType(typ)
	if typ != nil {
		out.types = append(out.types, typ)
		if _, ok := typ.Underlying().(*types.Interface); ok {
			out.unknown = true
		}
	}
	switch expr := expr.(type) {
	case *ast.IndexExpr:
		if obj, ok := s.object(expr).(*types.Func); ok {
			out.objects = append(out.objects, obj)
			return out
		}
	case *ast.IndexListExpr:
		if obj, ok := s.object(expr).(*types.Func); ok {
			out.objects = append(out.objects, obj)
			return out
		}
	case *ast.TypeAssertExpr:
		return s.origin(expr.X, visiting, depth+1)
	case *ast.ParenExpr:
		return s.origin(expr.X, visiting, depth+1)
	case *ast.UnaryExpr:
		out.add(s.origin(expr.X, visiting, depth+1))
		return out
	case *ast.Ident:
		obj := s.info.ObjectOf(expr)
		if obj == nil {
			return dynamicOrigin{unknown: true}
		}
		if _, ok := obj.(*types.Func); ok {
			out.objects = append(out.objects, obj)
			return out
		}
		values := s.definitions[obj]
		if len(values) > 0 && !visiting[obj] {
			visiting[obj] = true
			for _, value := range values {
				out.add(s.origin(value, visiting, depth+1))
			}
			delete(visiting, obj)
			return out
		}
		if _, ok := typUnderlying(typ).(*types.Signature); ok {
			out.unknown = true
		}
		if isReflectType(typ) || visiting[obj] {
			out.unknown = true
		}
		return out
	case *ast.SelectorExpr:
		obj := s.object(expr)
		if _, ok := obj.(*types.Func); ok {
			out.objects = append(out.objects, obj)
		} else if isReflectType(typ) {
			out.unknown = true
		}
		return out
	case *ast.CallExpr:
		obj := s.object(expr.Fun)
		if reflectedObject(obj) {
			switch obj.Name() {
			case "ValueOf", "TypeOf", "Indirect", "New", "NewAt":
				if len(expr.Args) > 0 {
					origin := s.origin(expr.Args[0], visiting, depth+1)
					origin.reflected = true
					if obj.Name() == "New" || obj.Name() == "NewAt" {
						origin = transformDynamicTypes(origin, "Addr")
					}
					if obj.Name() == "Indirect" {
						origin = transformDynamicTypes(origin, "Elem")
					}
					return origin
				}
			case "MethodByName", "Method":
				if sel, ok := expr.Fun.(*ast.SelectorExpr); ok {
					receiver := s.origin(sel.X, visiting, depth+1)
					name, known := "", false
					if obj.Name() == "MethodByName" && len(expr.Args) > 0 {
						name, known = s.stringConstant(expr.Args[0])
					}
					methods := dynamicOrigin{unknown: receiver.unknown, reflected: true}
					for _, typ := range receiver.types {
						if isReflectType(typ) {
							continue
						}
						if known {
							if method, _, _ := types.LookupFieldOrMethod(typ, false, nil, name); method != nil {
								methods.objects = append(methods.objects, method)
							}
						} else {
							methods.unknown = true
							for _, t := range []types.Type{typ} {
								set := types.NewMethodSet(t)
								for i := 0; i < set.Len(); i++ {
									methods.objects = append(methods.objects, set.At(i).Obj())
								}
							}
						}
					}
					return methods
				}
			case "Elem", "Interface", "Convert", "Addr":
				if sel, ok := expr.Fun.(*ast.SelectorExpr); ok {
					origin := s.origin(sel.X, visiting, depth+1)
					if obj.Name() == "Elem" || obj.Name() == "Addr" {
						origin = transformDynamicTypes(origin, obj.Name())
					}
					return origin
				}
			}
		}
		// Unknown function results and memory transformations need further analysis.
		// Retain their concrete result type, but do not treat it as proven value flow.
		if isReflectType(typ) || objectPackage(obj) == "unsafe" {
			out.unknown = true
		}
		if tv, ok := s.info.Types[expr.Fun]; ok && tv.IsType() && len(expr.Args) > 0 {
			out.add(s.origin(expr.Args[0], visiting, depth+1))
		}
		return out
	}
	if isReflectType(typ) {
		out.unknown = true
	}
	return out
}

// Reflect method sets follow the value's actual type; Go's implicit address
// taking must not invent pointer-receiver methods on a non-pointer Value.
func transformDynamicTypes(origin dynamicOrigin, operation string) dynamicOrigin {
	var transformed []types.Type
	for _, typ := range origin.types {
		if isReflectType(typ) {
			continue
		}
		if operation == "Addr" {
			transformed = append(transformed, types.NewPointer(typ))
			continue
		}
		if ptr, ok := types.Unalias(typ).(*types.Pointer); ok {
			transformed = append(transformed, ptr.Elem())
		}
		if _, ok := typ.Underlying().(*types.Interface); ok {
			origin.unknown = true
		}
	}
	origin.types = transformed
	if len(transformed) == 0 && !origin.unknown {
		origin.objects = nil
	}
	return origin
}

func typUnderlying(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}
func isReflectType(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, ok := t.(*types.Named)
	return ok && objectPackage(n.Obj()) == "reflect"
}
func (s *dynamicSource) stringConstant(expr ast.Expr) (string, bool) {
	if tv, ok := s.info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		return constant.StringVal(tv.Value), true
	}
	return "", false
}

func (s *dynamicSource) candidates(file *ast.File) []dynamicCandidate {
	var result []dynamicCandidate
	emit := func(node ast.Node, kind, evidence string, origin dynamicOrigin, keepUnknown bool) {
		pos := s.fset.Position(node.Pos())
		result = append(result, dynamicCandidate{kind: kind, location: fmt.Sprintf("%s:%d:%d", pos.Filename, pos.Line, pos.Column), evidence: evidence, origin: origin, keepUnknown: keepUnknown})
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			obj := s.object(n.Fun)
			if reflectedObject(obj) {
				switch obj.Name() {
				case "ValueOf":
					if len(n.Args) > 0 {
						emit(n, "value_of", "Affected value passed to reflect.ValueOf; invocation not established", s.origin(n.Args[0], make(map[types.Object]bool), 0), false)
					}
				case "MethodByName", "Method":
					emit(n, "method_lookup", "Typed reflection method lookup; invocation not established", s.origin(n, make(map[types.Object]bool), 0), true)
				case "Call", "CallSlice":
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
						emit(n, "reflection_call", "Typed reflect."+obj.Name()+" invocation; validate entry-point reachability", s.origin(sel.X, make(map[types.Object]bool), 0), true)
					}
				case "NewAt":
					emit(n, "unsafe_pointer", "reflect.NewAt constructs a value from raw memory; target requires investigation", dynamicOrigin{unknown: true}, true)
				}
			}
			if obj == nil {
				origin := s.origin(n.Fun, make(map[types.Object]bool), 0)
				if origin.reflected {
					emit(n, "reflection_call", "Function obtained through reflection is invoked; validate the target and entry point", origin, true)
				}
			}
			if objectPackage(obj) == "unsafe" && (obj.Name() == "Pointer" || obj.Name() == "Add" || obj.Name() == "Slice" || obj.Name() == "String") {
				origin := dynamicOrigin{unknown: true}
				for _, arg := range n.Args {
					origin.add(s.origin(arg, make(map[types.Object]bool), 0))
				}
				emit(n, "unsafe_pointer", "unsafe."+obj.Name()+" memory operation; no affected invocation established", origin, true)
			}
		case *ast.CompositeLit:
			if _, ok := typUnderlying(s.info.TypeOf(n)).(*types.Map); ok {
				for _, elt := range n.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						emit(kv, "function_registry", "Affected function stored in a map; lookup and invocation require investigation", s.origin(kv.Value, make(map[types.Object]bool), 0), false)
					}
				}
			}
		case *ast.AssignStmt:
			for i, left := range n.Lhs {
				if len(n.Lhs) != len(n.Rhs) {
					continue
				}
				if index, ok := left.(*ast.IndexExpr); ok {
					if _, ok := typUnderlying(s.info.TypeOf(index.X)).(*types.Map); ok {
						emit(n, "function_registry", "Affected function assigned to a map entry; invocation not established", s.origin(n.Rhs[i], make(map[types.Object]bool), 0), false)
					}
				}
			}
		}
		return true
	})
	return result
}

func mergeReflectionRisks(existing, added []ReflectionRisk) []ReflectionRisk {
	byKey := make(map[string]ReflectionRisk, len(existing)+len(added))
	for _, risks := range [][]ReflectionRisk{existing, added} {
		for _, risk := range risks {
			key := risk.Location + "\x00" + risk.Type + "\x00" + risk.Package + "\x00" + risk.Symbol + "\x00" + risk.Association
			previous, ok := byKey[key]
			if ok {
				risk.Evidence = append(append([]string(nil), previous.Evidence...), risk.Evidence...)
			}
			sort.Strings(risk.Evidence)
			risk.Evidence = compactStrings(risk.Evidence)
			byKey[key] = risk
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ReflectionRisk, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result
}
func compactStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
