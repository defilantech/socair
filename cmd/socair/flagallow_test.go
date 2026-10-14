package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// flagUse is what one function does with a *flagSet: the keys it reads by a
// literal, the parameter that names a key it reads (trustedFor's flag), and
// the functions it hands the flagSet to.
type flagUse struct {
	keys     map[string]bool
	keyParam int // index of a string parameter read as a key, or -1
	calls    []flagCall
	allowed  map[string]bool
	parses   bool // calls parseFlags
	hasAllow bool
}

type flagCall struct {
	fn  string
	lit []string // string literal arguments, by position ("" for others)
}

// readFlagUses reads every non-test file of this package and records, per
// function, the flags it reads and allows.
func readFlagUses(t *testing.T) map[string]*flagUse {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	uses := map[string]*flagUse{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv != nil {
				continue
			}
			u := &flagUse{keys: map[string]bool{}, allowed: map[string]bool{}, keyParam: -1}
			// The function's flagSet variables (a parameter or a parseFlags
			// result) and its string parameters, by name.
			fsVars, strParams := map[string]bool{}, map[string]int{}
			i := 0
			for _, p := range fd.Type.Params.List {
				for _, n := range p.Names {
					if star, ok := p.Type.(*ast.StarExpr); ok {
						if id, ok := star.X.(*ast.Ident); ok && id.Name == "flagSet" {
							fsVars[n.Name] = true
						}
					}
					if id, ok := p.Type.(*ast.Ident); ok && id.Name == "string" {
						strParams[n.Name] = i
					}
					i++
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok && len(as.Rhs) == 1 {
					if c, ok := as.Rhs[0].(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "parseFlags" {
							u.parses = true
							if v, ok := as.Lhs[0].(*ast.Ident); ok {
								fsVars[v.Name] = true
							}
						}
					}
				}
				return true
			})
			isFS := func(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && fsVars[id.Name] }
			lit := func(e ast.Expr) (string, bool) {
				b, ok := e.(*ast.BasicLit)
				if !ok || b.Kind != token.STRING {
					return "", false
				}
				s, err := strconv.Unquote(b.Value)
				return s, err == nil
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && isFS(sel.X) {
						switch sel.Sel.Name {
						case "val", "has", "patterns":
							if s, ok := lit(x.Args[0]); ok {
								u.keys[s] = true
							} else if id, ok := x.Args[0].(*ast.Ident); ok {
								if i, ok := strParams[id.Name]; ok {
									u.keyParam = i
								}
							}
						case "allow":
							u.hasAllow = true
							for _, a := range x.Args {
								if s, ok := lit(a); ok {
									u.allowed[s] = true
								}
							}
						}
					}
					if id, ok := x.Fun.(*ast.Ident); ok {
						passes := false
						var lits []string
						for _, a := range x.Args {
							s, _ := lit(a)
							lits = append(lits, s)
							passes = passes || isFS(a)
						}
						if passes {
							u.calls = append(u.calls, flagCall{fn: id.Name, lit: lits})
						}
					}
				case *ast.IndexExpr:
					if sel, ok := x.X.(*ast.SelectorExpr); ok && isFS(sel.X) {
						switch sel.Sel.Name {
						case "bare", "all", "vals":
							if s, ok := lit(x.Index); ok {
								u.keys[s] = true
							}
						}
					}
				}
				return true
			})
			uses[fd.Name.Name] = u
		}
	}
	return uses
}

// reads is every key fn reads, through the functions it hands its flagSet
// to.
func reads(uses map[string]*flagUse, fn string, seen map[string]bool) map[string]bool {
	out := map[string]bool{}
	u, ok := uses[fn]
	if !ok || seen[fn] {
		return out
	}
	seen[fn] = true
	for k := range u.keys {
		out[k] = true
	}
	for _, c := range u.calls {
		callee := uses[c.fn]
		if callee == nil {
			continue
		}
		if callee.keyParam >= 0 && callee.keyParam < len(c.lit) && c.lit[callee.keyParam] != "" {
			out[c.lit[callee.keyParam]] = true
		}
		for k := range reads(uses, c.fn, seen) {
			out[k] = true
		}
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestEveryCommandAllowsWhatItReads: a command refuses a flag it does not
// take (flagSet.allow), so a mistyped --stroe is an error, not the default
// store. This holds each command's allowed flags to the flags it reads,
// through its helpers, read from the source: a flag read but not allowed
// would always be refused, and one allowed but never read would be accepted
// and ignored. Falsification: drop a name from any allow call, or read a new
// flag without allowing it, and this names the command.
func TestEveryCommandAllowsWhatItReads(t *testing.T) {
	uses := readFlagUses(t)
	commands := 0
	for name, u := range uses {
		if !u.parses {
			continue
		}
		commands++
		read := reads(uses, name, map[string]bool{})
		if !u.hasAllow {
			t.Errorf("%s parses flags but never calls allow; it reads %v", name, sortedSet(read))
			continue
		}
		for k := range read {
			if !u.allowed[k] {
				t.Errorf("%s reads --%s but does not allow it", name, k)
			}
		}
		for k := range u.allowed {
			if !read[k] {
				t.Errorf("%s allows --%s but never reads it", name, k)
			}
		}
		if testing.Verbose() {
			t.Logf("%s: %s", name, strings.Join(sortedSet(read), ", "))
		}
	}
	if commands < 15 {
		t.Fatalf("found only %d commands that parse flags; the source scan is broken", commands)
	}
}

func TestAllowRefusesAMistypedFlag(t *testing.T) {
	fs := parseFlags([]string{"x", "--stroe", "/tmp/s"})
	err := fs.allow("store")
	if err == nil || !strings.Contains(err.Error(), "--stroe") || !strings.Contains(err.Error(), "--store") {
		t.Fatalf("allow: %v", err)
	}
	if err := parseFlags([]string{"--store", "/tmp/s"}).allow("store"); err != nil {
		t.Fatal(err)
	}
}
