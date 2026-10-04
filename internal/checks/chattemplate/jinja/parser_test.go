package jinja

import (
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) []Node {
	t.Helper()
	n, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return n
}

func TestParseLoopAndBranches(t *testing.T) {
	src := "{%- for m in messages if m.role != 'tool' -%}" +
		"{% if m['role'] == 'user' %}U{% elif m.role is defined %}D{% else %}E{% endif %}" +
		"{% else %}none{% endfor %}"
	nodes := mustParse(t, src)
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(nodes))
	}
	f, ok := nodes[0].(For)
	if !ok {
		t.Fatalf("got %T, want For", nodes[0])
	}
	if !reflect.DeepEqual(f.Targets, []string{"m"}) || f.Filter == nil || len(f.Else) != 1 {
		t.Fatalf("for = %+v", f)
	}
	ifn, ok := f.Body[0].(If)
	if !ok || len(ifn.Branches) != 2 || len(ifn.Else) != 1 {
		t.Fatalf("if = %+v", f.Body[0])
	}
	want := Bin{Op: "==", L: Index{X: Name{N: "m"}, I: Str{V: "role"}}, R: Str{V: "user"}}
	if !reflect.DeepEqual(ifn.Branches[0].Cond, want) {
		t.Fatalf("cond = %#v", ifn.Branches[0].Cond)
	}
	if _, ok := ifn.Branches[1].Cond.(Test); !ok {
		t.Fatalf("elif cond = %#v, want a Test", ifn.Branches[1].Cond)
	}
}

func TestParseExpressions(t *testing.T) {
	cases := map[string]Expr{
		"{{ 'a' ~ 'b' }}":       Bin{Op: "~", L: Str{V: "a"}, R: Str{V: "b"}},
		"{{ 'ab'|reverse }}":    Filter{X: Str{V: "ab"}, Name: "reverse"},
		"{{ 'a' 'b' }}":         Str{V: "ab"},
		"{{ x[::-1] }}":         Slice{X: Name{N: "x"}, Step: Unary{Op: "-", X: Num{V: "1"}}},
		"{{ '\\x5f\\x5f' }}":    Str{V: "__"},
		"{{ {'a': {'b': 1}} }}": Dict{Keys: []Expr{Str{V: "a"}}, Vals: []Expr{Dict{Keys: []Expr{Str{V: "b"}}, Vals: []Expr{Num{V: "1"}}}}},
		"{{ x|attr('y')|join(', ') }}": Filter{X: Filter{X: Name{N: "x"}, Name: "attr", Args: []Expr{Str{V: "y"}}},
			Name: "join", Args: []Expr{Str{V: ", "}}},
		"{{ a if b else c }}": Cond{Then: Name{N: "a"}, If: Name{N: "b"}, Else: Name{N: "c"}},
		"{{ x is not none }}": Test{X: Name{N: "x"}, Name: "none", Not: true},
		"{{ 'x' not in y }}":  Bin{Op: "not in", L: Str{V: "x"}, R: Name{N: "y"}},
	}
	for src, want := range cases {
		nodes := mustParse(t, src)
		out, ok := nodes[0].(Output)
		if !ok {
			t.Errorf("%s: got %T", src, nodes[0])
			continue
		}
		if !reflect.DeepEqual(out.X, want) {
			t.Errorf("%s:\n got %#v\nwant %#v", src, out.X, want)
		}
	}
}

func TestParseStatements(t *testing.T) {
	src := "{# a comment {{ not parsed }} #}" +
		"{% set ns = namespace(found=false) %}{% set ns.found = true %}" +
		"{% set block %}captured{% endset %}" +
		"{% macro m(a, b=1) %}{{ a }}{% endmacro %}" +
		"{% raw %}{{ literal }}{% endraw %}" +
		"{% generation %}g{% endgeneration %}" +
		"{% for k, v in d.items() %}{% if k %}{% break %}{% endif %}{% endfor %}"
	nodes := mustParse(t, src)
	var kinds []string
	for _, n := range nodes {
		kinds = append(kinds, reflect.TypeOf(n).Name())
	}
	want := []string{"Set", "Set", "Set", "Macro", "Text", "Generation", "For"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	if raw := nodes[4].(Text).S; raw != "{{ literal }}" {
		t.Errorf("raw block = %q", raw)
	}
}

// A template the parser cannot read is reported, never half-analysed.
func TestParseErrors(t *testing.T) {
	for _, src := range []string{
		"{{ x",
		"{% if x %}no end",
		"{% for x in y %}{% endif %}",
		"{% include 'other' %}",
		"{{ 'unterminated }}",
		"{% endif %}",
		"{{ x | }}",
		"{# never closed",
	} {
		if _, err := Parse(src); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", src)
		} else if !strings.Contains(err.Error(), "line ") {
			t.Errorf("Parse(%q) error %q lacks a line", src, err)
		}
	}
}

// TestDeepNestingIsRefused: nesting is bounded so hostile input cannot drive
// unbounded recursion.
func TestDeepNestingIsRefused(t *testing.T) {
	for _, src := range []string{
		"{{ " + strings.Repeat("(", 5000) + "x" + strings.Repeat(")", 5000) + " }}",
		"{{ " + strings.Repeat("not ", 5000) + "x }}",
		"{{ " + strings.Repeat("-", 5000) + "x }}",
		strings.Repeat("{% if x %}", 5000) + strings.Repeat("{% endif %}", 5000),
		"{{ 'a'" + strings.Repeat(" ~ 'a'", 5000) + " }}",
	} {
		if _, err := Parse(src); err == nil || !(strings.Contains(err.Error(), "deep") || strings.Contains(err.Error(), "too many")) {
			t.Errorf("deep nesting (%d bytes) was not refused: %v", len(src), err)
		}
	}
}

// FuzzParse: the parser reads hostile input, so it must never panic or hang.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"{{ a ~ 'b' }}", "{% for m in messages %}{{ m }}{% endfor %}",
		"{% if a %}{% elif b %}{% else %}{% endif %}", "{{ {'a': [1, (2, 3)]}|tojson }}", "{% raw %}x{% endraw %}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Parse(s)
	})
}

// TestParseFilterBlock: {% filter name %} takes its first filter without a
// pipe, as Jinja writes it (firefunction-v2 uses {% filter trim %}). The
// parser used to demand a leading pipe, so real filter blocks did not parse.
func TestParseFilterBlock(t *testing.T) {
	cases := map[string][]string{
		"{% filter trim %} x {% endfilter %}":                        {"trim"},
		"{% filter replace('a', 'b') %}a{% endfilter %}":             {"replace"},
		"{% filter trim | upper %}x{% endfilter %}":                  {"trim", "upper"},
		"{% set s %}{% filter trim %} y {% endfilter %}{% endset %}": nil,
	}
	for src, want := range cases {
		nodes := mustParse(t, src)
		if want == nil {
			continue
		}
		fb, ok := nodes[0].(FilterBlock)
		if !ok {
			t.Fatalf("%q: got %T, want FilterBlock", src, nodes[0])
		}
		var got []string
		for x := fb.Filter; ; {
			f, ok := x.(Filter)
			if !ok {
				break
			}
			got = append([]string{f.Name}, got...)
			x = f.X
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: filters %v, want %v", src, got, want)
		}
	}
	if _, err := Parse("{% filter %}x{% endfilter %}"); err == nil {
		t.Error("a filter block with no filter name must not parse")
	}
}
