package jinja

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func render(t *testing.T, tpl string, vars map[string]any, lim Limits) ([]Piece, error) {
	t.Helper()
	nodes, err := Parse(tpl)
	if err != nil {
		t.Fatalf("%q: %v", tpl, err)
	}
	return Render(nodes, vars, lim)
}

// TestRenderProvenance: every rendered byte is attributed to the inputs or
// to the template, through the operations real templates use. Falsification:
// mark every string as template text (or every one as input) and this fails.
func TestRenderProvenance(t *testing.T) {
	vars := map[string]any{
		"m":     M("role", "user", "content", " hi "),
		"tools": []any{M("name", "f", "n", 1)},
	}
	cases := []struct {
		tpl  string
		want []Piece
	}{
		{"<|im_start|>{{ m.role }}\n{{ m.content | trim }}{{ ' added' }}",
			[]Piece{{"<|im_start|>", false}, {"user", true}, {"\n", false}, {"hi", true}, {" added", false}}},
		{"{{ '[' ~ m['content'].strip().upper() ~ ']' }}",
			[]Piece{{"[", false}, {"HI", true}, {"]", false}}},
		{"{{ m.content | replace('h', 'H') }}",
			[]Piece{{" ", true}, {"H", false}, {"i ", true}}},
		{"{{ tools | tojson }}", []Piece{{`[{"name": "f", "n": 1}]`, true}}},
		{"{{ [m.role] | tojson }}", []Piece{{"[", false}, {`"user"`, true}, {"]", false}}},
		{"{% set s = m.content.split('i') %}{{ s[0] }}|{{ s | join('-') }}",
			[]Piece{{" h", true}, {"|", false}, {" h", true}, {"-", false}, {" ", true}}},
		{"{% macro wrap(x) %}<{{ x }}>{% endmacro %}{{ wrap(m.role) }}",
			[]Piece{{"<", false}, {"user", true}, {">", false}}},
		{"{{ 'Today: ' + strftime_now('%d') }}", []Piece{{"Today: " + DatePlaceholder, false}}},
	}
	for _, c := range cases {
		got, err := render(t, c.tpl, vars, DefaultLimits)
		if err != nil {
			t.Errorf("%q: %v", c.tpl, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%q:\n got %+v\nwant %+v", c.tpl, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q:\n got %+v\nwant %+v", c.tpl, got, c.want)
				break
			}
		}
	}
}

// fanOut is n macros, each calling the one before twice: 2^n calls that
// emit nothing, nest only n deep, and use no loop.
func fanOut(n int) string {
	var b strings.Builder
	b.WriteString("{% macro m0() %}{% endmacro %}")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "{%% macro m%d() %%}{{ m%d() }}{{ m%d() }}{%% endmacro %%}", i, i-1, i-1)
	}
	fmt.Fprintf(&b, "{{ m%d() }}", n)
	return b.String()
}

// TestRenderIsBounded: a template built to loop, recurse, or grow its output
// without end stops at a named bound, promptly. Falsification: remove any
// one bound and its case runs out of time or memory.
func TestRenderIsBounded(t *testing.T) {
	cases := map[string]string{
		"{% for i in range(10 ** 9) %}x{% endfor %}":                                                       "list",
		"{% for a in range(1000) %}{% for b in range(1000) %}{% endfor %}{% endfor %}":                     "iterations",
		"{% set ns = namespace(s='ab') %}{% for i in range(64) %}{% set ns.s = ns.s ~ ns.s %}{% endfor %}": "string",
		"{% set ns = namespace(l=[1]) %}{% for i in range(64) %}{% set ns.l = ns.l + ns.l %}{% endfor %}":  "list",
		"{% macro f(n) %}{{ f(n) }}{% endmacro %}{{ f(1) }}":                                               "nested",
		"{% for i in range(90000) %}{{ 'x' * 100 }}{% endfor %}":                                           "output",
		"{{ 'a' * 10 ** 15 }}": "string",
		"{{ [0] * 10 ** 15 }}": "list",
		"{{ 'ab'|replace('a', 'a' * 900000)|replace('a', 'aaaa') }}": "string",
		fanOut(40): "steps",
		"{% set big = range(90000) | list %}{% for i in range(90000) %}{% if i in big %}{% endif %}{% endfor %}":   "steps",
		"{% set big = range(90000) | list %}{% for i in range(90000) %}{{ big | unique | length }}{% endfor %}":    "steps",
		"{% set big = range(90000) | list %}{% for i in range(90000) %}{% if big == big %}{% endif %}{% endfor %}": "steps",
		"{{ ('x' * 200000) | list | length }}": "list",
	}
	lim := DefaultLimits
	for tpl, bound := range cases {
		start := time.Now()
		_, err := render(t, tpl, nil, lim)
		var le *LimitError
		if !errors.As(err, &le) {
			t.Errorf("%.60q: err %v, want a render bound", tpl, err)
			continue
		}
		if !strings.Contains(le.Limit, bound) {
			t.Errorf("%.60q: bound %q, want one naming %q", tpl, le.Limit, bound)
		}
		if el := time.Since(start); el > 10*time.Second {
			t.Errorf("%.60q: took %s", tpl, el)
		}
	}
}

// TestRenderRefusesWhatItDoesNotModel: a construct outside the subset stops
// the render with its name; it is never guessed at.
func TestRenderRefusesWhatItDoesNotModel(t *testing.T) {
	for _, tpl := range []string{
		"{{ 'x' | wordwrap }}",
		"{{ x is filter }}",
		"{% macro m() %}{{ caller() }}{% endmacro %}{% call m() %}x{% endcall %}",
		"{{ lipsum() }}",
		"{{ x.__class__ }}",
		"{{ x['__globals__'] }}",
		"{{ namespace().__init__ }}",
	} {
		_, err := render(t, tpl, map[string]any{"x": "s"}, DefaultLimits)
		var ue *UnsupportedError
		if !errors.As(err, &ue) {
			t.Errorf("%q: err %v, want unsupported", tpl, err)
		}
	}
}

// TestRenderSandboxSemantics: what transformers' immutable sandbox and
// Jinja's lazy filters do, the evaluator does: a mutating method fails the
// render as the sandbox's SecurityError does, and a map or select result is
// a generator, always true, with no length and no JSON form. Each case
// was checked against Jinja2 3.1.
func TestRenderSandboxSemantics(t *testing.T) {
	fails := []string{
		"{% set l = [] %}{% do l.append(1) %}",
		"{{ {'a': 1}.update({'b': 2}) }}",
		"{{ [1, 2] | map('string') | tojson }}",
		"{{ [1, 2] | select | length }}",
		"{{ [1, 2] | map('string') }}",
	}
	for _, tpl := range fails {
		_, err := render(t, tpl, nil, DefaultLimits)
		var fe *FailError
		if !errors.As(err, &fe) {
			t.Errorf("%q: err %v, want the render to fail as Jinja's does", tpl, err)
		}
	}
	works := map[string]string{
		"{% if [] | select %}truthy{% endif %}":                                                                                            "truthy",
		"{{ none | selectattr('type', 'equalto', 'x') | list | length }}{{ none | map('upper') | list }}":                                  "0[]",
		"{{ 'a'|safe + '<b>' }}|{{ '<b>' + 'a'|safe }}|{{ 'a'|safe ~ '<b>' }}|{{ ('<'|safe + '<') + '>' }}|{{ '<'|safe|e }}|{{ '<'|e|e }}": "a&lt;b&gt;|&lt;b&gt;a|a<b>|<&lt;&gt;|<|&lt;",
		"{{ ([1, 2] | select)[0] }}|{{ ([1, 2] | select)[1:] }}|":                                                                          "||",
		"{{ [3, 1] | map('string') | join(',') }}":                                                                                         "3,1",
		"{{ [3, 1] | select | list | length }}":                                                                                            "2",
		"{{ ['a', 'b'] | map('upper') | first }}":                                                                                          "A",
		"{% for x in [1, 2] | reject('equalto', 1) %}{{ x }}{% endfor %}":                                                                  "2",
	}
	for tpl, want := range works {
		got, err := render(t, tpl, nil, DefaultLimits)
		if err != nil || flatten(got) != want {
			t.Errorf("%q: %q, %v; want %q", tpl, flatten(got), err, want)
		}
	}
}

// FuzzRender: the evaluator runs hostile templates, so it must never panic
// or run past its bounds on any input.
func FuzzRender(f *testing.F) {
	for _, s := range []string{
		"{% for m in messages %}{{ m.role }}{{ m.content | trim }}{% endfor %}",
		"{{ 'ab'[::-1] ~ ('x' * 3) }}{{ [1, 2][-1:] }}",
		"{% set ns = namespace(a=1) %}{% set ns.a = ns.a + 1 %}{{ ns.a | tojson }}",
		"{% macro m(a, b=2) %}{{ a ~ b }}{% endmacro %}{{ m(1) }}",
		"{{ messages | selectattr('role', 'equalto', 'user') | map(attribute='content') | join(', ') }}",
	} {
		f.Add(s)
	}
	small := Limits{Steps: 20_000, Output: 1 << 16, Iterations: 2_000, Depth: 16, Items: 2_000}
	vars := map[string]any{"messages": []any{M("role", "user", "content", "hi")}}
	f.Fuzz(func(t *testing.T, s string) {
		nodes, err := Parse(s)
		if err != nil {
			return
		}
		_, _ = Render(nodes, vars, small)
	})
}
