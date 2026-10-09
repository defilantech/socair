package jinja

import (
	"strings"
	"testing"
)

// emitted joins the rendered text of every Text node, depth first, which is
// what a render emits when every branch is taken once.
func emitted(nodes []Node) string {
	var b strings.Builder
	var walk func([]Node)
	walk = func(ns []Node) {
		for _, n := range ns {
			switch n := n.(type) {
			case Text:
				b.WriteString(n.Out)
			case If:
				for _, br := range n.Branches {
					walk(br.Body)
				}
				walk(n.Else)
			case For:
				walk(n.Body)
			}
		}
	}
	walk(nodes)
	return b.String()
}

// TestWhitespaceControl: a Text node's Out is what Jinja emits with the
// settings Hugging Face renders under (trim_blocks, lstrip_blocks, no
// trailing newline), and its S stays the text as written, which the static
// analysis reads. Each want was produced by Jinja2 3.1 with those settings.
// Falsification: drop the whitespace pass (Out = S) and all but one case
// fails.
func TestWhitespaceControl(t *testing.T) {
	cases := map[string]string{
		"  {% if true %}\n  x\n  {% endif %}\n  y\n":                           "  x\n  y",
		"x  \n  {%- if true -%}  \n  y  {%+ if true %}z{% endif %}{% endif %}": "xy  z",
		"a\n{# c #}\nb":                       "a\nb",
		"{% raw %}  {{ a }}  {% endraw %}\nz": "  {{ a }}  z",
		"{{ x }}  \n  {% if x %}y{% endif %}": "  \ny",
		"{{ x }}  {% if x %}y{% endif %}":     "  y",
		"a {{- x -}} \n b":                    "ab",
		"{% if x %}\r\nA\r\n{% endif %}":      "A\n",
		"{% if x +%}\nA{% endif %}":           "\nA",
		"keep\n\n":                            "keep\n",
	}
	for src, want := range cases {
		nodes := mustParse(t, src)
		if got := emitted(nodes); got != want {
			t.Errorf("%q: emits %q, want %q", src, got, want)
		}
	}
	nodes := mustParse(t, "  {% if x %}{% endif %}\n")
	if got := nodes[0].(Text).S; got != "  " {
		t.Errorf("S must stay as written, got %q", got)
	}
}
