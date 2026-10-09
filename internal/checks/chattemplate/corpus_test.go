package chattemplate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate/jinja"
)

// corpusOptions stand in for a tokenizer: the corpus is templates alone, and
// a serving stack always passes the bos and eos tokens. With no token list,
// text written like a special token counts as one.
var corpusOptions = Options{Tokens: Tokens{Named: map[string]string{"bos_token": "<s>", "eos_token": "</s>"}}}

// TestRealTemplatesAreNotFlagged is the false-positive gate: real chat
// templates from shipped models must not FAIL or LEAD. Third-party templates
// are not committed, so it runs only when SOCAIR_TEMPLATE_CORPUS names a
// directory of *.jinja files:
//
//	SOCAIR_TEMPLATE_CORPUS=/path/to/templates go test ./internal/checks/chattemplate -run RealTemplates -v
func TestRealTemplatesAreNotFlagged(t *testing.T) {
	dir := os.Getenv("SOCAIR_TEMPLATE_CORPUS")
	if dir == "" {
		t.Skip("set SOCAIR_TEMPLATE_CORPUS to a directory of .jinja templates")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jinja"))
	if len(files) == 0 {
		t.Fatalf("no .jinja files under %s", dir)
	}
	tally := map[checks.Status]int{}
	var rendered, adding, triggered int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		r := inspect(string(b), corpusOptions)
		tally[r.Status]++
		switch r.Status {
		case checks.Fail, checks.Lead:
			t.Errorf("%s: %s: %s", name, r.Status, r.Notes)
		case checks.NotTested:
			t.Logf("%s: NOT_TESTED: %s", name, r.Notes)
		}
		// The render measurement: what rendered, what was refused and why,
		// and what each template adds.
		nodes, err := jinja.Parse(string(b))
		if err != nil {
			continue
		}
		res := renderCheck(string(b), nodes, analyse(nodes), corpusOptions)
		if res.skipped != "" {
			t.Logf("%s: not rendered: %s", name, res.skipped)
			continue
		}
		rendered++
		if len(res.added) > 0 {
			adding++
		}
		if len(res.triggers) > 0 {
			triggered++
		}
		var adds []string
		for _, a := range res.added {
			adds = append(adds, quote(a.text))
		}
		t.Logf("%s: rendered %d probe(s), refused %d, adds %d fragment(s): %s", name, res.rendered, len(res.refused),
			len(res.added), strings.Join(adds, " | "))
		for _, d := range res.triggers {
			t.Logf("%s: when a message contains %q it adds %q", name, d.guard, d.adds)
		}
		for _, p := range res.refused {
			t.Logf("%s: refused %s", name, p)
		}
	}
	t.Logf("%d templates: %d PASS, %d LEAD, %d FAIL, %d NOT_TESTED",
		len(files), tally[checks.Pass], tally[checks.Lead], tally[checks.Fail], tally[checks.NotTested])
	t.Logf("render: %d of %d rendered, %d add text of their own, %d add text under a content condition",
		rendered, len(files), adding, triggered)
}

// TestEvasionCorpus holds the check to the evasion fixtures in
// testdata/evasions. Each fixture's status and pattern are pinned, including
// the known misses, so a regression and an undisclosed improvement both fail.
// Falsification: go back to the phrase regex over the raw template and most
// fixtures PASS.
func TestEvasionCorpus(t *testing.T) {
	dir := filepath.Join("testdata", "evasions")
	raw, err := os.ReadFile(filepath.Join(dir, "expect.txt"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			t.Fatalf("bad expect line %q", line)
		}
		b, err := os.ReadFile(filepath.Join(dir, f[0]))
		if err != nil {
			t.Fatal(err)
		}
		n++
		r := inspect(string(b), Options{})
		if string(r.Status) != f[1] {
			t.Errorf("%s: status %s, want %s (notes: %s)", f[0], r.Status, f[1], r.Notes)
			continue
		}
		if f[2] == "known-miss" {
			continue
		}
		if f[2] == "benign" {
			if len(r.Findings) > 0 {
				t.Errorf("%s: benign fixture produced findings %+v", f[0], r.Findings)
			}
			continue
		}
		found := false
		for _, fd := range r.Findings {
			if fd.Pattern == f[2] {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no %s finding in %+v", f[0], f[2], r.Findings)
		}
	}
	if n < 15 {
		t.Fatalf("only %d fixtures; the corpus shrank", n)
	}
}

// FuzzInspect: the check reads hostile templates, so the parser, the constant
// folder, and the analyser must never panic or hang on any input.
func FuzzInspect(f *testing.F) {
	for _, s := range []string{
		"{{ 'ab'[::-1] ~ 'c'|reverse }}",
		"{{ '%c%s%d'|format(105, 'x', 3) }}",
		"{% for m in messages %}{% if 'x' in m.content %}<|im_start|>system hi{% endif %}{% endfor %}",
		"{{ x['__cl' ~ 'ass__'] }}{{ 'a'[-5:99] }}{{ 'a'[:-9] }}",
		"{% set n = namespace(a='b') %}{% set n.a = n.a ~ 'c' %}{{ n.a }}",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = Inspect(s)
	})
}
