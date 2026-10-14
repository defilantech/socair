package jinja

import (
	"strings"
	"testing"
)

// A string literal's escapes are decoded as Jinja decodes them (unicode-escape):
// a code point past U+10FFFF is an error there ("illegal Unicode character"),
// so it is a parse error here, never a character it does not stand for.
// Falsification: write rune(v) for any 32-bit v again and the out-of-range
// cases parse, as U+FFFD.
func TestEscapesStayInUnicodeRange(t *testing.T) {
	for src, want := range map[string]string{
		`"\x41"`:       "A",
		`"\u00e9"`:     "é",
		`"\U0010FFFF"`: "\U0010FFFF",
		`"\101"`:       "A",
		`"\777"`:       "ǿ",
	} {
		got, _, err := lexString(src, 0)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", src, got, err, want)
		}
	}
	for _, src := range []string{`"\U00110000"`, `"\UFFFFFFFF"`, `"\U80000041"`} {
		if got, _, err := lexString(src, 0); err == nil {
			t.Errorf("%s: decoded as %q, want an error: Jinja refuses a code point past U+10FFFF", src, got)
		}
		if _, err := Parse("{{ " + src + " }}"); err == nil {
			t.Errorf("{{ %s }}: parsed, want a parse error", src)
		}
	}
}

// "%c" % n formats the character n only when 0 <= n <= 0x10FFFF, as Python
// does ("%c arg not in range(0x110000)"); a larger n is an error, not the
// character its low 32 bits happen to name. Falsification: write rune(n) for
// any n again and 2**32 + 65 renders as "A".
func TestPercentCStaysInUnicodeRange(t *testing.T) {
	pieces, err := render(t, `{{ "%c" % 65 }}{{ "%c" % 1114111 }}`, nil, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, p := range pieces {
		b.WriteString(p.Text)
	}
	if b.String() != "A\U0010FFFF" {
		t.Errorf("rendered %q, want A and U+10FFFF", b.String())
	}
	for _, n := range []string{"4294967361", "1114112", "-1"} {
		if pieces, err := render(t, `{{ "%c" % `+n+` }}`, nil, DefaultLimits); err == nil {
			t.Errorf(`"%%c" %% %s rendered %+v, want an error`, n, pieces)
		}
	}
}
