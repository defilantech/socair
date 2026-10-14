package chattemplate

import "testing"

// Folding "%c" with a constant gives the character only for a code point
// Python's %c accepts (0 to 0x10FFFF); any other value does not fold, so the
// static verdict stands as for any expression the folder cannot evaluate,
// rather than folding to the character the value's low 32 bits name.
// Falsification: write rune(n) for any n again and 2**32 + 65 folds to "A".
func TestPrintfPercentCStaysInUnicodeRange(t *testing.T) {
	if got, ok := printf("%c%c", []string{"65", "1114111"}); !ok || got != "A\U0010FFFF" {
		t.Errorf("printf(%%c%%c, 65, 1114111) = %q, %v; want A and U+10FFFF", got, ok)
	}
	for _, n := range []string{"4294967361", "1114112", "-1"} {
		if got, ok := printf("%c", []string{n}); ok {
			t.Errorf("printf(%%c, %s) folded to %q, want no fold", n, got)
		}
	}
}
