package license

import (
	"strings"
	"testing"
)

// The repository carries no license text, so the body matcher is tested on
// a made-up one with the same parts a real license has: a placeholder a copy
// fills in and an appendix a copy may leave out. The real fingerprints are
// measured in docs/false-positive-baseline.md.
const grant = `Grant of use. The holder {{the HOLDER}} grants every recipient of this work the right to copy,
change, and share it, provided this notice travels with every copy of the work.

No warranty. The work is given as it is, without promise of any kind, and
{{the HOLDER}} is not liable for any harm that comes from using it.

[[How to apply. Put this notice at the top of each file you share, with
your own name in place of the holder.]]`

var grantEntry = &Entry{ID: "example-grant", Name: "Example Grant License"}

func grantBody(t *testing.T) body {
	t.Helper()
	seq, err := Fingerprint(grant)
	if err != nil {
		t.Fatal(err)
	}
	return newBody(seq)
}

func matchesGrant(t *testing.T, text string) bool {
	t.Helper()
	f := grantBody(t).fit(words(text))
	return f.matches() && f.titled(grantEntry)
}

func canonicalGrant(holder string, appendix bool) string {
	s := strings.NewReplacer("{{", "", "}}", "", "[[", "", "]]", "").Replace(grant)
	s = strings.ReplaceAll(s, "the HOLDER", holder)
	if !appendix {
		s = s[:strings.Index(s, "How to apply.")]
	}
	return s
}

func TestBodyMatchesCopiesOfTheLicense(t *testing.T) {
	plain := canonicalGrant("the HOLDER", true)
	for name, text := range map[string]string{
		"verbatim":           plain,
		"rewrapped and case": strings.ToUpper(strings.ReplaceAll(plain, "\n", " ")),
		"holder filled in":   canonicalGrant("Example Labs, Inc.", true),
		"appendix left out":  canonicalGrant("the HOLDER", false),
		"title and notice":   "Example Grant License\n\nCopyright (c) 2026 Example Labs\nAll rights reserved.\n\n" + plain,
		"numbered":           strings.Replace(plain, "No warranty.", "2. No warranty.", 1),
	} {
		if !matchesGrant(t, text) {
			t.Errorf("%s: a copy of the license did not match", name)
		}
	}
}

// Falsification for the matcher: every way of changing what the license
// says, outside its placeholder and appendix, is not that license.
func TestBodyRejectsAChangedLicense(t *testing.T) {
	plain := canonicalGrant("the HOLDER", true)
	for name, text := range map[string]string{
		"a clause appended":         plain + "\nThe work may not be used for any commercial purpose.\n",
		"a clause inserted":         strings.Replace(plain, "No warranty.", "Commercial use is not allowed. No warranty.", 1),
		"a word removed":            strings.Replace(plain, "change, ", "", 1),
		"a word changed":            strings.Replace(plain, "every recipient", "each recipient", 1),
		"a restriction before it":   "NON-COMMERCIAL USE ONLY\n\n" + plain,
		"the appendix changed":      strings.Replace(plain, "with\nyour own name", "with your own name and a fee", 1),
		"half the license":          plain[:len(plain)/2],
		"a long text in the holder": canonicalGrant("the holder, who may revoke this grant at any time and for any reason, and who forbids any use for profit", true),
	} {
		if matchesGrant(t, text) {
			t.Errorf("%s: a changed license matched", name)
		}
	}
}

func TestNoticeLinesAreDropped(t *testing.T) {
	got := strings.Join(words("Microsoft.\nCopyright (c) Microsoft Corporation.\n\nMIT License\n\nThe copyright\nnotice that is included stays.\nCopyright 2024 Example\nmore text"), " ")
	want := "mit license the copyright notice that is included stays more text"
	if got != want {
		t.Fatalf("words = %q, want %q", got, want)
	}
}

func TestFingerprintRejectsUnbalancedMarkers(t *testing.T) {
	for _, s := range []string{"a b c d e [[f g", "a b c d e {{f]] g h", "a b"} {
		if _, err := Fingerprint(s); err == nil {
			t.Errorf("%q: want an error", s)
		}
	}
}

// Every embedded fingerprint loads and was generated from a text with
// required words.
func TestEmbeddedBodiesLoad(t *testing.T) {
	for _, e := range catalogue {
		if e.Body == "" {
			continue
		}
		b, ok := bodies[e.ID]
		if !ok || b.required < 100 {
			t.Errorf("%s: body %q did not load or is too short (%d required shingles)", e.ID, e.Body, b.required)
		}
	}
}
