package license

import (
	"strings"
	"testing"
)

// TestCatalogue holds the catalogue to its own rules: every id, tag, and SPDX
// id names one entry; tags and links are written the way they are matched;
// every entry can be identified somehow; and no entry's phrase rule is
// satisfied by another entry's phrases.
func TestCatalogue(t *testing.T) {
	names := map[string]string{}
	for _, e := range catalogue {
		for _, n := range append([]string{e.ID, strings.ToLower(e.SPDX)}, e.Tags...) {
			if n == "" {
				continue
			}
			if prev, ok := names[n]; ok && prev != e.ID {
				t.Errorf("%q names both %s and %s", n, prev, e.ID)
			}
			names[n] = e.ID
			if got, ok := Lookup(strings.ToUpper(n)); !ok || got.ID != e.ID {
				t.Errorf("Lookup(%q) = %s, want %s", n, got.ID, e.ID)
			}
		}
		for _, s := range append(append([]string{}, e.Tags...), append(e.Links, e.BaseRepos...)...) {
			if s != strings.ToLower(s) || strings.HasPrefix(s, "http") || strings.HasPrefix(s, "www.") {
				t.Errorf("%s: %q must be lowercase, without scheme or www.", e.ID, s)
			}
		}
		if len(e.Tags) == 0 && len(e.Links) == 0 && len(e.Texts) == 0 && e.Body == "" {
			t.Errorf("%s: nothing identifies it", e.ID)
		}
		if e.Name == "" || e.Family == "" {
			t.Errorf("%s: needs a name and a family", e.ID)
		}
		if !strings.HasPrefix(e.ID, "socair-") && e.ID != strings.ToLower(e.ID) {
			t.Errorf("%s: a ScanCode key is lowercase", e.ID)
		}
	}
	for _, e := range catalogue {
		for _, r := range e.Texts {
			text := strings.Join(r.Phrases, " ")
			for _, other := range catalogue {
				if other.ID != e.ID && textMatches(&other, strings.Fields(text), text) {
					t.Errorf("%s's phrases also identify %s", e.ID, other.ID)
				}
			}
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	for _, n := range []string{"", "other", "unknown", "apache", "bsd"} {
		if e, ok := Lookup(n); ok {
			t.Errorf("Lookup(%q) = %s; a placeholder or an ambiguous name names no license", n, e.ID)
		}
	}
}
