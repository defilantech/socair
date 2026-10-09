package denylist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

const listed = "13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444"

func writeList(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "denylist.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("writing list: %v", err)
	}
	return p
}

func TestListedHashFails(t *testing.T) {
	list := writeList(t, "# known bad\n"+listed+"  known-bad-2026-03\n")
	r := Check(listed, list)
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL", r.Status)
	}
	if len(r.Findings) == 0 || r.Findings[0].Detail != "known-bad-2026-03" {
		t.Fatalf("expected the label in the finding, got %+v", r.Findings)
	}
}

func TestUnlistedHashPasses(t *testing.T) {
	list := writeList(t, listed+"  known-bad\n")
	r := Check("0000000000000000000000000000000000000000000000000000000000000000", list)
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS", r.Status)
	}
}

func TestNoListNotTested(t *testing.T) {
	r := Check(listed, "")
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestEmptyListNotTested(t *testing.T) {
	list := writeList(t, "# nothing yet\n")
	if got := Check(listed, list).Status; got != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", got)
	}
}

// TestInvalidLineRefusesTheList: any text was taken as a hash, so a list
// holding only "garbage" PASSed "among 1 known-bad hashes". As the feed loader
// does, a line that does not start with a SHA-256 refuses the whole list, and
// the row is NOT_TESTED naming the line: a list that is partly wrong may be
// missing the entry that matters. Falsification: accept any first field again
// and these PASS.
func TestInvalidLineRefusesTheList(t *testing.T) {
	for name, body := range map[string]string{
		"garbage only":   "garbage\n",
		"mixed":          listed + "  known-bad\nnot-a-hash  oops\n",
		"short hex":      listed[:63] + "  one digit short\n",
		"non-hex digits": strings.Repeat("g", 64) + "  not hex\n",
	} {
		list := writeList(t, body)
		if _, err := Load(list); err == nil {
			t.Errorf("%s: Load must refuse the list", name)
		}
		r := Check("0000000000000000000000000000000000000000000000000000000000000000", list)
		if r.Status != checks.NotTested {
			t.Errorf("%s: status = %s, want NOT_TESTED: %s", name, r.Status, r.Notes)
		}
		if !strings.Contains(r.Notes, "not a SHA-256") || !strings.Contains(r.Notes, "line") {
			t.Errorf("%s: notes must name the bad line, got %q", name, r.Notes)
		}
	}
	// Case is not a reason to refuse: hashes are compared in lower case.
	entries, err := Load(writeList(t, strings.ToUpper(listed)+"  upper-case\n"))
	if err != nil || entries[listed].Label != "upper-case" {
		t.Fatalf("an upper-case hash should load: %v %v", entries, err)
	}
}

// Falsification anchor: remove the entry and the hash must stop failing.
func TestRemovingEntryStopsFailing(t *testing.T) {
	list := writeList(t, listed+"  known-bad\n")
	if Check(listed, list).Status != checks.Fail {
		t.Fatal("listed hash must fail before the entry is removed")
	}
	list2 := writeList(t, "# entry removed\n")
	if Check(listed, list2).Status == checks.Fail {
		t.Fatal("with the entry removed the hash must not fail")
	}
}
