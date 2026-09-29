package denylist

import (
	"os"
	"path/filepath"
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
