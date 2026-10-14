package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// LoadKnownBad reads the lists a scan reads, by the same rules: the feed's
// list and the local list, each named, a hash on both matched on both.
// Falsification: drop either list from LoadKnownBad and a match goes missing.
func TestLoadKnownBadReadsTheFeedAndTheLocalList(t *testing.T) {
	both, feedOnly, localOnly := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	signedFeed(t, map[string]string{"denylist.txt": both + "  feed label\n" + feedOnly + "  feed only\n"})
	local := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(local, []byte(both+"  local label\n"+strings.ToUpper(localOnly)+"  local only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_DENYLIST", local)

	k, err := LoadKnownBad(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if k.Feed == nil || k.Feed.Issuer != "Example Intel" || k.Unread != "" {
		t.Fatalf("%+v", k)
	}
	// The local list is named as the Known-bad row names it, by file name and
	// hash, never by its path on the host (#170).
	body, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	named := "denylist deny.txt (sha256 " + sha(string(body)) + ")"
	if got := strings.Join(k.Sources(), " | "); got != "feed Example Intel 2026.10.1 | "+named {
		t.Fatalf("sources %q", got)
	}
	if got := k.Match(both); len(got) != 2 || got[0] != "feed label (feed Example Intel 2026.10.1)" || got[1] != "local label ("+named+")" {
		t.Fatalf("a hash on both lists: %v", got)
	}
	if got := k.Match(strings.ToUpper(feedOnly)); len(got) != 1 {
		t.Fatalf("feed only: %v", got)
	}
	if got := k.Match(localOnly); len(got) != 1 {
		t.Fatalf("local only: %v", got)
	}
	if got := k.Match(strings.Repeat("d", 64)); len(got) != 0 {
		t.Fatalf("an unlisted hash: %v", got)
	}
}

// A feed that does not verify stops LoadKnownBad as it stops a scan; an
// unreadable local list is reported, as a scan leaves its row NOT_TESTED.
func TestLoadKnownBadRefusesWhatAScanRefuses(t *testing.T) {
	signedFeed(t, map[string]string{"denylist.txt": strings.Repeat("a", 64) + "  label\n"})
	t.Setenv("SOCAIR_DENYLIST", "")
	if _, err := LoadKnownBad(time.Now().Add(365 * 24 * time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired feed must stop it: %v", err)
	}

	t.Setenv("SOCAIR_FEED", "")
	t.Setenv("SOCAIR_DENYLIST", filepath.Join(t.TempDir(), "missing.txt"))
	k, err := LoadKnownBad(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Lists) != 0 || !strings.Contains(k.Unread, "could not read denylist") {
		t.Fatalf("%+v", k)
	}

	t.Setenv("SOCAIR_DENYLIST", "")
	if k, err := LoadKnownBad(time.Now()); err != nil || len(k.Lists) != 0 || k.Feed != nil || k.Unread != "" {
		t.Fatalf("nothing configured: %+v %v", k, err)
	}
}
