package feed

import (
	"errors"
	"strings"
	"testing"
)

// signedAt builds and loads a feed issued at issued, signed by its own key.
func signedAt(t *testing.T, version, issued, deny string) *Feed {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "denylist.txt", deny+"  known bad\n")
	id, sign, keys := signer(t)
	in := Info{Issuer: "Example Intel", Version: version, Issued: issued, Expires: "2026-12-31T00:00:00Z"}
	if err := Sign(dir, in, id, sign); err != nil {
		t.Fatal(err)
	}
	f, err := Load(dir, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// The issue's falsification: a feed older than the recorded one is refused,
// whoever signed it. Make Newer accept everything and the older cases pass.
func TestNewerRefusesAnOlderFeed(t *testing.T) {
	sep := signedAt(t, "2026.9.1", "2026-09-20T00:00:00Z", h1)
	oct := signedAt(t, "2026.10.1", "2026-10-01T00:00:00Z", h2)
	if sep.StatementSHA256 == "" || sep.StatementSHA256 == oct.StatementSHA256 {
		t.Fatalf("each feed must be named by its own statement: %q %q", sep.StatementSHA256, oct.StatementSHA256)
	}

	if newer, err := Newer(sep.Record(), oct.Record()); !newer || err != nil {
		t.Errorf("a feed issued later must replace the record: %v %v", newer, err)
	}
	if newer, err := Newer(oct.Record(), oct.Record()); newer || err != nil {
		t.Errorf("the recorded feed itself is neither newer nor refused: %v %v", newer, err)
	}

	_, err := Newer(oct.Record(), sep.Record())
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("an older feed must be refused as a rollback: %v", err)
	}
	for _, want := range []string{"2026.9.1", "2026-09-20T00:00:00Z", "2026.10.1", "2026-10-01T00:00:00Z", "older"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name both feeds (%q): %v", want, err)
		}
	}

	// Another issuer and key are held to the same order.
	other := sep.Record()
	other.Issuer, other.KeyID = "Another Issuer", strings.Repeat("ef", 32)
	if _, err := Newer(oct.Record(), other); !errors.Is(err, ErrRollback) {
		t.Errorf("an older feed from another issuer and key must be refused too: %v", err)
	}

	// Two different feeds with one issue time cannot be ordered.
	twin := signedAt(t, "2026.10.1-b", "2026-10-01T00:00:00Z", h3)
	if _, err := Newer(oct.Record(), twin.Record()); !errors.Is(err, ErrRollback) || !strings.Contains(err.Error(), "same time") {
		t.Errorf("a different feed issued at the same time must be refused: %v", err)
	}

	// A record that does not parse is an error, never a pass.
	broken := oct.Record()
	broken.Issued = "last Tuesday"
	if _, err := Newer(broken, sep.Record()); err == nil {
		t.Error("a record with an unreadable issue time must not let a feed through")
	}
}

// The statement digest is the same feed's on every load, and changes when
// anything signed changes.
func TestStatementNamesTheFeed(t *testing.T) {
	dir, keys := built(t)
	a, err := Load(dir, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.StatementSHA256 != b.StatementSHA256 || len(a.StatementSHA256) != 64 {
		t.Fatalf("statement digest: %q %q", a.StatementSHA256, b.StatementSHA256)
	}
	r := a.Record()
	if r.Issuer != "Example Intel" || r.Version != "2026.10.1" || r.KeyID != a.KeyID || r.Statement != a.StatementSHA256 {
		t.Fatalf("record: %+v", r)
	}
	if s := r.String(); !strings.Contains(s, "2026.10.1") || !strings.Contains(s, a.StatementSHA256[:16]) {
		t.Errorf("record string: %s", s)
	}
}
