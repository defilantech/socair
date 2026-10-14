package feed

import (
	"strings"
	"testing"
	"time"
)

// The issue's falsification: a feed inside the last third of its validity
// warns, and one outside it does not. Make ExpiresSoon return false and the
// inside cases fail; make it return true and the outside cases fail.
func TestExpiryNoticeWindow(t *testing.T) {
	// 30 days of validity: the window is the last 10.
	in := Info{Issuer: "Example Intel", Version: "2026.10.1", Issued: "2026-10-01T00:00:00Z", Expires: "2026-10-31T00:00:00Z"}
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		now  string
		warn bool
		want string
	}{
		{"2026-10-01T00:00:00Z", false, ""},
		{"2026-10-20T23:59:59Z", false, ""},
		{"2026-10-21T00:00:00Z", true, "in 10 days"},
		{"2026-10-25T06:00:00Z", true, "in 5 days"},
		{"2026-10-30T20:00:00Z", true, "in 4 hours"},
		{"2026-10-30T23:00:00Z", true, "in less than two hours"},
		{"2026-10-31T00:00:00Z", true, "expired at 2026-10-31T00:00:00Z"},
	} {
		now := at(c.now)
		if got := in.ExpiresSoon(now); got != c.warn {
			t.Errorf("%s: ExpiresSoon %v, want %v", c.now, got, c.warn)
		}
		n := in.ExpiryNotice(now)
		if !c.warn {
			if n != "" {
				t.Errorf("%s: a feed outside the window must not warn: %s", c.now, n)
			}
			continue
		}
		for _, want := range []string{c.want, "Example Intel 2026.10.1", "2026-10-31T00:00:00Z", "every scan and recheck that uses it stops"} {
			if !strings.Contains(n, want) {
				t.Errorf("%s: the warning must say %q: %s", c.now, want, n)
			}
		}
	}

	// The window scales with the validity: a 90-day feed warns 30 days out.
	long := Info{Issuer: "x", Version: "1", Issued: "2026-10-01T00:00:00Z", Expires: "2026-12-30T00:00:00Z"}
	if long.ExpiresSoon(at("2026-11-29T23:59:59Z")) || !long.ExpiresSoon(at("2026-11-30T00:00:00Z")) {
		t.Error("a 90-day feed must warn in its last 30 days and not before")
	}

	// Times that do not parse are not reported here; Load refuses them.
	if (Info{Issued: "soon", Expires: "later"}).ExpiryNotice(at("2026-10-25T00:00:00Z")) != "" {
		t.Error("an unparseable feed must not produce a notice")
	}
}

// A loaded feed carries the notice through its Info.
func TestLoadedFeedWarns(t *testing.T) {
	dir, keys := built(t)
	f, err := Load(dir, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.ExpiryNotice(now) != "" {
		t.Errorf("two days into a month-long feed must not warn: %s", f.ExpiryNotice(now))
	}
	late := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	if _, err := Load(dir, keys, late); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.ExpiryNotice(late), "in 4 days") {
		t.Errorf("late in its window the feed must warn: %q", f.ExpiryNotice(late))
	}
}
