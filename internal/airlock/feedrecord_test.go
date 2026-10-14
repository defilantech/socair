package airlock

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/feed"
)

// release signs a feed issued at issued, listing deny, and returns its
// directory. It does not point the engine at it.
func (f feedSigner) release(t *testing.T, version string, issued time.Time, deny string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "denylist.txt"), []byte(deny+"  known bad\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := feed.Info{Issuer: "Example Intel", Version: version,
		Issued: issued.UTC().Format(time.RFC3339), Expires: time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)}
	if err := feed.Sign(dir, info, f.key.ID, f.key.Sign); err != nil {
		t.Fatal(err)
	}
	return dir
}

// loaded verifies a released feed as a scan would.
func (f feedSigner) loaded(t *testing.T, dir string) *feed.Feed {
	t.Helper()
	keys, err := attest.LoadKeyring(f.pub)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := feed.Load(dir, keys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// releases are three feeds from one issuer, oldest first.
func releases(t *testing.T) (feedSigner, *feed.Feed, *feed.Feed, *feed.Feed) {
	t.Helper()
	s := newFeedSigner(t)
	base := time.Now().Add(-20 * 24 * time.Hour)
	return s,
		s.loaded(t, s.release(t, "2026.9.1", base, strings.Repeat("a", 64))),
		s.loaded(t, s.release(t, "2026.10.1", base.Add(10*24*time.Hour), strings.Repeat("b", 64))),
		s.loaded(t, s.release(t, "2026.10.2", base.Add(15*24*time.Hour), strings.Repeat("c", 64)))
}

func feedEvents(t *testing.T, s *Store) []Event {
	t.Helper()
	ev, err := s.Events()
	if err != nil {
		t.Fatal(err)
	}
	var out []Event
	for _, e := range ev {
		if e.Action == ActionFeed {
			out = append(out, e)
		}
	}
	return out
}

// The issue's falsification: once a store has used a feed, an older feed that
// still verifies and is inside its window is refused, with both named, and
// the refusal is logged. A newer feed moves the record forward. Remove the
// comparison in CheckFeed and the older feed is accepted.
func TestStoreRefusesAnOlderFeed(t *testing.T) {
	s := trustedStore(t)
	_, sep, oct, later := releases(t)

	if err := s.CheckFeed(oct); err != nil {
		t.Fatalf("a first feed must be recorded: %v", err)
	}
	rec, err := s.readFeedRecord()
	if err != nil || rec == nil || rec.Record != oct.Record() || rec.Accepted != "" {
		t.Fatalf("record after first use: %+v %v", rec, err)
	}
	if ev := feedEvents(t, s); len(ev) != 1 || ev[0].Outcome != OutcomeOK || ev[0].Feed == nil || *ev[0].Feed != oct.Record() ||
		ev[0].SHA256 != oct.StatementSHA256 || !strings.Contains(ev[0].Detail, "first feed") {
		t.Fatalf("first use must be logged: %+v", ev)
	}

	err = s.CheckFeed(sep)
	if !errors.Is(err, feed.ErrRollback) {
		t.Fatalf("an older feed must be refused: %v", err)
	}
	for _, want := range []string{"2026.9.1", "2026.10.1", "older", "socair airlock feed accept"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q: %v", want, err)
		}
	}
	if rec, _ := s.readFeedRecord(); rec.Record != oct.Record() {
		t.Fatalf("a refusal must not move the record: %+v", rec)
	}
	ev := feedEvents(t, s)
	if last := ev[len(ev)-1]; last.Outcome != OutcomeRefused || *last.Feed != sep.Record() || !strings.Contains(last.Detail, "older") {
		t.Fatalf("the refusal must be logged: %+v", last)
	}

	// The recorded feed passes and writes nothing; a newer one replaces it.
	before, _ := os.ReadFile(s.LogPath())
	if err := s.CheckFeed(oct); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(s.LogPath()); !bytes.Equal(before, after) {
		t.Error("re-using the recorded feed must not write to the log")
	}
	if err := s.CheckFeed(later); err != nil {
		t.Fatal(err)
	}
	if rec, _ := s.readFeedRecord(); rec.Record != later.Record() {
		t.Fatalf("a newer feed must become the record: %+v", rec)
	}
	if err := s.CheckFeed(oct); !errors.Is(err, feed.ErrRollback) {
		t.Fatalf("the feed before the record is now older: %v", err)
	}
	chainIntact(t, s)
}

// A scan with the store gets the check through engine.Inputs, and the recheck
// runs it before writing any evidence.
func TestScanAndRecheckWithAStoreRefuseAnOlderFeed(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	signer := newFeedSigner(t)
	base := time.Now().Add(-10 * 24 * time.Hour)
	newer := signer.release(t, "2026.10.2", base.Add(5*24*time.Hour), strings.Repeat("c", 64))
	older := signer.release(t, "2026.10.1", base, id)
	t.Setenv("SOCAIR_FEED_KEYS", signer.pub)

	t.Setenv("SOCAIR_FEED", newer)
	recheckOnly(t, s, RecheckOptions{})
	evidence, err := os.ReadFile(filepath.Join(s.CleanPath(id), RecheckFile))
	if err != nil {
		t.Fatal(err)
	}

	// The older feed names the model as known-bad, but it must not be used
	// at all: neither by a recheck nor by a scan with this store.
	t.Setenv("SOCAIR_FEED", older)
	if _, err := s.Recheck(RecheckOptions{}); !errors.Is(err, feed.ErrRollback) {
		t.Fatalf("a recheck with an older feed must stop: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(s.CleanPath(id), RecheckFile)); !bytes.Equal(evidence, after) {
		t.Fatal("a refused recheck must write no evidence")
	}
	art := s.cleanArtifact(s.CleanPath(id))
	if _, err := engine.ScanWith(art, engine.ModeFull, engine.Inputs{Feed: s.CheckFeed}); !errors.Is(err, feed.ErrRollback) {
		t.Fatalf("a scan with the store and an older feed must stop: %v", err)
	}
	// Without the store there is no record to compare with.
	if _, err := engine.ScanWith(art, engine.ModeFull, engine.Inputs{}); err != nil {
		t.Fatalf("a scan without a store keeps no record: %v", err)
	}
}

// A deliberate rollback: the operator accepts an older feed with a reason,
// and the log keeps it. The store then follows the accepted feed. An empty
// reason is refused.
func TestAcceptFeedRollsBackOnPurpose(t *testing.T) {
	s := trustedStore(t)
	s.Actor = "jane"
	_, sep, oct, later := releases(t)
	for _, f := range []*feed.Feed{sep, later} {
		if err := s.CheckFeed(f); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AcceptFeed(oct, "  "); err == nil {
		t.Fatal("an acceptance with no reason must be refused")
	}
	prev, err := s.AcceptFeed(oct, "release 2026.10.2 was withdrawn: it listed a false positive")
	if err != nil || prev == nil || *prev != later.Record() {
		t.Fatalf("accept: %+v %v", prev, err)
	}
	rec, _ := s.readFeedRecord()
	if rec.Record != oct.Record() || !strings.Contains(rec.Accepted, "withdrawn") {
		t.Fatalf("record after acceptance: %+v", rec)
	}
	ev := feedEvents(t, s)
	last := ev[len(ev)-1]
	if last.Outcome != OutcomeAccepted || last.Actor != "jane" || *last.Feed != oct.Record() ||
		!strings.Contains(last.Detail, "a rollback from feed Example Intel 2026.10.2") || !strings.Contains(last.Detail, "withdrawn") ||
		!strings.Contains(last.Detail, "2026.10.2") {
		t.Fatalf("the acceptance must be logged with the reason and what it replaced: %+v", last)
	}
	if err := s.CheckFeed(oct); err != nil {
		t.Fatalf("the accepted feed must now pass: %v", err)
	}
	if err := s.CheckFeed(sep); !errors.Is(err, feed.ErrRollback) {
		t.Fatalf("a feed older than the accepted one is still refused: %v", err)
	}
	if err := s.CheckFeed(later); err != nil {
		t.Fatalf("a newer feed moves the record forward again: %v", err)
	}
	chainIntact(t, s)
}

// The record has two witnesses, the file and the log. Deleting or editing
// either alone stops the scan rather than resetting the record, and
// AcceptFeed repairs it. Falsification: treat a missing record file as a
// first use, or skip the comparison with the log, and a case passes.
func TestFeedRecordWitnessesMustAgree(t *testing.T) {
	cases := map[string]struct {
		tamper func(t *testing.T, s *Store, sep, oct *feed.Feed)
		want   string
	}{
		"record file deleted": {func(t *testing.T, s *Store, _, _ *feed.Feed) {
			if err := os.Remove(s.FeedRecordPath()); err != nil {
				t.Fatal(err)
			}
		}, "is missing, but the activity log"},
		"record file names the older feed": {func(t *testing.T, s *Store, sep, _ *feed.Feed) {
			rewriteRecord(t, s, sep.Record())
		}, "but the activity log's newest feed entry"},
		"record file does not parse": {func(t *testing.T, s *Store, _, _ *feed.Feed) {
			if err := os.WriteFile(s.FeedRecordPath(), []byte("{"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "does not parse"},
		"log deleted": {func(t *testing.T, s *Store, _, _ *feed.Feed) {
			if err := os.Remove(s.LogPath()); err != nil {
				t.Fatal(err)
			}
		}, "the activity log has no feed entry"},
		"older feed forged into the log and the record": {func(t *testing.T, s *Store, sep, _ *feed.Feed) {
			r := sep.Record()
			if err := s.Record(Event{Action: ActionFeed, Outcome: OutcomeOK, Feed: &r}); err != nil {
				t.Fatal(err)
			}
			rewriteRecord(t, s, r)
		}, "with no accepted rollback"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := trustedStore(t)
			_, sep, oct, _ := releases(t)
			if err := s.CheckFeed(oct); err != nil {
				t.Fatal(err)
			}
			c.tamper(t, s, sep, oct)
			for _, f := range []*feed.Feed{sep, oct} {
				if err := s.CheckFeed(f); err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "cannot be trusted") {
					t.Fatalf("%s must not pass on a record whose witnesses disagree: %v", f.Version, err)
				}
			}
			if _, err := s.ReviewFeed(oct); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("review must report the same: %v", err)
			}
			if _, err := s.AcceptFeed(oct, "repair after the incident on 2026-10-14"); err != nil {
				t.Fatal(err)
			}
			if err := s.CheckFeed(oct); err != nil {
				t.Fatalf("an accepted feed repairs the record: %v", err)
			}
			if err := s.CheckFeed(sep); !errors.Is(err, feed.ErrRollback) {
				t.Fatalf("after the repair an older feed is refused again: %v", err)
			}
		})
	}
}

func rewriteRecord(t *testing.T, s *Store, r feed.Record) {
	t.Helper()
	b, err := json.Marshal(FeedRecord{Format: FeedRecordFormat, Record: r, RecordedUTC: "2026-10-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.FeedRecordPath(), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ReviewFeed reports without writing: no record, no log entry.
func TestReviewFeedWritesNothing(t *testing.T) {
	s := trustedStore(t)
	_, sep, oct, _ := releases(t)
	if rec, err := s.ReviewFeed(oct); rec != nil || err != nil {
		t.Fatalf("an empty store has no record and refuses nothing: %v %v", rec, err)
	}
	if _, err := os.Stat(s.FeedRecordPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a review must not record the feed")
	}
	fresh, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := fresh.ReviewFeed(oct); rec != nil || err != nil {
		t.Fatalf("a store with no log: %v %v", rec, err)
	}
	if _, err := os.Stat(fresh.LogPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a review must not create the log")
	}
	if err := s.CheckFeed(oct); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.LogPath())
	rec, err := s.ReviewFeed(sep)
	if rec == nil || *rec != oct.Record() || !errors.Is(err, feed.ErrRollback) || !strings.Contains(err.Error(), "would refuse") {
		t.Fatalf("review of an older feed: %+v %v", rec, err)
	}
	if after, _ := os.ReadFile(s.LogPath()); !bytes.Equal(before, after) {
		t.Fatal("a review must not log")
	}
}
