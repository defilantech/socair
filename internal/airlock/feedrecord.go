package airlock

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/feed"
)

// A store remembers the newest feed it has used, so a scan or recheck with
// the store cannot be moved back to an older feed that is still inside its
// validity window (a rollback; docs/feed.md). The order is the feeds' signed
// issue time, across every issuer and key (feed.Newer).
//
// The record has two witnesses, and they must agree:
//
//   - FeedRecordFile in the store root, written through a temp file and a
//     rename;
//   - the activity log's feed entries, under its hash chain. Replayed in
//     order, each "ok" entry must be newer than the one before; only an
//     "accepted" entry, written by AcceptFeed, may go back.
//
// A missing, unreadable, or contradicting witness stops the scan with the
// reason, never resets the record: deleting or editing one witness does not
// downgrade the store, and doing it to both needs the log rewritten, which
// `socair airlock log --verify --expect-head` detects. An operator who means
// to go back (a feed release was withdrawn) runs AcceptFeed, which writes
// both witnesses and logs the reason.

// FeedRecordFile is the store's record of the newest feed it has used.
const FeedRecordFile = "feed-record.json"

// FeedRecordFormat names the record's format.
const FeedRecordFormat = "socair.feed-record/v1"

// ActionFeed is the log action of a change to the store's feed record, or of
// a feed it refused.
const ActionFeed = "feed"

// OutcomeAccepted is a feed an operator accepted on purpose (AcceptFeed).
const OutcomeAccepted = "accepted"

// FeedRecord is FeedRecordFile.
type FeedRecord struct {
	Format string `json:"format"`
	feed.Record
	RecordedUTC string `json:"recorded_utc"`
	// Accepted is the operator's reason when the feed was accepted with
	// AcceptFeed rather than recorded by a scan.
	Accepted string `json:"accepted,omitempty"`
}

// FeedRecordPath is where the store keeps its feed record.
func (s *Store) FeedRecordPath() string { return filepath.Join(s.Root, FeedRecordFile) }

// acceptHint is how an operator moves the record on purpose.
const acceptHint = "to use it on purpose (for example, a newer feed release was withdrawn), run " +
	"`socair airlock feed accept <feed dir> --keys <key.pub|dir> --reason <why>`, which records it and logs the reason"

// CheckFeed checks f against the newest feed the store has used, as a scan or
// recheck with the store does before it reads anything. A first feed, or one
// issued after the recorded one, becomes the record and is logged. The
// recorded feed itself passes and writes nothing. An older feed, a different
// feed issued at the same time, or a record whose witnesses disagree is
// refused: the refusal is logged and returned, naming both feeds, and the
// scan stops, as it does for an expired feed.
func (s *Store) CheckFeed(f *feed.Feed) error {
	cand := f.Record()
	return s.withLog(func(log *os.File) error {
		cur, err := s.feedState(log)
		if err != nil {
			err = fmt.Errorf("refused %s: the store's record of the newest feed it has used cannot be trusted: %w. "+
				"Check the activity log with `socair airlock log --verify`; %s", cand.String(), err, acceptHint)
			return s.refuseFeed(log, cand, err)
		}
		why := "the first feed this store has used"
		if cur != nil {
			newer, err := feed.Newer(*cur, cand)
			if err != nil {
				err = fmt.Errorf("refused: %w. A store does not move back to an older feed, "+
					"which could undo a newer one's known-bad entries and reviews. Import a current feed; %s", err, acceptHint)
				return s.refuseFeed(log, cand, err)
			}
			if !newer {
				return nil
			}
			why = "newer than " + cur.String()
		}
		return s.setFeed(log, cand, "", Event{Action: ActionFeed, Outcome: OutcomeOK, SHA256: cand.Statement,
			Detail: "recorded " + cand.String() + " as the newest feed this store has used: " + why})
	})
}

// ReviewFeed says whether CheckFeed would let f through, without writing
// anything, and returns the store's record (nil when it has none). It is for
// commands that report on a feed without using it.
func (s *Store) ReviewFeed(f *feed.Feed) (*feed.Record, error) {
	cand := f.Record()
	// Read under the log's lock, but never create the log.
	var log io.ReaderAt = bytes.NewReader(nil)
	lf, err := os.Open(s.LogPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("open activity log: %w", err)
	default:
		defer lf.Close()
		unlock, err := lockFile(lf)
		if err != nil {
			return nil, fmt.Errorf("lock activity log: %w", err)
		}
		defer unlock()
		log = lf
	}
	cur, err := s.feedState(log)
	if err != nil {
		return nil, fmt.Errorf("a scan with this store would stop: the store's record of the newest feed it has used cannot be trusted: %w; %s", err, acceptHint)
	}
	if cur != nil {
		if _, err := feed.Newer(*cur, cand); err != nil {
			return cur, fmt.Errorf("a scan with this store would refuse it: %w; %s", err, acceptHint)
		}
	}
	return cur, nil
}

// AcceptFeed records f as the newest feed the store has used, whatever the
// record says, and logs it with the operator's reason. It is the one way to
// move a store back to an older feed, and the way to repair a record whose
// witnesses disagree. f must verify and be current: the caller loads it with
// feed.Load. It returns the record it replaced, or nil.
func (s *Store) AcceptFeed(f *feed.Feed, reason string) (*feed.Record, error) {
	reason = strings.Join(strings.Fields(reason), " ")
	if reason == "" {
		return nil, errors.New("accepting a feed needs a reason, recorded in the log (--reason)")
	}
	cand := f.Record()
	var prev *feed.Record
	err := s.withLog(func(log *os.File) error {
		cur, err := s.feedState(log)
		var what string
		switch {
		case err != nil:
			what = "replacing a record that could not be trusted (" + err.Error() + ")"
		case cur == nil:
			what = "the store had no record"
		default:
			prev = cur
			if newer, err := feed.Newer(*cur, cand); err != nil {
				what = "a rollback from " + cur.String()
			} else if newer {
				what = "replacing " + cur.String()
			} else {
				what = "the feed the store had recorded"
			}
		}
		return s.setFeed(log, cand, reason, Event{Action: ActionFeed, Outcome: OutcomeAccepted, SHA256: cand.Statement,
			Detail: "accepted " + cand.String() + " as the newest feed this store has used, " + what + "; reason: " + reason})
	})
	return prev, err
}

// setFeed writes the record, then its log entry, with the log locked.
func (s *Store) setFeed(log *os.File, rec feed.Record, accepted string, e Event) error {
	b, err := json.MarshalIndent(FeedRecord{Format: FeedRecordFormat, Record: rec,
		RecordedUTC: time.Now().UTC().Format(time.RFC3339), Accepted: accepted}, "", "  ")
	if err != nil {
		return err
	}
	if err := s.WriteFile(s.FeedRecordPath(), append(b, '\n')); err != nil {
		return fmt.Errorf("record the feed: %w", err)
	}
	e.Feed = &rec
	return s.appendLocked(log, e)
}

// refuseFeed logs a refused feed and returns the refusal.
func (s *Store) refuseFeed(log *os.File, rec feed.Record, refusal error) error {
	if err := s.appendLocked(log, Event{Action: ActionFeed, Outcome: OutcomeRefused, SHA256: rec.Statement,
		Detail: refusal.Error(), Feed: &rec}); err != nil {
		return fmt.Errorf("%w (and the refusal could not be logged: %v)", refusal, err)
	}
	return refusal
}

// feedState is the newest feed the store has used, from its two witnesses,
// or nil when neither names one. log is the activity log, read under its
// lock.
func (s *Store) feedState(log io.ReaderAt) (*feed.Record, error) {
	hist, line, err := feedHistory(log)
	if err != nil {
		return nil, err
	}
	rec, err := s.readFeedRecord()
	switch {
	case err != nil:
		return nil, err
	case rec == nil && hist == nil:
		return nil, nil
	case rec == nil:
		return nil, fmt.Errorf("%s is missing, but the activity log (line %d) names %s as the newest feed this store has used",
			FeedRecordFile, line, hist.String())
	case hist == nil:
		return nil, fmt.Errorf("%s names %s, but the activity log has no feed entry", FeedRecordFile, rec.Record.String())
	case rec.Record != *hist:
		return nil, fmt.Errorf("%s names %s, but the activity log's newest feed entry (line %d) names %s",
			FeedRecordFile, rec.Record.String(), line, hist.String())
	}
	return hist, nil
}

// readFeedRecord reads FeedRecordFile, or returns nil when there is none.
func (s *Store) readFeedRecord() (*FeedRecord, error) {
	b, err := os.ReadFile(s.FeedRecordPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %v", FeedRecordFile, err)
	}
	var r FeedRecord
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%s does not parse: %v", FeedRecordFile, err)
	}
	if r.Format != FeedRecordFormat {
		return nil, fmt.Errorf("%s is not %s", FeedRecordFile, FeedRecordFormat)
	}
	return &r, nil
}

// feedMarker selects the log lines worth decoding: every feed entry the
// store writes holds it.
var feedMarker = []byte(`"action":"` + ActionFeed + `"`)

// feedHistory replays the log's feed entries and returns the newest feed the
// store has used, and its line. Each "ok" entry must be newer than the record
// before it; an "accepted" entry replaces the record whatever it was, and
// clears any break before it. Refusals change nothing.
func feedHistory(log io.ReaderAt) (*feed.Record, int, error) {
	var cur *feed.Record
	var at int
	var broken error
	sc := bufio.NewScanner(io.NewSectionReader(log, 0, 1<<62))
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		if !bytes.Contains(line, feedMarker) {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, 0, fmt.Errorf("activity log line %d does not parse: %v", n, err)
		}
		if e.Action != ActionFeed || e.Outcome == OutcomeRefused {
			continue
		}
		if e.Feed == nil || (e.Outcome != OutcomeOK && e.Outcome != OutcomeAccepted) {
			return nil, 0, fmt.Errorf("activity log line %d is a feed entry that names no feed, or an unknown outcome %q", n, e.Outcome)
		}
		if e.Outcome == OutcomeAccepted {
			cur, at, broken = e.Feed, n, nil
			continue
		}
		if broken != nil {
			continue
		}
		if cur != nil {
			newer, err := feed.Newer(*cur, *e.Feed)
			if err != nil {
				broken = fmt.Errorf("activity log line %d records %s after %s (line %d) with no accepted rollback between them",
					n, e.Feed.String(), cur.String(), at)
				continue
			}
			if !newer {
				continue
			}
		}
		cur, at = e.Feed, n
	}
	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("read the activity log: %v", err)
	}
	if broken != nil {
		return nil, 0, broken
	}
	return cur, at, nil
}
