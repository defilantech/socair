package airlock

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Event is one airlock activity record. The log is append-only evidence, not
// state: nothing reads it to decide a promotion.
//
// The log is hash-chained: each entry's Prev is the sha256 of the previous
// line's exact bytes, and the first entry's is Genesis. Editing, deleting,
// inserting, or reordering a line breaks the chain at the line after it, and
// Verify names that line. Cutting lines off the end leaves a shorter valid
// chain; that is caught only against a head recorded earlier (VerifyOptions).
type Event struct {
	TS      string `json:"ts"`
	Action  string `json:"action"`           // pull | ingest | promote | refuse
	Outcome string `json:"outcome"`          // ok | conditional | refused
	Source  string `json:"source,omitempty"` // airlock | local | cache
	Repo    string `json:"repo,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// Prev is the sha256 of the previous log line, or Genesis for the first.
	// Empty only on entries written before the log was chained.
	Prev string `json:"prev,omitempty"`
}

// Genesis is the Prev of the first entry in a chained log.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// maxLine bounds one log line, for the reader and the tail scan alike.
const maxLine = 1024 * 1024

// Activity actions.
const (
	ActionPull    = "pull"
	ActionIngest  = "ingest"
	ActionPromote = "promote"
	ActionRefuse  = "refuse"
	ActionTrust   = "trust"
)

// Activity outcomes.
const (
	OutcomeOK          = "ok"
	OutcomeConditional = "conditional"
	OutcomeRefused     = "refused"
)

// Record appends one event to the activity log, stamping the time and the
// default source when they are empty.
func (s *Store) Record(e Event) error {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Source == "" {
		e.Source = "airlock"
	}

	f, err := os.OpenFile(s.LogPath(), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("open activity log: %w", err)
	}
	defer f.Close()
	unlock, err := lockFile(f)
	if err != nil {
		return fmt.Errorf("lock activity log: %w", err)
	}
	defer unlock()

	last, err := lastLine(f)
	if err != nil {
		return fmt.Errorf("read activity log tail: %w", err)
	}
	e.Prev = Genesis
	if last != nil {
		e.Prev = lineHash(last)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	// One write per line keeps appends whole for a reader that splits on
	// newlines.
	if _, err := f.Write(b); err != nil {
		return err
	}
	return nil
}

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// lastLine returns the last non-empty line of f, without its newline, or nil
// for an empty file. It reads only the tail.
func lastLine(f *os.File) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	n := min(size, maxLine+1)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = bytes.TrimRight(buf, "\n")
	if len(buf) == 0 {
		return nil, nil
	}
	i := bytes.LastIndexByte(buf, '\n')
	if i < 0 && n < size {
		return nil, fmt.Errorf("last line exceeds %d bytes", maxLine)
	}
	return buf[i+1:], nil
}

// Events reads the activity log in order. A missing log is empty, not an error.
func (s *Store) Events() ([]Event, error) {
	f, err := os.Open(s.LogPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("activity log line %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// ExpectHead is a head recorded earlier. When set, it must still be the
	// hash of some line, which catches lines cut off the end.
	ExpectHead string
}

// ChainReport is the result of verifying the log.
type ChainReport struct {
	// Entries is the number of lines; Legacy how many lead the log unchained,
	// written before chaining. Legacy lines are not covered by the chain.
	Entries int
	Legacy  int
	// Head is the hash of the last line: record it to detect truncation later.
	Head string
	// Broken is the 1-based line where the chain fails, 0 when intact.
	Broken int
	Reason string
}

// Verify walks the chain. A break is reported in the result, not as an
// error; the error is for a log that cannot be read at all.
func (s *Store) Verify(opts VerifyOptions) (ChainReport, error) {
	var r ChainReport
	f, err := os.Open(s.LogPath())
	if errors.Is(err, os.ErrNotExist) {
		if opts.ExpectHead != "" {
			r.Broken, r.Reason = 1, "the log is missing, but a head was recorded"
		}
		return r, nil
	}
	if err != nil {
		return r, err
	}
	defer f.Close()

	expect := strings.ToLower(strings.TrimSpace(opts.ExpectHead))
	seenHead := false
	prev := ""
	chained := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		r.Entries++
		n := r.Entries
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			r.Broken, r.Reason = n, "not a valid log entry: "+err.Error()
			return r, nil
		}
		switch {
		case e.Prev == "" && !chained:
			r.Legacy++
		case e.Prev == "":
			r.Broken, r.Reason = n, "entry has no chain link after the chain began"
			return r, nil
		case !chained && n == 1 && e.Prev != Genesis:
			r.Broken, r.Reason = n, "the first entry does not start the chain: an earlier entry was removed"
			return r, nil
		case !chained && n > 1 && e.Prev != prev:
			r.Broken, r.Reason = n, "the chain does not start from the entry before it"
			return r, nil
		case chained && e.Prev != prev:
			r.Broken, r.Reason = n, "previous-entry hash does not match: an entry before this one was edited, removed, inserted, or reordered"
			return r, nil
		default:
			chained = true
		}
		prev = lineHash(line)
		if prev == expect {
			seenHead = true
		}
	}
	if err := sc.Err(); err != nil {
		return r, err
	}
	r.Head = prev
	if expect != "" && !seenHead {
		r.Broken, r.Reason = r.Entries+1, "the recorded head "+expect+" is not in the log: entries were cut off the end or the log was rewritten"
	}
	return r, nil
}
