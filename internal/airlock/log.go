package airlock

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Event is one airlock activity record. The log is append-only evidence, not
// state: nothing reads it to decide a promotion.
type Event struct {
	TS      string `json:"ts"`
	Action  string `json:"action"`           // pull | ingest | promote | refuse
	Outcome string `json:"outcome"`          // ok | conditional | refused
	Source  string `json:"source,omitempty"` // airlock | local | cache
	Repo    string `json:"repo,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Activity actions.
const (
	ActionPull    = "pull"
	ActionIngest  = "ingest"
	ActionPromote = "promote"
	ActionRefuse  = "refuse"
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
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	f, err := os.OpenFile(s.LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open activity log: %w", err)
	}
	defer f.Close()
	// One write per line keeps concurrent appends whole for a reader that
	// splits on newlines.
	if _, err := f.Write(b); err != nil {
		return err
	}
	return nil
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
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
