package airlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventsOnMissingLogIsEmpty(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ev, err := s.Events()
	if err != nil {
		t.Fatalf("Events on a fresh store: %v", err)
	}
	if len(ev) != 0 {
		t.Fatalf("expected no events, got %d", len(ev))
	}
}

func TestRecordAppendsInOrderWithDefaults(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Event{Action: ActionPull, Outcome: OutcomeOK, Repo: "org/name", SHA256: "aa"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Event{Action: ActionPromote, Outcome: OutcomeConditional, SHA256: "aa", Detail: "2 surfaces accepted"}); err != nil {
		t.Fatal(err)
	}

	ev, err := s.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 2 {
		t.Fatalf("expected 2 events, got %d", len(ev))
	}
	if ev[0].Action != ActionPull || ev[1].Action != ActionPromote {
		t.Fatalf("events out of order: %s then %s", ev[0].Action, ev[1].Action)
	}
	for i, e := range ev {
		if e.TS == "" {
			t.Errorf("event %d has no timestamp", i)
		}
		if e.Source != "airlock" {
			t.Errorf("event %d source = %q, want default airlock", i, e.Source)
		}
	}
	if ev[1].Outcome != OutcomeConditional {
		t.Errorf("a conditional promotion must log its outcome, got %q", ev[1].Outcome)
	}

	// The log is one JSON object per line, so a reader can split it without a
	// parser.
	raw, _ := os.ReadFile(s.LogPath())
	if n := strings.Count(string(raw), "\n"); n != 2 {
		t.Errorf("expected 2 lines, got %d", n)
	}
	if !strings.HasPrefix(string(raw), "{") {
		t.Errorf("log line is not a JSON object: %q", string(raw[:min(40, len(raw))]))
	}
}

func TestEventsRejectsACorruptLine(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root, logName), []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Events(); err == nil {
		t.Fatal("a corrupt log line must be an error, not a silent skip")
	}
}
