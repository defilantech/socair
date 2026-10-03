package airlock

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

func chainedStore(t *testing.T, n int) *Store {
	t.Helper()
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := s.Record(Event{Action: ActionPull, Outcome: OutcomeOK, Detail: fmt.Sprintf("entry %d", i+1)}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func logLines(t *testing.T, s *Store) [][]byte {
	t.Helper()
	b, err := os.ReadFile(s.LogPath())
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
}

func writeLines(t *testing.T, s *Store, lines [][]byte) {
	t.Helper()
	if err := os.WriteFile(s.LogPath(), append(bytes.Join(lines, []byte("\n")), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestChainIntact(t *testing.T) {
	s := chainedStore(t, 5)
	r, err := s.Verify(VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Broken != 0 || r.Entries != 5 || r.Legacy != 0 || len(r.Head) != 64 {
		t.Fatalf("intact chain reported %+v", r)
	}
	if ev, _ := s.Events(); ev[0].Prev != Genesis {
		t.Errorf("the first entry must start from Genesis, got %q", ev[0].Prev)
	}
}

// Each tampering breaks the chain at a named line. Falsification: make
// Verify skip the prev comparison and every case reads intact.
func TestChainDetectsTampering(t *testing.T) {
	cases := map[string]struct {
		tamper func([][]byte) [][]byte
		line   int
	}{
		"edit a middle entry": {func(l [][]byte) [][]byte {
			l[2] = bytes.Replace(l[2], []byte("entry 3"), []byte("entry X"), 1)
			return l
		}, 4},
		"delete a middle entry":  {func(l [][]byte) [][]byte { return append(l[:2], l[3:]...) }, 3},
		"delete the first entry": {func(l [][]byte) [][]byte { return l[1:] }, 1},
		"swap two entries":       {func(l [][]byte) [][]byte { l[1], l[2] = l[2], l[1]; return l }, 2},
		"insert a forged entry": {func(l [][]byte) [][]byte {
			forged := []byte(`{"ts":"2026-01-01T00:00:00Z","action":"promote","outcome":"ok","prev":"` + lineHash(l[1]) + `"}`)
			return append(l[:2], append([][]byte{forged}, l[2:]...)...)
		}, 4},
		"strip the chain link": {func(l [][]byte) [][]byte {
			l[3] = []byte(strings.Replace(string(l[3]), `"prev"`, `"was"`, 1))
			return l
		}, 4},
		"garbage line": {func(l [][]byte) [][]byte { l[1] = []byte("{not json"); return l }, 2},
	}
	for name, c := range cases {
		s := chainedStore(t, 5)
		writeLines(t, s, c.tamper(logLines(t, s)))
		r, err := s.Verify(VerifyOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Broken != c.line {
			t.Errorf("%s: broken at %d (%s), want line %d", name, r.Broken, r.Reason, c.line)
		}
	}
}

// Cutting entries off the end leaves a valid shorter chain, so truncation is
// caught against a head recorded earlier.
func TestTruncationNeedsARecordedHead(t *testing.T) {
	s := chainedStore(t, 5)
	before, _ := s.Verify(VerifyOptions{})
	mid := lineHash(logLines(t, s)[2])
	writeLines(t, s, logLines(t, s)[:3])

	if r, _ := s.Verify(VerifyOptions{}); r.Broken != 0 {
		t.Fatalf("a truncated chain is still internally valid, got %+v", r)
	}
	if r, _ := s.Verify(VerifyOptions{ExpectHead: before.Head}); r.Broken == 0 {
		t.Fatal("truncation past a recorded head must be reported")
	}
	if r, _ := s.Verify(VerifyOptions{ExpectHead: mid}); r.Broken != 0 {
		t.Fatalf("a recorded head still in the log must verify: %+v", r)
	}
}

// A log written before chaining verifies, with its unchained prefix counted,
// and the chain continues from its last line.
func TestLegacyPrefix(t *testing.T) {
	s, _ := Init(t.TempDir())
	legacy := `{"ts":"2026-01-01T00:00:00Z","action":"pull","outcome":"ok"}` + "\n" + `{"ts":"2026-01-02T00:00:00Z","action":"pull","outcome":"ok"}` + "\n"
	if err := os.WriteFile(s.LogPath(), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Record(Event{Action: ActionPull, Outcome: OutcomeOK}); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := s.Verify(VerifyOptions{})
	if r.Broken != 0 || r.Legacy != 2 || r.Entries != 4 {
		t.Fatalf("legacy prefix: %+v", r)
	}
}

// Concurrent appends must not fork the chain.
func TestConcurrentAppendsStayChained(t *testing.T) {
	s, _ := Init(t.TempDir())
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Record(Event{Action: ActionPull, Outcome: OutcomeOK, Detail: fmt.Sprint(i)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	r, _ := s.Verify(VerifyOptions{})
	if r.Broken != 0 || r.Entries != 40 {
		t.Fatalf("concurrent appends: %+v", r)
	}
}
