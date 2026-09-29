package airlock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/gguf/gguftest"
)

func fixtureSHA(t *testing.T) ([]byte, string) {
	t.Helper()
	b := gguftest.BuildGGUF(gguftest.Clean())
	p := filepath.Join(t.TempDir(), "x.gguf")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	sha, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b, sha
}

func TestEgressDeniedIsActionable(t *testing.T) {
	s, _ := Init(t.TempDir())
	pol := EgressPolicy{Allow: []string{"example.invalid"}, Endpoint: "https://huggingface.co", Timeout: time.Second}

	_, err := Pull(context.Background(), s, s.StagingPath(strings.Repeat("a", 64)),
		"org/name", "main", strings.Repeat("a", 64), pol)
	if err == nil {
		t.Fatal("a host outside the allowlist must be denied")
	}
	for _, want := range []string{"huggingface.co", "denied by policy", "SOCAIR_EGRESS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("denied egress should be actionable, %q missing from %q", want, err)
		}
	}

	// A hard deny wins even with the host allowlisted.
	t.Setenv("SOCAIR_EGRESS", "deny")
	pol.Allow = []string{"huggingface.co"}
	if _, err := Pull(context.Background(), s, s.StagingPath(strings.Repeat("a", 64)),
		"org/name", "main", strings.Repeat("a", 64), pol); err == nil {
		t.Fatal("SOCAIR_EGRESS=deny must refuse regardless of the allowlist")
	}
}

func TestPullEgressDeniedFailsWithinTimeout(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A stalled egress: hold until the client gives up, then unwind so the
		// test server can close promptly.
		select {
		case <-time.After(10 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer blocked.Close()

	s, _ := Init(t.TempDir())
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: blocked.URL, Timeout: 300 * time.Millisecond}

	start := time.Now()
	_, err := Pull(context.Background(), s, s.StagingPath(strings.Repeat("a", 64)),
		"org/name", "main", strings.Repeat("a", 64), pol)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a stalled egress must fail, not return success")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("a blocked pull must fail within its budget, took %s", elapsed)
	}
	if !strings.Contains(err.Error(), "budget") {
		t.Errorf("the timeout error should name the budget, got %q", err)
	}
}

func TestPullVerifiesLogsAndRecordsProvenance(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	want, sha := fixtureSHA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(want)
	}))
	defer srv.Close()

	s, _ := Init(t.TempDir())
	dst := s.StagingPath(sha)
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: srv.URL, Timeout: 5 * time.Second}

	e, err := Pull(context.Background(), s, dst, "org/name", "main", sha, pol)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("staged artifact: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("the staged bytes are not what the source served")
	}

	mb, err := os.ReadFile(filepath.Join(filepath.Dir(dst), "provenance.json"))
	if err != nil {
		t.Fatalf("provenance manifest: %v", err)
	}
	var m provenance.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.RepoURL, "org/name") || m.CommitOrTag != "main" {
		t.Errorf("manifest should record origin facts, got %+v", m)
	}
	if m.SigningStatus != "" {
		t.Errorf("the pull must not assert a signing status, got %q", m.SigningStatus)
	}

	ev, err := s.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Action != ActionPull || ev[0].Outcome != OutcomeOK {
		t.Fatalf("every pull must be logged, got %+v", ev)
	}
	if ev[0].SHA256 != sha || ev[0].Repo != "org/name" {
		t.Errorf("the pull log must carry the source and hash, got %+v", ev[0])
	}
	if e.SHA256 != sha {
		t.Errorf("event hash = %q, want %q", e.SHA256, sha)
	}
}

func TestPullHashMismatchRefuses(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	_, sha := fixtureSHA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not the artifact you asked for"))
	}))
	defer srv.Close()

	s, _ := Init(t.TempDir())
	dst := s.StagingPath(sha)
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: srv.URL, Timeout: 5 * time.Second}

	_, err := Pull(context.Background(), s, dst, "org/name", "main", sha, pol)
	if err == nil {
		t.Fatal("bytes that do not hash to the requested hash must refuse")
	}
	if !strings.Contains(err.Error(), "not the requested") {
		t.Errorf("the refusal should name the mismatch, got %q", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Error("a refused download must not be left staged")
	}
	ev, _ := s.Events()
	if len(ev) != 1 || ev[0].Outcome != OutcomeRefused {
		t.Errorf("a refused pull must be logged, got %+v", ev)
	}
}

func TestPullRequiresAnExpectedHash(t *testing.T) {
	s, _ := Init(t.TempDir())
	if _, err := Pull(context.Background(), s, s.StagingPath("aa"), "org/name", "main", "", DefaultEgressPolicy()); err == nil {
		t.Fatal("a pull without an expected hash must refuse")
	}
}
