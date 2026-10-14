package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/feed"
	"github.com/defilantech/socair/internal/gguf/gguftest"
)

// outputs runs f and returns what it wrote to stdout and stderr.
func outputs(t *testing.T, f func() error) (string, string, error) {
	t.Helper()
	capture := func(dst **os.File) func() string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := *dst
		*dst = w
		var b bytes.Buffer
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = io.Copy(&b, r) }()
		return func() string { *dst = orig; _ = w.Close(); wg.Wait(); return b.String() }
	}
	outDone := capture(&os.Stdout)
	errDone := capture(&os.Stderr)
	runErr := f()
	return outDone(), errDone(), runErr
}

// cliFeeds signs feeds with one key, as an issuer does.
type cliFeeds struct {
	key *attest.PrivateKey
	pub string
}

func newCLIFeeds(t *testing.T) cliFeeds {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "feed")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	return cliFeeds{key: k, pub: prefix + ".pub"}
}

// release signs a feed valid from issued to expires and returns its
// directory; use also configures it for the engine.
func (c cliFeeds) release(t *testing.T, version string, issued, expires time.Time) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "denylist.txt"), []byte(strings.Repeat("ab", 32)+"  "+version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := feed.Info{Issuer: "Example Intel", Version: version,
		Issued: issued.UTC().Format(time.RFC3339), Expires: expires.UTC().Format(time.RFC3339)}
	if err := feed.Sign(dir, info, c.key.ID, c.key.Sign); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (c cliFeeds) use(t *testing.T, dir string) {
	t.Setenv("SOCAIR_FEED", dir)
	t.Setenv("SOCAIR_FEED_KEYS", c.pub)
}

func cliFixture(t *testing.T) string {
	t.Helper()
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_ACCEPTED_BY", "SOCAIR_STORE", "SOCAIR_TOKENIZER_REFERENCE"} {
		t.Setenv(k, "")
	}
	p := filepath.Join(t.TempDir(), "fixture-Q5_K_M.gguf")
	if err := os.WriteFile(p, gguftest.BuildGGUF(gguftest.Clean()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// socair scan says on stderr when the feed is in the last third of its
// validity, and only then; the report on stdout is a report either way.
func TestScanCommandWarnsBeforeTheFeedExpires(t *testing.T) {
	art := cliFixture(t)
	c := newCLIFeeds(t)
	now := time.Now()

	c.use(t, c.release(t, "2026.9.1", now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour)))
	out, errOut, err := outputs(t, func() error { return scan([]string{art}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "warning: feed Example Intel 2026.9.1 expires at") || !strings.Contains(errOut, "stops") {
		t.Fatalf("a feed in its last third must warn on stderr: %q", errOut)
	}
	if !strings.Contains(out, `"schema_version"`) || strings.Contains(out, "warning") {
		t.Fatalf("the warning must not reach the report: %s", out)
	}

	c.use(t, c.release(t, "2026.10.1", now.Add(-time.Hour), now.Add(89*24*time.Hour)))
	if _, errOut, err := outputs(t, func() error { return scan([]string{art}) }); err != nil || strings.Contains(errOut, "warning") {
		t.Fatalf("a fresh feed must not warn: %v %q", err, errOut)
	}
}

// With --store or SOCAIR_STORE, socair scan refuses a feed older than the
// newest the store has used; without a store it keeps no record.
func TestScanCommandWithAStoreRefusesAnOlderFeed(t *testing.T) {
	art := cliFixture(t)
	root := filepath.Join(t.TempDir(), "store")
	if _, err := airlock.Init(root); err != nil {
		t.Fatal(err)
	}
	c := newCLIFeeds(t)
	now := time.Now()
	newer := c.release(t, "2026.10.2", now.Add(-time.Hour), now.Add(60*24*time.Hour))
	older := c.release(t, "2026.10.1", now.Add(-48*time.Hour), now.Add(60*24*time.Hour))

	c.use(t, newer)
	if _, _, err := outputs(t, func() error { return scan([]string{art, "--store", root}) }); err != nil {
		t.Fatal(err)
	}
	c.use(t, older)
	if _, _, err := outputs(t, func() error { return scan([]string{art, "--store", root}) }); !errors.Is(err, feed.ErrRollback) {
		t.Fatalf("--store: an older feed must stop the scan: %v", err)
	}
	t.Setenv("SOCAIR_STORE", root)
	if _, _, err := outputs(t, func() error { return scan([]string{art}) }); !errors.Is(err, feed.ErrRollback) {
		t.Fatalf("SOCAIR_STORE: an older feed must stop the scan: %v", err)
	}
	t.Setenv("SOCAIR_STORE", "")
	if _, _, err := outputs(t, func() error { return scan([]string{art}) }); err != nil {
		t.Fatalf("without a store there is nothing to compare with: %v", err)
	}

	// feed verify with the store says the same, and writes nothing.
	out, _, err := outputs(t, func() error { return feedCmd([]string{"verify", older, "--keys", c.pub, "--store", root}) })
	if !errors.Is(err, feed.ErrRollback) || !strings.Contains(out, "verified:") || !strings.Contains(out, "2026.10.2") {
		t.Fatalf("feed verify --store: %v\n%s", err, out)
	}

	// The deliberate rollback: a reason is required, and then the older
	// feed is the store's record.
	if _, _, err := outputs(t, func() error { return airlockFeed([]string{"accept", older, "--keys", c.pub, "--store", root}) }); err == nil ||
		!strings.Contains(err.Error(), "usage") {
		t.Fatalf("accept with no reason: %v", err)
	}
	out, _, err = outputs(t, func() error {
		return airlockFeed([]string{"accept", older, "--keys", c.pub, "--reason", "2026.10.2 was withdrawn", "--store", root})
	})
	if err != nil || !strings.Contains(out, "2026.10.1") || !strings.Contains(out, "replacing feed Example Intel 2026.10.2") {
		t.Fatalf("accept: %v\n%s", err, out)
	}
	if _, _, err := outputs(t, func() error { return scan([]string{art, "--store", root}) }); err != nil {
		t.Fatalf("the accepted feed must scan: %v", err)
	}
	s, _ := airlock.Open(root)
	ev, _ := s.Events()
	if last := ev[len(ev)-1]; last.Action != airlock.ActionFeed || last.Outcome != airlock.OutcomeAccepted || !strings.Contains(last.Detail, "withdrawn") {
		t.Fatalf("the rollback must be logged with its reason: %+v", last)
	}
}
