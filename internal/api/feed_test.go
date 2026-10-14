package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/feed"
)

// feedKey signs test feeds; feeds released with one key share a keyring.
type feedKey struct {
	key *attest.PrivateKey
	pub string
}

func newFeedKey(t *testing.T) feedKey {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "feed")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	return feedKey{key: k, pub: prefix + ".pub"}
}

// use signs a feed valid from issued to expires and configures it, as
// SOCAIR_FEED and SOCAIR_FEED_KEYS would.
func (k feedKey) use(t *testing.T, version string, issued, expires time.Time) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "denylist.txt"), []byte(strings.Repeat("ab", 32)+"  "+version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := feed.Info{Issuer: "Example Intel", Version: version,
		Issued: issued.UTC().Format(time.RFC3339), Expires: expires.UTC().Format(time.RFC3339)}
	if err := feed.Sign(dir, info, k.key.ID, k.key.Sign); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_FEED", dir)
	t.Setenv("SOCAIR_FEED_KEYS", k.pub)
}

func feedStatusOf(t *testing.T, ts interface{ Client() *http.Client }, url string) FeedStatus {
	t.Helper()
	resp, err := ts.Client().Get(url + "/api/feed")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/feed: %d", resp.StatusCode)
	}
	var st FeedStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// GET /api/feed says when the configured feed expires once it is in the last
// third of its validity, and says nothing of it before. Falsification: drop
// the notice and the console has nothing to show.
func TestFeedStatusWarnsBeforeExpiry(t *testing.T) {
	t.Setenv("SOCAIR_FEED", "")
	ts := server(t, Options{})
	if st := feedStatusOf(t, ts, ts.URL); st.Configured || st.Feed != nil || st.Notice != "" {
		t.Fatalf("no feed configured: %+v", st)
	}

	k := newFeedKey(t)
	now := time.Now()
	k.use(t, "2026.10.1", now.Add(-time.Hour), now.Add(89*24*time.Hour))
	st := feedStatusOf(t, ts, ts.URL)
	if !st.Configured || st.Feed == nil || st.Feed.Version != "2026.10.1" || st.ExpiresSoon || st.Notice != "" || st.Error != "" {
		t.Fatalf("a fresh feed must not warn: %+v", st)
	}

	k.use(t, "2026.9.1", now.Add(-80*24*time.Hour), now.Add(5*24*time.Hour))
	st = feedStatusOf(t, ts, ts.URL)
	if !st.ExpiresSoon || !strings.Contains(st.Notice, "in 4 days") && !strings.Contains(st.Notice, "in 5 days") ||
		!strings.Contains(st.Notice, "stops") || st.Error != "" {
		t.Fatalf("a feed in its last third must warn: %+v", st)
	}

	k.use(t, "2026.8.1", now.Add(-90*24*time.Hour), now.Add(-time.Hour))
	if st := feedStatusOf(t, ts, ts.URL); !st.Configured || !strings.Contains(st.Error, "expired") {
		t.Fatalf("an expired feed must say scans stop: %+v", st)
	}
}

// With a store, a scan through the API is held to the store's record: an
// older feed than the newest it has used stops the scan, and GET /api/feed
// says so without writing anything.
func TestAPIScanWithAStoreRefusesAnOlderFeed(t *testing.T) {
	p := fixture(t)
	root := t.TempDir()
	if _, err := airlock.Init(root); err != nil {
		t.Fatal(err)
	}
	ts := server(t, Options{StoreRoot: root, ScanRoots: []string{filepath.Dir(p)}})
	k := newFeedKey(t)
	now := time.Now()

	k.use(t, "2026.10.2", now.Add(-time.Hour), now.Add(60*24*time.Hour))
	if code, body := post(t, ts, "/api/scan", map[string]string{"path": p}); code != http.StatusOK {
		t.Fatalf("scan with a first feed: %d %s", code, body)
	}

	k.use(t, "2026.10.1", now.Add(-48*time.Hour), now.Add(60*24*time.Hour))
	logBefore, _ := os.ReadFile(filepath.Join(root, "log.jsonl"))
	st := feedStatusOf(t, ts, ts.URL)
	if st.StoreRecord == nil || st.StoreRecord.Version != "2026.10.2" || !strings.Contains(st.Error, "older") {
		t.Fatalf("the status must name the store's record and the refusal: %+v", st)
	}
	if logAfter, _ := os.ReadFile(filepath.Join(root, "log.jsonl")); string(logBefore) != string(logAfter) {
		t.Fatal("GET /api/feed must not write to the store")
	}
	code, body := post(t, ts, "/api/scan", map[string]string{"path": p})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "older") || !strings.Contains(string(body), "2026.10.2") {
		t.Fatalf("a scan with an older feed must stop: %d %s", code, body)
	}

	// The same scan with no store has no record to compare with.
	plain := server(t, Options{ScanRoots: []string{filepath.Dir(p)}})
	if code, body := post(t, plain, "/api/scan", map[string]string{"path": p}); code != http.StatusOK {
		t.Fatalf("a scan without a store: %d %s", code, body)
	}
}
