package engine

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/feed"
)

// signedFeedAt is signedFeed with the feed's validity window given: it writes
// the data files, signs them with a fresh key, and points the engine at it.
func signedFeedAt(t *testing.T, files map[string]string, issued, expires time.Time) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prefix := filepath.Join(t.TempDir(), "feed")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	info := feed.Info{Issuer: "Example Intel", Version: "2026.10.1",
		Issued: issued.UTC().Format(time.RFC3339), Expires: expires.UTC().Format(time.RFC3339)}
	if err := feed.Sign(dir, info, k.ID, k.Sign); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_FEED", dir)
	t.Setenv("SOCAIR_FEED_KEYS", prefix+".pub")
}

// Inputs.Feed sees the verified feed before the artifact is read, and its
// error stops the scan there: no snapshot is taken, no report is made. With
// no feed configured it is not called. Falsification: drop the call in
// ScanWith and the refusal never happens.
func TestFeedHookCanStopTheScan(t *testing.T) {
	dir := modelRepo(t, nil)
	refused := errors.New("refused by the store")
	var seen *feed.Feed
	hook := func(f *feed.Feed) error { seen = f; return refused }

	t.Setenv("SOCAIR_FEED", "")
	if _, err := ScanWith(dir, ModeFull, Inputs{Feed: hook}); err != nil || seen != nil {
		t.Fatalf("without a feed the hook must not run: %v %v", err, seen)
	}

	signedFeed(t, map[string]string{"denylist.txt": strings.Repeat("aa", 32) + "  unrelated\n"})
	snapshots := 0
	afterSnapshot = func(string) { snapshots++ }
	t.Cleanup(func() { afterSnapshot = nil })
	d, err := ScanWith(dir, ModeFull, Inputs{Feed: hook})
	if !errors.Is(err, refused) || d != nil {
		t.Fatalf("the hook's error must stop the scan: %v %v", d, err)
	}
	if seen == nil || seen.Issuer != "Example Intel" || seen.StatementSHA256 == "" {
		t.Fatalf("the hook must get the verified feed: %+v", seen)
	}
	if snapshots != 0 {
		t.Fatal("a refused feed must stop the scan before any snapshot is taken")
	}
	if _, err := ScanWith(dir, ModeFull, Inputs{Feed: func(*feed.Feed) error { return nil }}); err != nil {
		t.Fatal(err)
	}
}

// The expiry warning changes no verdict: the same data in a feed inside its
// warning window and in one outside it gives the same rows, promotion state,
// and bounded statement. Only the feed's own times differ in scope.
func TestExpiryWindowChangesNoVerdict(t *testing.T) {
	t.Setenv("SOCAIR_DENYLIST", "")
	dir := leadRepo(t)
	files := map[string]string{
		"templates.txt": sha(leadTemplate) + "  reviewed by Example Intel\n",
		"denylist.txt":  strings.Repeat("aa", 32) + "  unrelated\n",
	}
	now := time.Now()

	signedFeedAt(t, files, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	if f, err := LoadFeed(now); err != nil || f.ExpiryNotice(now) == "" {
		t.Fatalf("the first feed must be inside its warning window: %v", err)
	}
	soon, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	signedFeedAt(t, files, now.Add(-time.Hour), now.Add(89*24*time.Hour))
	if f, err := LoadFeed(now); err != nil || f.ExpiryNotice(now) != "" {
		t.Fatalf("the second feed must be outside its warning window: %v", err)
	}
	later, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(soon.Checks, later.Checks) || !reflect.DeepEqual(soon.Findings, later.Findings) ||
		!reflect.DeepEqual(soon.PromotionAuthorization, later.PromotionAuthorization) || soon.BoundedStatement != later.BoundedStatement {
		t.Fatalf("a feed near its expiry must grade exactly as one that is not:\n%+v\n%+v", soon.Checks, later.Checks)
	}
	for _, d := range []string{soon.Scope.ReferenceData, later.Scope.ReferenceData} {
		if strings.Contains(d, "warn") || strings.Contains(d, "stops") {
			t.Errorf("the report must not carry the warning: %q", d)
		}
	}
}
