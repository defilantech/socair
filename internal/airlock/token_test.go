package airlock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "hf_testtoken"

// gatedHub is the fake hub behind a gate: every hub request needs the bearer
// token, and large files redirect to a CDN on another host, which records any
// Authorization header it is sent.
func gatedHub(t *testing.T) (hub *httptest.Server, cdnAuth func() []string) {
	t.Helper()
	h := newFakeHub()
	var mu sync.Mutex
	var seen []string
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if a := r.Header.Get("Authorization"); a != "" {
			seen = append(seen, a)
		}
		mu.Unlock()
		h.write(w, strings.TrimPrefix(r.URL.Path, "/cdn/"))
	}))
	t.Cleanup(cdn.Close)
	srv := h.start(t)
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "gated", http.StatusUnauthorized)
			return
		}
		if p, ok := strings.CutPrefix(r.URL.Path, "/org/tiny/resolve/"+hubCommit+"/"); ok && h.lfs[p] {
			http.Redirect(w, r, cdn.URL+"/cdn/"+p, http.StatusFound)
			return
		}
		inner.ServeHTTP(w, r)
	})
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// A gated repo pulls with HF_TOKEN, and the token reaches only the hub's own
// host: a redirect to the CDN, even one on the same machine at another port,
// carries no Authorization header. Falsification: drop the token from the
// hub's requests and the pull is refused; drop the strip on redirect and the
// CDN records the token.
func TestPullRepoSendsTheTokenToTheHubOnly(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv, cdnAuth := gatedHub(t)
	s, _ := Init(t.TempDir())

	pol := hubPolicy(srv)
	pol.Token = testToken
	if _, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", pol); err != nil {
		t.Fatalf("a gated repo must pull with its token: %v", err)
	}
	if got := cdnAuth(); len(got) != 0 {
		t.Fatalf("the token crossed a redirect to another host: %q", got)
	}
}

// Without a token, a gated repo's refusal says what is missing, and no
// refusal or log line carries the token.
func TestPullRepoNamesHFTokenWhenGated(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv, _ := gatedHub(t)
	s, _ := Init(t.TempDir())
	_, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(srv))
	if err == nil || !strings.Contains(err.Error(), "HF_TOKEN") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a refusal naming HF_TOKEN, got %v", err)
	}

	pol := hubPolicy(srv)
	pol.Token = "hf_wrongtoken"
	_, _, err = PullRepo(context.Background(), s, "org/tiny", hubCommit, "", pol)
	if err == nil || strings.Contains(err.Error(), "hf_wrongtoken") {
		t.Fatalf("a refused token must not be echoed: %v", err)
	}
	if log, _ := os.ReadFile(s.LogPath()); strings.Contains(string(log), "hf_") {
		t.Fatal("the activity log must never hold a token")
	}
}

func TestPullSendsTheToken(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	want := []byte("gated single file")
	sum := sha256.Sum256(want)
	sha := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "gated", http.StatusUnauthorized)
			return
		}
		w.Write(want)
	}))
	defer srv.Close()
	s, _ := Init(t.TempDir())
	dst, err := s.StagingFile(sha, "model.safetensors")
	if err != nil {
		t.Fatal(err)
	}
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: srv.URL, Timeout: 5 * time.Second}
	if _, err := Pull(context.Background(), s, dst, "org/name", "main", sha, pol); err == nil || !strings.Contains(err.Error(), "HF_TOKEN") {
		t.Fatalf("want a refusal naming HF_TOKEN, got %v", err)
	}
	pol.Token = testToken
	if _, err := Pull(context.Background(), s, dst, "org/name", "main", sha, pol); err != nil {
		t.Fatalf("a gated file must pull with its token: %v", err)
	}
}

func TestDefaultEgressPolicyReadsHFToken(t *testing.T) {
	t.Setenv("HF_TOKEN", " "+testToken+"\n")
	if got := DefaultEgressPolicy().Token; got != testToken {
		t.Fatalf("Token = %q", got)
	}
	t.Setenv("HF_TOKEN", "")
	if got := DefaultEgressPolicy().Token; got != "" {
		t.Fatalf("no HF_TOKEN must mean no token, got %q", got)
	}
}

// The hub masks a gated repo's large-file hashes (asterisks) in a listing
// for a caller without access. The pull still refuses, as it must without a
// hash, but says why. Falsification: drop the masked-hash branch and the
// refusal no longer names HF_TOKEN.
func TestPullRepoNamesHFTokenForAMaskedListing(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	hub := newFakeHub()
	masked := treeEntry{Type: "file", Path: "model-00001-of-00004.safetensors", Size: 10, OID: strings.Repeat("a", 40)}
	masked.LFS = &struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	}{strings.Repeat("*", 64), 10}
	hub.extra = []treeEntry{masked}
	s, _ := Init(t.TempDir())
	_, _, err := PullRepo(context.Background(), s, "org/tiny", hubCommit, "", hubPolicy(hub.start(t)))
	if err == nil || !strings.Contains(err.Error(), "HF_TOKEN") || !strings.Contains(err.Error(), "masks") {
		t.Fatalf("want a refusal explaining the masked hash, got %v", err)
	}
}
