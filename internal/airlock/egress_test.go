package airlock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// localhostURL rewrites an httptest URL from 127.0.0.1 to localhost, a second
// host name for the same server, so a redirect between them crosses hosts.
func localhostURL(u string) string { return strings.Replace(u, "127.0.0.1", "localhost", 1) }

// TestRedirectToUnlistedHostIsRefused: the allowlist was checked against the
// first URL only, and the client followed redirects anywhere. Falsification:
// remove CheckRedirect and the pull succeeds via the unlisted host.
func TestRedirectToUnlistedHostIsRefused(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	want, sha := fixtureSHA(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(want) }))
	defer target.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, localhostURL(target.URL)+r.URL.Path, http.StatusFound)
	}))
	defer front.Close()

	s, _ := Init(t.TempDir())
	dst := s.StagingPath(sha)
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: front.URL, Timeout: 5 * time.Second}
	_, err := Pull(context.Background(), s, dst, "org/name", "main", sha, pol)
	if err == nil {
		t.Fatal("a redirect to a host outside the allowlist must be refused")
	}
	if !strings.Contains(err.Error(), "localhost") || !strings.Contains(err.Error(), "denied") {
		t.Errorf("the refusal should name the redirect host, got %q", err)
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("nothing may be staged from a refused redirect")
	}

	// The same redirect is allowed once the host is listed.
	pol.Allow = append(pol.Allow, "localhost")
	if _, err := Pull(context.Background(), s, dst, "org/name", "main", sha, pol); err != nil {
		t.Fatalf("a redirect to a listed host must succeed: %v", err)
	}
}

func TestAllowlistMatching(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	pol := EgressPolicy{Allow: []string{"huggingface.co", ".hf.co"}}
	for _, u := range []string{"https://huggingface.co/x", "https://us.aws.cdn.hf.co/x", "https://cdn-lfs.hf.co/x"} {
		if _, ok := pol.allows(u); !ok {
			t.Errorf("%s should be allowed", u)
		}
	}
	for _, u := range []string{"https://evilhuggingface.co/x", "https://hf.co.evil.com/x", "https://evilhf.co/x", "https://cdn.huggingface.co/x"} {
		if _, ok := pol.allows(u); ok {
			t.Errorf("%s must not be allowed", u)
		}
	}
}

// TestDefaultPolicyCoversTheHubCDN: real LFS downloads redirect to
// <region>.cdn.hf.co, so the shipped allowlist must cover it once redirects are
// enforced, or every real model pull breaks.
func TestDefaultPolicyCoversTheHubCDN(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	t.Setenv("SOCAIR_HF_ENDPOINT", "")
	t.Setenv("SOCAIR_EGRESS_ALLOW", "")
	pol := DefaultEgressPolicy()
	for _, u := range []string{"https://huggingface.co/x", "https://us.aws.cdn.hf.co/xet-bridge-us/x", "https://cas-bridge.xethub.hf.co/x"} {
		if _, ok := pol.allows(u); !ok {
			t.Errorf("default policy must allow %s", u)
		}
	}
}

// TestEgressAllowlistIsConfigurable: the error told operators to add a host
// to the allowlist, but nothing could. A configured mirror endpoint is an
// explicit operator choice, so its host is allowed; SOCAIR_EGRESS_ALLOW adds
// more, such as the mirror's own redirect targets.
func TestEgressAllowlistIsConfigurable(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	t.Setenv("SOCAIR_HF_ENDPOINT", "https://hf-mirror.internal")
	t.Setenv("SOCAIR_EGRESS_ALLOW", "blobs.internal, .store.internal")
	pol := DefaultEgressPolicy()
	for _, u := range []string{"https://hf-mirror.internal/x", "https://blobs.internal/x", "https://a.store.internal/x"} {
		if _, ok := pol.allows(u); !ok {
			t.Errorf("configured policy must allow %s", u)
		}
	}
}

func TestRedirectDowngradeIsRefused(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	pol := EgressPolicy{Allow: []string{"example.com"}}
	from, _ := http.NewRequest(http.MethodGet, "https://example.com/a", nil)
	to, _ := http.NewRequest(http.MethodGet, "http://example.com/b", nil)
	if err := pol.checkRedirect(to, []*http.Request{from}); err == nil {
		t.Fatal("an https to http redirect must be refused")
	}
}

// TestSlowSteadyDownloadCompletes: the whole download used to share one
// 30-second client timeout, so a real multi-GB model could never finish. The
// budget now bounds stalls: a body that keeps arriving completes even when the
// total time exceeds the budget. Falsification: put back http.Client.Timeout
// and this fails at the budget.
func TestSlowSteadyDownloadCompletes(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	want, sha := fixtureSHA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		chunk := (len(want) + 7) / 8
		for i := 0; i < len(want); i += chunk {
			end := min(i+chunk, len(want))
			w.Write(want[i:end])
			fl.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer srv.Close()

	s, _ := Init(t.TempDir())
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: srv.URL, Timeout: 400 * time.Millisecond}
	start := time.Now()
	if _, err := Pull(context.Background(), s, s.StagingPath(sha), "org/name", "main", sha, pol); err != nil {
		t.Fatalf("a steady download longer than the budget must complete: %v", err)
	}
	if time.Since(start) < pol.Timeout {
		t.Fatal("fixture did not outlast the budget, so it proves nothing")
	}
}

// TestStalledBodyFailsWithinBudget: headers arrive, then the body stops.
func TestStalledBodyFailsWithinBudget(t *testing.T) {
	t.Setenv("SOCAIR_EGRESS", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-time.After(10 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	s, _ := Init(t.TempDir())
	pol := EgressPolicy{Allow: []string{"127.0.0.1"}, Endpoint: srv.URL, Timeout: 300 * time.Millisecond}
	start := time.Now()
	_, err := Pull(context.Background(), s, s.StagingPath(strings.Repeat("a", 64)), "org/name", "main", strings.Repeat("a", 64), pol)
	if err == nil {
		t.Fatal("a stalled body must fail")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("a stalled body must fail within its budget, took %s", el)
	}
}
