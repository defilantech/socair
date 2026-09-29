package airlock

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/checks/provenance"
)

// EgressPolicy controls what the airlock is allowed to reach and how long a
// pull may take.
type EgressPolicy struct {
	// Allow is the set of permitted source hosts.
	Allow []string
	// Timeout is the hard per-pull budget. A blocked egress fails within it
	// rather than hanging.
	Timeout time.Duration
	// Endpoint is the base URL, overridable so tests can point at a local
	// server instead of the public hub.
	Endpoint string
}

// DefaultEgressPolicy is the shipped policy: the Hugging Face hub hosts and a
// thirty second budget. SOCAIR_HF_ENDPOINT and SOCAIR_PULL_TIMEOUT override the
// endpoint and the budget.
func DefaultEgressPolicy() EgressPolicy {
	pol := EgressPolicy{
		Allow:    []string{"huggingface.co", "cdn-lfs.huggingface.co", "cdn-lfs.hf.co"},
		Timeout:  30 * time.Second,
		Endpoint: "https://huggingface.co",
	}
	if e := strings.TrimSpace(os.Getenv("SOCAIR_HF_ENDPOINT")); e != "" {
		pol.Endpoint = e
	}
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("SOCAIR_PULL_TIMEOUT"))); err == nil && d > 0 {
		pol.Timeout = d
	}
	return pol
}

// Pull fetches one artifact into dst through controlled egress, verifies it
// against wantSHA, records the pull, and writes a provenance manifest beside it.
//
// Controlled egress means an allowlisted host plus a hard timeout: a blocked or
// stalled egress returns an actionable error within the budget, never a hang.
// The manifest records origin facts (repo, revision); it never asserts a
// signing status.
func Pull(ctx context.Context, s *Store, dst, repo, revision, wantSHA string, pol EgressPolicy) (Event, error) {
	fail := func(detail string) (Event, error) {
		e := Event{Action: ActionPull, Outcome: OutcomeRefused, Repo: repo, SHA256: normalizeSHA(wantSHA), Detail: detail}
		if s != nil {
			_ = s.Record(e)
		}
		return e, fmt.Errorf("airlock pull %s: %s", repo, detail)
	}

	if strings.TrimSpace(repo) == "" {
		return fail("repo is required")
	}
	if len(normalizeSHA(wantSHA)) != 64 {
		return fail("an expected 64-hex artifact hash is required")
	}
	if strings.TrimSpace(revision) == "" {
		revision = "main"
	}
	pol = pol.withDefaults()

	host, allowed := pol.allows(pol.Endpoint)
	if !allowed {
		return fail(fmt.Sprintf("egress to %q is denied by policy (set SOCAIR_EGRESS=allow and add the host to the allowlist)", host))
	}

	src := strings.TrimRight(pol.Endpoint, "/") + "/" + repo + "/resolve/" + revision + "/" + filepath.Base(dst)

	cctx, cancel := context.WithTimeout(ctx, pol.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, src, nil)
	if err != nil {
		return fail(err.Error())
	}
	client := &http.Client{Timeout: pol.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fail(fmt.Sprintf("pull failed within the %s budget: %v", pol.Timeout, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Sprintf("source returned HTTP %d for %s", resp.StatusCode, src))
	}

	if err := writeTemp(filepath.Dir(dst), dst, resp.Body); err != nil {
		return fail("write artifact: " + err.Error())
	}
	got, err := hashFile(dst)
	if err != nil {
		return fail(err.Error())
	}
	if got != normalizeSHA(wantSHA) {
		_ = os.Remove(dst)
		return fail(fmt.Sprintf("downloaded artifact hashes to %s, not the requested %s", got, normalizeSHA(wantSHA)))
	}

	manifest := provenance.Manifest{RepoURL: "https://huggingface.co/" + repo, CommitOrTag: revision}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fail("encode provenance manifest: " + err.Error())
	}
	if err := writeBytes(filepath.Dir(dst), filepath.Join(filepath.Dir(dst), "provenance.json"), b); err != nil {
		return fail("write provenance manifest: " + err.Error())
	}

	e := Event{Action: ActionPull, Outcome: OutcomeOK, Repo: repo, SHA256: got, Detail: "revision " + revision}
	if s != nil {
		if err := s.Record(e); err != nil {
			return e, err
		}
	}
	return e, nil
}

func (p EgressPolicy) withDefaults() EgressPolicy {
	d := DefaultEgressPolicy()
	if strings.TrimSpace(p.Endpoint) == "" {
		p.Endpoint = d.Endpoint
	}
	if p.Timeout <= 0 {
		p.Timeout = d.Timeout
	}
	if len(p.Allow) == 0 {
		p.Allow = d.Allow
	}
	return p
}

// allows reports the endpoint host and whether policy permits reaching it.
// SOCAIR_EGRESS=deny is a hard stop regardless of the allowlist.
func (p EgressPolicy) allows(endpoint string) (string, bool) {
	host := hostOf(endpoint)
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SOCAIR_EGRESS")), "deny") {
		return host, false
	}
	for _, a := range p.Allow {
		if strings.EqualFold(strings.TrimSpace(a), host) {
			return host, true
		}
	}
	return host, false
}

func hostOf(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
