package airlock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/diskfree"
)

// EgressPolicy controls what the airlock is allowed to reach and how long a
// pull may stall.
type EgressPolicy struct {
	// Allow is the set of permitted hosts, checked on the first request and on
	// every redirect. An entry with a leading dot, such as ".hf.co", matches
	// any subdomain of that domain but not the domain itself.
	Allow []string
	// Timeout is the stall budget: connecting, receiving response headers,
	// and every gap between body reads must each finish within it. It does
	// not bound the whole transfer, so a multi-GB model that keeps arriving
	// completes, and a blocked or stalled egress fails within the budget
	// rather than hanging.
	Timeout time.Duration
	// Endpoint is the base URL, overridable so tests can point at a local
	// server instead of the public hub.
	Endpoint string
	// Token is a Hugging Face access token for gated and private repos. It is
	// sent only to the endpoint's own host, never across a redirect to another
	// host such as the CDN, and never written to a log or an error.
	Token string
}

// DefaultEgressPolicy is the shipped policy: the Hugging Face hub and its CDN
// subdomains (LFS and Xet downloads redirect to <region>.cdn.hf.co and
// *.xethub.hf.co), with a thirty second stall budget.
//
//   - SOCAIR_HF_ENDPOINT points at a mirror; its host is allowed, since
//     configuring it is the operator's explicit choice.
//   - SOCAIR_EGRESS_ALLOW adds comma-separated hosts, such as a mirror's own
//     redirect targets.
//   - SOCAIR_PULL_TIMEOUT overrides the stall budget.
//   - HF_TOKEN is the access token for gated and private repos.
//   - SOCAIR_EGRESS=deny refuses all egress.
func DefaultEgressPolicy() EgressPolicy {
	pol := EgressPolicy{
		Allow:    []string{"huggingface.co", ".huggingface.co", "hf.co", ".hf.co"},
		Timeout:  30 * time.Second,
		Endpoint: "https://huggingface.co",
	}
	if e := strings.TrimSpace(os.Getenv("SOCAIR_HF_ENDPOINT")); e != "" {
		pol.Endpoint = e
		if h := hostOf(e); h != "" {
			pol.Allow = append(pol.Allow, h)
		}
	}
	for _, h := range strings.Split(os.Getenv("SOCAIR_EGRESS_ALLOW"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			pol.Allow = append(pol.Allow, h)
		}
	}
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("SOCAIR_PULL_TIMEOUT"))); err == nil && d > 0 {
		pol.Timeout = d
	}
	pol.Token = strings.TrimSpace(os.Getenv("HF_TOKEN"))
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
	refuse := func(err error) (Event, error) {
		e := Event{Action: ActionPull, Outcome: OutcomeRefused, Repo: repo, SHA256: normalizeSHA(wantSHA), Detail: err.Error()}
		if s != nil {
			_ = s.Record(e)
		}
		return e, fmt.Errorf("airlock pull %s: %w", repo, err)
	}
	fail := func(detail string) (Event, error) { return refuse(errors.New(detail)) }

	if strings.TrimSpace(repo) == "" {
		return fail("repo is required")
	}
	if err := ValidSHA256(wantSHA); err != nil {
		return fail(err.Error())
	}
	if err := validRepo(repo); err != nil {
		return fail(err.Error())
	}
	if strings.TrimSpace(revision) == "" {
		revision = "main"
	}
	if err := validRevision(revision); err != nil {
		return fail(err.Error())
	}
	if err := validFileName(filepath.Base(dst)); err != nil {
		return fail(err.Error())
	}
	if err := notEvidenceName(filepath.Base(dst)); err != nil {
		return fail(err.Error())
	}
	pol = pol.withDefaults()

	host, allowed := pol.allows(pol.Endpoint)
	if !allowed {
		return fail(fmt.Sprintf("egress to %q is denied by policy (unset SOCAIR_EGRESS=deny and add the host to SOCAIR_EGRESS_ALLOW)", host))
	}

	src := strings.TrimRight(pol.Endpoint, "/") + "/" + repo + "/resolve/" + revision + "/" + url.PathEscape(filepath.Base(dst))

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := pol.newRequest(cctx, src)
	if err != nil {
		return fail(err.Error())
	}
	// The hub names the immutable commit a revision resolved to in
	// X-Repo-Commit on its first response, before any CDN redirect. It is
	// captured there, so the record names the commit the bytes came from,
	// not a branch that can move.
	client := pol.client()
	commit := ""
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if commit == "" && r.Response != nil {
			commit = repoCommit(r.Response.Header)
		}
		return checkRedirect(r, via)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(fmt.Sprintf("pull failed within the %s stall budget: %v", pol.Timeout, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return refuse(pol.statusError("source", resp.StatusCode, src))
	}
	if err := diskfree.Need(filepath.Dir(dst), resp.ContentLength); err != nil {
		return refuse(err)
	}

	body := newStallReader(resp.Body, pol.Timeout, cancel)
	defer body.stop()
	if err := writeTemp(filepath.Dir(dst), dst, body); err != nil {
		if body.stalled() {
			return fail(fmt.Sprintf("download stalled for longer than the %s stall budget", pol.Timeout))
		}
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

	if commit == "" {
		commit = repoCommit(resp.Header)
	}
	manifest := provenance.Manifest{
		ArtifactSHA256: got,
		RepoURL:        strings.TrimRight(pol.Endpoint, "/") + "/" + repo,
		CommitOrTag:    revision,
		CommitSHA:      commit,
		Source:         "airlock pull",
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fail("encode provenance manifest: " + err.Error())
	}
	if err := writeBytes(filepath.Dir(dst), filepath.Join(filepath.Dir(dst), "provenance.json"), b); err != nil {
		return fail("write provenance manifest: " + err.Error())
	}

	detail := "revision " + revision
	if commit != "" {
		detail += " at commit " + commit
	} else {
		detail += " (the source named no commit; the revision is not pinned)"
	}
	e := Event{Action: ActionPull, Outcome: OutcomeOK, Repo: repo, SHA256: got, Detail: detail}
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
	if host == "" {
		return host, false
	}
	h := strings.ToLower(host)
	for _, a := range p.Allow {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "":
		case strings.HasPrefix(a, "."):
			if strings.HasSuffix(h, a) && len(h) > len(a) {
				return host, true
			}
		case a == h:
			return host, true
		}
	}
	return host, false
}

// client is an HTTP client that enforces the policy: bounded connect,
// handshake, and response-header time, and the allowlist on every redirect.
// It sets no overall timeout, which would cut off a large download that is
// still making progress; stalls in the body are bounded by stallReader.
func (p EgressPolicy) client() *http.Client {
	dialer := &net.Dialer{Timeout: p.Timeout}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   p.Timeout,
			ResponseHeaderTimeout: p.Timeout,
		},
		CheckRedirect: p.checkRedirect,
	}
}

// checkRedirect applies the allowlist to every hop. Checking only the first URL
// let a listed host bounce the pull anywhere. A hop to any other host, the
// hub's CDN included, loses the token: net/http would keep it for the same
// host name at another port and for any subdomain.
func (p EgressPolicy) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect from https to %s://%s is refused", req.URL.Scheme, req.URL.Host)
	}
	if host, ok := p.allows(req.URL.String()); !ok {
		return fmt.Errorf("redirect to %q is denied by policy (add it to SOCAIR_EGRESS_ALLOW)", host)
	}
	if !p.isEndpointHost(req.URL) {
		req.Header.Del("Authorization")
	}
	return nil
}

// newRequest is a GET through the policy, carrying the token when, and only
// when, it goes to the endpoint's own host.
func (p EgressPolicy) newRequest(ctx context.Context, u string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if p.Token != "" && p.isEndpointHost(req.URL) {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	return req, nil
}

// isEndpointHost reports whether u is on exactly the endpoint's host and port.
func (p EgressPolicy) isEndpointHost(u *url.URL) bool {
	e, err := url.Parse(p.Endpoint)
	return err == nil && e.Host != "" && strings.EqualFold(e.Host, u.Host)
}

// statusError explains a non-200 answer. A gated or private repo answers 401
// or 403, so those name HF_TOKEN; the token itself is never repeated.
func (p EgressPolicy) statusError(who string, code int, u string) error {
	msg := fmt.Sprintf("%s returned HTTP %d for %s", who, code, u)
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		if p.Token == "" {
			msg += " (a gated or private repo needs HF_TOKEN set to a Hugging Face access token)"
		} else {
			msg += " (HF_TOKEN was sent; check it has access to this repo and that the repo's terms are accepted)"
		}
	}
	return errors.New(msg)
}

// stallReader cancels the transfer when no bytes arrive for the budget. The
// timer resets on every read that makes progress.
type stallReader struct {
	r      io.Reader
	budget time.Duration
	timer  *time.Timer
	fired  atomic.Bool
}

func newStallReader(r io.Reader, budget time.Duration, cancel context.CancelFunc) *stallReader {
	s := &stallReader{r: r, budget: budget}
	s.timer = time.AfterFunc(budget, func() {
		s.fired.Store(true)
		cancel()
	})
	return s
}

func (s *stallReader) Read(b []byte) (int, error) {
	n, err := s.r.Read(b)
	if n > 0 {
		s.timer.Reset(s.budget)
	}
	return n, err
}

func (s *stallReader) stop()         { s.timer.Stop() }
func (s *stallReader) stalled() bool { return s.fired.Load() }

// repoCommit returns a well-formed commit id from X-Repo-Commit, or "".
func repoCommit(h http.Header) string {
	c := strings.ToLower(strings.TrimSpace(h.Get("X-Repo-Commit")))
	if len(c) != 40 && len(c) != 64 {
		return ""
	}
	for _, r := range c {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return ""
		}
	}
	return c
}

func hostOf(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
