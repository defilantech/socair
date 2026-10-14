package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrEgressDenied is returned for any request while SOCAIR_EGRESS=deny.
var ErrEgressDenied = errors.New("egress is denied by policy (SOCAIR_EGRESS=deny)")

// egressDenied is SOCAIR_EGRESS=deny, the airlock's hard stop, read on every
// request.
func egressDenied() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SOCAIR_EGRESS")), "deny")
}

// Options configure a Client.
type Options struct {
	// Credentials, when set, supplies a username and password per registry.
	Credentials Credentials
	// Timeout bounds each request, connection to last byte. Everything this
	// client moves is small; zero means one minute.
	Timeout time.Duration
	// Transport replaces the HTTP transport (tests).
	Transport http.RoundTripper
}

// Client talks to OCI registries. It is safe for concurrent use.
type Client struct {
	http  *http.Client
	creds Credentials

	mu     sync.Mutex
	tokens map[string]string // "host scope" -> Authorization value
}

// New makes a client.
func New(o Options) *Client {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	tr := o.Transport
	if tr == nil {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		tr = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: timeout,
		}
	}
	return &Client{
		http:   &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: checkRedirect},
		creds:  o.Credentials,
		tokens: map[string]string{},
	}
}

// checkRedirect follows at most ten hops, refuses https to http, stops when
// egress is denied, and drops the Authorization header on any hop to another
// host or port: a registry's blob can redirect to a storage service, which
// must not receive the registry's token. net/http alone keeps it for a
// subdomain.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if egressDenied() {
		return ErrEgressDenied
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	prev := via[len(via)-1]
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect from https to %s://%s is refused", req.URL.Scheme, req.URL.Host)
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		req.Header.Del("Authorization")
	}
	return nil
}

// isLoopback reports whether host (no port) is a loopback name or address.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// baseURL is the registry's API root: https, or http for a loopback host,
// where a local test registry listens without TLS.
func baseURL(host string) string {
	h := host
	if hn, _, err := net.SplitHostPort(host); err == nil {
		h = hn
	}
	if isLoopback(h) {
		return "http://" + host
	}
	return "https://" + host
}

// mayCarry reports whether a credential may be sent to u: https, or a
// loopback host. A credential sent over plain http is readable on the wire.
func mayCarry(u *url.URL) bool {
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

// request is one registry API call.
type request struct {
	method  string
	url     string
	body    []byte
	header  http.Header
	scope   string // repository:<name>:pull or :pull,push
	host    string // the registry API host, which a token is for
	regName string // the registry as the reference names it, for credentials
}

// do sends r, answering one authentication challenge: Basic with the
// registry's credential, or Bearer with a token from the challenge's realm.
// The caller closes the response body.
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	if egressDenied() {
		return nil, ErrEgressDenied
	}
	key := r.host + " " + r.scope
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, r.method, r.url, bodyReader(r.body))
		if err != nil {
			return nil, err
		}
		if r.body != nil {
			req.ContentLength = int64(len(r.body))
			b := r.body
			req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
		}
		for k, v := range r.header {
			req.Header[k] = v
		}
		req.Header.Set("User-Agent", "socair")
		c.mu.Lock()
		auth := c.tokens[key]
		c.mu.Unlock()
		if auth != "" && strings.EqualFold(req.URL.Host, r.host) && mayCarry(req.URL) {
			req.Header.Set("Authorization", auth)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusUnauthorized || attempt > 0 || !strings.EqualFold(resp.Request.URL.Host, r.host) {
			return resp, nil
		}
		ch, ok := parseChallenge(resp.Header.Get("WWW-Authenticate"))
		drain(resp)
		if !ok {
			return nil, fmt.Errorf("%s answered 401 with no challenge this client understands", r.host)
		}
		auth, err = c.authenticate(ctx, r, ch)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.tokens[key] = auth
		c.mu.Unlock()
	}
}

func bodyReader(b []byte) io.Reader {
	if b == nil {
		return nil
	}
	return bytes.NewReader(b)
}

// authenticate answers a challenge, returning the Authorization value.
func (c *Client) authenticate(ctx context.Context, r request, ch challenge) (string, error) {
	var cred Credential
	var have bool
	if c.creds != nil {
		cred, have = c.creds.Lookup(r.regName)
	}
	switch ch.scheme {
	case "basic":
		u, _ := url.Parse(r.url)
		if !have {
			return "", fmt.Errorf("%s asks for a username and password and none is configured (%s)", r.regName, c.why(r.regName))
		}
		if !mayCarry(u) {
			return "", fmt.Errorf("%s asks for a password over plain http; refused", r.regName)
		}
		return basicAuth(cred), nil
	case "bearer":
		return c.fetchToken(ctx, r, ch, cred, have)
	}
	return "", fmt.Errorf("%s asks for %q authentication, which this client does not support", r.regName, ch.scheme)
}

// fetchToken gets a bearer token from the realm a challenge names
// (distribution token authentication: GET realm?service=&scope=). The
// registry's credential goes to the realm only over https or to a loopback
// host; without one, or over plain http elsewhere, the request is anonymous.
func (c *Client) fetchToken(ctx context.Context, r request, ch challenge, cred Credential, have bool) (string, error) {
	realm := ch.params["realm"]
	u, err := url.Parse(realm)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("%s names token realm %q, which is not an http(s) URL", r.regName, realm)
	}
	if baseIsHTTPS := strings.HasPrefix(r.url, "https://"); baseIsHTTPS && u.Scheme != "https" {
		return "", fmt.Errorf("%s (https) names a plain-http token realm %s; refused", r.regName, u.Host)
	}
	q := u.Query()
	if s := ch.params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", r.scope)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "socair")
	if have && mayCarry(u) {
		req.Header.Set("Authorization", basicAuth(cred))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request to %s: %w", u.Host, redact(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("token service %s returned HTTP %d for %s", u.Host, resp.StatusCode, r.scope)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			msg += " (" + c.credNote(r.regName, have) + ")"
		}
		return "", errors.New(msg)
	}
	b, err := readLimited(resp.Body, 1<<20)
	if err != nil {
		return "", fmt.Errorf("token response from %s: %w", u.Host, err)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &tok); err != nil {
		return "", fmt.Errorf("token response from %s is not JSON", u.Host)
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" {
		return "", fmt.Errorf("token response from %s has no token", u.Host)
	}
	return "Bearer " + t, nil
}

func (c *Client) why(registry string) string {
	if dc, ok := c.creds.(*DockerConfig); ok {
		return dc.Why(registry)
	}
	return "no credentials configured"
}

// credNote says, for a 401 or 403, which credential was sent.
func (c *Client) credNote(registry string, have bool) string {
	if have {
		return "a credential for " + registry + " was sent; check it may read and write this repository"
	}
	return "no credential was sent: " + c.why(registry)
}

// statusError explains an unexpected response, with the registry's own
// error code and message when it sent one.
func (c *Client) statusError(r request, resp *http.Response) error {
	b, _ := readLimited(resp.Body, 64<<10)
	what := fmt.Sprintf("%s %s returned HTTP %d", r.method, redactURL(resp.Request.URL), resp.StatusCode)
	var e struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(b, &e) == nil && len(e.Errors) > 0 {
		m := e.Errors[0].Code
		if e.Errors[0].Message != "" {
			m += ": " + e.Errors[0].Message
		}
		if len(m) > 200 {
			m = m[:200]
		}
		what += " (" + m + ")"
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		have := false
		if c.creds != nil {
			_, have = c.creds.Lookup(r.regName)
		}
		what += "; " + c.credNote(r.regName, have)
	}
	return &StatusError{Code: resp.StatusCode, msg: what}
}

// StatusError is an unexpected HTTP status from a registry.
type StatusError struct {
	Code int
	msg  string
}

func (e *StatusError) Error() string { return e.msg }

// IsNotFound reports whether err is a 404 from a registry.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// readLimited reads at most max bytes, and fails on more.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response is larger than %d bytes", max)
	}
	return b, nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// redactURL drops the query and any userinfo: a redirect target can be a
// signed storage URL, a read capability until it expires.
func redactURL(u *url.URL) string {
	c := *u
	c.RawQuery, c.Fragment, c.User = "", "", nil
	return c.String()
}

func redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil {
			ue.URL = redactURL(u)
		} else {
			ue.URL = "(unparseable URL)"
		}
	}
	return err
}
