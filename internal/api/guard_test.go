package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func send(t *testing.T, h http.Handler, method, target, ctype string, hdr map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader([]byte(`{"path":"/nonexistent"}`)))
	req.Host = "127.0.0.1:8080"
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestCrossSitePostIsRefused: the API ignored Content-Type and Origin, so any
// web page the operator visited could send a no-preflight text/plain POST to
// 127.0.0.1:8080, including a forged promotion or a pull. Falsification:
// drop the guard and these requests reach the handlers.
func TestCrossSitePostIsRefused(t *testing.T) {
	h := Options{}.Handler()

	if got := send(t, h, http.MethodPost, "/api/scan", "text/plain", nil); got != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST = %d, want 415", got)
	}
	if got := send(t, h, http.MethodPost, "/api/scan", "", nil); got != http.StatusUnsupportedMediaType {
		t.Errorf("POST with no content type = %d, want 415", got)
	}
	if got := send(t, h, http.MethodPost, "/api/scan", "application/json", map[string]string{"Origin": "https://evil.example"}); got != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d, want 403", got)
	}
	if got := send(t, h, http.MethodPost, "/api/scan", "application/json", map[string]string{"Sec-Fetch-Site": "cross-site"}); got != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site cross-site POST = %d, want 403", got)
	}
}

// TestRebindingHostIsRefused: with DNS rebinding, an attacker's name resolves
// to 127.0.0.1 and their page reads API responses, a file-existence and hash
// oracle through /api/scan. The request then carries the attacker's Host.
func TestRebindingHostIsRefused(t *testing.T) {
	h := Options{}.Handler()
	for _, host := range []string{"evil.example:8080", "evil.example", "127.0.0.1.evil.example:8080"} {
		if got := send(t, h, http.MethodGet, "/api/version", "", map[string]string{"Host": host}); got != http.StatusForbidden {
			t.Errorf("GET with Host %q = %d, want 403", host, got)
		}
	}
}

// TestSameOriginStillWorks: the wizard is served by this server and sends
// JSON with its own origin; nothing about the guard may break it.
func TestSameOriginStillWorks(t *testing.T) {
	h := Options{}.Handler()
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		code := send(t, h, http.MethodPost, "/api/scan", "application/json; charset=utf-8",
			map[string]string{"Host": host, "Origin": "http://" + host, "Sec-Fetch-Site": "same-origin"})
		if code == http.StatusForbidden || code == http.StatusUnsupportedMediaType {
			t.Errorf("same-origin JSON POST via %s was refused with %d", host, code)
		}
		if got := send(t, h, http.MethodGet, "/api/version", "", map[string]string{"Host": host}); got != http.StatusOK {
			t.Errorf("GET /api/version via %s = %d, want 200", host, got)
		}
	}
}

// TestPublicModeSkipsTheHostCheck: an operator who binds a public address on
// purpose reaches the API by a real host name. The origin and content-type
// rules still hold.
func TestPublicModeSkipsTheHostCheck(t *testing.T) {
	h := Options{AllowAnyHost: true}.Handler()
	if got := send(t, h, http.MethodGet, "/api/version", "", map[string]string{"Host": "socair.internal:8080"}); got != http.StatusOK {
		t.Errorf("public mode GET = %d, want 200", got)
	}
	if got := send(t, h, http.MethodPost, "/api/scan", "text/plain", map[string]string{"Host": "socair.internal:8080"}); got != http.StatusUnsupportedMediaType {
		t.Errorf("public mode text/plain POST = %d, want 415", got)
	}
}

// TestHeavyWorkIsBounded: scans read whole artifacts, so unbounded parallel
// scans exhaust memory and disk bandwidth. Past the limit a heavy request is
// turned away with 503, not queued without bound.
func TestHeavyWorkIsBounded(t *testing.T) {
	sem := make(chan struct{}, 1)
	h := Options{}.handler(sem)
	sem <- struct{}{} // the one slot is taken
	if got := send(t, h, http.MethodPost, "/api/scan", "application/json", nil); got != http.StatusServiceUnavailable {
		t.Fatalf("scan with no free slot = %d, want 503", got)
	}
	if got := send(t, h, http.MethodGet, "/api/version", "", nil); got != http.StatusOK {
		t.Fatalf("light requests are not limited, got %d", got)
	}
	<-sem
	if got := send(t, h, http.MethodPost, "/api/scan", "application/json", nil); got == http.StatusServiceUnavailable {
		t.Fatal("a freed slot must admit the next scan")
	}
}
