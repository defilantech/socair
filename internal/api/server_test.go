package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/demo"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
)

func server(t *testing.T, opts Options) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(opts.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func post(t *testing.T, ts *httptest.Server, path string, body any) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, got
}

func get(t *testing.T, ts *httptest.Server, path string) (int, string, []byte) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), got
}

func fixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture-Q5_K_M.gguf")
	if err := os.WriteFile(p, gguftest.BuildGGUF(gguftest.Clean()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersionAndHealth(t *testing.T) {
	ts := server(t, Options{Version: "9.9.9"})
	code, _, body := get(t, ts, "/api/version")
	if code != http.StatusOK || !bytes.Contains(body, []byte("9.9.9")) {
		t.Fatalf("version: %d %s", code, body)
	}
	code, ct, body := get(t, ts, "/api/health")
	if code != http.StatusOK {
		t.Fatalf("health with no store must be ok, got %d %s", code, body)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("health content type = %q, want JSON", ct)
	}
	if !bytes.Contains(body, []byte(`"store":"absent"`)) {
		t.Errorf("health should say the store is absent, got %s", body)
	}
}

func TestHealthReflectsAnUnopenableStore(t *testing.T) {
	// A directory that exists but was never initialized by the airlock.
	ts := server(t, Options{StoreRoot: t.TempDir()})
	code, _, body := get(t, ts, "/api/health")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("an unopenable store is a degraded engine, want 503, got %d %s", code, body)
	}
	if !bytes.Contains(body, []byte(`"ok":false`)) {
		t.Errorf("health must report not-ok, got %s", body)
	}

	// An initialized store is healthy.
	root := t.TempDir()
	if _, err := airlock.Init(root); err != nil {
		t.Fatal(err)
	}
	ts2 := server(t, Options{StoreRoot: root})
	if code, _, body := get(t, ts2, "/api/health"); code != http.StatusOK {
		t.Fatalf("an initialized store is healthy, got %d %s", code, body)
	}
}

func TestScanReturnsAValidDocument(t *testing.T) {
	ts := server(t, Options{Version: "test"})
	code, body := post(t, ts, "/api/scan", map[string]string{"path": fixture(t)})
	if code != http.StatusOK {
		t.Fatalf("scan: %d %s", code, body)
	}
	var out struct {
		Report *report.Document `json:"report"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("scan response: %v", err)
	}
	if out.Report == nil {
		t.Fatal("scan returned no report")
	}
	if problems := report.Validate(out.Report); len(problems) != 0 {
		t.Errorf("the API served an unfilable document: %v", problems)
	}
}

func TestScanFailureIsNotASuccess(t *testing.T) {
	ts := server(t, Options{})
	code, body := post(t, ts, "/api/scan", map[string]string{"path": filepath.Join(t.TempDir(), "absent.gguf")})
	if code == http.StatusOK {
		t.Fatalf("a failed scan must not be a success, got 200 %s", body)
	}
	if code < 400 {
		t.Fatalf("a failed scan must be a client or server error, got %d", code)
	}
	var out struct {
		Error  string           `json:"error"`
		Report *report.Document `json:"report"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("error body: %v", err)
	}
	if out.Report != nil {
		t.Error("a failed scan must carry no report")
	}
	if strings.TrimSpace(out.Error) == "" {
		t.Error("a failed scan must carry an actionable error")
	}

	if code, _ := post(t, ts, "/api/scan", map[string]string{}); code == http.StatusOK {
		t.Error("a scan with no path must not be a success")
	}
}

func TestRenderProducesBytes(t *testing.T) {
	d, err := demo.Document()
	if err != nil {
		t.Fatal(err)
	}
	ts := server(t, Options{})

	code, _ := post(t, ts, "/api/render", map[string]any{"report": d, "format": "html"})
	if code != http.StatusOK {
		t.Fatalf("html render: %d", code)
	}

	b, _ := json.Marshal(map[string]any{"report": d, "format": "pdf"})
	resp, err := http.Post(ts.URL+"/api/render", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pdf render: %d %s", resp.StatusCode, body)
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		t.Error("pdf render did not return a PDF")
	}
}

func TestRenderRejectsAnInvalidDocument(t *testing.T) {
	d, err := demo.Document()
	if err != nil {
		t.Fatal(err)
	}
	d.Header.DocumentID = "" // unfilable

	ts := server(t, Options{})
	code, body := post(t, ts, "/api/render", map[string]any{"report": d, "format": "html"})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("an unfilable document must be refused, got %d %s", code, body)
	}
	if !bytes.Contains(body, []byte("document_id")) {
		t.Errorf("the refusal should name the missing field, got %s", body)
	}

	if code, _ := post(t, ts, "/api/render", map[string]any{"format": "html"}); code == http.StatusOK {
		t.Error("a render with no report must not be a success")
	}
}

func TestDefaultBindIsLoopback(t *testing.T) {
	if !isLoopback(DefaultAddr) {
		t.Fatalf("DefaultAddr %q must be loopback", DefaultAddr)
	}
	// Serving a public address refuses before it listens.
	err := Serve("0.0.0.0:8080", Options{})
	if err == nil {
		t.Fatal("binding a public address must refuse without the override")
	}
	if !strings.Contains(err.Error(), "no authentication") {
		t.Errorf("the refusal should say why, got %q", err)
	}
	if isLoopback(":8080") || isLoopback("0.0.0.0:8080") {
		t.Error("an all-interface address is not loopback")
	}
}

func TestAPIRoutesAreNotShadowedByTheSPA(t *testing.T) {
	web := t.TempDir()
	if err := os.WriteFile(filepath.Join(web, "200.html"), []byte("<!doctype html><title>spa</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := server(t, Options{WebDir: web, Version: "1.2.3"})

	code, ct, body := get(t, ts, "/api/version")
	if code != http.StatusOK {
		t.Fatalf("version: %d", code)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("the SPA shadowed /api: content type %q, body %s", ct, body)
	}
	if !bytes.Contains(body, []byte("1.2.3")) {
		t.Errorf("version body = %s", body)
	}
}

func TestSPAFallbackServesTheShellAndStaysInRoot(t *testing.T) {
	web := t.TempDir()
	if err := os.WriteFile(filepath.Join(web, "200.html"), []byte("<!doctype html><title>spa</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := server(t, Options{WebDir: web})

	code, _, body := get(t, ts, "/scan/step-2")
	if code != http.StatusOK || !bytes.Contains(body, []byte("spa")) {
		t.Fatalf("a client route should serve the fallback, got %d %s", code, body)
	}
	// A traversal must not escape the build directory.
	code, _, body = get(t, ts, "/../../../../etc/hosts")
	if bytes.Contains(body, []byte("localhost")) && !bytes.Contains(body, []byte("spa")) {
		t.Fatalf("the static handler escaped its root: %d %s", code, body)
	}
}

func TestAirlockEndpointsNeedAStore(t *testing.T) {
	ts := server(t, Options{})
	if code, _ := post(t, ts, "/api/airlock/promote", map[string]any{"artifact": "x"}); code != http.StatusBadRequest {
		t.Errorf("airlock endpoints without a store must be a clean 400, got %d", code)
	}
	code, _, body := get(t, ts, "/api/airlock/log")
	if code != http.StatusBadRequest || !bytes.Contains(body, []byte("store")) {
		t.Errorf("log without a store: %d %s", code, body)
	}
}

func TestAirlockPromoteRefusesAWithheldDocument(t *testing.T) {
	root := t.TempDir()
	s, err := airlock.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "operator")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(prefix + ".pub"); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	d, err := demo.Document()
	if err != nil {
		t.Fatal(err)
	}
	if d.PromotionAuthorization.State != report.StateWithheld {
		t.Fatalf("demo fixture is %s, want withheld", d.PromotionAuthorization.State)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}

	ts := server(t, Options{StoreRoot: root})
	code, body := post(t, ts, "/api/airlock/promote", map[string]any{"artifact": "x.gguf", "attestation": json.RawMessage(env)})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("a withheld document must be refused with 422, got %d %s", code, body)
	}
	if !bytes.Contains(body, []byte("withholds promotion")) {
		t.Errorf("the refusal should name the state, got %s", body)
	}
}

// TestAirlockPromoteRefusesABareReport: the API used to take a report document
// as the ticket. A document is not a ticket until a trusted key signs it.
func TestAirlockPromoteRefusesABareReport(t *testing.T) {
	root := t.TempDir()
	if _, err := airlock.Init(root); err != nil {
		t.Fatal(err)
	}
	d, err := demo.Document()
	if err != nil {
		t.Fatal(err)
	}
	ts := server(t, Options{StoreRoot: root})
	code, body := post(t, ts, "/api/airlock/promote", map[string]any{"artifact": "x.gguf", "report": d})
	if code != http.StatusBadRequest || !bytes.Contains(body, []byte("signed attestation")) {
		t.Fatalf("a bare report must be refused with 400 naming the signed attestation, got %d %s", code, body)
	}
}
