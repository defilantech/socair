package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// consoleStore is an initialized store with one staged safetensors entry.
func consoleStore(t *testing.T) (root, id string) {
	t.Helper()
	root = t.TempDir()
	s, err := airlock.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	data := safetensorstest.Clean()
	sum := sha256.Sum256(data)
	id = hex.EncodeToString(sum[:])
	dir := s.StagingPath(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.safetensors"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, airlock.ProvenanceFile), []byte(`{"artifact_sha256":"`+id+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, id
}

func TestConsoleListsAndDetails(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})

	code, _, body := get(t, ts, "/api/airlock/models")
	var list struct{ Models []airlock.Model }
	if code != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Models) != 1 || list.Models[0].Stage != airlock.StageStaged {
		t.Fatalf("%d %s", code, body)
	}

	code, _, body = get(t, ts, "/api/airlock/models/"+id)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if code, _, _ := get(t, ts, "/api/airlock/models/"+id+"/files/"+airlock.ProvenanceFile); code != http.StatusOK {
		t.Fatalf("provenance download: %d", code)
	}
}

// Review: the download serves evidence names only, and never leaves the store.
// Each refusal must come from the handler (a JSON error naming the reason),
// not from an unmatched route, and must never carry artifact or log bytes.
func TestConsoleFileDownloadIsConfined(t *testing.T) {
	root, id := consoleStore(t)
	s, err := airlock.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Record(airlock.Event{Action: airlock.ActionIngest, Outcome: airlock.OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	logBytes, err := os.ReadFile(filepath.Join(root, "log.jsonl"))
	if err != nil || len(logBytes) == 0 {
		t.Fatalf("log.jsonl not written: %v", err)
	}
	artifact := safetensorstest.Clean()
	ts := server(t, Options{StoreRoot: root})

	// Positive control: the same route serves a real evidence file.
	code, _, body := get(t, ts, "/api/airlock/models/"+id+"/files/"+airlock.ProvenanceFile)
	if want := `{"artifact_sha256":"` + id + `"}`; code != http.StatusOK || string(body) != want {
		t.Fatalf("provenance control: %d %s", code, body)
	}

	for _, c := range []struct{ path, reason string }{
		{"/api/airlock/models/" + id + "/files/fixture.safetensors", "is not an evidence file"},
		{"/api/airlock/models/" + id + "/files/..%2Flog.jsonl", "is not an evidence file"},
		{"/api/airlock/models/..%2F..%2Fetc/files/provenance.json", ""},
		{"/api/airlock/models/" + id + "/files/report.json", ""},
	} {
		code, _, body := get(t, ts, c.path)
		if code != http.StatusNotFound {
			t.Errorf("%s: %d", c.path, code)
		}
		var e struct{ Error string }
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			t.Errorf("%s: not a handler JSON error: %q", c.path, body)
		}
		if bytes.Equal(body, artifact) || bytes.Equal(body, logBytes) {
			t.Errorf("%s: served protected bytes", c.path)
		}
		if c.reason != "" && !strings.Contains(e.Error, c.reason) {
			t.Errorf("%s: error %q lacks %q", c.path, e.Error, c.reason)
		}
	}
	if code, _, _ := get(t, ts, "/api/airlock/models/"+id[:63]+"0"); code != http.StatusNotFound {
		t.Errorf("unknown id: %d", code)
	}
}

func TestConsoleNeedsAStore(t *testing.T) {
	ts := server(t, Options{})
	if code, _, _ := get(t, ts, "/api/airlock/models"); code != http.StatusBadRequest {
		t.Fatalf("%d", code)
	}
}

func TestConsoleScanStagedWritesTheReport(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	code, body := post(t, ts, "/api/airlock/models/"+id+"/scan", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	var out struct{ Model airlock.Model }
	if json.Unmarshal(body, &out) != nil || out.Model.Stage != airlock.StageScanned {
		t.Fatalf("%s", body)
	}
}

func TestConsoleUploadRefusesWhatDoesNotVerify(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	code, body := post(t, ts, "/api/airlock/models/"+id+"/attestation", map[string]any{"payloadType": "x", "payload": "e30=", "signatures": []any{}})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %s", code, body)
	}
	big := map[string]any{"payload": strings.Repeat("A", 5<<20)}
	if code, _ := post(t, ts, "/api/airlock/models/"+id+"/attestation", big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload: %d", code)
	}
}

func TestConsoleExportIsAZip(t *testing.T) {
	root, _ := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	resp, err := http.Post(ts.URL+"/api/airlock/export", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/zip" || !bytes.HasPrefix(b, []byte("PK\x03\x04")) {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	allowed := regexp.MustCompile(`^(index\.html|log\.jsonl|log-head\.txt|inventory\.json|models/[0-9a-f]{64}/(report\.html|attestation\.json|attestation\.dsse\.json))$`)
	var sawIndex bool
	for _, f := range zr.File {
		if !allowed.MatchString(f.Name) {
			t.Errorf("entry outside the snapshot layout: %s", f.Name)
		}
		if f.Name == "index.html" {
			sawIndex = true
			rc, _ := f.Open()
			body, _ := io.ReadAll(rc)
			rc.Close()
			if !strings.Contains(string(body), "UNSIGNED SNAPSHOT") {
				t.Error("the zip's index must say UNSIGNED SNAPSHOT")
			}
		}
	}
	if !sawIndex {
		t.Error("no index.html in the zip")
	}
}

// signedStaged scans the staged fixture of consoleStore with the three trust
// inputs supplied, signs the authorized document with a fresh operator key,
// trusts that key in the store, and returns the envelope.
func signedStaged(t *testing.T, root, id string) []byte {
	t.Helper()
	dir := t.TempDir()
	mirror := filepath.Join(dir, "mirror")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_REPO_MIRROR", mirror)
	deny := filepath.Join(dir, "denylist.txt")
	if err := os.WriteFile(deny, []byte(strings.Repeat("0", 64)+"  known-bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_DENYLIST", deny)
	prov := filepath.Join(dir, "provenance.json")
	bound := `{"artifact_sha256":"` + id + `","publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/example/model","commit_or_tag":"main","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`
	if err := os.WriteFile(prov, []byte(bound), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_PROVENANCE", prov)
	t.Setenv("SOCAIR_ACCEPTED_BY", "")
	artifact := filepath.Join(dir, "fixture.safetensors")
	if err := os.WriteFile(artifact, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.SHA256 != id || d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("fixture: %s %s", d.Artifact.SHA256, d.PromotionAuthorization.State)
	}
	prefix := filepath.Join(dir, "op")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	s, err := airlock.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(prefix + ".pub"); err != nil {
		t.Fatal(err)
	}
	return env
}

func postRaw(t *testing.T, ts *httptest.Server, path string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, got
}

// An upload that verifies is stored in the staging entry and moves its stage;
// one whose subject is another entry is refused. Falsification: drop the
// subject check in SaveAttestation and the second upload is stored.
func TestConsoleUploadStoresWhatVerifies(t *testing.T) {
	root, id := consoleStore(t)
	env := signedStaged(t, root, id)
	ts := server(t, Options{StoreRoot: root})

	code, body := postRaw(t, ts, "/api/airlock/models/"+id+"/attestation", env)
	var out struct {
		File  string
		Model airlock.Model
	}
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil || out.File != airlock.StagedAttestation ||
		out.Model.Stage != airlock.StageReady || out.Model.Location != "staging" {
		t.Fatalf("%d %s", code, body)
	}
	s, _ := airlock.Open(root)
	if b, err := os.ReadFile(filepath.Join(s.StagingPath(id), airlock.StagedAttestation)); err != nil || !bytes.Equal(b, env) {
		t.Fatalf("the upload was not stored: %v", err)
	}

	other := strings.Repeat("b", 64)
	if err := os.MkdirAll(s.StagingPath(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.StagingPath(other), "other.safetensors"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, body = postRaw(t, ts, "/api/airlock/models/"+other+"/attestation", env)
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "not this entry") {
		t.Fatalf("an attestation for another entry: %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(s.StagingPath(other), airlock.StagedAttestation)); !os.IsNotExist(err) {
		t.Fatal("a refused upload must not be stored")
	}
}

// The console's POSTs sit behind the same guard as the rest of the API: a
// cross-origin page cannot trigger a scan or plant an attestation.
func TestConsoleActionsRefuseCrossOrigin(t *testing.T) {
	root, id := consoleStore(t)
	h := Options{StoreRoot: root}.Handler()
	for _, p := range []string{"/api/airlock/models/" + id + "/scan", "/api/airlock/models/" + id + "/attestation"} {
		if got := send(t, h, http.MethodPost, p, "application/json", map[string]string{"Origin": "https://evil.example"}); got != http.StatusForbidden {
			t.Errorf("cross-origin POST %s = %d, want 403", p, got)
		}
		if got := send(t, h, http.MethodPost, p, "application/json", map[string]string{"Sec-Fetch-Site": "cross-site"}); got != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", p, got)
		}
		if got := send(t, h, http.MethodPost, p, "text/plain", nil); got != http.StatusUnsupportedMediaType {
			t.Errorf("text/plain POST %s = %d, want 415", p, got)
		}
	}
	s, _ := airlock.Open(root)
	for _, name := range []string{airlock.StagedReport, airlock.StagedAttestation} {
		if _, err := os.Stat(filepath.Join(s.StagingPath(id), name)); !os.IsNotExist(err) {
			t.Errorf("a refused request wrote %s", name)
		}
	}
}

// Promote leaves the staged copy, so an id can be in clean and staging. Scan
// and upload act on the staged copy; with none they are 404, even though the
// id is in clean. Falsification: resolve through Store.Model (clean first)
// and the first scan is a 404.
func TestConsoleScanActsOnTheStagedCopy(t *testing.T) {
	root, id := consoleStore(t)
	env := signedStaged(t, root, id)
	s, _ := airlock.Open(root)
	envPath := filepath.Join(t.TempDir(), "attestation.dsse.json")
	if err := os.WriteFile(envPath, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := airlock.Promote(s, filepath.Join(s.StagingPath(id), "fixture.safetensors"), envPath); err != nil {
		t.Fatal(err)
	}
	ts := server(t, Options{StoreRoot: root})

	code, body := post(t, ts, "/api/airlock/models/"+id+"/scan", map[string]any{})
	var out struct{ Model airlock.Model }
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil || out.Model.Location != "staging" || out.Model.Stage != airlock.StageScanned {
		t.Fatalf("scan of a staged copy of a clean id: %d %s", code, body)
	}
	if code, body := postRaw(t, ts, "/api/airlock/models/"+id+"/attestation", env); code != http.StatusOK ||
		json.Unmarshal(body, &out) != nil || out.Model.Location != "staging" {
		t.Fatalf("upload to a staged copy of a clean id: %d %s", code, body)
	}

	// No artifact in the staged copy: 422 with the reason.
	if err := os.Remove(filepath.Join(s.StagingPath(id), "fixture.safetensors")); err != nil {
		t.Fatal(err)
	}
	if code, body := post(t, ts, "/api/airlock/models/"+id+"/scan", map[string]any{}); code != http.StatusUnprocessableEntity ||
		!strings.Contains(string(body), "no artifact") {
		t.Fatalf("scan with no staged artifact: %d %s", code, body)
	}

	// No staged copy at all: 404, though the id is in clean.
	if err := os.RemoveAll(s.StagingPath(id)); err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, ts, "/api/airlock/models/"+id+"/scan", map[string]any{}); code != http.StatusNotFound {
		t.Fatalf("scan of a clean-only id: %d", code)
	}
	if code, _ := postRaw(t, ts, "/api/airlock/models/"+id+"/attestation", env); code != http.StatusNotFound {
		t.Fatalf("upload to a clean-only id: %d", code)
	}
	if code, _ := post(t, ts, "/api/airlock/models/"+strings.Repeat("c", 64)+"/scan", map[string]any{}); code != http.StatusNotFound {
		t.Fatalf("scan of an unknown id: %d", code)
	}
}
