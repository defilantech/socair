package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/airlock"
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
