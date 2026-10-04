package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
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
	_ = os.WriteFile(filepath.Join(dir, "fixture.safetensors"), data, 0o644)
	_ = os.WriteFile(filepath.Join(dir, airlock.ProvenanceFile), []byte(`{"artifact_sha256":"`+id+`"}`), 0o644)
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
func TestConsoleFileDownloadIsConfined(t *testing.T) {
	root, id := consoleStore(t)
	ts := server(t, Options{StoreRoot: root})
	for _, p := range []string{
		"/api/airlock/models/" + id + "/files/fixture.safetensors",
		"/api/airlock/models/" + id + "/files/..%2Flog.jsonl",
		"/api/airlock/models/..%2F..%2Fetc/files/provenance.json",
		"/api/airlock/models/" + id + "/files/report.json",
	} {
		if code, _, _ := get(t, ts, p); code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("%s: %d", p, code)
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
