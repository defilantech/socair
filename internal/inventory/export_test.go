package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// promotedStore initializes a store, trusts the authorized fixture's signing
// key, and promotes the fixture into clean.
func promotedStore(t *testing.T) (s *airlock.Store, id string, k *attest.PrivateKey, ring attest.Keyring) {
	t.Helper()
	env, id, k, ring, pub := authorizedEnvelopeKey(t)
	s, err := airlock.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(pub); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	artifact := filepath.Join(dir, "fixture.safetensors")
	if err := os.WriteFile(artifact, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, "attestation.dsse.json")
	if err := os.WriteFile(envPath, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := airlock.Promote(s, artifact, envPath); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	return s, id, k, ring
}

func TestExportThenVerify(t *testing.T) {
	s, id, k, ring := promotedStore(t)
	dir := filepath.Join(t.TempDir(), "snap")
	if _, err := Export(s, dir, k, time.Now(), "socair test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, ring, VerifyOptions{}); err != nil {
		t.Fatalf("a fresh export must verify: %v", err)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(idx), id[:12]) || !strings.Contains(string(idx), "model inventory") || strings.Contains(string(idx), "UNSIGNED SNAPSHOT") {
		t.Fatalf("index.html: %s", idx)
	}
	if _, err := os.Stat(filepath.Join(dir, "models", id, "report.html")); err != nil {
		t.Fatal(err)
	}
	// No model bytes leave the store.
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, _ error) error {
		if strings.HasSuffix(p, ".safetensors") {
			t.Errorf("model bytes exported: %s", p)
		}
		return nil
	})
}

func TestUnsignedExportSaysSo(t *testing.T) {
	s, _, _, ring := promotedStore(t)
	dir := filepath.Join(t.TempDir(), "snap")
	if _, err := Export(s, dir, nil, time.Now(), "socair test"); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(idx), "UNSIGNED SNAPSHOT") {
		t.Fatal("an unsigned snapshot must say so")
	}
	if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
		t.Fatal("an unsigned snapshot must not verify without --allow-unsigned")
	}
	if _, err := Verify(dir, ring, VerifyOptions{AllowUnsigned: true}); err != nil {
		t.Fatalf("its contents check: %v", err)
	}
}

// A store with no approved models exports and verifies.
func TestExportEmptyStore(t *testing.T) {
	_, _, k, ring := promotedStore(t)
	s, err := airlock.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "snap")
	if _, err := Export(s, dir, k, time.Now(), "socair test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, ring, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(idx), "No approved models") {
		t.Fatal("an empty snapshot says so")
	}
}

// Falsification: a log whose chain link is wrong refuses the export.
func TestExportRefusesBrokenChain(t *testing.T) {
	s, _, k, _ := promotedStore(t)
	f, err := os.OpenFile(s.LogPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"prev":"deadbeef","action":"promote"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Export(s, filepath.Join(t.TempDir(), "snap"), k, time.Now(), "socair test"); err == nil {
		t.Fatal("export must refuse a broken log chain")
	}
}
