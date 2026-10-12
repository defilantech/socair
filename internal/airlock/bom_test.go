package airlock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/render/cyclonedx"
)

// TestPromoteRefusesASignedBOM: a signed CycloneDX BOM is an inventory, not a
// ticket. Even when the store trusts the key that signed it, it is about the
// exact bytes, and the report behind it authorizes promotion, the gate
// refuses it and nothing crosses; the attestation itself still promotes.
// Falsification: make Store.Assess accept the CycloneDX predicate and the BOM
// crosses.
func TestPromoteRefusesASignedBOM(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	s, err := Init(t.TempDir())
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
	att, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	_, bomEnv, err := cyclonedx.Sign(att, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cyclonedx.Verify(bomEnv, attest.Keyring{k.ID: k.Public()}); err != nil {
		t.Fatalf("the BOM must itself verify, so the refusal is about what it is: %v", err)
	}
	bomPath := filepath.Join(t.TempDir(), "r.cdx.dsse.json")
	if err := os.WriteFile(bomPath, bomEnv, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Promote(s, artifact, bomPath)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "predicate type") {
		t.Fatalf("a signed BOM must be refused as a ticket, got %v", err)
	}
	if entries, _ := os.ReadDir(s.CleanPath(d.Artifact.SHA256)); len(entries) != 0 {
		t.Fatalf("nothing may cross on a signed BOM, found %d entries", len(entries))
	}

	attPath := filepath.Join(t.TempDir(), "r.dsse.json")
	if err := os.WriteFile(attPath, att, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(s, artifact, attPath); err != nil {
		t.Fatalf("the attestation the BOM came from must still promote: %v", err)
	}
}
