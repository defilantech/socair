package airlock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// stage writes the clean fixture into incoming/<sha>/fixture.safetensors with
// a provenance file, as a pull does, and returns the id.
func stage(t *testing.T, s *Store) string {
	t.Helper()
	data := safetensorstest.Clean()
	sum := sha256.Sum256(data)
	id := hex.EncodeToString(sum[:])
	dir := s.StagingPath(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.safetensors"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ProvenanceFile), []byte(`{"artifact_sha256":"`+id+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStagedArtifactIgnoresEvidence(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_ = os.WriteFile(filepath.Join(s.StagingPath(id), StagedReport), []byte("{}"), 0o644)
	p, err := s.stagedArtifact(id)
	if err != nil || filepath.Base(p) != "fixture.safetensors" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestSaveReportBindsTheEntry(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	if err := s.SaveReport(id, d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.StagingPath(id), StagedReport)); err != nil {
		t.Fatal(err)
	}
	other := *d
	other.Artifact.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := s.SaveReport(id, &other); err == nil {
		t.Fatal("a report for another artifact must not be saved under this entry")
	}
	if err := s.SaveReport("not-hex", d); !errors.Is(err, ErrNoModel) {
		t.Fatalf("bad id: %v", err)
	}
}

// Falsification: skip Assess in SaveAttestation and the forged envelope is stored.
func TestSaveAttestationVerifiesAndChecksTheSubject(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	name, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now())
	if err != nil || name != StagedAttestation {
		t.Fatalf("%q %v", name, err)
	}

	withholdForGap(d)
	if name, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now()); err != nil || name != StagedAttestation {
		t.Fatalf("a withheld attestation is evidence too: %q %v", name, err)
	}

	forged := envelopeFor(t, d)
	forged[len(forged)-5] ^= 1
	if _, err := s.SaveAttestation(id, forged, time.Now()); err == nil {
		t.Fatal("a tampered envelope must be refused")
	}

	wrong := *d
	wrong.Artifact.SHA256 = "1111111111111111111111111111111111111111111111111111111111111111"
	if _, err := s.SaveAttestation(id, envelopeFor(t, &wrong), time.Now()); err == nil {
		t.Fatal("an attestation for another artifact must be refused")
	}
}

func TestEvidencePathRefusesUnknownNamesAndTraversal(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	if _, err := s.EvidencePath(id, ProvenanceFile); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fixture.safetensors", "../log.jsonl", "", "report.json/.."} {
		if _, err := s.EvidencePath(id, name); err == nil {
			t.Errorf("%q served", name)
		}
	}
	if _, err := s.EvidencePath("../../etc", ProvenanceFile); !errors.Is(err, ErrNoModel) {
		t.Errorf("traversal id: %v", err)
	}
}
