package airlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defilantech/socair/internal/report"
)

// Evidence a staging entry can hold beside its artifact. The report names
// are what socair sign, socair accept, and socair sign --acceptance write
// next to their input, so the CLI run against incoming/<id>/report.json
// produces exactly the files the console reads.
const (
	ProvenanceFile    = "provenance.json"
	StagedReport      = "report.json"
	StagedAttestation = "report.dsse.json"
	StagedAcceptance  = "report.acceptance.dsse.json"
	StagedConditional = "report.conditional.dsse.json"
)

// ErrNoModel marks an id that names no entry in the store.
var ErrNoModel = errors.New("no such model in the store")

// IsEvidence reports whether name is an evidence file the console serves.
func IsEvidence(name string) bool {
	switch name {
	case ProvenanceFile, StagedReport, StagedAttestation, StagedAcceptance, StagedConditional,
		attestationDoc, attestationEnvelope:
		return true
	}
	return false
}

// entryDir returns the directory of an existing entry, clean first.
func (s *Store) entryDir(id string) (string, error) {
	if !hexSHA256.MatchString(id) {
		return "", ErrNoModel
	}
	for _, d := range []string{s.CleanPath(id), s.StagingPath(id)} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d, nil
		}
	}
	return "", ErrNoModel
}

// EvidencePath is the path of one evidence file of an entry. Only names on
// the evidence list are served, and the id must be 64 hex, so no request can
// reach the artifact bytes or leave the store.
func (s *Store) EvidencePath(id, name string) (string, error) {
	if !IsEvidence(name) {
		return "", fmt.Errorf("%q is not an evidence file", name)
	}
	dir, err := s.entryDir(id)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%s has no %s", id, name)
	}
	return p, nil
}

// Evidence lists the evidence files an entry holds (names IsEvidence
// accepts), sorted, so a client offers only files EvidencePath will serve.
func (s *Store) Evidence(id string) ([]string, error) {
	dir, err := s.entryDir(id)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, d := range des {
		if IsEvidence(d.Name()) && !d.IsDir() {
			names = append(names, d.Name())
		}
	}
	return names, nil
}

// stagedArtifact returns the one artifact (a file or a model directory) in
// incoming/<id>/, ignoring evidence files.
func (s *Store) stagedArtifact(id string) (string, error) {
	if !hexSHA256.MatchString(id) {
		return "", ErrNoModel
	}
	entries, err := os.ReadDir(s.StagingPath(id))
	if err != nil {
		return "", ErrNoModel
	}
	var found []string
	for _, e := range entries {
		if !IsEvidence(e.Name()) {
			found = append(found, e.Name())
		}
	}
	switch len(found) {
	case 0:
		return "", errors.New("the staging entry holds no artifact (an interrupted pull?)")
	case 1:
		return filepath.Join(s.StagingPath(id), found[0]), nil
	}
	return "", fmt.Errorf("the staging entry holds %d artifacts, not one: %v", len(found), found)
}

// SaveReport writes an unsigned scan result into a staging entry. The report
// must be for this entry's artifact.
func (s *Store) SaveReport(id string, d *report.Document) error {
	if _, err := s.stagedArtifact(id); errors.Is(err, ErrNoModel) {
		return err
	}
	if normalizeSHA(d.Artifact.SHA256) != id {
		return fmt.Errorf("the report is for %s, not this entry %s", d.Artifact.SHA256, id)
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return s.WriteFile(filepath.Join(s.StagingPath(id), StagedReport), b)
}

// SaveAttestation stores a signed attestation in a staging entry after the
// gate's own checks: a trusted signature, the issuer, a current acceptance
// when conditional, and a subject that is this entry. A withheld attestation
// is stored too: it is the evidence a reviewer reads. A conditional one is
// stored under the name socair sign --acceptance gives it.
func (s *Store) SaveAttestation(id string, envelope []byte, at time.Time) (string, error) {
	if _, err := s.stagedArtifact(id); errors.Is(err, ErrNoModel) {
		return "", err
	}
	a, err := s.Assess(envelope, at)
	if err != nil {
		return "", err
	}
	if a.SHA256 != id {
		return "", fmt.Errorf("the attestation is for %s, not this entry %s", a.SHA256, id)
	}
	name := StagedAttestation
	if a.State == report.StateAuthorizedWithConditions {
		name = StagedConditional
	}
	return name, s.WriteFile(filepath.Join(s.StagingPath(id), name), envelope)
}
