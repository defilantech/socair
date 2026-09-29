package airlock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/report"
)

// ErrRefused marks a promotion the gate declined. The reason is in the error.
var ErrRefused = errors.New("promotion refused")

// Promote moves an artifact into the clean store, gated on its attestation.
//
// The bytes that cross must hash to the attestation that authorizes them, so no
// artifact crosses on another artifact's ticket. A withheld or escalated
// attestation never crosses; an authorized or authorized_with_conditions one
// does, and a conditional crossing keeps its accepted surfaces in the stored
// attestation. A refusal is recorded and returned, never softened to a warning.
func Promote(s *Store, artifactPath, reportPath string) (Event, error) {
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		return Event{}, fmt.Errorf("read attestation %q: %w", reportPath, err)
	}
	var d report.Document
	if err := json.Unmarshal(reportBytes, &d); err != nil {
		return Event{}, fmt.Errorf("parse attestation %q: %w", reportPath, err)
	}

	refuse := func(reason string) (Event, error) {
		e := Event{
			Action:  ActionRefuse,
			Outcome: OutcomeRefused,
			SHA256:  normalizeSHA(d.Artifact.SHA256),
			Detail:  reason,
		}
		if err := s.Record(e); err != nil {
			return e, fmt.Errorf("%w: %s (also failed to log: %v)", ErrRefused, reason, err)
		}
		return e, fmt.Errorf("%w: %s", ErrRefused, reason)
	}

	if problems := report.Validate(&d); len(problems) != 0 {
		return refuse("attestation does not validate: " + strings.Join(problems, "; "))
	}

	switch d.PromotionAuthorization.State {
	case report.StateAuthorized, report.StateAuthorizedWithConditions:
		// crosses
	default:
		return refuse(fmt.Sprintf("attestation state %q withholds promotion; a FAIL is clearable only by escalated review",
			d.PromotionAuthorization.State))
	}

	onDisk, err := hashFile(artifactPath)
	if err != nil {
		return Event{}, err
	}
	want := normalizeSHA(d.Artifact.SHA256)
	if onDisk != want {
		return refuse(fmt.Sprintf("artifact on disk hashes to %s but the attestation authorizes %s", onDisk, want))
	}

	clean := s.CleanPath(want)
	attestPath := filepath.Join(clean, "attestation.json")

	conditional := d.PromotionAuthorization.State == report.StateAuthorizedWithConditions
	outcome := OutcomeOK
	detail := "clean attestation"
	if conditional {
		outcome = OutcomeConditional
		detail = fmt.Sprintf("authorized with conditions accepted by %s on %d surface(s)",
			d.PromotionAuthorization.AcceptedBy, len(d.PromotionAuthorization.AcceptedSurfaces))
	}

	// Re-promotion of an identical identity is a no-op on the store contents,
	// but still evidence in the log.
	if already, _ := sameBytes(attestPath, reportBytes); already {
		detail += "; already promoted"
	} else {
		if _, err := s.Place(artifactPath, clean); err != nil {
			return Event{}, fmt.Errorf("place artifact: %w", err)
		}
		if err := s.WriteFile(attestPath, reportBytes); err != nil {
			return Event{}, fmt.Errorf("write attestation: %w", err)
		}
	}

	e := Event{
		Action:  ActionPromote,
		Outcome: outcome,
		SHA256:  want,
		Detail:  detail,
	}
	if err := s.Record(e); err != nil {
		return e, err
	}
	return e, nil
}

// hashFile is the SHA-256 of a file's bytes on disk.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open artifact %q: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash artifact %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sameBytes reports whether path already holds b.
func sameBytes(path string, b []byte) (bool, error) {
	got, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return bytes.Equal(got, b), nil
}
