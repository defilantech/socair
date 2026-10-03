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
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/report"
)

// now is the clock acceptance expiry is enforced against; tests replace it.
var now = time.Now

// ErrRefused marks a promotion the gate declined. The reason is in the error.
var ErrRefused = errors.New("promotion refused")

// Store metadata names in a clean entry. An artifact may not take one, or the
// metadata would overwrite it.
const (
	attestationDoc      = "attestation.json"
	attestationEnvelope = "attestation.dsse.json"
)

// Promote moves an artifact into the clean store, gated on a signed
// attestation.
//
// The ticket is a DSSE envelope: an in-toto statement signed by a key in the
// store's trust policy (<store>/trusted-keys), whose subject digest is the
// artifact's hash and whose document validates. The bytes that cross are
// hashed as they are copied and must equal that digest, so no artifact
// crosses on another artifact's ticket and nothing is trusted because it
// parses. A withheld or escalated attestation never crosses; an authorized or
// authorized_with_conditions one does, and the conditions travel with it. A
// refusal is recorded and returned, never softened to a warning.
func Promote(s *Store, artifactPath, envelopePath string) (Event, error) {
	envelope, err := os.ReadFile(envelopePath)
	if err != nil {
		return Event{}, fmt.Errorf("read attestation %q: %w", envelopePath, err)
	}

	sha := ""
	refuse := func(reason string) (Event, error) {
		e := Event{Action: ActionRefuse, Outcome: OutcomeRefused, SHA256: sha, Detail: reason}
		if err := s.Record(e); err != nil {
			return e, fmt.Errorf("%w: %s (also failed to log: %v)", ErrRefused, reason, err)
		}
		return e, fmt.Errorf("%w: %s", ErrRefused, reason)
	}

	ring, err := s.TrustedKeys()
	if err != nil {
		return refuse(err.Error())
	}
	v, err := attest.Verify(envelope, ring)
	if err != nil {
		return refuse(err.Error())
	}
	d := v.Document
	sha = normalizeSHA(v.SHA256)

	switch d.PromotionAuthorization.State {
	case report.StateAuthorized, report.StateAuthorizedWithConditions:
		// crosses
	default:
		return refuse(fmt.Sprintf("attestation state %q withholds promotion; a FAIL or LEAD is clearable only by escalated review",
			d.PromotionAuthorization.State))
	}

	isDir := false
	if fi, err := os.Stat(artifactPath); err == nil && fi.IsDir() {
		isDir = true
	}
	switch {
	case len(d.Artifact.Files) > 0 && !isDir:
		return refuse("the attestation is for a model directory, but " + artifactPath + " is not a directory")
	case len(d.Artifact.Files) == 0 && isDir:
		return refuse("the attestation is for a single file, but " + artifactPath + " is a directory")
	}

	name := filepath.Base(filepath.Clean(artifactPath))
	if err := validFileName(name); err != nil {
		return refuse(err.Error())
	}
	if name == attestationDoc || name == attestationEnvelope {
		return refuse(fmt.Sprintf("artifact name %q collides with the store's attestation file; rename it", name))
	}

	clean := s.CleanPath(sha)
	pa := d.PromotionAuthorization
	conditional := pa.State == report.StateAuthorizedWithConditions
	outcome := OutcomeOK
	detail := "clean attestation signed by " + attest.ShortID(v.KeyID)
	if conditional {
		// An acceptance covers its gaps only until it expires. Verify has
		// already required an RFC 3339 expiry; a lapsed one is refused, and
		// the gaps need a fresh scan and a fresh acceptance.
		exp, err := time.Parse(time.RFC3339, pa.AcceptanceExpires)
		if err != nil {
			return refuse(fmt.Sprintf("acceptance expiry %q cannot be enforced", pa.AcceptanceExpires))
		}
		if !now().Before(exp) {
			return refuse(fmt.Sprintf("the acceptance by %s of %d untested surface(s) expired at %s; re-scan and re-accept",
				pa.AcceptedBy, len(pa.AcceptedSurfaces), exp.UTC().Format(time.RFC3339)))
		}
		// The acceptance must be the acceptor's own signature, from a key in
		// acceptor-keys, never the operator's: a name typed at scan time
		// (SOCAIR_ACCEPTED_BY) is not an acceptance the airlock honours.
		acceptors, err := s.AcceptorKeys()
		if err != nil {
			return refuse(err.Error())
		}
		acc, err := attest.VerifyAcceptance(v, acceptors, now())
		if err != nil {
			return refuse("the conditional attestation's acceptance does not hold: " + err.Error())
		}
		outcome = OutcomeConditional
		detail = fmt.Sprintf("authorized with conditions accepted by %s (signed acceptance, acceptor key %s) on %d surface(s) until %s, attestation signed by %s",
			acc.AcceptedBy, attest.ShortID(acc.KeyID), len(pa.AcceptedSurfaces), exp.UTC().Format(time.RFC3339), attest.ShortID(v.KeyID))
	}
	if already, _ := sameBytes(filepath.Join(clean, attestationEnvelope), envelope); already {
		detail += "; already promoted"
	}

	// The artifact is always re-placed, even on a repeat promotion: one read
	// hashes the bytes as they are copied and renames the copy into place only
	// on a match, so a clean copy that was deleted or altered is restored, and
	// a file swapped mid-copy never lands.
	if isDir {
		if err := s.placeVerifiedDir(artifactPath, clean, name, sha, d.Artifact.Files); err != nil {
			var mm *dirMismatchError
			if errors.As(err, &mm) {
				return refuse(mm.Error())
			}
			return Event{}, fmt.Errorf("place model directory: %w", err)
		}
	} else if _, err := s.placeVerified(artifactPath, clean, sha); err != nil {
		var mm *hashMismatchError
		if errors.As(err, &mm) {
			return refuse(fmt.Sprintf("artifact on disk hashes to %s but the attestation is for %s", mm.got, sha))
		}
		return Event{}, fmt.Errorf("place artifact: %w", err)
	}
	docJSON, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return Event{}, err
	}
	if err := s.WriteFile(filepath.Join(clean, attestationDoc), docJSON); err != nil {
		return Event{}, fmt.Errorf("write attestation: %w", err)
	}
	if err := s.WriteFile(filepath.Join(clean, attestationEnvelope), envelope); err != nil {
		return Event{}, fmt.Errorf("write attestation envelope: %w", err)
	}

	e := Event{Action: ActionPromote, Outcome: outcome, SHA256: sha, Detail: detail}
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
