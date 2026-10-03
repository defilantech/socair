// Package acceptance is the signed acceptance record: a named person's
// signature accepting the untested surfaces of one reviewed report, until a
// set time.
//
// The flow is review, accept, re-issue. A scan is signed as usual and its
// attestation reads withheld, because some checks were NOT_TESTED. The
// acceptor reviews that report and signs an acceptance bound to it: the
// artifact's hash, the reviewed report's document hash, exactly its
// NOT_TESTED surfaces, and an expiry. The operator then re-issues the same
// report as authorized_with_conditions with the acceptance embedded, so one
// attestation carries both signatures. A verifier that checks only the
// operator's signature (LLMKube's gate) admits it as before; the airlock
// verifies the acceptor's signature too, against its own acceptor keys,
// distinct from the keys that sign attestations.
//
// An acceptance is an in-toto Statement v1 (predicate type
// https://socair.ai/acceptance/v1) in a DSSE envelope signed with Ed25519,
// the same machinery as an attestation. This package imports nothing of
// Socair's, so the report model can check an embedded acceptance's
// consistency without a cycle; signatures are checked by Verify, with keys
// the caller loads.
package acceptance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/defilantech/socair/internal/dsse"
	"sort"
	"strings"
	"time"
)

const (
	// PredicateType names a Socair acceptance.
	PredicateType = "https://socair.ai/acceptance/v1"
	statementType = "https://in-toto.io/Statement/v1"
)

// ErrVerify marks an acceptance that does not verify.
var ErrVerify = errors.New("acceptance does not verify")

// Predicate is what the acceptor signs.
type Predicate struct {
	// ReviewedDocumentHash is the document hash of the withheld report the
	// acceptor reviewed (its verification.document_hash).
	ReviewedDocumentHash string `json:"reviewed_document_hash"`
	ReviewedDocumentID   string `json:"reviewed_document_id"`
	// AcceptedSurfaces are the report's NOT_TESTED rows, all of them.
	AcceptedSurfaces []string `json:"accepted_surfaces"`
	// AcceptedBy names the acceptor, as they wrote it; the key is the proof.
	AcceptedBy string `json:"accepted_by"`
	AcceptedAt string `json:"accepted_at"`
	Expires    string `json:"expires"`
	Rationale  string `json:"rationale,omitempty"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Acceptance is a parsed acceptance.
type Acceptance struct {
	Predicate
	ArtifactName   string
	ArtifactSHA256 string
	// KeyID is the acceptor's key id: the SHA-256 of its PKIX DER encoding,
	// as Socair names keys. From Parse it is the claimed id; from Verify, the
	// key that verified.
	KeyID string
}

// KeyID is a public key's id: the hex SHA-256 of its PKIX DER encoding.
func KeyID(pub ed25519.PublicKey) (string, error) { return dsse.KeyID(pub) }

// Sign signs an acceptance of p for the artifact (name, sha256) with the
// acceptor's key. The predicate must be well-formed (see Check).
func Sign(p Predicate, artifactName, artifactSHA256 string, key ed25519.PrivateKey, keyID string) ([]byte, error) {
	a := &Acceptance{Predicate: p, ArtifactName: artifactName, ArtifactSHA256: artifactSHA256}
	if err := a.wellFormed(); err != nil {
		return nil, err
	}
	surfaces := append([]string{}, p.AcceptedSurfaces...)
	sort.Strings(surfaces)
	p.AcceptedSurfaces = surfaces
	payload, err := json.Marshal(statement{
		Type:          statementType,
		Subject:       []subject{{Name: artifactName, Digest: map[string]string{"sha256": artifactSHA256}}},
		PredicateType: PredicateType,
		Predicate:     p,
	})
	if err != nil {
		return nil, err
	}
	return dsse.Sign(payload, keyID, func(msg []byte) []byte { return ed25519.Sign(key, msg) })
}

func verifyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, args...))
}

// decode reads an envelope and its statement, without checking a signature.
func decode(raw []byte) (*Acceptance, []byte, []byte, error) {
	payload, sig, keyID, err := dsse.Open(raw)
	if err != nil {
		return nil, nil, nil, verifyErr("%v", err)
	}
	var st statement
	sdec := json.NewDecoder(bytes.NewReader(payload))
	sdec.DisallowUnknownFields()
	if err := sdec.Decode(&st); err != nil {
		return nil, nil, nil, verifyErr("payload is not an acceptance statement: %v", err)
	}
	if st.Type != statementType || st.PredicateType != PredicateType {
		return nil, nil, nil, verifyErr("predicate type %q is not %s", st.PredicateType, PredicateType)
	}
	if len(st.Subject) != 1 {
		return nil, nil, nil, verifyErr("want one subject, got %d", len(st.Subject))
	}
	a := &Acceptance{
		Predicate:      st.Predicate,
		ArtifactName:   st.Subject[0].Name,
		ArtifactSHA256: strings.ToLower(st.Subject[0].Digest["sha256"]),
		KeyID:          keyID,
	}
	if err := a.wellFormed(); err != nil {
		return nil, nil, nil, verifyErr("%v", err)
	}
	return a, payload, sig, nil
}

// Parse reads an acceptance without checking its signature: for the report
// model's consistency check, which holds no keys.
func Parse(raw []byte) (*Acceptance, error) {
	a, _, _, err := decode(raw)
	return a, err
}

// Verify checks an acceptance's signature against the acceptor keys, by key
// id. It does not check expiry; see Current.
func Verify(raw []byte, acceptors map[string]ed25519.PublicKey) (*Acceptance, error) {
	a, payload, sig, err := decode(raw)
	if err != nil {
		return nil, err
	}
	pub, ok := acceptors[a.KeyID]
	if !ok {
		return nil, verifyErr("signed by key %s, which is not a trusted acceptor key", short(a.KeyID))
	}
	if !ed25519.Verify(pub, dsse.PAE(payload), sig) {
		return nil, verifyErr("the signature does not verify against acceptor key %s", short(a.KeyID))
	}
	return a, nil
}

// Current reports an acceptance that has expired at now as an error.
func (a *Acceptance) Current(now time.Time) error {
	exp, _ := time.Parse(time.RFC3339, a.Expires)
	if !now.Before(exp) {
		return fmt.Errorf("the acceptance by %s expired at %s", a.AcceptedBy, exp.UTC().Format(time.RFC3339))
	}
	return nil
}

// wellFormed checks the fields every acceptance needs.
func (a *Acceptance) wellFormed() error {
	switch {
	case len(a.ArtifactSHA256) != 64 || !isHex(a.ArtifactSHA256):
		return errors.New("the acceptance names no artifact sha256")
	case len(a.ReviewedDocumentHash) != 64 || !isHex(a.ReviewedDocumentHash):
		return errors.New("the acceptance names no reviewed document hash")
	case strings.TrimSpace(a.AcceptedBy) == "":
		return errors.New("the acceptance names no acceptor")
	case len(a.AcceptedSurfaces) == 0:
		return errors.New("the acceptance accepts no surfaces")
	}
	at, err := time.Parse(time.RFC3339, a.AcceptedAt)
	if err != nil {
		return fmt.Errorf("accepted_at %q is not RFC 3339", a.AcceptedAt)
	}
	exp, err := time.Parse(time.RFC3339, a.Expires)
	if err != nil {
		return fmt.Errorf("expires %q is not RFC 3339", a.Expires)
	}
	if !exp.After(at) {
		return errors.New("the acceptance expires before it was made")
	}
	return nil
}

// SameSurfaces reports whether two surface lists hold the same names.
func SameSurfaces(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func short(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}
