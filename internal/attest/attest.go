// Package attest signs and verifies Socair attestations.
//
// An attestation is an in-toto Statement v1 whose subject is the artifact's
// SHA-256 and whose predicate is the socair.report/v1 document, wrapped in a
// DSSE envelope and signed with Ed25519. That is the shape OpenSSF Model
// Signing and SLSA tooling read, and it verifies offline: no transparency log
// or certificate authority is needed, so it works on an air-gapped box.
//
// The signature binds the artifact hash, the document, and the signer's key.
// It does not make the document's claims stronger than its bounded statement:
// a signed report still certifies only what it says it tested.
package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/defilantech/socair/internal/report"
)

const (
	// StatementType is the in-toto Statement v1 type.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateType names the Socair report predicate.
	PredicateType = "https://socair.ai/attestation/v1"
	// PayloadType is the DSSE payload type for an in-toto statement.
	PayloadType = "application/vnd.in-toto+json"
	// SigningMethod is recorded in a signed document's verification section.
	SigningMethod = "DSSE Ed25519 over an in-toto Statement v1"
)

// Statement is an in-toto Statement v1 carrying a Socair report.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     report.Document `json:"predicate"`
}

// Subject is one attested artifact, named and digested.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// ErrVerify marks an attestation that failed verification. The reason is in
// the error.
var ErrVerify = errors.New("attestation does not verify")

func verifyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, args...))
}

// pae is DSSE's pre-authentication encoding: what is actually signed. It binds
// the payload type, so a payload cannot be replayed as another type.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// DocumentHash is the SHA-256 of a document's JSON with both document_hash
// fields empty. It is recorded in the signed document, so a reader of the
// rendered report can tie it to the attestation.
func DocumentHash(d report.Document) (string, error) {
	d.Verification.DocumentHash = ""
	d.Header.DocumentHash = ""
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Sign wraps d in a statement and signs it. The document's verification
// section is filled with the signing method, key id, and document hash
// before signing, so those fields are covered by the signature.
func Sign(d report.Document, k *PrivateKey) ([]byte, error) {
	if problems := report.Validate(&d); len(problems) != 0 {
		return nil, fmt.Errorf("refusing to sign an invalid document: %v", problems)
	}
	sha := d.Artifact.SHA256
	if sha == "" {
		return nil, errors.New("refusing to sign a document with no artifact hash (a header-only scan is not an attestation)")
	}
	d.Verification.SigningMethod = SigningMethod
	d.Verification.SignerKeyID = k.ID
	d.Header.SignerKeyID = k.ID
	h, err := DocumentHash(d)
	if err != nil {
		return nil, err
	}
	d.Verification.DocumentHash = h
	d.Header.DocumentHash = h

	st := Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: d.Artifact.FileName, Digest: map[string]string{"sha256": sha}}},
		PredicateType: PredicateType,
		Predicate:     d,
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(k.key, pae(PayloadType, payload))
	env := Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	return json.MarshalIndent(env, "", "  ")
}

// Verified is an attestation that passed verification.
type Verified struct {
	Document report.Document
	KeyID    string
	SHA256   string
}

// Verify checks an envelope against a set of trusted keys and returns the
// document it carries. It checks, in order: the envelope shape, a signature
// by a trusted key over the DSSE encoding, the statement and predicate types,
// that the subject digest is the document's artifact hash, the recorded
// document hash, and that the document validates (including its promotion
// state against its checks). Any failure is ErrVerify with the reason.
func Verify(envelope []byte, trusted Keyring) (*Verified, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, verifyErr("not a DSSE envelope: %v", err)
	}
	if env.PayloadType != PayloadType {
		return nil, verifyErr("payload type %q, want %q", env.PayloadType, PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, verifyErr("payload is not base64: %v", err)
	}
	if len(env.Signatures) == 0 {
		return nil, verifyErr("envelope is unsigned")
	}

	signedBy := ""
	msg := pae(env.PayloadType, payload)
	for _, s := range env.Signatures {
		pub, ok := trusted[s.KeyID]
		if !ok {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, msg, sig) {
			signedBy = s.KeyID
			break
		}
	}
	if signedBy == "" {
		ids := make([]string, 0, len(env.Signatures))
		for _, s := range env.Signatures {
			ids = append(ids, s.KeyID)
		}
		return nil, verifyErr("no valid signature by a trusted key (signed by %v; %d key(s) trusted)", ids, len(trusted))
	}

	var st Statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, verifyErr("payload is not a Socair statement: %v", err)
	}
	if st.Type != StatementType {
		return nil, verifyErr("statement type %q, want %q", st.Type, StatementType)
	}
	if st.PredicateType != PredicateType {
		return nil, verifyErr("predicate type %q, want %q", st.PredicateType, PredicateType)
	}
	if len(st.Subject) != 1 {
		return nil, verifyErr("statement has %d subjects, want 1", len(st.Subject))
	}
	sha := st.Subject[0].Digest["sha256"]
	d := st.Predicate
	if sha == "" || sha != d.Artifact.SHA256 {
		return nil, verifyErr("subject digest %q is not the document's artifact hash %q", sha, d.Artifact.SHA256)
	}
	if d.Verification.SignerKeyID != signedBy {
		return nil, verifyErr("document names signer %q but was signed by %q", d.Verification.SignerKeyID, signedBy)
	}
	h, err := DocumentHash(d)
	if err != nil {
		return nil, verifyErr("hash document: %v", err)
	}
	if h != d.Verification.DocumentHash {
		return nil, verifyErr("document hash %s does not match the recorded %s", h, d.Verification.DocumentHash)
	}
	if problems := report.Validate(&d); len(problems) != 0 {
		return nil, verifyErr("document does not validate: %v", problems)
	}
	return &Verified{Document: d, KeyID: signedBy, SHA256: sha}, nil
}
