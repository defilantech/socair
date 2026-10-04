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
	"strings"

	"github.com/defilantech/socair-verify"

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
	// The issuer is whoever holds the signing key, as its file names them.
	// The signature covers this claim; a verifier confirms it against its
	// own name for the key (Verified.Issuer).
	d.Issuer.SignedBy = IssuerLabel(k.Issuer, k.ID)
	d.Issuer.Authority = d.Issuer.SignedBy
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
// document it carries.
//
// The envelope, signature, statement, subject, and promotion-state checks are
// github.com/defilantech/socair-verify, the same code an admission controller
// such as LLMKube runs, so Socair and its consumers cannot disagree about what
// verifies. Socair then holds its own documents to its full model: the
// predicate must decode into report.Document with no unknown fields, match its
// recorded document hash, and pass report.Validate. Any failure is ErrVerify
// with the reason.
func Verify(envelope []byte, trusted Keyring) (*Verified, error) {
	a, err := verify.Verify(envelope, verify.Keyring(trusted))
	if err != nil {
		return nil, verifyErr("%s", strings.TrimPrefix(err.Error(), verify.ErrVerify.Error()+": "))
	}
	var d report.Document
	dec := json.NewDecoder(bytes.NewReader(a.Predicate))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, verifyErr("predicate is not a Socair report document: %v", err)
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
	return &Verified{Document: d, KeyID: a.KeyID, SHA256: a.SHA256}, nil
}

// IssuerLabel names an issuer for a report: the key's declared name, or, for
// a key that declares none, its id.
func IssuerLabel(name, keyID string) string {
	if name != "" {
		return name
	}
	return "unnamed issuer (key " + ShortID(keyID) + ")"
}

// ErrIssuer marks an attestation whose claimed issuer is not who the
// verifier's trust list says holds the key.
var ErrIssuer = errors.New("attestation issuer does not match the trusted key")

// Issuer resolves who issued a verified attestation, against the names the
// verifier's trust list gives its keys. When the trust list names the
// signing key, the attestation's claimed issuer must be that name, and the
// result is confirmed; a different claim is ErrIssuer. When it does not, the
// claim is returned unconfirmed: a key can call itself anything.
func (v *Verified) Issuer(names Names) (name string, confirmed bool, err error) {
	claimed := v.Document.Issuer.SignedBy
	if trusted, ok := names[v.KeyID]; ok && trusted != "" {
		if claimed != trusted {
			return "", false, fmt.Errorf("%w: it claims %q, but key %s is %q in the trust list", ErrIssuer, claimed, ShortID(v.KeyID), trusted)
		}
		return trusted, true, nil
	}
	if claimed == "" {
		claimed = IssuerLabel("", v.KeyID)
	}
	return claimed, false, nil
}
