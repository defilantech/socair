package cyclonedx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/dsse"
)

// PredicateType is the in-toto predicate type of a CycloneDX BOM, as the
// in-toto attestation framework and actions/attest-sbom name it. It is not
// the Socair attestation predicate (attest.PredicateType): a signed BOM is an
// inventory, never a promotion ticket, and attest.Verify, which the airlock
// gate runs, refuses it.
const PredicateType = "https://cyclonedx.org/bom"

// Statement is an in-toto Statement v1 whose predicate is a CycloneDX BOM and
// whose subject is the artifact the BOM describes.
type Statement struct {
	Type          string           `json:"_type"`
	Subject       []attest.Subject `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     json.RawMessage  `json:"predicate"`
}

// ErrVerify marks a signed BOM that failed verification. The reason is in the
// error.
var ErrVerify = errors.New("signed BOM does not verify")

func verifyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, args...))
}

// Sign derives the BOM of an attestation and signs it, as a DSSE envelope over
// an in-toto statement whose subject is the attested artifact's digest. It
// returns the BOM, as Render writes it, and the envelope.
//
// The key must be the one that signed the attestation, which Sign verifies
// against that key alone. So the BOM's author, the report's issuer, is whoever
// signs the BOM, and a BOM is never signed for a report its signer did not
// issue.
func Sign(attestation []byte, k *attest.PrivateKey) (bom, envelope []byte, err error) {
	v, err := attest.Verify(attestation, attest.Keyring{k.ID: k.Public()})
	if err != nil {
		return nil, nil, fmt.Errorf("a BOM is signed with the key that signed its attestation, so that its author is the attestation's issuer: %w", err)
	}
	var b bytes.Buffer
	if err := Render(&b, &v.Document); err != nil {
		return nil, nil, err
	}
	st := Statement{
		Type:          attest.StatementType,
		Subject:       []attest.Subject{{Name: v.Document.Artifact.FileName, Digest: map[string]string{"sha256": v.SHA256}}},
		PredicateType: PredicateType,
		Predicate:     b.Bytes(),
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, nil, err
	}
	envelope, err = dsse.Sign(payload, k.ID, k.Sign)
	if err != nil {
		return nil, nil, err
	}
	return b.Bytes(), envelope, nil
}

// Verified is a signed BOM that passed Verify.
type Verified struct {
	// BOM is the signed BOM, indented as Render writes it.
	BOM []byte
	// SHA256 is the digest of the artifact the BOM describes, its subject.
	SHA256 string
	// Name is the subject's name.
	Name string
	// KeyID is the trusted key that signed it.
	KeyID string
	// Author is the BOM's first metadata author, as the BOM states it.
	Author string
}

// Verify checks a signed BOM against trusted keys: one signature by a trusted
// key over the DSSE encoding, an in-toto Statement v1 with the CycloneDX
// predicate type and one subject, and a CycloneDX BOM whose described
// component (metadata.component) carries that subject's SHA-256 as its hash.
// Any change to the BOM breaks the signature.
//
// It verifies an inventory, not an attestation: the result authorizes no
// promotion.
func Verify(envelope []byte, trusted attest.Keyring) (*Verified, error) {
	payload, keyID, err := dsse.Verify(envelope, trusted)
	if err != nil {
		return nil, verifyErr("%v", err)
	}
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, verifyErr("payload is not an in-toto statement: %v", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, verifyErr("trailing data after the statement")
	}
	if st.Type != attest.StatementType {
		return nil, verifyErr("statement type %q, want %q", st.Type, attest.StatementType)
	}
	if st.PredicateType != PredicateType {
		return nil, verifyErr("predicate type %q is not a CycloneDX BOM (%s)", st.PredicateType, PredicateType)
	}
	if len(st.Subject) != 1 {
		return nil, verifyErr("statement has %d subjects, want 1", len(st.Subject))
	}
	sha := st.Subject[0].Digest["sha256"]
	if !hex64.MatchString(sha) {
		return nil, verifyErr("subject digest %q is not a SHA-256", sha)
	}
	var head struct {
		BOMFormat string `json:"bomFormat"`
		Metadata  struct {
			Authors []struct {
				Name string `json:"name"`
			} `json:"authors"`
			Component *struct {
				Hashes []hash `json:"hashes"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(st.Predicate, &head); err != nil || head.BOMFormat != "CycloneDX" {
		return nil, verifyErr("predicate is not a CycloneDX BOM")
	}
	if head.Metadata.Component == nil {
		return nil, verifyErr("the BOM describes no component (metadata.component)")
	}
	found := false
	for _, h := range head.Metadata.Component.Hashes {
		if h.Alg != "SHA-256" {
			continue
		}
		if h.Content != sha {
			return nil, verifyErr("the BOM's component hash %s is not the subject digest %s", h.Content, sha)
		}
		found = true
	}
	if !found {
		return nil, verifyErr("the BOM's component carries no SHA-256 hash to bind the subject %s to", sha)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, st.Predicate, "", "  "); err != nil {
		return nil, verifyErr("predicate: %v", err)
	}
	out.WriteByte('\n')
	v := &Verified{BOM: out.Bytes(), SHA256: sha, Name: st.Subject[0].Name, KeyID: keyID}
	if len(head.Metadata.Authors) > 0 {
		v.Author = head.Metadata.Authors[0].Name
	}
	return v, nil
}

// ErrAuthor marks a signed BOM whose stated author is not who the verifier's
// trust list says holds the signing key.
var ErrAuthor = errors.New("BOM author does not match the trusted key")

// Issuer resolves who issued a verified BOM, as attest.Verified.Issuer does
// for an attestation: when the trust list names the signing key, the BOM's
// stated author must be that name, and the result is confirmed; otherwise the
// stated author is returned unconfirmed.
func (v *Verified) Issuer(names attest.Names) (name string, confirmed bool, err error) {
	if trusted, ok := names[v.KeyID]; ok && trusted != "" {
		if v.Author != trusted {
			return "", false, fmt.Errorf("%w: it states %q, but key %s is %q in the trust list", ErrAuthor, v.Author, attest.ShortID(v.KeyID), trusted)
		}
		return trusted, true, nil
	}
	if v.Author == "" {
		return attest.IssuerLabel("", v.KeyID), false, nil
	}
	return v.Author, false, nil
}

// IsSignedBOM reports whether an envelope carries a CycloneDX BOM statement,
// without verifying it, so a caller can say why an attestation verifier
// refused it.
func IsSignedBOM(envelope []byte) bool {
	payload, _, _, err := dsse.Open(envelope)
	if err != nil {
		return false
	}
	var st struct {
		PredicateType string `json:"predicateType"`
	}
	return json.Unmarshal(payload, &st) == nil && st.PredicateType == PredicateType
}
