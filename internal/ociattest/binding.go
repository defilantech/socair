// Package ociattest attaches Socair attestations to OCI artifacts as
// referrers, and verifies them there.
//
// A Socair attestation's subject is the model's bytes: a file's SHA-256, or a
// model directory's manifest digest. An OCI artifact is addressed by its
// manifest digest, and an admission policy checks a statement about that
// digest. Attach connects the two: it verifies the attestation, confirms
// that the artifact's layers carry exactly the attested bytes
// (MatchLayers), and signs a binding, an in-toto statement whose subject is
// the OCI manifest digest and whose predicate
// (https://socair.ai/oci-binding/v1) names the attestation by hash and
// carries its promotion state. Both envelopes are pushed in one referrer
// manifest whose subject is the artifact.
//
// Verify does not take the binding's word for the match: it fetches the
// artifact's manifest, verifies both envelopes, checks that the binding is
// for this manifest digest and this attestation, and matches the layers to
// the attested files again.
package ociattest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/dsse"
	"github.com/defilantech/socair/internal/registry"
)

const (
	// BindingPredicateType names the binding predicate.
	BindingPredicateType = "https://socair.ai/oci-binding/v1"
	// ArtifactType is the artifactType of the referrer manifest Socair
	// pushes: its layers are the binding and the attestation, each a DSSE
	// envelope.
	ArtifactType = "application/vnd.socair.attestation.v1+json"
	// EnvelopeMediaType is the layer media type of a DSSE envelope.
	EnvelopeMediaType = "application/vnd.dsse.envelope.v1+json"
	// AnnotationPredicateType names, on a referrer layer, the predicate type
	// of the statement in the envelope. It is a hint for a reader browsing
	// the registry; Verify reads the signed statement instead.
	AnnotationPredicateType = "ai.socair.predicate-type"
	statementType           = "https://in-toto.io/Statement/v1"
)

// Binding is the binding predicate: what attach checked and vouches for.
type Binding struct {
	Artifact    BoundArtifact    `json:"artifact"`
	Attestation BoundAttestation `json:"attestation"`
	BoundUTC    string           `json:"bound_utc"`
	ToolVersion string           `json:"tool_version"`
}

// BoundArtifact is the OCI artifact as attach read it.
type BoundArtifact struct {
	// Name is registry/repository; the statement's subject is Digest.
	Name         string `json:"name"`
	Digest       string `json:"digest"`
	MediaType    string `json:"media_type"`
	ArtifactType string `json:"artifact_type,omitempty"`
	// ConfigMediaType and ConfigDigest name the manifest's config blob,
	// which is not matched: the attestation does not cover it.
	ConfigMediaType string `json:"config_media_type"`
	ConfigDigest    string `json:"config_digest"`
	// Match is MatchFile or MatchDirectory, and Layers are the layers that
	// carry the attested bytes: every layer of the manifest.
	Match  string  `json:"match"`
	Layers []Layer `json:"layers"`
}

// BoundAttestation names the Socair attestation the binding is for and
// carries what an admission policy decides on.
type BoundAttestation struct {
	// SHA256 is the hash of the attestation envelope's bytes, as pushed.
	SHA256        string `json:"sha256"`
	PredicateType string `json:"predicate_type"`
	// SubjectSHA256 is the attestation's subject: the file's SHA-256 or
	// the model directory's manifest digest.
	SubjectSHA256     string   `json:"subject_sha256"`
	SubjectName       string   `json:"subject_name"`
	DocumentID        string   `json:"document_id"`
	DocumentHash      string   `json:"document_hash"`
	IssuedUTC         string   `json:"issued_utc"`
	SignerKeyID       string   `json:"signer_key_id"`
	Issuer            string   `json:"issuer"`
	CheckSetVersion   string   `json:"check_set_version"`
	PromotionState    string   `json:"promotion_state"`
	AcceptedBy        string   `json:"accepted_by,omitempty"`
	AcceptedSurfaces  []string `json:"accepted_surfaces,omitempty"`
	AcceptanceExpires string   `json:"acceptance_expires,omitempty"`
}

// Subject is an in-toto subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is the binding statement.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Binding   `json:"predicate"`
}

// SignBinding wraps a binding in a statement about the OCI manifest digest
// and signs it.
func SignBinding(b Binding, k *attest.PrivateKey) ([]byte, error) {
	st := Statement{
		Type:          statementType,
		Subject:       []Subject{{Name: b.Artifact.Name, Digest: map[string]string{"sha256": hexOf(b.Artifact.Digest)}}},
		PredicateType: BindingPredicateType,
		Predicate:     b,
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return dsse.Sign(payload, k.ID, k.Sign)
}

// VerifiedBinding is a binding whose signature verified.
type VerifiedBinding struct {
	Binding
	KeyID string
	// Subject is the statement's subject digest, "sha256:<hex>".
	Subject string
}

// ErrBinding marks a binding envelope that does not verify.
var ErrBinding = errors.New("binding does not verify")

// VerifyBinding checks a binding envelope's signature against trusted keys
// and decodes it strictly. It does not check what the binding is for; the
// caller compares Subject and the attestation hash with what it fetched.
func VerifyBinding(raw []byte, trusted attest.Keyring) (*VerifiedBinding, error) {
	payload, keyID, err := dsse.Verify(raw, trusted)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%w: not a binding statement: %v", ErrBinding, err)
	}
	if st.Type != statementType || st.PredicateType != BindingPredicateType {
		return nil, fmt.Errorf("%w: statement %q with predicate %q", ErrBinding, st.Type, st.PredicateType)
	}
	if len(st.Subject) != 1 || len(st.Subject[0].Digest) != 1 {
		return nil, fmt.Errorf("%w: want one subject with one digest", ErrBinding)
	}
	sub := "sha256:" + st.Subject[0].Digest["sha256"]
	if err := registry.ValidDigest(sub); err != nil {
		return nil, fmt.Errorf("%w: subject %v", ErrBinding, err)
	}
	if st.Predicate.Artifact.Digest != sub {
		return nil, fmt.Errorf("%w: its subject %s and its artifact %s disagree", ErrBinding, sub, st.Predicate.Artifact.Digest)
	}
	return &VerifiedBinding{Binding: st.Predicate, KeyID: keyID, Subject: sub}, nil
}

// PredicateTypeOf reads the predicate type of the statement in a DSSE
// envelope, unverified: it routes an envelope to its verifier, nothing more.
func PredicateTypeOf(raw []byte) string {
	var e struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return ""
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return ""
	}
	var st struct {
		PredicateType string `json:"predicateType"`
	}
	if json.Unmarshal(payload, &st) != nil {
		return ""
	}
	return st.PredicateType
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func hexOf(digest string) string {
	if len(digest) > 7 && digest[:7] == "sha256:" {
		return digest[7:]
	}
	return digest
}
