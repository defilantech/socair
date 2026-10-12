package ociattest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/defilantech/socair/internal/acceptance"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/report"
)

// VerifyOptions are the keys verify checks against.
type VerifyOptions struct {
	// Trusted verify both the binding and the attestation; Names are the
	// issuer names the trust list gives them.
	Trusted attest.Keyring
	Names   attest.Names
	// Acceptors, when set, verify a conditional attestation's signed
	// acceptance. Without them it is reported unchecked.
	Acceptors attest.Keyring
	Now       func() time.Time
}

// Found is one Socair referrer of the artifact and what verifying it showed.
// Err is nil only when every check held.
type Found struct {
	Referrer registry.Descriptor
	Err      error

	Binding         *VerifiedBinding
	Attestation     *attest.Verified
	Issuer          string
	IssuerConfirmed bool
	Match           *Match
	// Acceptance is the verified acceptance of a conditional attestation,
	// nil when there is none or no acceptor keys were given.
	Acceptance *acceptance.Acceptance
	// Bundle is the Sigstore bundle referrer that carries this binding's
	// signed statement, the copy cosign-based verifiers read; nil when none
	// was found. It is reported, not required.
	Bundle *registry.Descriptor

	bindingEnv []byte
}

// Result is everything verify found for one artifact.
type Result struct {
	Ref      registry.Reference
	Artifact registry.Descriptor
	// Via is how the referrers were listed.
	Via   string
	Found []Found
	// Unchecked counts Socair referrers past MaxReferrers, listed but not
	// checked.
	Unchecked int
}

// MaxReferrers bounds how many Socair referrers of one artifact verify
// checks: anyone who can push can add referrers, and each costs fetches.
// Past the bound, the rest are counted, not checked, so a flood can make
// verify fail but never pass.
const MaxReferrers = 64

// Verified returns the referrers that verified.
func (r *Result) Verified() []Found {
	var out []Found
	for _, f := range r.Found {
		if f.Err == nil {
			out = append(out, f)
		}
	}
	return out
}

// ErrNoAttestation marks an artifact with no Socair referrer that verifies.
var ErrNoAttestation = errors.New("no Socair attestation on this artifact verifies")

// Verify finds the Socair referrers of the artifact ref names and checks
// each: both envelopes verify against trusted keys; the referrer's subject
// and the binding's subject are this artifact's manifest digest; the binding
// names this attestation's hash and subject; and the manifest's layers,
// matched again here, carry exactly the attested bytes. The error is
// ErrNoAttestation when none verifies; Result says why for each.
func Verify(ctx context.Context, c *registry.Client, ref registry.Reference, o VerifyOptions) (*Result, error) {
	repo := c.Repo(ref)
	f, err := repo.Manifest(ctx, ref.Ref())
	if err != nil {
		return nil, err
	}
	var m registry.Manifest
	if err := json.Unmarshal(f.Bytes, &m); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", f.Descriptor.Digest, err)
	}
	list, via, err := repo.Referrers(ctx, f.Descriptor.Digest, ArtifactType)
	if err != nil {
		return nil, err
	}
	res := &Result{Ref: ref.WithDigest(f.Descriptor.Digest), Artifact: f.Descriptor, Via: via}
	if len(list) > MaxReferrers {
		res.Unchecked = len(list) - MaxReferrers
		list = list[:MaxReferrers]
	}
	for _, d := range list {
		found := Found{Referrer: d}
		found.Err = checkReferrer(ctx, repo, f, m, &found, o)
		if found.Err == nil {
			found.Bundle, _ = findBundle(ctx, repo, f.Descriptor.Digest, found.bindingEnv)
		}
		res.Found = append(res.Found, found)
	}
	if len(res.Verified()) == 0 {
		if len(res.Found) == 0 {
			return res, fmt.Errorf("%w: it has no Socair referrer (listed via %s)", ErrNoAttestation, via)
		}
		return res, ErrNoAttestation
	}
	return res, nil
}

// checkReferrer runs every check on one referrer, filling found as it goes.
func checkReferrer(ctx context.Context, repo *registry.Repo, art *registry.Fetched, m registry.Manifest, found *Found, o VerifyOptions) error {
	rf, err := repo.Manifest(ctx, found.Referrer.Digest)
	if err != nil {
		return err
	}
	var rm registry.Manifest
	if err := json.Unmarshal(rf.Bytes, &rm); err != nil {
		return fmt.Errorf("referrer manifest: %w", err)
	}
	if rm.ArtifactType != ArtifactType {
		return fmt.Errorf("referrer artifactType %q, want %q", rm.ArtifactType, ArtifactType)
	}
	// The registry listed it for this artifact; its own subject must say so.
	if rm.Subject == nil || rm.Subject.Digest != art.Descriptor.Digest {
		got := "none"
		if rm.Subject != nil {
			got = rm.Subject.Digest
		}
		return fmt.Errorf("the referrer's subject is %s, not this artifact %s", got, art.Descriptor.Digest)
	}
	var bindingRaw, attRaw []byte
	for _, l := range rm.Layers {
		if l.MediaType != EnvelopeMediaType {
			return fmt.Errorf("referrer layer %s has media type %q, want %q", l.Digest, l.MediaType, EnvelopeMediaType)
		}
		raw, err := repo.Blob(ctx, l.Digest, registry.MaxBlob)
		if err != nil {
			return err
		}
		switch PredicateTypeOf(raw) {
		case BindingPredicateType:
			if bindingRaw != nil {
				return errors.New("the referrer holds two bindings")
			}
			bindingRaw = raw
		case attest.PredicateType:
			if attRaw != nil {
				return errors.New("the referrer holds two attestations")
			}
			attRaw = raw
		default:
			return fmt.Errorf("referrer layer %s is not a Socair binding or attestation", l.Digest)
		}
	}
	if bindingRaw == nil || attRaw == nil {
		return errors.New("the referrer lacks its binding or its attestation")
	}

	b, err := VerifyBinding(bindingRaw, o.Trusted)
	if err != nil {
		return err
	}
	found.Binding, found.bindingEnv = b, bindingRaw
	// The signed statement is about this manifest digest, not merely
	// listed beside it.
	if b.Subject != art.Descriptor.Digest {
		return fmt.Errorf("the binding is for artifact %s, not this artifact %s", b.Subject, art.Descriptor.Digest)
	}
	v, err := attest.Verify(attRaw, o.Trusted)
	if err != nil {
		return err
	}
	found.Attestation = v
	if found.Issuer, found.IssuerConfirmed, err = v.Issuer(o.Names); err != nil {
		return err
	}
	if b.Attestation.SHA256 != sha256Hex(attRaw) {
		return fmt.Errorf("the binding names attestation %s, but the referrer carries %s", b.Attestation.SHA256, sha256Hex(attRaw))
	}
	if err := agrees(b.Attestation, v); err != nil {
		return err
	}
	match, err := MatchLayers(art.Descriptor.MediaType, m, v.Document.Artifact)
	if err != nil {
		return err
	}
	found.Match = match
	pa := v.Document.PromotionAuthorization
	if pa.State == report.StateAuthorizedWithConditions && len(o.Acceptors) > 0 {
		now := time.Now
		if o.Now != nil {
			now = o.Now
		}
		a, err := attest.VerifyAcceptance(v, o.Acceptors, now())
		if err != nil {
			return fmt.Errorf("%w: acceptance: %v", attest.ErrVerify, err)
		}
		found.Acceptance = a
	}
	return nil
}

// agrees checks that what the binding states about the attestation is what
// the attestation says. The binding carries these for an admission policy,
// so a binding that misstates them must not verify.
func agrees(b BoundAttestation, v *attest.Verified) error {
	d := v.Document
	pa := d.PromotionAuthorization
	type pair struct {
		field, bound, actual string
	}
	for _, p := range []pair{
		{"predicate_type", b.PredicateType, attest.PredicateType},
		{"subject_sha256", b.SubjectSHA256, v.SHA256},
		{"subject_name", b.SubjectName, d.Artifact.FileName},
		{"document_id", b.DocumentID, d.Header.DocumentID},
		{"document_hash", b.DocumentHash, d.Verification.DocumentHash},
		{"issued_utc", b.IssuedUTC, d.Header.IssuedUTC},
		{"signer_key_id", b.SignerKeyID, v.KeyID},
		{"check_set_version", b.CheckSetVersion, d.Scope.CheckSetVersion},
		{"promotion_state", b.PromotionState, pa.State},
		{"accepted_by", b.AcceptedBy, pa.AcceptedBy},
		{"acceptance_expires", b.AcceptanceExpires, pa.AcceptanceExpires},
	} {
		if p.bound != p.actual {
			return fmt.Errorf("the binding states %s %q, but the attestation says %q", p.field, p.bound, p.actual)
		}
	}
	if !slices.Equal(b.AcceptedSurfaces, pa.AcceptedSurfaces) {
		return fmt.Errorf("the binding states accepted_surfaces %v, but the attestation says %v", b.AcceptedSurfaces, pa.AcceptedSurfaces)
	}
	if b.Issuer != v.Document.Issuer.SignedBy && b.Issuer != attest.IssuerLabel("", v.KeyID) {
		return fmt.Errorf("the binding states issuer %q, but the attestation says %q", b.Issuer, v.Document.Issuer.SignedBy)
	}
	return nil
}
