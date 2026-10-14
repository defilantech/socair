package ociattest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/report"
)

// AttachOptions are the keys and inputs attach needs.
type AttachOptions struct {
	// Key signs the binding.
	Key *attest.PrivateKey
	// Trusted are the keys the attestation must verify against, and Names
	// the issuer names the trust list gives them.
	Trusted attest.Keyring
	Names   attest.Names
	// Acceptors verify a conditional attestation's signed acceptance. A
	// conditional attestation is attached only when it verifies.
	Acceptors attest.Keyring
	// Map sets the model root an image's tar layers are mapped under
	// (DefaultModelRoot when empty) and the mapping's bounds.
	Map MapOptions
	// ToolVersion is recorded in the binding.
	ToolVersion string
	// Now is the binding time; nil means time.Now.
	Now func() time.Time
}

// Attached is what attach pushed.
type Attached struct {
	// Artifact is the OCI artifact's manifest, as resolved.
	Artifact registry.Descriptor
	Ref      registry.Reference
	// Referrer is the pushed referrer manifest, and Via the path the
	// registry took (the referrers API, or the referrers tag schema).
	Referrer registry.Descriptor
	Via      string
	// Bundle is the Sigstore bundle referrer carrying the binding, for
	// cosign-based verifiers, and BundleVia the path the registry took.
	Bundle    registry.Descriptor
	BundleVia string
	Binding   Binding
	// Issuer is the attestation's issuer, and IssuerConfirmed whether the
	// trust list names its key.
	Issuer          string
	IssuerConfirmed bool
}

// Attach verifies an attestation, checks that the OCI artifact ref names
// carries exactly its bytes, signs a binding of the two, and pushes both as
// a referrer of the artifact. Nothing is pushed unless every check holds.
func Attach(ctx context.Context, c *registry.Client, ref registry.Reference, envelope []byte, o AttachOptions) (*Attached, error) {
	if o.Key == nil {
		return nil, errors.New("attach needs a signing key for the binding")
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	v, err := attest.Verify(envelope, o.Trusted)
	if err != nil {
		return nil, err
	}
	issuer, confirmed, err := v.Issuer(o.Names)
	if err != nil {
		return nil, err
	}
	pa := v.Document.PromotionAuthorization
	if pa.State == report.StateAuthorizedWithConditions {
		// The binding states the promotion state an admission policy reads.
		// A conditional state is stated only when its acceptance is the
		// acceptor's signed one and holds, as the airlock requires.
		if !pa.Signed() {
			return nil, fmt.Errorf("the attestation is authorized_with_conditions on an unsigned acceptance (named at scan time); re-issue it with a signed acceptance (socair accept, socair sign --acceptance) before attaching")
		}
		if len(o.Acceptors) == 0 {
			return nil, errors.New("the attestation is authorized_with_conditions: pass --acceptors <key.pub|dir> (or --store) so its signed acceptance is verified before it is attached")
		}
		if _, err := attest.VerifyAcceptance(v, o.Acceptors, now()); err != nil {
			return nil, fmt.Errorf("%w: acceptance: %v", attest.ErrVerify, err)
		}
	}

	repo := c.Repo(ref)
	f, err := repo.Manifest(ctx, ref.Ref())
	if err != nil {
		return nil, err
	}
	var m registry.Manifest
	if err := json.Unmarshal(f.Bytes, &m); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", f.Descriptor.Digest, err)
	}
	match, err := matchArtifact(ctx, repo, f.Descriptor.MediaType, m, v.Document.Artifact, o.Map)
	if err != nil {
		return nil, fmt.Errorf("%s@%s: %w", ref.Name(), f.Descriptor.Digest, err)
	}
	if o.Map.ModelRoot != "" && match.Kind != MatchModelRoot {
		return nil, fmt.Errorf("%s@%s: a model root applies to an image's tar layers, and this artifact's layers are raw model layers", ref.Name(), f.Descriptor.Digest)
	}

	d := v.Document
	b := Binding{
		Artifact: BoundArtifact{
			Name: ref.Name(), Digest: f.Descriptor.Digest, MediaType: f.Descriptor.MediaType, ArtifactType: m.ArtifactType,
			ConfigMediaType: m.Config.MediaType, ConfigDigest: m.Config.Digest, Match: match.Kind,
			ModelRoot: match.ModelRoot, LayerRules: match.Rules, Layers: match.Layers,
		},
		Attestation: BoundAttestation{
			SHA256: sha256Hex(envelope), PredicateType: attest.PredicateType,
			SubjectSHA256: v.SHA256, SubjectName: d.Artifact.FileName,
			DocumentID: d.Header.DocumentID, DocumentHash: d.Verification.DocumentHash, IssuedUTC: d.Header.IssuedUTC,
			SignerKeyID: v.KeyID, Issuer: issuer, CheckSetVersion: d.Scope.CheckSetVersion,
			PromotionState: pa.State, AcceptedBy: pa.AcceptedBy, AcceptedSurfaces: pa.AcceptedSurfaces, AcceptanceExpires: pa.AcceptanceExpires,
		},
		BoundUTC:    now().UTC().Format(time.RFC3339),
		ToolVersion: o.ToolVersion,
	}
	bindingEnv, err := SignBinding(b, o.Key)
	if err != nil {
		return nil, err
	}

	var layers []registry.Descriptor
	for _, part := range []struct {
		raw  []byte
		pred string
	}{{bindingEnv, BindingPredicateType}, {envelope, attest.PredicateType}} {
		desc, err := repo.PushBlob(ctx, part.raw)
		if err != nil {
			return nil, err
		}
		desc.MediaType = EnvelopeMediaType
		desc.Annotations = map[string]string{AnnotationPredicateType: part.pred}
		layers = append(layers, desc)
	}
	if _, err := repo.PushBlob(ctx, registry.EmptyJSON); err != nil {
		return nil, err
	}
	subject := registry.Descriptor{MediaType: f.Descriptor.MediaType, Digest: f.Descriptor.Digest, Size: f.Descriptor.Size}
	referrer := registry.Manifest{
		ArtifactType: ArtifactType,
		Config:       registry.EmptyDescriptor(),
		Layers:       layers,
		Subject:      &subject,
		Annotations:  map[string]string{"org.opencontainers.image.created": b.BoundUTC},
	}
	desc, via, err := repo.PushReferrer(ctx, referrer)
	if err != nil {
		return nil, err
	}
	bundle, bundleVia, err := pushBundle(ctx, repo, bindingEnv, subject, b.BoundUTC)
	if err != nil {
		return nil, fmt.Errorf("the Socair referrer %s was pushed, but its Sigstore bundle copy was not: %w", desc.Digest, err)
	}
	return &Attached{Artifact: f.Descriptor, Ref: ref.WithDigest(f.Descriptor.Digest), Referrer: desc, Via: via,
		Bundle: bundle, BundleVia: bundleVia, Binding: b, Issuer: issuer, IssuerConfirmed: confirmed}, nil
}
