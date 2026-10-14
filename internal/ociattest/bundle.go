package ociattest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/defilantech/socair/internal/dsse"
	"github.com/defilantech/socair/internal/registry"
)

// The Sigstore bundle copy of the binding, laid out as cosign v3 writes an
// attestation (pkg/oci/remote/write.go, WriteAttestationNewBundleFormat), so
// cosign verify-attestation and Kyverno's ImageValidatingPolicy find it as
// an OCI referrer and check it with the operator's public key.
const (
	// BundleMediaType is the Sigstore bundle v0.3 media type: the referrer's
	// artifactType and its one layer's media type.
	BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	// AnnotationBundleContent and AnnotationBundlePredicateType are the
	// referrer annotations cosign writes.
	AnnotationBundleContent       = "dev.sigstore.bundle.content"
	AnnotationBundlePredicateType = "dev.sigstore.bundle.predicateType"
)

type bundleJSON struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		PublicKey struct {
			Hint string `json:"hint,omitempty"`
		} `json:"publicKey"`
	} `json:"verificationMaterial"`
	DSSEEnvelope *bundleDSSE `json:"dsseEnvelope"`
}

type bundleDSSE struct {
	Payload     string      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []bundleSig `json:"signatures"`
}

type bundleSig struct {
	Sig   string `json:"sig"`
	KeyID string `json:"keyid,omitempty"`
}

// SigstoreBundle wraps a one-signature DSSE envelope in a Sigstore bundle
// v0.3 whose verification material is a public key, with no transparency
// log entry: it verifies offline, against a key the verifier is given.
//
// The DSSE key id is dropped, and the bundle gives no key hint. The key id
// is not signed (DSSE signs the payload type and payload only), so the
// signature is unchanged. It has to go: sigstore-go, which cosign and
// Kyverno verify bundles with, skips a signature whose key id is not its own
// form of id for the key (an SSH-style SHA256 fingerprint), and Socair's id
// is the hex SHA-256 of the key's DER. The bundle specification requires a
// hint, when one is given, to equal the envelope's key id, so it gives none.
func SigstoreBundle(env []byte) ([]byte, error) {
	payload, sig, _, err := dsse.Open(env)
	if err != nil {
		return nil, err
	}
	var b bundleJSON
	b.MediaType = BundleMediaType
	b.DSSEEnvelope = &bundleDSSE{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: dsse.PayloadType,
		Signatures:  []bundleSig{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	return json.Marshal(b)
}

// bundleCarries reports whether a Sigstore bundle holds exactly the payload
// and signature of a DSSE envelope: the same signed statement, which then
// verifies with the same key.
func bundleCarries(bundle, env []byte) bool {
	payload, sig, _, err := dsse.Open(env)
	if err != nil {
		return false
	}
	var b bundleJSON
	if json.Unmarshal(bundle, &b) != nil || b.MediaType != BundleMediaType || b.DSSEEnvelope == nil ||
		b.DSSEEnvelope.PayloadType != dsse.PayloadType || len(b.DSSEEnvelope.Signatures) != 1 {
		return false
	}
	bp, err1 := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	bs, err2 := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Signatures[0].Sig)
	return err1 == nil && err2 == nil && bytes.Equal(bp, payload) && bytes.Equal(bs, sig)
}

// pushBundle pushes the binding's Sigstore bundle as a referrer of subject.
func pushBundle(ctx context.Context, repo *registry.Repo, bindingEnv []byte, subject registry.Descriptor, created string) (registry.Descriptor, string, error) {
	b, err := SigstoreBundle(bindingEnv)
	if err != nil {
		return registry.Descriptor{}, "", err
	}
	layer, err := repo.PushBlob(ctx, b)
	if err != nil {
		return registry.Descriptor{}, "", err
	}
	layer.MediaType = BundleMediaType
	if _, err := repo.PushBlob(ctx, registry.EmptyJSON); err != nil {
		return registry.Descriptor{}, "", err
	}
	return repo.PushReferrer(ctx, registry.Manifest{
		ArtifactType: BundleMediaType,
		Config:       registry.EmptyDescriptor(),
		Layers:       []registry.Descriptor{layer},
		Subject:      &subject,
		Annotations: map[string]string{
			"org.opencontainers.image.created": created,
			AnnotationBundleContent:            "dsse-envelope",
			AnnotationBundlePredicateType:      BindingPredicateType,
		},
	})
}

// findBundle looks for the Sigstore bundle referrer that carries the
// binding, returning its descriptor, or nil when there is none.
func findBundle(ctx context.Context, repo *registry.Repo, subject string, bindingEnv []byte) (*registry.Descriptor, error) {
	list, _, err := repo.Referrers(ctx, subject, BundleMediaType)
	if err != nil {
		return nil, err
	}
	for _, d := range list {
		f, err := repo.Manifest(ctx, d.Digest)
		if err != nil {
			continue
		}
		var m registry.Manifest
		if json.Unmarshal(f.Bytes, &m) != nil || m.Subject == nil || m.Subject.Digest != subject || len(m.Layers) != 1 {
			continue
		}
		raw, err := repo.Blob(ctx, m.Layers[0].Digest, registry.MaxBlob)
		if err != nil {
			continue
		}
		if bundleCarries(raw, bindingEnv) {
			return &d, nil
		}
	}
	return nil, nil
}
