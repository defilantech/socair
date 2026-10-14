// Package registry is a narrow OCI distribution client: what attaching an
// attestation to an OCI artifact needs, and nothing else. It resolves a tag to
// a manifest digest, fetches a manifest or a small blob and checks it against
// its digest, pushes a blob and a manifest, and lists a manifest's referrers,
// falling back to the referrers tag schema on a registry without the
// referrers API (OCI distribution spec v1.1).
//
// A raw model layer is never downloaded: it is named by its digest in the
// manifest, and that is what a binding checks. An image's tar layers are
// streamed (OpenBlob) and hashed as read, so the files inside can be mapped
// to the attested ones; they are never held in memory or written to disk.
//
// Authentication is anonymous, HTTP Basic, or the bearer-token flow a
// registry's WWW-Authenticate challenge names, with static credentials from a
// Docker config file. A credential goes only to the registry's own host and
// the token service its challenge names, over https (or to a loopback host),
// and never across a redirect to another host. SOCAIR_EGRESS=deny refuses
// every request.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Media types this client reads and writes.
const (
	MediaTypeImageManifest  = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeImageIndex     = "application/vnd.oci.image.index.v1+json"
	MediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	// MediaTypeEmpty is the OCI empty descriptor's media type, the config of
	// an artifact that has none (image-spec v1.1 manifest.md, "Guidance for
	// an Empty Descriptor").
	MediaTypeEmpty = "application/vnd.oci.empty.v1+json"
)

// EmptyJSON is the empty descriptor's content, "{}".
var EmptyJSON = []byte("{}")

// EmptyDescriptor is the OCI empty descriptor. Its content is not inlined
// (the optional data field), as cosign does not inline it either; the
// caller pushes the "{}" blob.
func EmptyDescriptor() Descriptor {
	return Descriptor{MediaType: MediaTypeEmpty, Digest: Digest(EmptyJSON), Size: int64(len(EmptyJSON))}
}

// Size limits. A manifest is small JSON; the spec asks registries and
// clients to handle at least 4 MiB. A blob this client fetches is an
// attestation envelope, never model bytes.
const (
	MaxManifest = 4 << 20
	MaxBlob     = 64 << 20
)

// Descriptor names content by digest (image-spec descriptor.md).
type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Data         []byte            `json:"data,omitempty"`
	// URLs are places a layer may be fetched from other than the registry
	// (image-spec descriptor.md); they are read so a layer that names them
	// can be refused.
	URLs []string `json:"urls,omitempty"`
}

// Manifest is an OCI image manifest (or a Docker schema 2 manifest, which
// has the same fields this client reads).
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Subject       *Descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Index is an OCI image index: what the referrers API and the referrers tag
// schema return.
type Index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Manifests     []Descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Digest is the "sha256:<hex>" digest of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ValidDigest checks a digest this client can verify: sha256 only, as
// Socair attests SHA-256.
func ValidDigest(d string) error {
	if !sha256Digest.MatchString(d) {
		return fmt.Errorf("digest %q is not sha256:<64 lowercase hex>", d)
	}
	return nil
}

// Hex is the hex part of a sha256 digest.
func Hex(d string) string { return strings.TrimPrefix(d, "sha256:") }

// ReferrersTag is the referrers tag schema's tag for a subject digest:
// <alg>-<ref>, the ref cut to 64 characters (distribution-spec v1.1,
// "Referrers Tag Schema").
func ReferrersTag(subject string) string {
	alg, ref, _ := strings.Cut(subject, ":")
	if len(ref) > 64 {
		ref = ref[:64]
	}
	return alg + "-" + ref
}
