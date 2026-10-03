// Package provenance records where an artifact came from and whether the
// publisher's signature is present, offline.
//
// There is no network call. Provenance comes from a provenance manifest
// (written by the airlock's pull, or supplied by whoever fetched the artifact),
// from a publisher signature checked by the engine (an OMS signature, see
// internal/oms), and from other signature sidecars next to the artifact.
//
// A publisher signature decides the row when it is from a trusted signer: a
// verified one PASSes, stated as origin and integrity and never as safety, and
// one that does not hold FAILs. A signature from an untrusted or unsupported
// signer is named, and the manifest rules below decide.
//
// A manifest counts only when it is bound to this artifact: it must name the
// artifact's sha256, so a manifest for another file, or one that names no
// file, says nothing about this one. And the row PASSes only when the origin
// is immutable: a repo and the commit the bytes came from, not a branch such
// as "main" that can move. Any other sidecar is surfaced but not verified, and a
// signing status in the manifest is reported as that manifest's claim. Short
// of all that the row is NOT_TESTED, never a silent pass.
package provenance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defilantech/socair/internal/checks"
)

// Manifest is a provenance record for one artifact.
type Manifest struct {
	// ArtifactSHA256 binds the record to one artifact. Without it, or with
	// another artifact's hash, the record does not count.
	ArtifactSHA256 string `json:"artifact_sha256"`
	Publisher      string `json:"publisher"`
	SigningStatus  string `json:"signing_status"` // "signed", "unsigned", or empty
	RepoURL        string `json:"repo_url"`
	// CommitOrTag is the revision requested, which may be a movable branch.
	CommitOrTag string `json:"commit_or_tag"`
	// CommitSHA is the immutable commit the bytes came from.
	CommitSHA string `json:"commit_sha"`
	// Source says how the artifact arrived, such as "airlock pull".
	Source string `json:"source,omitempty"`
	AIBOM  string `json:"aibom"`
}

// Options configures the provenance check.
type Options struct {
	// ArtifactPath is the artifact under attestation, used to find a signature
	// sidecar next to it.
	ArtifactPath string
	// ArtifactSHA256 is the scanned artifact's hash, which a manifest must
	// name. Empty (a header-only scan) means no manifest can bind.
	ArtifactSHA256 string
	// ManifestPath is a supplied provenance manifest. Empty means no manifest.
	ManifestPath string
	// Signature is the result of verifying a publisher signature over the
	// artifact (an OMS signature); nil when there is none.
	Signature *Signature
}

// Signature states of a publisher signature.
const (
	SignatureVerified   = "verified"
	SignatureInvalid    = "invalid"
	SignatureUnverified = "unverified"
)

// Signature is a checked publisher signature.
type Signature struct {
	State  string
	Format string // "OMS"
	Signer string
	Detail string
	// Uncovered names files the signer excluded from the signature.
	Uncovered []string
}

// NotSafety is what a verified signature does and does not say.
const NotSafety = "a valid publisher signature proves these are the bytes the key holder signed; it is a statement of origin and integrity, not of safety"

// sidecarSuffixes are the signature sidecar names we recognise locally.
var sidecarSuffixes = []string{".sigstore.json", ".sigstore", ".minisig", ".sig"}

// commitHash is a git commit id: 40 hex (SHA-1) or 64 hex (SHA-256).
var commitHash = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// Bind loads the manifest and reports whether it is bound to this artifact.
// It returns the manifest (nil when there is none) and, when it does not
// bind, why.
func Bind(opts Options) (*Manifest, string) {
	if opts.ManifestPath == "" {
		return nil, "no provenance manifest supplied"
	}
	raw, err := os.ReadFile(opts.ManifestPath)
	if err != nil {
		return nil, "could not read provenance manifest: " + err.Error()
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "provenance manifest is not valid JSON: " + err.Error()
	}
	want := strings.ToLower(strings.TrimSpace(opts.ArtifactSHA256))
	got := strings.ToLower(strings.TrimSpace(m.ArtifactSHA256))
	switch {
	case want == "":
		return &m, "the artifact was not hashed (a header-only scan), so no manifest can be bound to it"
	case got == "":
		return &m, "the provenance manifest names no artifact_sha256, so it is not bound to this artifact"
	case got != want:
		return &m, fmt.Sprintf("the provenance manifest is for artifact %s, not this one (%s)", got, want)
	}
	return &m, ""
}

// Inspect reports the provenance result for one artifact.
func Inspect(opts Options) checks.Result {
	r := checks.Result{
		Name:     "Hash, provenance, lineage",
		LooksFor: "Traceable origin: a manifest bound to this hash, from an immutable upstream commit",
	}

	// A publisher signature that claims a trusted signer and does not hold is
	// positive evidence, whatever else is known.
	if sig := opts.Signature; sig != nil && sig.State == SignatureInvalid {
		r.Status = checks.Fail
		r.Findings = []checks.Finding{{Pattern: "publisher-signature-invalid", Span: sig.Format + " signature by " + orUnknownSigner(sig.Signer),
			Detail: sig.Detail}}
		r.Notes = sig.Format + " signature by a trusted signer does not hold: " + sig.Detail
		return r
	}
	if sig := opts.Signature; sig != nil && sig.State == SignatureVerified {
		r.Status = checks.Pass
		r.Notes = "publisher signature verified (" + sig.Format + ", " + sig.Signer + "): every signed file matches; " + NotSafety
		if len(sig.Uncovered) > 0 {
			r.Notes += ". Not covered by the signature (excluded by the signer): " + strings.Join(firstN(sig.Uncovered, 8), ", ")
		}
		if m, unbound := Bind(opts); m != nil && unbound == "" {
			r.Notes += ". Also bound to " + m.RepoURL
			if m.CommitSHA != "" {
				r.Notes += " at commit " + m.CommitSHA
			}
		}
		return r
	}

	m, unbound := Bind(opts)
	if opts.ManifestPath != "" && m == nil {
		r.Status = checks.NotTested
		r.Notes = unbound
		return r
	}
	sidecar := findSidecar(opts.ArtifactPath)
	if opts.Signature != nil {
		sidecar = "" // the signature file was read as a signature, below
	}
	if m == nil && sidecar == "" && opts.Signature == nil {
		r.Status = checks.NotTested
		r.Notes = "no provenance input: no supplied manifest and no signature sidecar next to the artifact"
		return r
	}

	var parts []string
	if m != nil && unbound == "" {
		if m.Publisher != "" {
			parts = append(parts, "publisher "+m.Publisher)
		}
		if m.RepoURL != "" {
			parts = append(parts, "repo "+m.RepoURL)
		}
		if m.CommitOrTag != "" {
			parts = append(parts, "revision "+m.CommitOrTag)
		}
		if m.CommitSHA != "" {
			parts = append(parts, "commit "+m.CommitSHA)
		}
		if m.Source != "" {
			parts = append(parts, "via "+m.Source)
		}
		if m.AIBOM != "" {
			parts = append(parts, "aibom "+m.AIBOM)
		}
		parts = append(parts, signingClaim(m.SigningStatus))
	}
	// A sidecar is surfaced, never reported as a signature: nothing here
	// verifies it.
	if sidecar != "" {
		parts = append(parts, "signature sidecar "+filepath.Base(sidecar)+" present, not verified")
	}
	if sig := opts.Signature; sig != nil {
		parts = append(parts, sig.Format+" signature present, not verified: "+sig.Detail)
	}
	detail := strings.Join(parts, "; ")
	if detail != "" {
		detail = ": " + detail
	}

	switch {
	case m == nil:
		r.Status = checks.NotTested
		r.Notes = "no provenance manifest" + detail
	case unbound != "":
		r.Status = checks.NotTested
		r.Notes = unbound + detail
	case strings.TrimSpace(m.RepoURL) == "":
		r.Status = checks.NotTested
		r.Notes = "the bound manifest records no repo, so the origin is not traceable" + detail
	case !commitHash.MatchString(strings.ToLower(strings.TrimSpace(m.CommitSHA))):
		r.Status = checks.NotTested
		r.Notes = "the origin is recorded only at a movable revision, not an immutable commit" + detail
	default:
		r.Status = checks.Pass
		r.Notes = "origin bound to this artifact's hash, at an immutable commit" + detail
	}
	return r
}

func signingClaim(status string) string {
	switch s := strings.ToLower(strings.TrimSpace(status)); s {
	case "":
		return "publisher signature not established"
	case "unsigned":
		return "manifest records the upstream as unsigned; publisher signature not established"
	default:
		return "signing claimed " + s + " by the supplied manifest, not verified"
	}
}

func findSidecar(artifactPath string) string {
	if artifactPath == "" {
		return ""
	}
	for _, suffix := range sidecarSuffixes {
		p := artifactPath + suffix
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func orUnknownSigner(s string) string {
	if s == "" {
		return "an unnamed signer"
	}
	return s
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(append([]string{}, s[:n]...), fmt.Sprintf("and %d more", len(s)-n))
	}
	return s
}
