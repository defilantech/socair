// Package provenance records where an artifact came from and whether the
// publisher's signature is present, offline.
//
// There is no network call. Provenance comes from a supplied provenance
// manifest (written by whoever ran the airlock) and from signature sidecars
// next to the artifact. With neither input the row is NOT_TESTED, never a
// silent pass: we did not verify, so we say so.
package provenance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/checks"
)

// Manifest is a supplied provenance record for one artifact.
type Manifest struct {
	Publisher     string `json:"publisher"`
	SigningStatus string `json:"signing_status"` // "signed", "unsigned", or empty
	RepoURL       string `json:"repo_url"`
	CommitOrTag   string `json:"commit_or_tag"`
	CommitSHA     string `json:"commit_sha"`
	AIBOM         string `json:"aibom"`
}

// Options configures the provenance check.
type Options struct {
	// ArtifactPath is the artifact under attestation, used to find a signature
	// sidecar next to it.
	ArtifactPath string
	// ManifestPath is a supplied provenance manifest. Empty means no manifest.
	ManifestPath string
}

// sidecarSuffixes are the signature sidecar names we recognise locally.
var sidecarSuffixes = []string{".sigstore.json", ".sigstore", ".minisig", ".sig"}

// Inspect reports the provenance result for one artifact.
func Inspect(opts Options) checks.Result {
	r := checks.Result{
		Name:     "Hash, provenance, lineage",
		LooksFor: "Traceable origin and declared quantization lineage",
	}

	var m Manifest
	haveManifest := false
	if opts.ManifestPath != "" {
		raw, err := os.ReadFile(opts.ManifestPath)
		if err != nil {
			r.Status = checks.NotTested
			r.Notes = "could not read provenance manifest: " + err.Error()
			return r
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			r.Status = checks.NotTested
			r.Notes = "provenance manifest is not valid JSON: " + err.Error()
			return r
		}
		haveManifest = true
	}

	sidecar := findSidecar(opts.ArtifactPath)

	if !haveManifest && sidecar == "" {
		r.Status = checks.NotTested
		r.Notes = "no provenance input: no supplied manifest and no signature sidecar next to the artifact"
		return r
	}

	signing := strings.ToLower(strings.TrimSpace(m.SigningStatus))
	if signing == "" && sidecar != "" {
		signing = "signed (local sidecar)"
	}
	if signing == "" {
		signing = "unknown"
	}

	parts := []string{}
	if haveManifest {
		if m.Publisher != "" {
			parts = append(parts, "publisher "+m.Publisher)
		}
		if m.CommitOrTag != "" {
			c := m.CommitOrTag
			if m.CommitSHA != "" {
				c += "@" + short(m.CommitSHA)
			}
			parts = append(parts, "commit "+c)
		}
		if m.RepoURL != "" {
			parts = append(parts, "repo "+m.RepoURL)
		}
		if m.AIBOM != "" {
			parts = append(parts, "aibom "+m.AIBOM)
		}
	}
	if sidecar != "" {
		parts = append(parts, "sidecar "+filepath.Base(sidecar))
	}
	parts = append(parts, "signing "+signing)

	r.Status = checks.Pass
	r.Notes = "provenance recorded: " + strings.Join(parts, "; ")
	if strings.HasPrefix(signing, "unsigned") || signing == "unknown" {
		r.Notes += ". The publisher signature is not established, so the origin rests on the supplied record, not on a verified signature."
	}
	return r
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

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
