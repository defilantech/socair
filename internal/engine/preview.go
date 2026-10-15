package engine

import (
	"time"

	"github.com/defilantech/socair/internal/report"
)

// PreviewDir reads a model directory the way a scan does, in place and as
// far as each check reads, and never hashes a file: each file's SHA-256 is
// the one stated gives for its path, as its source (a hub's API) states it,
// and every file needs one. Nothing it reads is copied, so a reader that
// fetches byte ranges on demand (socair.ai's browser preview) fetches only
// what the checks read: headers, configs, templates, tokenizers.
//
// It is a preview, never an attestation: the subject is the manifest digest
// of hashes the scan did not compute, and the caller must say so. Tier 2
// does not run.
func PreviewDir(dir string, stated map[string]string) (*report.Document, error) {
	start := time.Now().UTC()
	refs, err := loadReferences(start)
	if err != nil {
		return nil, err
	}
	if stated == nil {
		stated = map[string]string{}
	}
	return scanDir(dir, start, refs, Inputs{}, nil, stated)
}
