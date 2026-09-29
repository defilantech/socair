// Package structure validates the container structure of an artifact.
//
// The check yields PASS when the header parses cleanly, and NOT_TESTED when it
// cannot be parsed or carries an internal contradiction. It never returns
// FAIL: a container we cannot read is ambiguity, not evidence of malice.
package structure

import (
	"errors"
	"fmt"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/safetensors"
)

// Validate parses the container header at path and reports a structural result.
func Validate(path string) checks.Result {
	r := checks.Result{
		Name:     "Format and structure",
		LooksFor: "Malformed container structure, unexpected tensors",
	}

	if safetensors.IsSafetensors(path) {
		return validateSafetensors(r, path)
	}

	m, err := gguf.ReadHeader(path)
	if err != nil {
		r.Status = checks.NotTested
		switch {
		case errors.Is(err, gguf.ErrNotGGUF):
			r.Notes = "not a GGUF or safetensors artifact (unrecognized container)"
		default:
			r.Notes = "could not parse structure: " + err.Error()
		}
		return r
	}

	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("GGUF v%d parsed: %d tensors, %d metadata pairs", m.Version, m.TensorCount, m.KVCount)
	if m.MultiPart() {
		r.Notes = fmt.Sprintf("part %d of %d of a split model; this artifact is one shard, not the whole model (%s)",
			m.Split.No+1, m.Split.Count, r.Notes)
	}
	return r
}

func validateSafetensors(r checks.Result, path string) checks.Result {
	m, err := safetensors.ReadArtifact(path)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not parse safetensors header: " + err.Error()
		return r
	}
	if len(m.Malformed) > 0 {
		r.Status = checks.NotTested
		r.Notes = "safetensors header parsed but is not sound: " +
			strings.Join(m.Malformed, "; ")
		return r
	}
	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("safetensors parsed: %d tensors, %d metadata keys, %d data bytes",
		m.TensorCount, len(m.MetadataKeys), m.DataBytes)
	return r
}
