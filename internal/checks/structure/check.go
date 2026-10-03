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

	if len(m.DuplicateKeys) > 0 {
		return duplicateFail(r, m.DuplicateKeys, "GGUF metadata", "llama.cpp rejects the file and other readers disagree on which value wins")
	}

	l := m.ValidateLayout()
	if len(l.Violations) > 0 {
		for _, v := range l.Violations {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "tensor-layout", Span: v,
				Detail: "the tensor table does not describe the file; llama.cpp rejects this, and unaccounted bytes can hide a payload"})
		}
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d tensor layout violation(s): %s", len(l.Violations), strings.Join(l.Violations, "; "))
		return r
	}
	if l.Truncated != "" {
		r.Status = checks.NotTested
		r.Notes = "GGUF tensor table parsed but the file is shorter than it describes (truncated?): " + l.Truncated
		return r
	}
	if len(l.Unverified) > 0 {
		r.Status = checks.NotTested
		r.Notes = "GGUF tensor table parsed but its layout could not be fully checked: " + strings.Join(l.Unverified, "; ")
		return r
	}

	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("GGUF v%d: %d tensors tile the data section exactly, each sized by its dims and type; %d metadata pairs",
		m.Version, len(m.Tensors), m.KVCount)
	if m.MultiPart() {
		r.Notes = fmt.Sprintf("part %d of %d of a split model; this artifact is one shard, not the whole model (%s)",
			m.Split.No+1, m.Split.Count, r.Notes)
	}
	return r
}

func validateSafetensors(r checks.Result, path string) checks.Result {
	// The header is all this check reads; the engine hashes the file once.
	m, err := safetensors.ReadHeader(path)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not parse safetensors header: " + err.Error()
		return r
	}
	if len(m.Duplicates) > 0 {
		return duplicateFail(r, m.Duplicates, "safetensors header", "readers that keep the first and readers that keep the last load different tensors")
	}
	if len(m.Layout) > 0 {
		for _, l := range m.Layout {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "tensor-layout", Span: l,
				Detail: "the tensor ranges do not tile the data section; the reference loader rejects this, and unaccounted bytes can hide a payload"})
		}
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d tensor layout violation(s): %s", len(m.Layout), strings.Join(m.Layout, "; "))
		return r
	}
	if len(m.Malformed) > 0 {
		r.Status = checks.NotTested
		r.Notes = "safetensors header parsed but is not sound: " +
			strings.Join(m.Malformed, "; ")
		return r
	}
	if len(m.Unverified) > 0 {
		r.Status = checks.NotTested
		r.Notes = "safetensors header parsed but its layout could not be fully checked: " + strings.Join(m.Unverified, "; ")
		return r
	}
	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("safetensors layout verified: %d tensors tile %d data bytes exactly, each sized to its shape and dtype; %d metadata keys",
		m.TensorCount, m.DataBytes, len(m.MetadataKeys))
	return r
}

// duplicateFail reports repeated keys in a container header. A repeat is a
// parser differential: which value a loader sees depends on the loader, so the
// scanned artifact and the served artifact can differ. That is positive
// evidence of a malformed container, so it is a FAIL, not a gap.
func duplicateFail(r checks.Result, keys []string, where, why string) checks.Result {
	for _, k := range keys {
		r.Findings = append(r.Findings, checks.Finding{
			Pattern: "duplicate-key",
			Span:    k,
			Detail:  "key repeated in the " + where,
		})
	}
	r.Status = checks.Fail
	r.Notes = fmt.Sprintf("%d key(s) repeated in the %s (%s): %s",
		len(keys), where, why, strings.Join(keys, ", "))
	return r
}
