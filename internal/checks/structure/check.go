// Package structure validates the container structure of an artifact.
//
// The check yields PASS when the header parses, and NOT_TESTED when it cannot
// be parsed. It never returns FAIL: a container we cannot read is ambiguity,
// not evidence of malice.
package structure

import (
	"errors"
	"fmt"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
)

// Validate parses the GGUF header at path and reports a structural result.
func Validate(path string) checks.Result {
	r := checks.Result{
		Name:     "Format and structure",
		LooksFor: "Malformed GGUF structure, unexpected tensors",
	}

	m, err := gguf.ReadHeader(path)
	if err != nil {
		r.Status = checks.NotTested
		switch {
		case errors.Is(err, gguf.ErrNotGGUF):
			r.Notes = "not a GGUF artifact (bad magic)"
		default:
			r.Notes = "could not parse structure: " + err.Error()
		}
		return r
	}

	r.Status = checks.Pass
	r.Notes = fmt.Sprintf("GGUF v%d parsed: %d tensors, %d metadata pairs", m.Version, m.TensorCount, m.KVCount)
	return r
}
