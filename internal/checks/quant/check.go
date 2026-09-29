// Package quant compares the declared quantization against the observed GGML
// file type.
//
// The file-type mapping is deliberately small and provisional. A file type not
// in the mapping is NOT_TESTED, not a guess, until the mapping is verified
// against the current llama.cpp enum.
package quant

import (
	"fmt"

	"github.com/defilantech/socair/internal/checks"
)

// fileTypeToQuant maps a GGML file type to a quantization label. Only
// historically stable values are listed. Extend with verification, not memory.
var fileTypeToQuant = map[uint32]string{
	0: "F32",
	1: "F16",
	2: "Q4_0",
	3: "Q4_1",
}

// Compare reports whether the declared quantization matches the observed file
// type.
func Compare(declared string, fileType *uint32) checks.Result {
	r := checks.Result{
		Name:     "Quant match",
		LooksFor: "Declared quantization against observed weight layout",
	}

	if fileType == nil {
		r.Status = checks.NotTested
		r.Notes = "no general.file_type present in metadata"
		return r
	}
	if declared == "" {
		r.Status = checks.NotTested
		r.Notes = "no declared quantization parsed from the file name"
		return r
	}

	observed, ok := fileTypeToQuant[*fileType]
	if !ok {
		r.Status = checks.NotTested
		r.Notes = fmt.Sprintf("file type %d is not in our mapping; cannot compare against declared %s", *fileType, declared)
		return r
	}

	if observed == declared {
		r.Status = checks.Pass
		r.Notes = "declared " + declared + " matches observed file type"
		return r
	}

	r.Status = checks.Fail
	r.Findings = append(r.Findings, checks.Finding{
		Pattern: "quant-mismatch",
		Detail:  fmt.Sprintf("declared %s but observed file type %d (%s)", declared, *fileType, observed),
	})
	r.Notes = "declared quantization does not match the observed weight layout"
	return r
}
