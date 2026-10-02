// Package quant compares the declared quantization against the observed GGML
// file type.
//
// The mapping is taken from llama.cpp include/llama.h, enum llama_ftype. Keep
// it in step with that source; do not fill it from memory. A file type outside
// the mapping is NOT_TESTED, not a guess.
package quant

import (
	"fmt"

	"github.com/defilantech/socair/internal/checks"
)

// ftypeGuessed is LLAMA_FTYPE_GUESSED: the file does not declare a type.
const ftypeGuessed = 1024

// fileTypeToQuant maps a GGML file type to a quantization label, per
// llama.cpp include/llama.h.
var fileTypeToQuant = map[uint32]string{
	0:  "F32",
	1:  "F16",
	2:  "Q4_0",
	3:  "Q4_1",
	7:  "Q8_0",
	8:  "Q5_0",
	9:  "Q5_1",
	10: "Q2_K",
	11: "Q3_K_S",
	12: "Q3_K_M",
	13: "Q3_K_L",
	14: "Q4_K_S",
	15: "Q4_K_M",
	16: "Q5_K_S",
	17: "Q5_K_M",
	18: "Q6_K",
	19: "IQ2_XXS",
	20: "IQ2_XS",
	21: "Q2_K_S",
	22: "IQ3_XS",
	23: "IQ3_XXS",
	24: "IQ1_S",
	25: "IQ4_NL",
	26: "IQ3_S",
	27: "IQ3_M",
	28: "IQ2_S",
	29: "IQ2_M",
	30: "IQ4_XS",
	31: "IQ1_M",
	32: "BF16",
	36: "TQ1_0",
	37: "TQ2_0",
	38: "MXFP4_MOE",
}

// canonical is the set of llama.cpp file type names, the only declared labels
// a file type can be compared against.
var canonical = func() map[string]bool {
	m := make(map[string]bool, len(fileTypeToQuant))
	for _, v := range fileTypeToQuant {
		m[v] = true
	}
	return m
}()

// Compare reports whether the declared quantization matches the observed file
// type.
func Compare(declared string, fileType *uint32) checks.Result {
	r := checks.Result{
		Name:     "Quant match",
		LooksFor: "Declared quantization (file name) against the file type declared in metadata",
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
	if *fileType == ftypeGuessed {
		r.Status = checks.NotTested
		r.Notes = "general.file_type is GUESSED; the file does not declare a quantization"
		return r
	}

	// A community name such as Unsloth's UD-Q4_K_XL or bartowski's Q4_K_L has
	// no llama.cpp file type of its own (those files report Q4_K_M), so there
	// is nothing to compare it against. That is a gap, not a mismatch.
	if !canonical[declared] {
		r.Status = checks.NotTested
		r.Notes = fmt.Sprintf("declared %s is not a llama.cpp file type name (community naming), so it cannot be compared with file type %d", declared, *fileType)
		return r
	}

	observed, ok := fileTypeToQuant[*fileType]
	if !ok {
		r.Status = checks.NotTested
		r.Notes = fmt.Sprintf("file type %d is not in the llama.cpp mapping; cannot compare against declared %s", *fileType, declared)
		return r
	}

	if observed == declared {
		r.Status = checks.Pass
		r.Notes = "declared " + declared + " matches observed file type " + fmt.Sprint(*fileType)
		return r
	}

	r.Status = checks.Fail
	r.Findings = append(r.Findings, checks.Finding{
		Pattern: "quant-mismatch",
		Detail:  fmt.Sprintf("declared %s but observed file type %d (%s)", declared, *fileType, observed),
	})
	r.Notes = "the file name and the metadata file type disagree. Both are labels; the tensor types were not inspected"
	return r
}
