// Package quant compares the declared quantization against the observed GGML
// file type.
//
// The mapping is taken from llama.cpp include/llama.h, enum llama_ftype. Keep
// it in step with that source; do not fill it from memory. A file type outside
// the mapping is NOT_TESTED, not a guess.
package quant

import (
	"fmt"
	"regexp"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
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

const looksFor = "Declared quantization (file name) against the tensor types in the file"

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
		LooksFor: looksFor,
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
		r.Notes = "declared " + declared + " matches the metadata file type " + fmt.Sprint(*fileType) + ". Both are labels; the tensor types were not inspected"
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

// kQuant matches the k-quant family names whose base tensor type is fixed:
// Q4_K_M, Q5_K_S, Q3_K_L, Q6_K, and community variants such as Q4_K_XL.
var kQuant = regexp.MustCompile(`^Q([2-6])_K(_[A-Z]+)?$`)

// baseTypes maps a declared quantization to the ggml tensor type a file with
// that name must contain. Names whose base type is not fixed are absent, and
// are not judged: Unsloth's Q8_K_XL, for example, carries Q8_0 and F16 and no
// Q8_K at all. IQ3_M, IQ3_XS, and IQ2_M use IQ3_S and IQ2_S tensors, as real
// files show.
var baseTypes = map[string]string{
	"F32": "F32", "F16": "F16", "BF16": "BF16",
	"Q4_0": "Q4_0", "Q4_1": "Q4_1", "Q5_0": "Q5_0", "Q5_1": "Q5_1", "Q8_0": "Q8_0",
	"IQ1_S": "IQ1_S", "IQ1_M": "IQ1_M", "IQ2_XXS": "IQ2_XXS", "IQ2_XS": "IQ2_XS",
	"IQ2_S": "IQ2_S", "IQ2_M": "IQ2_S", "IQ3_XXS": "IQ3_XXS", "IQ3_XS": "IQ3_S",
	"IQ3_S": "IQ3_S", "IQ3_M": "IQ3_S", "IQ4_NL": "IQ4_NL", "IQ4_XS": "IQ4_XS",
	"TQ1_0": "TQ1_0", "TQ2_0": "TQ2_0", "MXFP4_MOE": "MXFP4", "MXFP4": "MXFP4",
}

func baseType(declared string) string {
	if m := kQuant.FindStringSubmatch(declared); m != nil {
		return "Q" + m[1] + "_K"
	}
	return baseTypes[declared]
}

// CompareObserved judges the declared quantization against the tensor types
// the file actually carries. It is positive evidence of a mislabel when a file
// named for a quantization contains no tensor of that type. Mixed layouts are
// normal (a Q4_K_M keeps some Q6_K tensors), so a present base type is a PASS
// and the full histogram is reported. With no tensor table it falls back to
// comparing the two labels.
func CompareObserved(declared string, fileType *uint32, observed []gguf.TypeShare) checks.Result {
	if len(observed) == 0 {
		return Compare(declared, fileType)
	}
	r := checks.Result{Name: "Quant match", LooksFor: looksFor}
	hist := gguf.HistogramString(observed)
	if declared == "" {
		r.Status = checks.NotTested
		r.Notes = "no declared quantization parsed from the file name; tensors carry " + hist
		return r
	}
	base := baseType(declared)
	if base == "" {
		r.Status = checks.NotTested
		r.Notes = fmt.Sprintf("declared %s has no single base tensor type to look for; tensors carry %s", declared, hist)
		return r
	}
	for _, s := range observed {
		if s.Type == base {
			r.Status = checks.Pass
			r.Notes = fmt.Sprintf("declared %s: the tensors include %s, as that quantization requires; tensors carry %s", declared, base, hist)
			return r
		}
	}
	r.Status = checks.Fail
	r.Findings = append(r.Findings, checks.Finding{Pattern: "quant-mismatch", Span: declared,
		Detail: fmt.Sprintf("the file is named %s but no tensor is %s; tensors carry %s", declared, base, hist)})
	r.Notes = fmt.Sprintf("declared %s, but no tensor is %s: the name does not describe the weights (%s)", declared, base, hist)
	return r
}
