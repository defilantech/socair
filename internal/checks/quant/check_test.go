package quant

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
)

func ptr(v uint32) *uint32 { return &v }

// Two labels that agree say nothing about the tensors, and the row's PASS means
// a tensor of the declared base type was seen. With no tensor table to read, a
// match is NOT_TESTED with that reason, never a PASS. Falsification: let a
// label match PASS again and this fails.
func TestLabelsAgreeIsNotTested(t *testing.T) {
	r := Compare("F16", ptr(1))
	if r.Status != checks.NotTested || len(r.Findings) != 0 {
		t.Fatalf("status = %s findings %v, want NOT_TESTED with no finding", r.Status, r.Findings)
	}
	if !strings.Contains(r.Notes, "matches") || !strings.Contains(r.Notes, "not inspected") {
		t.Fatalf("notes %q must say the labels match and the tensors were not inspected", r.Notes)
	}
}

// agree reports whether the two labels were compared and found to agree.
func agree(r checks.Result) bool {
	return r.Status == checks.NotTested && strings.Contains(r.Notes, "matches")
}

func TestMismatchFails(t *testing.T) {
	r := Compare("Q5_K_M", ptr(1)) // declared Q5_K_M but metadata says F16
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL", r.Status)
	}
	if len(r.Findings) == 0 {
		t.Error("a quant mismatch must carry a finding")
	}
}

func TestUnmappedFileTypeNotTested(t *testing.T) {
	r := Compare("Q5_K_M", ptr(9999)) // outside the llama.cpp mapping
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestMissingInputsNotTested(t *testing.T) {
	if got := Compare("F16", nil).Status; got != checks.NotTested {
		t.Fatalf("nil file type = %s, want NOT_TESTED", got)
	}
	if got := Compare("", ptr(1)).Status; got != checks.NotTested {
		t.Fatalf("empty declared = %s, want NOT_TESTED", got)
	}
}

// The mapping is from llama.cpp include/llama.h, enum llama_ftype. These
// values are the ones observed in real artifacts on disk.
func TestFullEnumMapping(t *testing.T) {
	if r := Compare("Q5_K_M", ptr(17)); !agree(r) {
		t.Errorf("Q5_K_M/17 = %s %q, want the labels to agree (gemma)", r.Status, r.Notes)
	}
	if r := Compare("IQ3_S", ptr(26)); !agree(r) {
		t.Errorf("IQ3_S/26 = %s %q, want the labels to agree (minimax)", r.Status, r.Notes)
	}
	if r := Compare("BF16", ptr(32)); !agree(r) {
		t.Errorf("BF16/32 = %s %q, want the labels to agree", r.Status, r.Notes)
	}
	if got := Compare("Q4_0", ptr(17)).Status; got != checks.Fail {
		t.Errorf("Q4_0/17 = %s, want FAIL: the mapping must tell the labels apart", got)
	}
	if got := Compare("Q5_K_M", ptr(1024)).Status; got != checks.NotTested {
		t.Errorf("guessed type = %s, want NOT_TESTED", got)
	}
	if got := Compare("Q5_K_M", ptr(9999)).Status; got != checks.NotTested {
		t.Errorf("unknown type = %s, want NOT_TESTED", got)
	}
}

// TestCommunityQuantNameIsNotTested: Unsloth's UD-Q4_K_XL and bartowski's
// Q4_K_L are community names with no llama.cpp file type of their own (the
// files report Q4_K_M), so comparing them is meaningless and FAIL was a false
// positive. Falsification: compare any declared name and these FAIL.
func TestCommunityQuantNameIsNotTested(t *testing.T) {
	for _, declared := range []string{"Q4_K_XL", "Q4_K_L", "Q8_K_XL", "IQ4_NL_XL"} {
		r := Compare(declared, ptr(15))
		if r.Status != checks.NotTested {
			t.Errorf("declared %s: status = %s, want NOT_TESTED", declared, r.Status)
		}
		if !strings.Contains(r.Notes, declared) {
			t.Errorf("declared %s: the note must name it, got %q", declared, r.Notes)
		}
	}
}

func shares(types ...string) []gguf.TypeShare {
	var out []gguf.TypeShare
	for i, ty := range types {
		out = append(out, gguf.TypeShare{Type: ty, Bytes: uint64(100 - i*10), Tensors: 1})
	}
	return out
}

// TestCompareObserved: the quant row used to compare two labels while the
// report said "observed weight layout". It now looks at the tensor types.
// Falsification: return PASS without consulting the histogram and the Q8_0
// file of Q4_K tensors passes.
func TestCompareObserved(t *testing.T) {
	cases := []struct {
		declared string
		types    []string
		want     checks.Status
	}{
		{"Q4_K_M", []string{"Q4_K", "Q6_K", "F32"}, checks.Pass},
		{"Q4_K_XL", []string{"Q4_K", "Q8_0", "F32"}, checks.Pass},     // Unsloth naming, real tensors
		{"Q6_K", []string{"Q6_K", "Q8_0", "F32"}, checks.Pass},        // Unsloth UD-Q6_K
		{"IQ3_M", []string{"IQ3_S", "Q6_K", "Q4_K"}, checks.Pass},     // bartowski IQ3_M
		{"MXFP4_MOE", []string{"MXFP4", "Q8_0", "F32"}, checks.Pass},  // gpt-oss
		{"Q8_0", []string{"Q4_K", "Q6_K", "F32"}, checks.Fail},        // named Q8_0, holds no Q8_0
		{"Q8_K_XL", []string{"F16", "Q8_0", "F32"}, checks.NotTested}, // no fixed base type
		{"", []string{"Q4_K"}, checks.NotTested},
	}
	for _, c := range cases {
		r := CompareObserved(c.declared, ptr(15), shares(c.types...))
		if r.Status != c.want {
			t.Errorf("%s over %v: status %s (%s), want %s", c.declared, c.types, r.Status, r.Notes, c.want)
		}
	}
	if r := CompareObserved("Q5_K_M", ptr(17), nil); !agree(r) {
		t.Errorf("no tensor table must fall back to the label comparison and stay a gap, got %s %q", r.Status, r.Notes)
	}
	if r := CompareObserved("Q4_0", ptr(17), nil); r.Status != checks.Fail {
		t.Errorf("no tensor table, labels that disagree: got %s, want FAIL", r.Status)
	}
}
