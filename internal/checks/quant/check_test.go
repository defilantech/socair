package quant

import (
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

func ptr(v uint32) *uint32 { return &v }

func TestMatchPasses(t *testing.T) {
	if got := Compare("F16", ptr(1)).Status; got != checks.Pass {
		t.Fatalf("status = %s, want PASS", got)
	}
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
	r := Compare("Q5_K_M", ptr(17)) // 17 is not in the provisional mapping
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
