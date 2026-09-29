package tokenizer

import (
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

func TestKnownFamilyPasses(t *testing.T) {
	if got := Inspect("llama").Status; got != checks.Pass {
		t.Fatalf("status = %s, want PASS", got)
	}
}

func TestUnknownFamilyNotTested(t *testing.T) {
	r := Inspect("mystery-tokenizer")
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestMissingFamilyNotTested(t *testing.T) {
	if got := Inspect("").Status; got != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", got)
	}
}
