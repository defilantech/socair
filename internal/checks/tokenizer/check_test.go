package tokenizer

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

// TestKnownFamilyIsLabelOnly: a recognized tokenizer.ggml.model string used
// to PASS with "no anomaly in the declared family", though no token, special
// token, merge, or BOS/EOS id was read. A label is not an inspection, so the
// row is NOT_TESTED and says what was not inspected. Falsification: return
// PASS for a known family again and this fails.
func TestKnownFamilyIsLabelOnly(t *testing.T) {
	r := Inspect("llama")
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED for a label-only result", r.Status)
	}
	for _, want := range []string{"llama", "not inspected"} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("notes must contain %q, got %q", want, r.Notes)
		}
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
