package engine

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// TestUnsuppliedInputsAreNamedNotRun: a check whose input neither the
// operator nor the artifact supplied does not run and withholds nothing; the
// report names it, with its reason, in out_of_scope.not_run. Falsification:
// grade the Known-bad hash match row NOT_TESTED without a list again, and a
// clean model pulled with its provenance is withheld; grade the Chat
// template row for a model with no template, and the GGUF case below gains a
// row.
func TestUnsuppliedInputsAreNamedNotRun(t *testing.T) {
	t.Run("no known-bad list", func(t *testing.T) {
		supplyInputs(t, safetensorstest.Clean())
		t.Setenv("SOCAIR_DENYLIST", "")
		d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if rowOf(d, "Known-bad hash match") != nil {
			t.Error("the Known-bad hash match row ran with no list supplied")
		}
		if c := notRunEntry(d, "Known-bad hash match"); c == nil || !strings.Contains(c.Reason, "no known-bad list was supplied") {
			t.Errorf("not_run entry %+v", c)
		}
		if d.PromotionAuthorization.State != report.StateAuthorized {
			t.Errorf("state %s: a check that did not run withheld promotion", d.PromotionAuthorization.State)
		}
		if p := report.Validate(d); len(p) != 0 {
			t.Errorf("Validate: %v", p)
		}
	})
	t.Run("a known-bad list supplied", func(t *testing.T) {
		supplyInputs(t, safetensorstest.Clean())
		d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if r := rowOf(d, "Known-bad hash match"); r == nil || r.Status != report.StatusPass {
			t.Errorf("Known-bad hash match row %+v, want PASS", r)
		}
		if notRunEntry(d, "Known-bad hash match") != nil {
			t.Error("a check that ran is also named as not run")
		}
	})
	t.Run("a GGUF with no chat template", func(t *testing.T) {
		var kvs []gguftest.KV
		for _, kv := range gguftest.Clean() {
			if kv.Key() != "tokenizer.chat_template" {
				kvs = append(kvs, kv)
			}
		}
		d, err := Scan(writeFixture(t, "base.gguf", gguftest.BuildGGUF(kvs)))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if rowOf(d, "Chat template") != nil {
			t.Error("the Chat template row ran on a GGUF with no template")
		}
		if c := notRunEntry(d, "Chat template"); c == nil || !strings.Contains(c.Reason, "no tokenizer.chat_template") {
			t.Errorf("not_run entry %+v", c)
		}
	})
	t.Run("a GGUF with a chat template", func(t *testing.T) {
		d, err := Scan(writeFixture(t, "chat.gguf", gguftest.BuildGGUF(gguftest.Clean())))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if rowOf(d, "Chat template") == nil || notRunEntry(d, "Chat template") != nil {
			t.Error("a GGUF that carries a template must get the Chat template row, and only the row")
		}
	})
}

// TestValidateRefusesARowNamedAsNotRun: a check either ran or did not.
// Falsification: drop the rule from report.Validate and this passes a
// report that says both.
func TestValidateRefusesARowNamedAsNotRun(t *testing.T) {
	supplyInputs(t, safetensorstest.Clean())
	d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
	if err != nil {
		t.Fatal(err)
	}
	d.OutOfScope.NotRun = append(d.OutOfScope.NotRun, knownBadNotRun)
	problems := report.Validate(d)
	if !strings.Contains(strings.Join(problems, "\n"), `not_run names "Known-bad hash match", which is also a checks row`) {
		t.Errorf("Validate: %v", problems)
	}
}

func rowOf(d *report.Document, name string) *report.CheckResult {
	for i := range d.Checks {
		if d.Checks[i].Name == name {
			return &d.Checks[i]
		}
	}
	return nil
}

func notRunEntry(d *report.Document, name string) *report.NotRunCheck {
	for i := range d.OutOfScope.NotRun {
		if d.OutOfScope.NotRun[i].Name == name {
			return &d.OutOfScope.NotRun[i]
		}
	}
	return nil
}
