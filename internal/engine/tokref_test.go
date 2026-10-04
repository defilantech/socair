package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
)

// TestTokenizerReferenceEndToEnd: with SOCAIR_TOKENIZER_REFERENCE set, a GGUF
// whose vocabulary differs from the canonical table in an ordinary token is a
// LEAD, which withholds it and which no acceptance clears (#135). The same
// GGUF against an exact table stays PASS and says what it was compared with.
func TestTokenizerReferenceEndToEnd(t *testing.T) {
	tokens := make([]string, 300)
	types := make([]int32, 300)
	for i := range tokens {
		tokens[i], types[i] = fmt.Sprintf("tok%d", i), 1
	}
	kvs := append(gguftest.Clean(),
		gguftest.StrArray("tokenizer.ggml.tokens", tokens...),
		gguftest.I32Array("tokenizer.ggml.token_type", types...))
	model := writeFixture(t, "ref-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	write := func(toks []string) string {
		p := filepath.Join(t.TempDir(), "canon.json")
		b, _ := json.Marshal(tokenizer.Table{Format: tokenizer.TableFormat, Name: "canon", Tokens: toks})
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Setenv("SOCAIR_TOKENIZER_REFERENCE", write(tokens))
	d, err := Scan(model)
	if err != nil {
		t.Fatal(err)
	}
	row := tokRow(t, d)
	if row.Status != report.StatusPass || !strings.Contains(row.Notes, "canonical canon") {
		t.Fatalf("exact reference: %s: %s", row.Status, row.Notes)
	}
	if !strings.Contains(d.Scope.ReferenceData, "local tokenizer reference") {
		t.Errorf("scope does not name the reference: %q", d.Scope.ReferenceData)
	}

	swapped := append([]string(nil), tokens...)
	swapped[7] = "evil"
	t.Setenv("SOCAIR_TOKENIZER_REFERENCE", write(swapped))
	d, err = Scan(model)
	if err != nil {
		t.Fatal(err)
	}
	if row := tokRow(t, d); row.Status != report.StatusLead || !strings.Contains(row.Evidence, "id 7") {
		t.Fatalf("changed token: %s: %s / %s", row.Status, row.Evidence, row.Notes)
	}

	t.Setenv("SOCAIR_TOKENIZER_REFERENCE", filepath.Join(t.TempDir(), "absent.json"))
	if _, err := Scan(model); err == nil {
		t.Fatal("an unreadable reference must stop the scan, not drop the comparison")
	}
}

func tokRow(t *testing.T, d *report.Document) report.CheckResult {
	t.Helper()
	for _, c := range d.Checks {
		if c.Name == "Tokenizer config" {
			return c
		}
	}
	t.Fatal("no tokenizer row")
	return report.CheckResult{}
}
