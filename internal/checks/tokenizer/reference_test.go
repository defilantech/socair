package tokenizer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
)

// family is a reference vocabulary: ordinary tokens plus a reserved marker.
func family(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("tok%d", i)
	}
	out[n-1] = "<|reserved_special_token_0|>"
	return out
}

func clone(s []string) []string { return append([]string(nil), s...) }

func noSpecial(int) bool { return false }

func pass() checks.Result {
	return checks.Result{Name: resultName, Status: checks.Pass, Notes: "consistent."}
}

func TestReferenceExactMatchStaysPass(t *testing.T) {
	ref := Table{Name: "fam", Tokens: family(200)}
	r := ApplyReference(pass(), Compare(clone(ref.Tokens), noSpecial, []Table{ref}))
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "canonical fam") || !strings.Contains(r.Notes, "0 ordinary") {
		t.Fatalf("%s: %s", r.Status, r.Notes)
	}
}

// TestChangedOrdinaryTokenIsLead: a swapped ordinary token used to pass,
// because the tokenizer was only checked for internal consistency (#135).
// Falsification: skip the per-id comparison and this passes.
func TestChangedOrdinaryTokenIsLead(t *testing.T) {
	ref := Table{Name: "fam", Tokens: family(200)}
	got := clone(ref.Tokens)
	got[42], got[43] = got[43], got[42]
	r := ApplyReference(pass(), Compare(got, noSpecial, []Table{ref}))
	if r.Status != checks.Lead {
		t.Fatalf("status = %s, want LEAD: %s", r.Status, r.Notes)
	}
	if len(r.Findings) != 2 || r.Findings[0].Pattern != "tokenizer-token-changed" || !strings.Contains(r.Findings[0].Span, "id 42") {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

// Fine-tunes rename reserved and special tokens; that is a note, not a lead.
func TestRenamedSpecialTokenIsANote(t *testing.T) {
	ref := Table{Name: "fam", Tokens: family(200)}
	got := clone(ref.Tokens)
	got[199] = "<tool_call>"
	r := ApplyReference(pass(), Compare(got, noSpecial, []Table{ref}))
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "1 special or reserved token(s) renamed") {
		t.Fatalf("%s: %s", r.Status, r.Notes)
	}
	// A token the artifact's own tables call special is a note too.
	got = clone(ref.Tokens)
	got[5] = "think"
	r = ApplyReference(pass(), Compare(got, func(id int) bool { return id == 5 }, []Table{ref}))
	if r.Status != checks.Pass {
		t.Fatalf("a token typed special must not lead: %s", r.Notes)
	}
}

func TestAddedTokensAreANoteAndMissingOnesLead(t *testing.T) {
	ref := Table{Name: "fam", Tokens: family(200)}
	added := append(clone(ref.Tokens), "<extra_0>", "<extra_1>")
	if r := ApplyReference(pass(), Compare(added, noSpecial, []Table{ref})); r.Status != checks.Pass || !strings.Contains(r.Notes, "2 token(s) added") {
		t.Fatalf("added: %s: %s", r.Status, r.Notes)
	}
	short := clone(ref.Tokens[:150])
	if r := ApplyReference(pass(), Compare(short, noSpecial, []Table{ref})); r.Status != checks.Lead {
		t.Fatalf("a vocabulary shorter than its reference must lead, got %s", r.Status)
	}
}

// A reference from another family is not a diff: below the agreement floor
// the tokens are not compared, and the row says so.
func TestOtherFamilyIsNotCompared(t *testing.T) {
	ref := Table{Name: "other", Tokens: family(200)}
	got := make([]string, 200)
	for i := range got {
		got[i] = fmt.Sprintf("x%d", i)
	}
	r := ApplyReference(pass(), Compare(got, noSpecial, []Table{ref}))
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "No canonical reference matches") {
		t.Fatalf("%s: %s", r.Status, r.Notes)
	}
	if r := ApplyReference(pass(), Compare(got, noSpecial, nil)); !strings.Contains(r.Notes, "No canonical tokenizer reference was configured") {
		t.Fatalf("no references: %s", r.Notes)
	}
}

// The best-matching of several references is the one diffed.
func TestBestReferenceIsChosen(t *testing.T) {
	a := Table{Name: "a", Tokens: family(200)}
	b := Table{Name: "b", Tokens: clone(a.Tokens)}
	for i := 0; i < 100; i++ {
		b.Tokens[i] = "b" + b.Tokens[i]
	}
	c := Compare(clone(a.Tokens), noSpecial, []Table{b, a})
	if c.Reference != "a" || c.Match != 1 {
		t.Fatalf("reference = %q at %.2f, want a at 1.00", c.Reference, c.Match)
	}
}

// A FAIL or NOT_TESTED row already says more than a comparison could.
func TestFailAndNotTestedAreLeftAlone(t *testing.T) {
	ref := Table{Name: "fam", Tokens: family(200)}
	got := clone(ref.Tokens)
	got[1] = "zzz"
	for _, s := range []checks.Status{checks.Fail, checks.NotTested} {
		in := checks.Result{Status: s, Notes: "n"}
		if r := ApplyReference(in, Compare(got, noSpecial, []Table{ref})); r.Status != s || r.Notes != "n" {
			t.Errorf("%s row changed to %s: %s", s, r.Status, r.Notes)
		}
	}
}

func TestParseTableFormats(t *testing.T) {
	table, _ := json.Marshal(Table{Format: TableFormat, Name: "qwen", Tokens: []string{"a", "b"}})
	if got, err := ParseTable(table, "ignored"); err != nil || got.Name != "qwen" || len(got.Tokens) != 2 {
		t.Fatalf("table: %+v %v", got, err)
	}
	hf := []byte(`{"model":{"type":"BPE","vocab":{"a":0,"b":1,"c":2}},"added_tokens":[{"id":3,"content":"<|im_start|>","special":true}]}`)
	got, err := ParseTable(hf, "local")
	if err != nil || strings.Join(got.Tokens, ",") != "a,b,c,<|im_start|>" || got.Name != "local" {
		t.Fatalf("tokenizer.json: %+v %v", got, err)
	}
	for _, bad := range []string{`{}`, `{"format":"socair.tokenizer-table/v1","name":"","tokens":[]}`, `not json`} {
		if _, err := ParseTable([]byte(bad), "x"); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestLoadTablesFromDirectory(t *testing.T) {
	dir := t.TempDir()
	table, _ := json.Marshal(Table{Format: TableFormat, Name: "qwen", Tokens: []string{"a"}})
	_ = os.WriteFile(filepath.Join(dir, "qwen.json"), table, 0o600)
	sub := filepath.Join(dir, "llama")
	_ = os.Mkdir(sub, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "llama.json"), []byte(`{"model":{"vocab":{"x":0}}}`), 0o600)
	tables, err := LoadTables(dir)
	if err != nil || len(tables) != 2 || tables[0].Name != "llama" || tables[1].Name != "qwen" {
		t.Fatalf("%+v %v", tables, err)
	}
	if _, err := LoadTables(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing reference path must be an error")
	}
}

func TestGGUFSpecialUsesTokenTypes(t *testing.T) {
	tok := gguf.Tokenizer{Tokens: []string{"a", "b", "c"}, TokenTypes: []int32{gguf.TokenNormal, gguf.TokenControl, gguf.TokenUserDefined}}
	s := GGUFSpecial(tok)
	if s(0) || !s(1) || !s(2) || s(7) {
		t.Fatal("token types not read as special")
	}
}
