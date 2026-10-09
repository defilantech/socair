package engine

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
)

func templateRow(t *testing.T, path string) report.CheckResult {
	t.Helper()
	d, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	return row(d, "Chat template (hero)")
}

// TestGGUFTemplateTokens: a GGUF's own special tokens reach the render: the
// bos token a template prints is the vocabulary's, and the control tokens it
// writes are structure, not text the template adds.
func TestGGUFTemplateTokens(t *testing.T) {
	t.Setenv("SOCAIR_FEED", "")
	t.Setenv("SOCAIR_TEMPLATE_REFERENCE", "")
	tpl := "{{ bos_token }}<|turn|>You are a helpful assistant.<|end|>{% for m in messages %}<|turn|>{{ m['content'] }}<|end|>{% endfor %}"
	kvs := append(gguftest.WithMeta("tokenizer.chat_template", gguftest.Str("tokenizer.chat_template", tpl)),
		gguftest.StrArray("tokenizer.ggml.tokens", "<BOS_X>", "<|turn|>", "<|end|>", "hello"),
		gguftest.I32Array("tokenizer.ggml.token_type", 3, 3, 3, 1),
		gguftest.U32("tokenizer.ggml.bos_token_id", 0))
	model := writeFixture(t, "tok-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))
	r := templateRow(t, model)
	if !strings.Contains(r.Notes, `This template adds to the prompt: "You are a helpful assistant."`) {
		t.Fatalf("notes: %s", r.Notes)
	}
	if strings.Contains(r.Notes, "<|turn|>You") {
		t.Errorf("a control token was counted as added text: %s", r.Notes)
	}
}
