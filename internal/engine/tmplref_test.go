package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// reviewedTemplate is a template a reviewer cleared; the near-miss adds a
// content-conditional branch to it.
const (
	reviewedTemplate = "{% for m in messages %}<|im_start|>{{ m['role'] }}\n{{ m['content'] }}<|im_end|>\n{% endfor %}" +
		"{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"
	nearMissTemplate = "{% for m in messages %}<|im_start|>{{ m['role'] }}\n{{ m['content'] }}" +
		"{% if 'ZZ_TRIGGER' in m['content'] %} INJECTED_MARKER{% endif %}<|im_end|>\n{% endfor %}" +
		"{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"
)

func templateRepo(t *testing.T, tpl string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"chat_template": tpl})
	return modelRepo(t, map[string]string{"tokenizer_config.json": string(b)})
}

// TestFeedReviewedTemplateText: a feed's reviewed template, with its text,
// is rendered beside the artifact's. A template that renders like it on
// every standard probe but adds a content-conditional branch is a LEAD; one
// that renders identically says so; with no feed, the row says nothing was
// compared. Falsification: drop the feed's texts from the scan and the
// near-miss PASSes.
func TestFeedReviewedTemplateText(t *testing.T) {
	t.Setenv("SOCAIR_DENYLIST", "")
	t.Setenv("SOCAIR_TEMPLATE_REFERENCE", "")
	near := templateRepo(t, nearMissTemplate)
	same := templateRepo(t, strings.ReplaceAll(reviewedTemplate, "m['content']", "m.content"))

	t.Setenv("SOCAIR_FEED", "")
	if r := templateRow(t, near); r.Status != report.StatusPass || !strings.Contains(r.Notes, "No reviewed template text") {
		t.Fatalf("without a feed: %s (%s), want PASS saying nothing was compared", r.Status, r.Notes)
	}

	h := sha(reviewedTemplate)
	signedFeed(t, map[string]string{
		"templates.txt":             h + "  org/model@abc1234\n",
		"templates/" + h + ".jinja": reviewedTemplate,
	})
	r := templateRow(t, near)
	if r.Status != report.StatusLead || !strings.Contains(r.Notes, "INJECTED_MARKER") || !strings.Contains(r.Notes, "org/model@abc1234") {
		t.Fatalf("near-miss with the feed: %s (%s), want LEAD with the diff", r.Status, r.Notes)
	}
	if r := templateRow(t, same); r.Status != report.StatusPass || !strings.Contains(r.Notes, "Renders identically to the reviewed template org/model@abc1234") {
		t.Fatalf("render-identical: %s (%s)", r.Status, r.Notes)
	}
	d, err := Scan(same)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Scope.ReferenceData, "1 reviewed template text(s)") {
		t.Errorf("scope does not name the template texts: %q", d.Scope.ReferenceData)
	}
}

// TestLocalTemplateReference: SOCAIR_TEMPLATE_REFERENCE supplies reviewed
// template texts without a feed. They are compared but never clear a lead,
// and a reference that cannot be read stops the scan.
func TestLocalTemplateReference(t *testing.T) {
	t.Setenv("SOCAIR_DENYLIST", "")
	t.Setenv("SOCAIR_FEED", "")
	refDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(refDir, "org-model.jinja"), []byte(reviewedTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_TEMPLATE_REFERENCE", refDir)
	if r := templateRow(t, templateRepo(t, nearMissTemplate)); r.Status != report.StatusLead || !strings.Contains(r.Notes, "org-model") {
		t.Fatalf("near-miss against a local reference: %s (%s)", r.Status, r.Notes)
	}
	lead := leadTemplate
	if err := os.WriteFile(filepath.Join(refDir, "lead.jinja"), []byte(lead), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := templateRow(t, templateRepo(t, lead)); r.Status != report.StatusLead || !strings.Contains(r.Notes, "Byte-identical to the reviewed template lead") {
		t.Fatalf("a local reference must not clear a lead: %s (%s)", r.Status, r.Notes)
	}

	t.Setenv("SOCAIR_TEMPLATE_REFERENCE", filepath.Join(refDir, "missing"))
	if _, err := Scan(templateRepo(t, reviewedTemplate)); err == nil || !strings.Contains(err.Error(), "SOCAIR_TEMPLATE_REFERENCE") {
		t.Fatalf("an unreadable reference must stop the scan, got %v", err)
	}
}
