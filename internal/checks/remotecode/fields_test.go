package remotecode

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

// CVE-2026-4372: a Hub kernel named in an attention field of config.json is
// downloaded and run by a plain from_pretrained in transformers 4.56.0 to
// 5.2.x. Every shape the loader reads is a FAIL that names the field.
func TestKernelInConfigFails(t *testing.T) {
	for name, cfg := range map[string]string{
		"internal field":     `{"model_type":"llama","_attn_implementation_internal":"research-lab/optimized-attn-kernel"}`,
		"property field":     `{"model_type":"llama","_attn_implementation":"research-lab/optimized-attn-kernel"}`,
		"sub-config":         `{"model_type":"llava","text_config":{"model_type":"llama","_attn_implementation_internal":"research-lab/optimized-attn-kernel"}}`,
		"per sub-config map": `{"model_type":"llava","_attn_implementation":{"":"sdpa","text_config":"research-lab/optimized-attn-kernel"}}`,
		"paged":              `{"model_type":"llama","_attn_implementation_internal":"paged|research-lab/optimized-attn-kernel"}`,
		"revision and name":  `{"model_type":"llama","_attn_implementation_internal":"research-lab/optimized-attn-kernel@v2:attention"}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := inspect(t, map[string]string{"config.json": cfg})
			if r.Status != checks.Fail || len(r.Findings) != 1 || r.Findings[0].Pattern != "config-kernel-injection" {
				t.Fatalf("status %s, findings %+v", r.Status, r.Findings)
			}
			f := r.Findings[0]
			if !strings.Contains(f.Span, "_attn_implementation") || !strings.Contains(f.Span, "research-lab/optimized-attn-kernel") ||
				!strings.Contains(f.Detail, "CVE-2026-4372") || !strings.Contains(r.Notes, "Do not load") {
				t.Fatalf("evidence does not name the field, the kernel, or the CVE: %+v (%s)", f, r.Notes)
			}
		})
	}
}

// A component's config.json is a transformers config too (a diffusers text
// encoder), and a FAIL there outranks an auto_map LEAD beside it.
func TestKernelInComponentConfigOutranksLead(t *testing.T) {
	r := inspect(t, map[string]string{
		"config.json":              `{"model_type":"bench","auto_map":{"AutoModel":"modeling_bench.BenchModel"}}`,
		"modeling_bench.py":        "class BenchModel:\n    pass\n",
		"text_encoder/config.json": `{"model_type":"clip_text_model","_attn_implementation_internal":"attacker/kernel"}`,
	})
	pats := map[string]bool{}
	for _, f := range r.Findings {
		pats[f.Pattern] = true
	}
	if r.Status != checks.Fail || !pats["config-kernel-injection"] || !pats["auto_map"] {
		t.Fatalf("status %s, findings %+v", r.Status, r.Findings)
	}
}

// transformers 5.3.0 and later still load a kernels-community kernel from
// the field, without trust_remote_code: code a loader runs, a LEAD.
func TestCuratedKernelInConfigIsLead(t *testing.T) {
	r := inspect(t, map[string]string{"config.json": `{"model_type":"llama","_attn_implementation":"kernels-community/flash-attn2"}`})
	if r.Status != checks.Lead || len(r.Findings) != 1 || r.Findings[0].Pattern != "config-hub-kernel" {
		t.Fatalf("status %s, findings %+v", r.Status, r.Findings)
	}
}

// The library's own implementations are not code from a repository, a
// public attn_implementation at the top level is replaced by the caller's
// own (from_dict), and only config.json is a PreTrainedConfig: none of these
// is a finding. Pinned so the stated limits stay true.
func TestAttentionFieldsWithoutKernelPass(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"library implementations": {"config.json": `{"model_type":"llama","_attn_implementation":"flash_attention_2","text_config":{"_attn_implementation_internal":"sdpa"},"vision_config":{"_attn_implementation":"paged|eager"}}`},
		"public field":            {"config.json": `{"model_type":"llama","attn_implementation":"research-lab/optimized-attn-kernel"}`},
		"other config file":       {"config.json": `{"model_type":"llama"}`, "generation_config.json": `{"_attn_implementation_internal":"research-lab/optimized-attn-kernel"}`},
		"null and false":          {"config.json": `{"model_type":"lightglue","_attn_implementation_internal":null,"trust_remote_code":false}`},
	} {
		t.Run(name, func(t *testing.T) {
			if r := inspect(t, files); r.Status != checks.Pass || len(r.Findings) != 0 {
				t.Fatalf("status %s, findings %+v (%s)", r.Status, r.Findings, r.Notes)
			}
		})
	}
}

// CVE-2026-5241: a config that grants its own loader trust_remote_code is a
// LEAD that names the repository LightGlue's loader would import from.
func TestConfigGrantingTrustIsLead(t *testing.T) {
	r := inspect(t, map[string]string{"config.json": `{"model_type":"lightglue","trust_remote_code":true,"keypoint_detector_config":{"model_type":"bench_detector","_name_or_path":"attacker/detector"}}`})
	if r.Status != checks.Lead || len(r.Findings) != 1 || r.Findings[0].Pattern != "config-trust-remote-code" {
		t.Fatalf("status %s, findings %+v", r.Status, r.Findings)
	}
	if f := r.Findings[0]; !strings.Contains(f.Span, "attacker/detector") || !strings.Contains(f.Detail, "CVE-2026-5241") {
		t.Fatalf("evidence %+v", f)
	}
	nested := inspect(t, map[string]string{"config.json": `{"model_type":"bench","sub":{"trust_remote_code":1}}`})
	if nested.Status != checks.Lead {
		t.Fatalf("a truthy trust_remote_code in a sub-config: %s", nested.Status)
	}
}
