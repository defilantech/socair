package tensorref

import (
	"errors"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tensors"
)

func hash(c byte) string { return strings.Repeat(string(c), 64) }

func t32(file, name string, h byte) tensors.Tensor {
	return tensors.Tensor{File: file, Name: name, Dtype: "F32", Shape: []int64{4}, Bytes: 16, SHA256: hash(h), Values: hash(h)}
}

func man(format string, ts ...tensors.Tensor) *tensors.Manifest {
	return &tensors.Manifest{Schema: tensors.Schema, ValueEncoding: tensors.ValueEncoding,
		Artifact: tensors.Artifact{Name: "m", Format: format}, Tensors: ts}
}

func patterns(r checks.Result) string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Pattern+" "+f.Span)
	}
	return strings.Join(out, "; ")
}

func TestRowNameIsTheReportsName(t *testing.T) {
	if Name != report.TensorReferenceCheck {
		t.Fatalf("row %q, report constant %q", Name, report.TensorReferenceCheck)
	}
	if report.PassMeaning(Name) == "" || report.MapsTo(Name) == nil {
		t.Fatal("the row has no PASS statement or framework mapping")
	}
}

func TestSameWeightsPass(t *testing.T) {
	ref := man("safetensors", t32("", "a", 'a'), t32("", "b", 'b'))
	art := man("safetensors", t32("", "a", 'a'), t32("", "b", 'b'))
	if r := Inspect(art, nil, ref, "ref.json"); r.Status != checks.Pass {
		t.Fatalf("the same weights: %s %s", r.Status, r.Notes)
	}
}

// TestChangedWeightsAreALead: within a format, a tensor that differs, one the
// reference lacks, or one missing is a LEAD naming it. Falsification: grade
// by tensor count, or by names alone, and these pass.
func TestChangedWeightsAreALead(t *testing.T) {
	ref := man("safetensors", t32("", "a", 'a'), t32("", "b", 'b'), t32("", "c", 'c'))
	art := man("safetensors", t32("", "a", 'a'), t32("", "b", 'f'), t32("", "d", 'd'))
	r := Inspect(art, nil, ref, "ref.json")
	if r.Status != checks.Lead {
		t.Fatalf("changed weights: %s %s", r.Status, r.Notes)
	}
	want := "tensor-differs b; tensor-not-in-reference d; tensor-missing c"
	if got := patterns(r); got != want {
		t.Fatalf("findings %q, want %q", got, want)
	}
}

// TestSwapIsALead: two same-shape tensors that exchanged places hold the
// reference's bytes under the wrong names.
func TestSwapIsALead(t *testing.T) {
	ref := man("safetensors", t32("", "layers.3.w", 'a'), t32("", "layers.5.w", 'b'))
	art := man("safetensors", t32("", "layers.3.w", 'b'), t32("", "layers.5.w", 'a'))
	if r := Inspect(art, nil, ref, "ref.json"); r.Status != checks.Lead {
		t.Fatalf("swapped tensors: %s %s", r.Status, r.Notes)
	}
}

// TestRenamedIsNotAPass: tensors matched only by content under other names
// could have exchanged places, so they do not PASS.
func TestRenamedIsNotAPass(t *testing.T) {
	ref := man("safetensors", t32("", "model.a", 'a'), t32("", "model.b", 'b'))
	art := man("safetensors", t32("", "a", 'a'), t32("", "b", 'b'))
	if r := Inspect(art, nil, ref, "ref.json"); r.Status != checks.NotTested || !strings.Contains(r.Notes, "under another name") {
		t.Fatalf("renamed tensors: %s %s", r.Status, r.Notes)
	}
}

// TestCrossFormatIsNotJudged: a GGUF against a safetensors reference leaves
// what did not match unjudged, since converters reorder and quantize.
func TestCrossFormatIsNotJudged(t *testing.T) {
	ref := man("safetensors", t32("", "model.layers.0.self_attn.q_proj.weight", 'a'), t32("", "model.norm.weight", 'n'))
	q := tensors.Tensor{Name: "blk.0.attn_q.weight", Dtype: "Q4_K", Shape: []int64{256}, Bytes: 144, SHA256: hash('q')}
	art := man("GGUF", q, t32("", "output_norm.weight", 'n'))
	r := Inspect(art, nil, ref, "ref.json")
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "quantized type") {
		t.Fatalf("cross format: %s %s", r.Status, r.Notes)
	}
}

func TestNotComparableIsNotTested(t *testing.T) {
	ref := man("GGUF", t32("", "w", 'a'))
	art := man("GGUF", tensors.Tensor{Name: "w", Dtype: "Q8_0", Shape: []int64{4}, Bytes: 34, SHA256: hash('q')})
	if r := Inspect(art, nil, ref, "ref.json"); r.Status != checks.NotTested {
		t.Fatalf("Q8_0 against F32: %s %s", r.Status, r.Notes)
	}
}

// TestUnreadIsAGapNotAMismatch: a tensor the scan could not read shows as
// missing from the artifact; that is a gap, not evidence of a change.
func TestUnreadIsAGapNotAMismatch(t *testing.T) {
	ref := man("GGUF", t32("", "a", 'a'), t32("", "b", 'b'))
	art := man("GGUF", t32("", "a", 'a'))
	art.Unread = []string{`m.gguf: tensor "b" has type type 99, whose size is not known`}
	if r := Inspect(art, nil, ref, "ref.json"); r.Status != checks.NotTested {
		t.Fatalf("an unread tensor: %s %s", r.Status, r.Notes)
	}
	// A real difference beside a gap is still a LEAD.
	art.Tensors[0] = t32("", "a", 'z')
	if r := Inspect(art, nil, ref, "ref.json"); r.Status != checks.Lead {
		t.Fatalf("a difference beside an unread tensor: %s %s", r.Status, r.Notes)
	}
}

func TestUnreadArtifactIsNotTested(t *testing.T) {
	ref := man("safetensors", t32("", "a", 'a'))
	if r := Inspect(nil, errors.New("not a GGUF or safetensors file"), ref, "ref.json"); r.Status != checks.NotTested {
		t.Fatalf("an unread artifact: %s", r.Status)
	}
	if r := Inspect(man("model directory"), nil, ref, "ref.json"); r.Status != checks.NotTested {
		t.Fatalf("no tensors: %s", r.Status)
	}
}

func TestFindingsAreBounded(t *testing.T) {
	var a, b []tensors.Tensor
	for i := 0; i < 80; i++ {
		n := strings.Repeat("x", i+1)
		a = append(a, t32("", n, 'a'))
		b = append(b, t32("", n, 'b'))
	}
	r := Inspect(man("safetensors", a...), nil, man("safetensors", b...), "ref.json")
	if r.Status != checks.Lead || len(r.Findings) != maxFindings || !strings.Contains(r.Notes, "30 more are not listed") {
		t.Fatalf("80 differing tensors: %s, %d findings, %s", r.Status, len(r.Findings), r.Notes)
	}
}
