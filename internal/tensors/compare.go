package tensors

import (
	"fmt"
	"sort"
	"strings"
)

// ComparisonSchema names the comparison format.
const ComparisonSchema = "socair.tensors-comparison/v1"

// Outcome is how one tensor compared.
type Outcome string

const (
	// Identical: the same dtype, shape, and bytes, under any name.
	Identical Outcome = "identical"
	// SameValues: the same shape and the same values in another float
	// dtype, as a lossless conversion (BF16 or F16 to F32) gives.
	SameValues Outcome = "same values"
	// Differs: a tensor of the same name holds other contents or another
	// shape.
	Differs Outcome = "differs"
	// NotComparable: a tensor of the same name has no encoding in common
	// with this one, such as a quantized type against a float.
	NotComparable Outcome = "not comparable"
	// OnlyArtifact and OnlyReference: no tensor on the other side matched
	// it by content or by name.
	OnlyArtifact  Outcome = "only in artifact"
	OnlyReference Outcome = "only in reference"
)

// Entry is one tensor's outcome. Artifact and Reference name the tensor on
// each side as file:name (name alone in a single file).
type Entry struct {
	Outcome   Outcome `json:"outcome"`
	Artifact  string  `json:"artifact,omitempty"`
	Reference string  `json:"reference,omitempty"`
	// Renamed marks a match by content between tensors of different names.
	// Names were not compared for it, so it cannot show that two tensors of
	// the same shape changed places.
	Renamed bool   `json:"renamed,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Comparison is a tensor-by-tensor comparison of an artifact with a
// reference.
type Comparison struct {
	Schema    string   `json:"schema"`
	Artifact  Artifact `json:"artifact"`
	Reference Artifact `json:"reference"`
	// CrossFormat is set when the two were read from different file formats
	// (GGUF against safetensors): a converter may rename, reorder, split, or
	// fuse tensors, so a tensor left unmatched is not evidence of a change.
	CrossFormat bool            `json:"cross_format"`
	Counts      map[Outcome]int `json:"counts"`
	Entries     []Entry         `json:"entries"`
	// ArtifactUnread and ReferenceUnread carry each side's unread files and
	// tensors, which no outcome covers.
	ArtifactUnread  []string `json:"artifact_unread,omitempty"`
	ReferenceUnread []string `json:"reference_unread,omitempty"`
}

// Identical reports whether every tensor on both sides matched one to one
// under its own name, by bytes or by values, and nothing on either side went
// unread.
func (c *Comparison) Identical() bool {
	if len(c.Entries) == 0 || len(c.ArtifactUnread) > 0 || len(c.ReferenceUnread) > 0 {
		return false
	}
	for _, e := range c.Entries {
		if e.Outcome != Identical && e.Outcome != SameValues || e.Renamed {
			return false
		}
	}
	return true
}

func (t Tensor) label() string {
	if t.File == "" {
		return t.Name
	}
	return t.File + ":" + t.Name
}

func shapeKey(s []int64) string { return fmt.Sprint(s) }

// formats returns the file formats a manifest's tensors came from.
func formats(m *Manifest) map[string]bool {
	out := map[string]bool{}
	if m.Artifact.Format != "model directory" {
		out[m.Artifact.Format] = true
		return out
	}
	for _, t := range m.Tensors {
		out[formatOfName(t.File)] = true
	}
	return out
}

func formatOfName(file string) string {
	if strings.HasSuffix(strings.ToLower(file), ".gguf") {
		return "GGUF"
	}
	return "safetensors"
}

// Compare matches an artifact's tensors to a reference's, one to one, each
// tensor used once: first by name, then, for names the other side lacks, by
// identical bytes or identical values in another float dtype with the same
// shape. What is left is on one side only.
func Compare(artifact, reference *Manifest) *Comparison {
	c := &Comparison{
		Schema:          ComparisonSchema,
		Artifact:        artifact.Artifact,
		Reference:       reference.Artifact,
		Counts:          map[Outcome]int{},
		ArtifactUnread:  artifact.Unread,
		ReferenceUnread: reference.Unread,
	}
	af, rf := formats(artifact), formats(reference)
	if len(artifact.Tensors) > 0 && len(reference.Tensors) > 0 {
		for f := range af {
			if !rf[f] {
				c.CrossFormat = true
			}
		}
		for f := range rf {
			if !af[f] {
				c.CrossFormat = true
			}
		}
	}

	a, r := artifact.Tensors, reference.Tensors
	usedA, usedR := make([]bool, len(a)), make([]bool, len(r))
	byBytes, byValues, byName := map[string][]int{}, map[string][]int{}, map[string][]int{}
	for j, t := range r {
		k := t.Dtype + "|" + shapeKey(t.Shape) + "|" + t.SHA256
		byBytes[k] = append(byBytes[k], j)
		if t.Values != "" {
			v := shapeKey(t.Shape) + "|" + t.Values
			byValues[v] = append(byValues[v], j)
		}
		byName[t.Name] = append(byName[t.Name], j)
	}
	add := func(i, j int, o Outcome, renamed bool, detail string) {
		e := Entry{Outcome: o, Renamed: renamed, Detail: detail}
		if i >= 0 {
			usedA[i] = true
			e.Artifact = a[i].label()
		}
		if j >= 0 {
			usedR[j] = true
			e.Reference = r[j].label()
		}
		c.Entries = append(c.Entries, e)
		c.Counts[o]++
	}

	// By name first: a tensor is compared with the reference's tensor of the
	// same name (in the same file when there is one), so two tensors that
	// exchanged places show as differing, not as matched.
	for i, t := range a {
		j := -1
		for _, k := range byName[t.Name] {
			if !usedR[k] && (j < 0 || r[k].File == t.File && r[j].File != t.File) {
				j = k
			}
		}
		if j < 0 {
			continue
		}
		rt := r[j]
		switch {
		case shapeKey(t.Shape) != shapeKey(rt.Shape):
			add(i, j, Differs, false, fmt.Sprintf("shape %v in the artifact, %v in the reference", t.Shape, rt.Shape))
		case t.Dtype == rt.Dtype && t.SHA256 == rt.SHA256:
			add(i, j, Identical, false, "")
		case t.Dtype == rt.Dtype:
			add(i, j, Differs, false, "same shape, different values")
		case t.Values != "" && t.Values == rt.Values:
			add(i, j, SameValues, false, t.Dtype+" in the artifact, "+rt.Dtype+" in the reference")
		case t.Values != "" && rt.Values != "":
			add(i, j, Differs, false, fmt.Sprintf("same shape, different values (%s in the artifact, %s in the reference; a cast that rounds also differs)", t.Dtype, rt.Dtype))
		default:
			add(i, j, NotComparable, false, fmt.Sprintf("%s in the artifact, %s in the reference: no exact encoding in common", t.Dtype, rt.Dtype))
		}
	}

	// Then by content, for tensors whose names the other side does not have:
	// a converter renames (GGUF's blk.0.attn_q.weight is a Hugging Face
	// model.layers.0.self_attn.q_proj.weight), so identical bytes, or the
	// same values in another float dtype, pair them under different names.
	first := func(cands []int) int {
		for _, j := range cands {
			if !usedR[j] {
				return j
			}
		}
		return -1
	}
	for i, t := range a {
		if usedA[i] {
			continue
		}
		if j := first(byBytes[t.Dtype+"|"+shapeKey(t.Shape)+"|"+t.SHA256]); j >= 0 {
			add(i, j, Identical, true, "")
		}
	}
	for i, t := range a {
		if usedA[i] || t.Values == "" {
			continue
		}
		if j := first(byValues[shapeKey(t.Shape)+"|"+t.Values]); j >= 0 {
			add(i, j, SameValues, true, t.Dtype+" in the artifact, "+r[j].Dtype+" in the reference")
		}
	}
	for i := range a {
		if !usedA[i] {
			add(i, -1, OnlyArtifact, false, "")
		}
	}
	for j := range r {
		if !usedR[j] {
			add(-1, j, OnlyReference, false, "")
		}
	}
	sort.SliceStable(c.Entries, func(x, y int) bool {
		ex, ey := c.Entries[x], c.Entries[y]
		kx, ky := ex.Artifact, ey.Artifact
		if kx == "" {
			kx = "\xff" + ex.Reference
		}
		if ky == "" {
			ky = "\xff" + ey.Reference
		}
		return kx < ky
	})
	return c
}
