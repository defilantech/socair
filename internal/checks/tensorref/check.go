// Package tensorref compares a model's tensors with a reference model's,
// tensor by tensor (SOCAIR_TENSOR_REFERENCE, docs/tensors.md).
//
// The operator names the model this artifact should be, by its tensor
// manifest. PASS means every tensor is that model's, under its own name, by
// bytes or by exact values in another float dtype. LEAD means, within one file
// format, a tensor differs or is on one side only: the weights are not the
// reference's. Across formats, a converter renames, reorders, splits, and
// fuses tensors (llama.cpp reorders the Q and K rows of Llama-style models),
// so an unmatched tensor there is not evidence of a change, and the row is
// NOT_TESTED with what matched. No FAIL: different weights are not evidence of
// malice, and a match says nothing about whether the reference is safe.
package tensorref

import (
	"fmt"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/tensors"
)

// Name and LooksFor label the row.
const (
	Name     = "Tensor reference"
	LooksFor = "Weights that are not, tensor for tensor, the reference model's"
)

// maxFindings bounds the findings a row lists; the notes count the rest.
const maxFindings = 50

// Inspect compares the artifact's manifest (or the error that kept it from
// being read) with the reference, which refName names in the notes.
func Inspect(art *tensors.Manifest, artErr error, ref *tensors.Manifest, refName string) checks.Result {
	r := checks.Result{Name: Name, LooksFor: LooksFor}
	against := "against " + refName
	if ref.Artifact.Name != "" {
		against += ", which describes " + ref.Artifact.Name
	}
	if artErr != nil {
		r.Status = checks.NotTested
		r.Notes = "the artifact's tensors were not read (" + artErr.Error() + "), so nothing was compared " + against
		return r
	}
	if len(art.Tensors) == 0 && len(art.Unread) == 0 {
		r.Status = checks.NotTested
		r.Notes = "the artifact holds no GGUF or safetensors tensors, so nothing was compared " + against
		return r
	}
	c := tensors.Compare(art, ref)

	var named, renamed int
	var differs, extra, missing, notComparable []tensors.Entry
	for _, e := range c.Entries {
		switch e.Outcome {
		case tensors.Identical, tensors.SameValues:
			if e.Renamed {
				renamed++
			} else {
				named++
			}
		case tensors.Differs:
			differs = append(differs, e)
		case tensors.OnlyArtifact:
			extra = append(extra, e)
		case tensors.OnlyReference:
			missing = append(missing, e)
		case tensors.NotComparable:
			notComparable = append(notComparable, e)
		}
	}
	summary := fmt.Sprintf("Compared %s: %d of %d tensor(s) match under their own name", against, named, len(art.Tensors))
	if v := c.Counts[tensors.SameValues] - countRenamed(c, tensors.SameValues); v > 0 {
		summary += fmt.Sprintf(" (%d of them by exact values in another float dtype)", v)
	}
	if renamed > 0 {
		summary += fmt.Sprintf(", and %d more by content under another name", renamed)
	}
	notes := []string{summary}
	stopped := "It compares weights only: it says nothing about whether the reference model is safe."

	// A tensor one side could not read shows as missing on the other: that
	// is a gap, not a mismatch.
	var gapped []tensors.Entry
	if len(c.ArtifactUnread) > 0 {
		gapped, missing = append(gapped, missing...), nil
	}
	if len(c.ReferenceUnread) > 0 {
		gapped, extra = append(gapped, extra...), nil
	}

	mismatch := len(differs) + len(extra) + len(missing)
	if mismatch > 0 && !c.CrossFormat {
		r.Status = checks.Lead
		for _, e := range differs {
			r.Findings = appendFinding(r.Findings, checks.Finding{Pattern: "tensor-differs", Span: e.Artifact, Detail: e.Detail})
		}
		for _, e := range extra {
			r.Findings = appendFinding(r.Findings, checks.Finding{Pattern: "tensor-not-in-reference", Span: e.Artifact})
		}
		for _, e := range missing {
			r.Findings = appendFinding(r.Findings, checks.Finding{Pattern: "tensor-missing", Span: e.Reference})
		}
		notes = append(notes, fmt.Sprintf("%d differ, %d are not in the reference, and %d of the reference's are missing: the weights are not the reference's", len(differs), len(extra), len(missing)))
		if mismatch > len(r.Findings) {
			notes = append(notes, fmt.Sprintf("%d more are not listed", mismatch-len(r.Findings)))
		}
		r.Notes = strings.Join(append(notes, unread(c)...), "; ") + ". " + stopped
		return r
	}

	var gaps []string
	if c.CrossFormat && mismatch > 0 {
		unmatched := append(append(differs, extra...), missing...)
		quantized := quantizedCount(art, ref, unmatched)
		gap := fmt.Sprintf("across file formats, %d tensor(s) did not match and are not judged", mismatch)
		if quantized > 0 {
			gap += fmt.Sprintf(": %d of them are in a quantized type, which has no exact encoding in common with a float tensor", quantized)
		}
		gap += fmt.Sprintf("; a converter also renames, reorders, splits, and fuses tensors (llama.cpp reorders the Q and K rows of Llama-style models): %s", labels(unmatched, 12))
		gaps = append(gaps, gap)
	}
	if renamed > 0 {
		gaps = append(gaps, "a tensor matched under another name was not compared by name, so this does not show that same-shape tensors kept their places")
	}
	if len(notComparable) > 0 {
		gaps = append(gaps, fmt.Sprintf("%d tensor(s) have no exact encoding in common with the reference's, such as a quantized type against a float: %s", len(notComparable), labels(notComparable, 12)))
	}
	if len(gapped) > 0 {
		gaps = append(gaps, fmt.Sprintf("%d tensor(s) are on one side only while the other side has unread files or tensors, so they are not judged: %s", len(gapped), labels(gapped, 12)))
	}
	gaps = append(gaps, unread(c)...)
	if len(gaps) > 0 {
		r.Status = checks.NotTested
		r.Notes = strings.Join(append(notes, gaps...), "; ") + ". " + stopped
		return r
	}
	r.Status = checks.Pass
	r.Notes = strings.Join(notes, "; ") + ": the weights are the reference's weights. " + stopped
	return r
}

// quantizedCount counts the entries whose tensor, on its own side, is in a
// type with no exact float encoding (no values hash), such as Q4_K.
func quantizedCount(art, ref *tensors.Manifest, es []tensors.Entry) int {
	noValues := func(m *tensors.Manifest) map[string]bool {
		out := map[string]bool{}
		for _, t := range m.Tensors {
			if t.Values == "" {
				l := t.Name
				if t.File != "" {
					l = t.File + ":" + t.Name
				}
				out[l] = true
			}
		}
		return out
	}
	a, r := noValues(art), noValues(ref)
	n := 0
	for _, e := range es {
		if e.Artifact != "" && a[e.Artifact] || e.Artifact == "" && r[e.Reference] {
			n++
		}
	}
	return n
}

func countRenamed(c *tensors.Comparison, o tensors.Outcome) int {
	n := 0
	for _, e := range c.Entries {
		if e.Outcome == o && e.Renamed {
			n++
		}
	}
	return n
}

func appendFinding(fs []checks.Finding, f checks.Finding) []checks.Finding {
	if len(fs) >= maxFindings {
		return fs
	}
	return append(fs, f)
}

func labels(es []tensors.Entry, max int) string {
	var out []string
	for _, e := range es {
		l := e.Artifact
		if l == "" {
			l = e.Reference + " (reference)"
		}
		out = append(out, l)
		if len(out) == max {
			break
		}
	}
	if len(es) > max {
		out = append(out, fmt.Sprintf("and %d more", len(es)-max))
	}
	return strings.Join(out, ", ")
}

func unread(c *tensors.Comparison) []string {
	var out []string
	if n := len(c.ArtifactUnread); n > 0 {
		out = append(out, fmt.Sprintf("%d of the artifact's files or tensors were not read: %s", n, strings.Join(first(c.ArtifactUnread, 5), "; ")))
	}
	if n := len(c.ReferenceUnread); n > 0 {
		out = append(out, fmt.Sprintf("the reference lists %d files or tensors it did not read", n))
	}
	return out
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(append([]string(nil), s[:n]...), fmt.Sprintf("and %d more", len(s)-n))
	}
	return s
}
