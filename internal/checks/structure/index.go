package structure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/safetensors"
)

// maxIndex bounds a shard index read into memory.
const maxIndex = 64 << 20

// ValidateIndex checks a sharded safetensors set against its index
// (model.safetensors.index.json), the map a loader follows to find each
// tensor. root is the directory snapshot and indexRel the index's path in it.
//
// The index and the shards must agree exactly: every tensor the index places
// in a shard is in that shard, and every tensor in an indexed shard is
// indexed to it. A disagreement is a FAIL, because the loader then reads a
// tensor from somewhere other than the shard a reviewer would look at, or a
// shard carries tensors no loader reads. A shard the index names but the
// directory lacks is NOT_TESTED (usually an incomplete download), as is an
// index that does not parse. Safetensors files the index does not name are
// noted, not judged: they are separate weights, validated on their own.
func ValidateIndex(root, indexRel string) checks.Result {
	r := checks.Result{Name: "Format and structure", LooksFor: "Malformed container structure, unexpected tensors"}
	p := filepath.Join(root, filepath.FromSlash(indexRel))
	fi, err := os.Stat(p)
	if err != nil {
		r.Status, r.Notes = checks.NotTested, "could not read the shard index: "+err.Error()
		return r
	}
	if fi.Size() > maxIndex {
		r.Status, r.Notes = checks.NotTested, fmt.Sprintf("shard index is %d bytes, over the %d-byte limit", fi.Size(), maxIndex)
		return r
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		r.Status, r.Notes = checks.NotTested, "could not read the shard index: "+err.Error()
		return r
	}
	var idx struct {
		WeightMap map[string]string `json:"weight_map"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil || len(idx.WeightMap) == 0 {
		r.Status, r.Notes = checks.NotTested, "the shard index has no readable weight_map"
		return r
	}

	dir := path.Dir(indexRel)
	byShard := map[string]map[string]bool{}
	for tensor, shard := range idx.WeightMap {
		clean := path.Clean(shard)
		if shard == "" || path.IsAbs(shard) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(shard, "\\") {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "shard-index", Span: tensor + " -> " + shard,
				Detail: "the index points a tensor outside the model directory"})
			continue
		}
		if byShard[clean] == nil {
			byShard[clean] = map[string]bool{}
		}
		byShard[clean][tensor] = true
	}

	shards := make([]string, 0, len(byShard))
	for s := range byShard {
		shards = append(shards, s)
	}
	sort.Strings(shards)
	var missing []string
	tensors := 0
	for _, shard := range shards {
		want := byShard[shard]
		m, err := safetensors.ReadHeader(filepath.Join(root, filepath.FromSlash(path.Join(dir, shard))))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				missing = append(missing, shard)
			} else {
				missing = append(missing, shard+" (unreadable: "+err.Error()+")")
			}
			continue
		}
		have := map[string]bool{}
		for _, t := range m.Tensors {
			have[t] = true
			tensors++
			if !want[t] {
				r.Findings = append(r.Findings, checks.Finding{Pattern: "shard-index", Span: shard + ": " + t,
					Detail: "the shard holds a tensor the index does not place in it"})
			}
		}
		for t := range want {
			if !have[t] {
				r.Findings = append(r.Findings, checks.Finding{Pattern: "shard-index", Span: shard + ": " + t,
					Detail: "the index places a tensor in a shard that does not hold it"})
			}
		}
	}
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].Span < r.Findings[j].Span })

	switch {
	case len(r.Findings) > 0:
		r.Status = checks.Fail
		shown := r.Findings
		if len(shown) > 5 {
			shown = shown[:5]
		}
		var spans []string
		for _, f := range shown {
			spans = append(spans, f.Span+" ("+f.Detail+")")
		}
		r.Notes = fmt.Sprintf("the shard index and the shards disagree in %d place(s): %s", len(r.Findings), strings.Join(spans, "; "))
		if len(r.Findings) > len(shown) {
			r.Notes += fmt.Sprintf("; and %d more", len(r.Findings)-len(shown))
		}
		if len(r.Findings) > 50 {
			r.Findings = r.Findings[:50]
		}
	case len(missing) > 0:
		r.Status = checks.NotTested
		r.Notes = "the index names shard(s) the directory does not hold, so the set was not checked: " + strings.Join(missing, ", ")
	default:
		r.Status = checks.Pass
		r.Notes = fmt.Sprintf("%d tensors across %d shard(s) match the index exactly", tensors, len(shards))
	}
	return r
}
