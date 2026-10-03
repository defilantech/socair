package structure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// shard builds a valid safetensors file holding the named F32 scalars.
func shard(names ...string) []byte {
	var specs []safetensorstest.TensorSpec
	for i, n := range names {
		specs = append(specs, safetensorstest.TensorSpec{Name: n, Start: int64(4 * i), End: int64(4*i + 4), Dtype: "F32", Shape: []int64{1}})
	}
	return safetensorstest.Build(nil, specs)
}

func indexed(t *testing.T, shards map[string][]string, weightMap map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, tensors := range shards {
		if err := os.WriteFile(filepath.Join(dir, name), shard(tensors...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var entries []string
	for k, v := range weightMap {
		entries = append(entries, fmt.Sprintf("%q:%q", k, v))
	}
	idx := `{"metadata":{},"weight_map":{` + strings.Join(entries, ",") + `}}`
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors.index.json"), []byte(idx), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

var twoShards = map[string][]string{"a.safetensors": {"x", "y"}, "b.safetensors": {"z"}}

func TestIndexAgreeingWithShardsPasses(t *testing.T) {
	dir := indexed(t, twoShards, map[string]string{"x": "a.safetensors", "y": "a.safetensors", "z": "b.safetensors"})
	if r := ValidateIndex(dir, "model.safetensors.index.json"); r.Status != checks.Pass {
		t.Fatalf("status %s (%s)", r.Status, r.Notes)
	}
}

// Falsification: skip either direction of the comparison and a case passes.
func TestIndexDisagreementFails(t *testing.T) {
	cases := map[string]map[string]string{
		"tensor misplaced":         {"x": "a.safetensors", "y": "b.safetensors", "z": "b.safetensors"},
		"shard tensor not indexed": {"x": "a.safetensors", "z": "b.safetensors"},
		"index escapes directory":  {"x": "a.safetensors", "y": "a.safetensors", "z": "../b.safetensors"},
		"indexed tensor missing":   {"x": "a.safetensors", "y": "a.safetensors", "z": "b.safetensors", "w": "b.safetensors"},
	}
	for name, wm := range cases {
		r := ValidateIndex(indexed(t, twoShards, wm), "model.safetensors.index.json")
		if r.Status != checks.Fail {
			t.Errorf("%s: status %s (%s), want FAIL", name, r.Status, r.Notes)
		}
	}
}

func TestMissingShardIsNotTested(t *testing.T) {
	dir := indexed(t, map[string][]string{"a.safetensors": {"x"}}, map[string]string{"x": "a.safetensors", "z": "b.safetensors"})
	if r := ValidateIndex(dir, "model.safetensors.index.json"); r.Status != checks.NotTested || !strings.Contains(r.Notes, "b.safetensors") {
		t.Fatalf("status %s (%s), want NOT_TESTED naming the missing shard", r.Status, r.Notes)
	}
}
