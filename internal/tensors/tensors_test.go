package tensors

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// tensor is one fixture tensor: its data is written into the file.
type tensor struct {
	name, dtype string
	shape       []int64
	data        []byte
}

func f32s(vs ...float32) []byte {
	b := make([]byte, 4*len(vs))
	for i, v := range vs {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return b
}

// f16s writes binary16 bits directly, so a test controls them exactly.
func f16s(bits ...uint16) []byte {
	b := make([]byte, 2*len(bits))
	for i, v := range bits {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

// writeST writes a safetensors file whose tensors hold their data, laid out
// in order.
func writeST(t *testing.T, path string, ts []tensor) {
	t.Helper()
	var specs []safetensorstest.TensorSpec
	var at int64
	for _, x := range ts {
		specs = append(specs, safetensorstest.TensorSpec{Name: x.name, Dtype: x.dtype, Shape: x.shape, Start: at, End: at + int64(len(x.data))})
		at += int64(len(x.data))
	}
	out := safetensorstest.Build(nil, specs)
	start := 8 + int(binary.LittleEndian.Uint64(out[:8]))
	for i, x := range ts {
		copy(out[start+int(specs[i].Start):], x.data)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

var ggufTypes = map[string]uint32{"F32": 0, "F16": 1, "Q8_0": 8, "BF16": 30}

// writeGGUF writes a GGUF file whose tensors hold their data at 32-byte
// aligned offsets. shape is the logical shape; GGUF stores it reversed.
func writeGGUF(t *testing.T, path string, ts []tensor) {
	t.Helper()
	var specs []gguftest.Tensor
	var at uint64
	for _, x := range ts {
		dims := make([]uint64, len(x.shape))
		for i, d := range x.shape {
			dims[len(x.shape)-1-i] = uint64(d)
		}
		specs = append(specs, gguftest.Tensor{Name: x.name, Dims: dims, Type: ggufTypes[x.dtype], Offset: at})
		at += uint64(len(x.data))
		for at%32 != 0 {
			at++
		}
	}
	out := gguftest.BuildWithTensors(gguftest.Clean(), specs, int(at))
	start := len(out) - int(at)
	for i, x := range ts {
		copy(out[start+int(specs[i].Offset):], x.data)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func manifest(t *testing.T, path string) *Manifest {
	t.Helper()
	m, err := File(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Unread) > 0 {
		t.Fatalf("unread: %v", m.Unread)
	}
	return m
}

// TestF16WidensExactly checks every binary16 value: a number widens to the
// float32 of the same value, and the widening is one to one, NaN payloads
// included. Falsification: drop the subnormal or NaN case and it fails.
func TestF16WidensExactly(t *testing.T) {
	seen := map[uint32]uint16{}
	for h := 0; h < 1<<16; h++ {
		got := f16ToF32Bits(uint16(h))
		if prev, dup := seen[got]; dup {
			t.Fatalf("0x%04x and 0x%04x both widen to 0x%08x", prev, h, got)
		}
		seen[got] = uint16(h)
		sign := 1.0
		if h&0x8000 != 0 {
			sign = -1
		}
		exp, mant := (h>>10)&0x1f, h&0x3ff
		var want float64
		switch {
		case exp == 0x1f && mant != 0:
			if f := math.Float32frombits(got); !math.IsNaN(float64(f)) || (got>>13)&0x3ff != uint32(mant) {
				t.Fatalf("NaN 0x%04x widened to 0x%08x, losing its payload", h, got)
			}
			continue
		case exp == 0x1f:
			want = math.Inf(int(sign))
		case exp == 0:
			want = sign * math.Ldexp(float64(mant), -24)
		default:
			want = sign * math.Ldexp(float64(mant|0x400), int(exp)-25)
		}
		if w := math.Float32bits(float32(want)); got != w {
			t.Fatalf("0x%04x widened to 0x%08x, want 0x%08x (%v)", h, got, w, want)
		}
	}
}

func TestIdenticalFilesAreIdentical(t *testing.T) {
	dir := t.TempDir()
	ts := []tensor{
		{"a.weight", "F32", []int64{2, 2}, f32s(1, 2, 3, 4)},
		{"b.bias", "F32", []int64{2}, f32s(0, 0)},
		{"c.bias", "F32", []int64{2}, f32s(0, 0)}, // the same bytes as b.bias
	}
	writeST(t, filepath.Join(dir, "x.safetensors"), ts)
	writeST(t, filepath.Join(dir, "y.safetensors"), ts)
	c := Compare(manifest(t, filepath.Join(dir, "x.safetensors")), manifest(t, filepath.Join(dir, "y.safetensors")))
	if !c.Identical() || c.Counts[Identical] != 3 || c.CrossFormat {
		t.Fatalf("identical files compare as %+v", c)
	}
	for _, e := range c.Entries {
		if e.Renamed || e.Artifact != e.Reference {
			t.Errorf("%s paired with %s: tensors with the same name and bytes must pair by name", e.Artifact, e.Reference)
		}
	}
}

// TestSwappedTensorsDiffer: two tensors of the same shape that exchanged
// contents are the same set of tensors under the wrong names. Falsification:
// match by content first and the swap reads as identical.
func TestSwappedTensorsDiffer(t *testing.T) {
	dir := t.TempDir()
	l3, l5 := f32s(1, 2, 3, 4), f32s(5, 6, 7, 8)
	writeST(t, filepath.Join(dir, "ref.safetensors"), []tensor{
		{"layers.3.mlp.weight", "F32", []int64{2, 2}, l3},
		{"layers.5.mlp.weight", "F32", []int64{2, 2}, l5},
	})
	writeST(t, filepath.Join(dir, "art.safetensors"), []tensor{
		{"layers.3.mlp.weight", "F32", []int64{2, 2}, l5},
		{"layers.5.mlp.weight", "F32", []int64{2, 2}, l3},
	})
	c := Compare(manifest(t, filepath.Join(dir, "art.safetensors")), manifest(t, filepath.Join(dir, "ref.safetensors")))
	if c.Identical() || c.Counts[Differs] != 2 {
		t.Fatalf("swapped tensors compare as %+v", c.Counts)
	}
}

// TestOneElementDiffers: one float changed in one tensor. Falsification:
// compare by name and shape only and it passes.
func TestOneElementDiffers(t *testing.T) {
	dir := t.TempDir()
	writeST(t, filepath.Join(dir, "ref.safetensors"), []tensor{{"w", "F32", []int64{4}, f32s(1, 2, 3, 4)}, {"v", "F32", []int64{1}, f32s(9)}})
	writeST(t, filepath.Join(dir, "art.safetensors"), []tensor{{"w", "F32", []int64{4}, f32s(1, 2, 3, 4.0000005)}, {"v", "F32", []int64{1}, f32s(9)}})
	c := Compare(manifest(t, filepath.Join(dir, "art.safetensors")), manifest(t, filepath.Join(dir, "ref.safetensors")))
	if c.Identical() || c.Counts[Differs] != 1 || c.Counts[Identical] != 1 {
		t.Fatalf("one changed element compares as %+v", c.Counts)
	}
}

func TestDroppedAndAddedTensors(t *testing.T) {
	dir := t.TempDir()
	writeST(t, filepath.Join(dir, "ref.safetensors"), []tensor{{"w", "F32", []int64{1}, f32s(1)}, {"gone", "F32", []int64{1}, f32s(2)}})
	writeST(t, filepath.Join(dir, "art.safetensors"), []tensor{{"w", "F32", []int64{1}, f32s(1)}, {"new", "F32", []int64{1}, f32s(3)}})
	c := Compare(manifest(t, filepath.Join(dir, "art.safetensors")), manifest(t, filepath.Join(dir, "ref.safetensors")))
	if c.Identical() || c.Counts[OnlyArtifact] != 1 || c.Counts[OnlyReference] != 1 {
		t.Fatalf("dropped and added tensors compare as %+v", c.Counts)
	}
}

// TestF16AndF32OfTheSameValues: a lossless widening keeps the values, so the
// tensors match by value though their bytes differ. Falsification: compare
// raw bytes only and it differs.
func TestF16AndF32OfTheSameValues(t *testing.T) {
	dir := t.TempDir()
	bits := []uint16{0x3c00, 0xc100, 0x0001, 0x7bff, 0x8000, 0x7e01} // 1, -2.5, the smallest subnormal, 65504, -0, a NaN with a payload
	var vals []byte
	for _, h := range bits {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, f16ToF32Bits(h))
		vals = append(vals, b...)
	}
	writeST(t, filepath.Join(dir, "f16.safetensors"), []tensor{{"w", "F16", []int64{2, 3}, f16s(bits...)}})
	writeST(t, filepath.Join(dir, "f32.safetensors"), []tensor{{"w", "F32", []int64{2, 3}, vals}})
	c := Compare(manifest(t, filepath.Join(dir, "f16.safetensors")), manifest(t, filepath.Join(dir, "f32.safetensors")))
	if !c.Identical() || c.Counts[SameValues] != 1 {
		t.Fatalf("F16 against the same values in F32 compares as %+v", c)
	}
	// BF16 is the top half of a float32.
	writeST(t, filepath.Join(dir, "bf16.safetensors"), []tensor{{"w", "BF16", []int64{2}, f16s(0x3f80, 0xc020)}})
	writeST(t, filepath.Join(dir, "bf32.safetensors"), []tensor{{"w", "F32", []int64{2}, f32s(1, -2.5)}})
	if c := Compare(manifest(t, filepath.Join(dir, "bf16.safetensors")), manifest(t, filepath.Join(dir, "bf32.safetensors"))); !c.Identical() {
		t.Fatalf("BF16 against the same values in F32 compares as %+v", c.Counts)
	}
}

// TestGGUFAgainstSafetensors: GGUF lists dimensions innermost first, and a
// converter renames tensors, so the same bytes pair by content across
// formats, flagged as renamed and cross-format.
func TestGGUFAgainstSafetensors(t *testing.T) {
	dir := t.TempDir()
	data := f32s(1, 2, 3, 4, 5, 6, 7, 8)
	writeGGUF(t, filepath.Join(dir, "m.gguf"), []tensor{{"blk.0.ffn_down.weight", "F32", []int64{2, 4}, data}})
	writeST(t, filepath.Join(dir, "m.safetensors"), []tensor{{"model.layers.0.mlp.down_proj.weight", "F32", []int64{2, 4}, data}})
	g := manifest(t, filepath.Join(dir, "m.gguf"))
	if got := g.Tensors[0].Shape; len(got) != 2 || got[0] != 2 || got[1] != 4 {
		t.Fatalf("GGUF shape read as %v, want [2 4] (dimensions reversed)", got)
	}
	c := Compare(g, manifest(t, filepath.Join(dir, "m.safetensors")))
	if !c.CrossFormat || c.Counts[Identical] != 1 || !c.Entries[0].Renamed || c.Identical() {
		t.Fatalf("GGUF against safetensors compares as %+v", c)
	}
}

func TestQuantizedAgainstFloatIsNotComparable(t *testing.T) {
	dir := t.TempDir()
	writeGGUF(t, filepath.Join(dir, "q.gguf"), []tensor{{"blk.0.ffn_down.weight", "Q8_0", []int64{32}, make([]byte, 34)}})
	writeGGUF(t, filepath.Join(dir, "f.gguf"), []tensor{{"blk.0.ffn_down.weight", "F16", []int64{32}, make([]byte, 64)}})
	c := Compare(manifest(t, filepath.Join(dir, "q.gguf")), manifest(t, filepath.Join(dir, "f.gguf")))
	if c.Identical() || c.Counts[NotComparable] != 1 {
		t.Fatalf("Q8_0 against F16 compares as %+v", c.Counts)
	}
}

func TestDirectoryAcrossShards(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	w1, w2 := tensor{"w1", "F32", []int64{1}, f32s(1)}, tensor{"w2", "F32", []int64{1}, f32s(2)}
	writeST(t, filepath.Join(a, "model.safetensors"), []tensor{w1, w2})
	writeST(t, filepath.Join(b, "model-00001-of-00002.safetensors"), []tensor{w1})
	writeST(t, filepath.Join(b, "model-00002-of-00002.safetensors"), []tensor{w2})
	if err := os.WriteFile(filepath.Join(b, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	ma, err := Dir(a, []string{"model.safetensors"}, "")
	if err != nil {
		t.Fatal(err)
	}
	mb, err := Dir(b, []string{"config.json", "model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if c := Compare(ma, mb); !c.Identical() {
		t.Fatalf("one file against the same tensors in two shards compares as %+v", c.Counts)
	}
}

// TestManifestRoundTrips: a written manifest loads back the same, and a
// strict decode refuses what it does not know.
func TestManifestRoundTrips(t *testing.T) {
	dir := t.TempDir()
	writeST(t, filepath.Join(dir, "m.safetensors"), []tensor{{"w", "BF16", []int64{2}, f16s(1, 2)}})
	m := manifest(t, filepath.Join(dir, "m.safetensors"))
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c := Compare(m, back); !c.Identical() {
		t.Fatalf("a manifest against its own round trip compares as %+v", c.Counts)
	}
	bad := map[string]string{
		"unknown field": strings.Replace(string(raw), `"schema"`, `"extra":1,"schema"`, 1),
		"other schema":  strings.Replace(string(raw), Schema, "socair.tensors/v0", 1),
		"short hash":    strings.Replace(string(raw), m.Tensors[0].SHA256, "abc", 1),
		"values on Q8":  strings.Replace(string(raw), `"BF16"`, `"Q8_0"`, 1),
		"trailing data": string(raw) + "{}",
	}
	for name, s := range bad {
		if _, err := Load([]byte(s)); err == nil {
			t.Errorf("%s: Load accepted it", name)
		}
	}
}

// TestInvalidLayoutIsNotRead: tensors in a file whose layout overlaps are
// not fingerprinted, since loaders disagree on what such a file holds.
func TestInvalidLayoutIsNotRead(t *testing.T) {
	dir := t.TempDir()
	out := safetensorstest.Build(nil, []safetensorstest.TensorSpec{
		{Name: "a", Dtype: "F32", Shape: []int64{2}, Start: 0, End: 8},
		{Name: "b", Dtype: "F32", Shape: []int64{2}, Start: 4, End: 12},
	})
	p := filepath.Join(dir, "x.safetensors")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := File(p, ""); err == nil {
		t.Fatal("a safetensors file with overlapping tensors was fingerprinted")
	}
}
