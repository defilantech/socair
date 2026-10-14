package convert

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/pickle/pickletest"
	"github.com/defilantech/socair/internal/checks/structure"
)

func writeFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// stFile is a safetensors file as this test reads it, with its own decoder:
// the header's entries and each tensor's bytes, by name.
type stFile struct {
	headerLen int
	order     []string // tensor names in data order
	meta      map[string]string
	dtype     map[string]string
	shape     map[string][]int64
	data      map[string][]byte
}

func readST(t *testing.T, path string) stFile {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := int(binary.LittleEndian.Uint64(b[:8]))
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(b[8:8+n], &entries); err != nil {
		t.Fatal(err)
	}
	f := stFile{headerLen: n, meta: map[string]string{}, dtype: map[string]string{}, shape: map[string][]int64{}, data: map[string][]byte{}}
	if err := json.Unmarshal(entries["__metadata__"], &f.meta); err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Dtype       string   `json:"dtype"`
		Shape       []int64  `json:"shape"`
		DataOffsets [2]int64 `json:"data_offsets"`
	}
	begins := map[int64][]string{}
	for name, raw := range entries {
		if name == "__metadata__" {
			continue
		}
		var e entry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		f.dtype[name], f.shape[name] = e.Dtype, e.Shape
		f.data[name] = b[8+n+int(e.DataOffsets[0]) : 8+n+int(e.DataOffsets[1])]
		begins[e.DataOffsets[0]] = append(begins[e.DataOffsets[0]], name)
	}
	// The header's own order, read from the raw bytes.
	dec := json.NewDecoder(bytes.NewReader(b[8 : 8+n]))
	_, _ = dec.Token()
	for dec.More() {
		k, _ := dec.Token()
		var skip json.RawMessage
		_ = dec.Decode(&skip)
		if k != "__metadata__" {
			f.order = append(f.order, k.(string))
		}
	}
	return f
}

// convertCheckpoint converts c and returns the output path and what Write
// reported.
func convertCheckpoint(t *testing.T, c pickletest.Checkpoint) (string, *Output, error) {
	t.Helper()
	in := writeFile(t, "pytorch_model.bin", c.Zip())
	p, err := PlanFile(in)
	if err != nil {
		return "", nil, err
	}
	dst := filepath.Join(t.TempDir(), "model.safetensors")
	out, err := p.Write(dst)
	return dst, out, err
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// mixed is a checkpoint with every supported dtype, a scalar, an empty
// tensor, a Parameter, an OrderedDict root, disjoint views of one storage
// (a fused buffer), and an exact alias (tied weights).
func mixed() pickletest.Checkpoint {
	s := func(dtype string, n int, seed byte) pickletest.Storage {
		return pickletest.Storage{Dtype: dtype, Data: pickletest.Seq(n*pickletest.Itemsize[dtype], seed)}
	}
	return pickletest.Checkpoint{
		Ordered: true,
		Storages: []pickletest.Storage{
			s("float32", 6, 1), s("float16", 1, 2), s("bfloat16", 8, 3), s("float32", 12, 4),
			s("int64", 4, 5), s("bool", 2, 6), s("uint8", 5, 7), s("int8", 3, 8), s("int16", 3, 9),
			s("int32", 3, 10), s("float64", 2, 11), s("uint16", 3, 12), s("uint32", 3, 13), s("uint64", 3, 14),
			s("float8_e4m3fn", 4, 15), s("float8_e5m2", 4, 16), s("float32", 0, 17), s("float32", 4, 18),
		},
		Tensors: []pickletest.Tensor{
			{Name: "layer.weight", Storage: 0, Shape: []int{2, 3}, Param: true},
			{Name: "scale", Storage: 1, Shape: []int{}},
			{Name: "attn.q", Storage: 2, Shape: []int{4}},
			{Name: "attn.k", Storage: 2, Shape: []int{2, 2}, Offset: 4},
			{Name: "embed.weight", Storage: 3, Shape: []int{3, 4}},
			{Name: "lm_head.weight", Storage: 3, Shape: []int{3, 4}},
			{Name: "ids", Storage: 4, Shape: []int{3}},
			{Name: "mask", Storage: 5, Shape: []int{2}},
			{Name: "u8", Storage: 6, Shape: []int{5}},
			{Name: "i8", Storage: 7, Shape: []int{3}},
			{Name: "i16", Storage: 8, Shape: []int{3}},
			{Name: "i32", Storage: 9, Shape: []int{3}},
			{Name: "f64", Storage: 10, Shape: []int{2}},
			{Name: "u16", Storage: 11, Shape: []int{3}},
			{Name: "u32", Storage: 12, Shape: []int{3}},
			{Name: "u64", Storage: 13, Shape: []int{3}},
			{Name: "fp8.e4m3", Storage: 14, Shape: []int{2, 2}},
			{Name: "fp8.e5m2", Storage: 15, Shape: []int{4}},
			{Name: "empty", Storage: 16, Shape: []int{0, 4}},
			// A dimension of size 1 may have any stride and stay contiguous.
			{Name: "row", Storage: 17, Shape: []int{1, 4}, Stride: []int{99, 1}},
		},
	}
}

var wantDtype = map[string]string{
	"layer.weight": "F32", "scale": "F16", "attn.q": "BF16", "attn.k": "BF16", "embed.weight": "F32",
	"ids": "I64", "mask": "BOOL", "u8": "U8", "i8": "I8", "i16": "I16", "i32": "I32", "f64": "F64",
	"u16": "U16", "u32": "U32", "u64": "U64", "fp8.e4m3": "F8_E4M3", "fp8.e5m2": "F8_E5M2", "empty": "F32", "row": "F32",
}

// TestConvertsEveryTensor: every tensor of the input is in the output, byte
// for byte, under its name, with its dtype and shape, read back by this
// test's own decoder; the exact alias is written once and named in
// __metadata__. Falsification: TestOneByteFailsTheComparison shows this
// comparison fails on a one-byte difference.
func TestConvertsEveryTensor(t *testing.T) {
	c := mixed()
	dst, out, err := convertCheckpoint(t, c)
	if err != nil {
		t.Fatal(err)
	}
	f := readST(t, dst)
	for _, p := range problems(c, f) {
		t.Error(p)
	}
	if f.headerLen%8 != 0 {
		t.Errorf("header of %d bytes is not padded to a multiple of 8", f.headerLen)
	}
	if !reflect.DeepEqual(f.meta, map[string]string{"format": "pt", "lm_head.weight": "embed.weight"}) {
		t.Errorf("__metadata__ %v", f.meta)
	}
	if _, ok := f.data["lm_head.weight"]; ok {
		t.Error("the alias is written twice")
	}
	// The serializer's order: dtype alignment, largest first, then name.
	want := []string{"u64", "ids", "f64", "embed.weight", "empty", "layer.weight", "row", "u32", "i32",
		"attn.k", "attn.q", "scale", "u16", "i16", "fp8.e4m3", "fp8.e5m2", "i8", "u8", "mask"}
	if !reflect.DeepEqual(f.order, want) {
		t.Errorf("order\n %v\nwant\n %v", f.order, want)
	}
	b, _ := os.ReadFile(dst)
	if out.SHA256 != sum(b) || out.Size != int64(len(b)) {
		t.Errorf("output hash %s size %d, file %s %d", out.SHA256, out.Size, sum(b), len(b))
	}
	if len(out.Tensors) != len(c.Tensors) {
		t.Fatalf("%d tensors reported, want %d", len(out.Tensors), len(c.Tensors))
	}
	for _, rt := range out.Tensors {
		for _, ct := range c.Tensors {
			if ct.Name == rt.Name && rt.SHA256 != sum(c.Bytes(ct)) {
				t.Errorf("%s: reported hash %s, its bytes hash to %s", rt.Name, rt.SHA256, sum(c.Bytes(ct)))
			}
		}
	}
	if r := structure.Validate(dst); r.Status != checks.Pass {
		t.Errorf("the output's structure row is %s: %s", r.Status, r.Notes)
	}
}

// problems holds an output to its checkpoint: each tensor, or the tensor it
// is an alias of, holds exactly the bytes the checkpoint's view holds, with
// its shape and dtype.
func problems(c pickletest.Checkpoint, f stFile) []string {
	var out []string
	for _, ct := range c.Tensors {
		name := ct.Name
		if kept, ok := f.meta[name]; ok {
			name = kept
		}
		got, ok := f.data[name]
		if !ok {
			out = append(out, ct.Name+": not in the output")
			continue
		}
		if !bytes.Equal(got, c.Bytes(ct)) {
			out = append(out, ct.Name+": the output's bytes differ from the checkpoint's")
		}
		shape := make([]int64, len(ct.Shape))
		for i, d := range ct.Shape {
			shape[i] = int64(d)
		}
		if !reflect.DeepEqual(f.shape[name], shape) {
			out = append(out, fmt.Sprintf("%s: shape %v, want %v", ct.Name, f.shape[name], shape))
		}
		if d, ok := wantDtype[name]; ok && f.dtype[name] != d {
			out = append(out, fmt.Sprintf("%s: dtype %s, want %s", ct.Name, f.dtype[name], d))
		}
	}
	return out
}

// TestOneByteFailsTheComparison is the falsification of the test above: an
// output with one byte of one tensor changed fails the comparison, for each
// tensor tried.
func TestOneByteFailsTheComparison(t *testing.T) {
	c := mixed()
	dst, _, err := convertCheckpoint(t, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"attn.k", "embed.weight", "scale", "mask", "u64"} {
		f := readST(t, dst)
		f.data[name][len(f.data[name])-1] ^= 0x01
		if len(problems(c, f)) == 0 {
			t.Errorf("a one-byte difference in %s passed the comparison", name)
		}
	}
}

func TestConversionIsByteStable(t *testing.T) {
	a, _, err := convertCheckpoint(t, mixed())
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := convertCheckpoint(t, mixed())
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if !bytes.Equal(ab, bb) {
		t.Fatal("two conversions of one checkpoint differ")
	}
}

// TestWriteComparesEveryTensor: a byte changed on its way into the output,
// in any tensor, is caught by the read-back comparison, and no output is
// left. Falsification: skip the comparison in readBack and the conversion
// succeeds.
func TestWriteComparesEveryTensor(t *testing.T) {
	t.Cleanup(func() { writeHook = nil })
	c := mixed()
	in := writeFile(t, "pytorch_model.bin", c.Zip())
	for _, victim := range []string{"layer.weight", "attn.k", "embed.weight", "mask", "fp8.e5m2"} {
		writeHook = func(name string, w io.Writer) io.Writer {
			if name != victim {
				return w
			}
			return &flipFirst{w: w}
		}
		p, err := PlanFile(in)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(t.TempDir(), "model.safetensors")
		_, err = p.Write(dst)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("tensor %q", victim)) {
			t.Errorf("%s corrupted on the way out: %v, want the comparison to name it", victim, err)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Errorf("%s: an unverified output was left at %s", victim, dst)
		}
	}
}

type flipFirst struct {
	w    io.Writer
	done bool
}

func (f *flipFirst) Write(b []byte) (int, error) {
	if !f.done && len(b) > 0 {
		c := append([]byte(nil), b...)
		c[0] ^= 0x01
		f.done = true
		return f.w.Write(c)
	}
	return f.w.Write(b)
}

// TestRefusals: each input the converter does not handle is refused with
// the reason, and nothing is written. Falsification: drop any one rule in
// PlanFile or Write and its case converts.
func TestRefusals(t *testing.T) {
	f32 := func(n int) pickletest.Storage {
		return pickletest.Storage{Dtype: "float32", Data: pickletest.Seq(4*n, 1)}
	}
	one := func(tensors ...pickletest.Tensor) pickletest.Checkpoint {
		return pickletest.Checkpoint{Storages: []pickletest.Storage{f32(8)}, Tensors: tensors}
	}
	w := pickletest.Tensor{Name: "w", Shape: []int{8}}
	crc := one(w).Zip()
	// One storage byte changed after the zip was written: its CRC-32 no
	// longer holds.
	at := bytes.Index(crc, pickletest.Seq(32, 1))
	crc[at+31] ^= 0x01
	cases := map[string]struct {
		file []byte
		want string
	}{
		"a non-contiguous view": {one(pickletest.Tensor{Name: "t", Shape: []int{2, 4}, Stride: []int{1, 2}}).Zip(), "not contiguous"},
		"overlapping views": {one(pickletest.Tensor{Name: "a", Shape: []int{4}},
			pickletest.Tensor{Name: "b", Shape: []int{4}, Offset: 2}).Zip(), "overlapping bytes"},
		"one range, two shapes": {one(pickletest.Tensor{Name: "a", Shape: []int{4}},
			pickletest.Tensor{Name: "b", Shape: []int{2, 2}}).Zip(), "only exact aliases"},
		"big-endian storages":         {pickletest.Checkpoint{Storages: []pickletest.Storage{f32(8)}, Tensors: []pickletest.Tensor{w}, ByteOrder: "big"}.Zip(), "big-endian"},
		"an unknown byte order":       {pickletest.Checkpoint{Storages: []pickletest.Storage{f32(8)}, Tensors: []pickletest.Tensor{w}, ByteOrder: "middle"}.Zip(), "torch.load rejects"},
		"compressed records":          {pickletest.Checkpoint{Storages: []pickletest.Storage{f32(8)}, Tensors: []pickletest.Tensor{w}, Deflate: true}.Zip(), "compressed"},
		"a CRC-32 that does not hold": {crc, "CRC-32"},
		"complex64": {pickletest.Checkpoint{Storages: []pickletest.Storage{{Dtype: "complex64", Data: make([]byte, 16)}},
			Tensors: []pickletest.Tensor{{Name: "c", Shape: []int{2}}}}.Zip(), "complex64, which this converter does not map"},
		"a quantized storage": {pickletest.Checkpoint{Storages: []pickletest.Storage{{Dtype: "qint8", Data: make([]byte, 4)}},
			Tensors: []pickletest.Tensor{{Name: "q", Shape: []int{4}}}}.Zip(), "qint8"},
		"the neg bit": {one(pickletest.Tensor{Name: "n", Shape: []int{8}, Metadata: []string{"neg"}}).Zip(), "conj or neg bit"},
		"an alias named format": {one(pickletest.Tensor{Name: "a", Shape: []int{8}},
			pickletest.Tensor{Name: "format", Shape: []int{8}}).Zip(), "format entry"},
		"a tensor named __metadata__": {one(pickletest.Tensor{Name: "__metadata__", Shape: []int{8}}).Zip(), "__metadata__"},
		"a name that is not UTF-8":    {one(pickletest.Tensor{Name: "w\xed\xa0\x80", Shape: []int{8}}).Zip(), "not valid UTF-8"},
		"no tensors":                  {pickletest.Checkpoint{}.Zip(), "no tensors"},
		"a LEAD":                      {one(pickletest.Tensor{Name: "w", Shape: []int{8}, Hook: true}).Zip(), "row is LEAD"},
		"a FAIL":                      {one(pickletest.Tensor{Name: "w", Shape: []int{8}, Stride: []int{2}}).Zip(), "row is FAIL"},
		"a list, not a dict": {pickletest.Checkpoint{Root: func(p *pickletest.Writer) { p.Raw("]").Put() }}.Zip(),
			"not a dict of names to tensors"},
	}
	for name, tc := range cases {
		in := writeFile(t, "pytorch_model.bin", tc.file)
		dst := filepath.Join(t.TempDir(), "model.safetensors")
		p, err := PlanFile(in)
		if err == nil {
			_, err = p.Write(dst)
		}
		reason, refused := IsRefused(err)
		t.Logf("%s: %s", name, reason)
		if !refused || !strings.Contains(reason, tc.want) {
			t.Errorf("%s: %v, want a refusal naming %q", name, err, tc.want)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Errorf("%s: an output was left at %s", name, dst)
		}
	}
}

// TestWriteRefusesAnExistingFile: Write never writes over a file.
func TestWriteRefusesAnExistingFile(t *testing.T) {
	p, err := PlanFile(writeFile(t, "pytorch_model.bin", mixed().Zip()))
	if err != nil {
		t.Fatal(err)
	}
	dst := writeFile(t, "model.safetensors", []byte("keep"))
	if _, err := p.Write(dst); err == nil {
		t.Fatal("Write replaced an existing file")
	}
	if b, _ := os.ReadFile(dst); string(b) != "keep" {
		t.Fatalf("the existing file now holds %q", b)
	}
}

// TestNotCarried: the plan names what the output does not carry.
func TestNotCarried(t *testing.T) {
	p, err := PlanFile(writeFile(t, "pytorch_model.bin", mixed().Zip()))
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(p.NotCarried, "\n")
	for _, s := range []string{"requires_grad", "_metadata", "1 exact alias", "2 tensors that share a storage", "byte(s) of storage that no tensor views"} {
		if !strings.Contains(all, s) {
			t.Errorf("not carried %q does not name %q", all, s)
		}
	}
	if !strings.HasPrefix(p.ByteOrder, "little (the byteorder record)") {
		t.Errorf("byte order %q", p.ByteOrder)
	}
	noRecord := mixed()
	noRecord.ByteOrder = "-"
	p, err = PlanFile(writeFile(t, "pytorch_model.bin", noRecord.Zip()))
	if err != nil || !strings.Contains(p.ByteOrder, "no byteorder record") {
		t.Fatalf("%v, byte order %q", err, p.ByteOrder)
	}
}
