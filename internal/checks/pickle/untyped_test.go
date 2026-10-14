package pickle

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/pickle/pickletest"
)

// torch.save writes a tensor of a dtype in torch.storage._new_dtypes()
// (uint16/32/64, the float8 family, ...) with _rebuild_tensor_v3 over an
// UntypedStorage, and names that class by its defining module:
// torch.storage.UntypedStorage. torch.UntypedStorage is the same class under
// the name torch exports it by; torch.save does not write it, and the grammar
// has accepted it since socair-wo/1. These tests hold the two spellings to
// the same checks, and every other spelling to none.

// spellings are the two names of the untyped storage class the grammar
// accepts, as a persistent id's GLOBAL writes them.
var spellings = [][2]string{{"torch.storage", "UntypedStorage"}, {"torch", "UntypedStorage"}}

// v3 is one tensor rebuild as torch.save writes it for a _new_dtypes()
// dtype, with each part a test may change.
type v3 struct {
	fn       string    // the rebuild: _rebuild_tensor_v3 unless set
	class    [2]string // the persistent id's storage class
	key      string    // the storage key: "0" unless set
	numel    int       // the persistent id's element count (bytes, for an untyped storage)
	offset   int
	size     []int
	stride   []int
	hooks    bool      // one backward hook, which torch.save never writes
	noDtype  bool      // leave the dtype argument out
	dtype    [2]string // the dtype argument's GLOBAL; {"torch", <dtype>}
	dtypeStr bool      // write the dtype argument as a string, not a GLOBAL
	legacy   bool      // a legacy stream's 6-field persistent id
}

func (p *pk) v3(t v3) *pk {
	fn := t.fn
	if fn == "" {
		fn = "_rebuild_tensor_v3"
	}
	key := t.key
	if key == "" {
		key = "0"
	}
	p.global("torch._utils", fn).raw("((")
	p.str("storage").global(t.class[0], t.class[1]).str(key).str("cpu").int(t.numel)
	if t.legacy {
		p.raw("N")
	}
	p.raw("t").put().raw("Q")
	p.int(t.offset).ints(t.size...).ints(t.stride...).raw("\x89")
	p.orderedDict()
	if t.hooks {
		p.int(0).raw("Ns")
	}
	switch {
	case t.noDtype:
	case t.dtypeStr:
		p.str(t.dtype[1])
	default:
		p.global(t.dtype[0], t.dtype[1])
	}
	return p.raw("t").put().raw("R").put()
}

// v3Zip is a torch zip of {"weight": t} with the given storage records.
func v3Zip(tb *testing.T, t v3, records map[string][]byte) []byte {
	tb.Helper()
	return torchZip(tb, newPK().dict("weight", func(p *pk) { p.v3(t) }).stop(), records)
}

// uint16x32 is a canonical weight: a (4, 8) uint16 tensor over a 64-byte
// untyped storage, as torch.save writes torch.zeros(4, 8, dtype=torch.uint16).
func uint16x32(class [2]string) v3 {
	return v3{class: class, numel: 64, size: []int{4, 8}, stride: []int{8, 1}, dtype: [2]string{"torch", "uint16"}}
}

// TestPickletestV3WritesWhatTorchWrites: the shared fixture builder's v3
// tensor is byte for byte CPython's vector torch-v3-uint16, which is
// torch.save's data.pkl for torch.zeros(4, 8, dtype=torch.uint16) (checked
// against torch 2.14.1's output when the vector was recorded; see
// docs/false-positive-baseline.md), and this package's builder writes the same.
func TestPickletestV3WritesWhatTorchWrites(t *testing.T) {
	want := loadVectors(t)["torch-v3-uint16"].bytes(t)
	c := pickletest.Checkpoint{
		Tensors:  []pickletest.Tensor{{Name: "weight", Shape: []int{4, 8}}},
		Storages: []pickletest.Storage{{Dtype: "uint16", Data: make([]byte, 64)}},
	}
	if got := c.Pickle(); !bytes.Equal(got, want) {
		t.Fatalf("pickletest wrote\n %x\ntorch.save writes\n %x", got, want)
	}
	if got := newPK().dict("weight", func(p *pk) { p.v3(uint16x32(spellings[0])) }).stop(); !bytes.Equal(got, want) {
		t.Fatalf("the package builder wrote\n %x\ntorch.save writes\n %x", got, want)
	}
}

// TestUntypedStorageAsTorchSavesIt: a checkpoint holding a tensor of each
// dtype torch.save writes over torch.storage.UntypedStorage PASSes, with the
// dtype named, and so does the same checkpoint spelled torch.UntypedStorage.
// Falsification: drop torch.storage.UntypedStorage from storageClass or
// valueGlobal and every case under its spelling is a LEAD (an unreviewed
// global, and a storage record nothing references).
func TestUntypedStorageAsTorchSavesIt(t *testing.T) {
	for _, dtype := range []string{"uint16", "uint32", "uint64", "float8_e4m3fn", "float8_e5m2"} {
		n := 32 * pickletest.Itemsize[dtype]
		c := pickletest.Checkpoint{
			Ordered:  true,
			Tensors:  []pickletest.Tensor{{Name: "w", Shape: []int{4, 8}}, {Name: "b", Shape: []int{8}, Storage: 1}},
			Storages: []pickletest.Storage{{Dtype: dtype, Data: pickletest.Seq(n, 1)}, {Dtype: "float32", Data: floats(8)}},
		}
		r := Inspect(writeFixture(t, "pytorch_model.bin", c.Zip()))
		if r.Status != checks.Pass || !strings.Contains(r.Notes, dtype+" x1") {
			t.Errorf("%s as torch.save writes it: status %s (%s), findings %+v; want PASS naming %s", dtype, r.Status, r.Notes, r.Findings, dtype)
		}
		for _, sp := range spellings {
			tensor := v3{class: sp, numel: n, size: []int{4, 8}, stride: []int{8, 1}, dtype: [2]string{"torch", dtype}}
			r := Inspect(writeFixture(t, "pytorch_model.bin", v3Zip(t, tensor, map[string][]byte{"0": make([]byte, n)})))
			if r.Status != checks.Pass || !strings.Contains(r.Notes, dtype+" x1") {
				t.Errorf("%s over %s.%s: status %s (%s), findings %+v; want PASS", dtype, sp[0], sp[1], r.Status, r.Notes, r.Findings)
			}
		}
	}
	sd, err := ReadStateDict(writeFixture(t, "pytorch_model.bin", v3Zip(t, uint16x32(spellings[0]), map[string][]byte{"0": make([]byte, 64)})))
	if err != nil {
		t.Fatal(err)
	}
	if st := sd.Storages["0"]; st.Class != "torch.storage.UntypedStorage" || st.Numel != 64 || st.Itemsize != 1 {
		t.Errorf("storage 0: %+v, want torch.storage.UntypedStorage of 64 bytes", st)
	}
	if len(sd.Tensors) != 1 || sd.Tensors[0].Dtype != "uint16" || sd.Tensors[0].Itemsize != 2 {
		t.Errorf("tensors %+v, want one uint16 tensor", sd.Tensors)
	}
}

// TestUntypedStorageNearMisses: only the two spellings are an untyped
// storage. A storage class from another module, or a name one character off,
// is an unreviewed global and its record is one nothing references, so the
// row is a LEAD where the same file under torch.storage.UntypedStorage
// PASSes. Falsification: accept the name by its last part, by a prefix, or
// any class under torch.storage, and a case here PASSes.
func TestUntypedStorageNearMisses(t *testing.T) {
	for _, class := range [][2]string{
		{"torch.storage", "UntypedStorageX"},
		{"torch.storage", "UntypedStorag"},
		{"torch.storage", "untypedstorage"},
		{"torchx.storage", "UntypedStorage"},
		{"torch.storagex", "UntypedStorage"},
		{"torch.cuda.storage", "UntypedStorage"},
		{"torch.nn", "UntypedStorage"},
		{"storage", "UntypedStorage"},
		{"numpy", "UntypedStorage"},
		{"torch.storage", "TypedStorage"},
		{"torch.storage", "FloatStorage"},
		{"torch.storage", "ByteStorage"},
	} {
		r := Inspect(writeFixture(t, "pytorch_model.bin", v3Zip(t, uint16x32(class), map[string][]byte{"0": make([]byte, 64)})))
		if r.Status != checks.Lead || !hasPattern(r, "pickle-unreviewed-global") {
			t.Errorf("%s.%s: status %s (%s), findings %+v; want LEAD on the unreviewed global", class[0], class[1], r.Status, r.Notes, r.Findings)
		}
	}

	// The class is admitted as a value only: a call of it, or the class
	// where the dtype argument goes, is a departure.
	calls := map[string][]byte{
		"a call of torch.storage.UntypedStorage": newPK().dict("s", func(p *pk) {
			p.global("torch.storage", "UntypedStorage").int(64).raw("\x85").put().raw("R").put()
		}).stop(),
		"torch.storage.UntypedStorage as the dtype": torchZip(t, newPK().dict("weight", func(p *pk) {
			tensor := uint16x32(spellings[0])
			tensor.dtype = spellings[0]
			p.v3(tensor)
		}).stop(), map[string][]byte{"0": make([]byte, 64)}),
	}
	for name, file := range calls {
		if r := Inspect(writeFixture(t, "model.bin", file)); r.Status != checks.Lead || !hasPattern(r, "pickle-grammar") {
			t.Errorf("%s: status %s (%s), findings %+v; want LEAD", name, r.Status, r.Notes, r.Findings)
		}
	}
}

// TestUntypedStorageLayout: under either spelling, a v3 tensor's storage is
// held to its record (numel bytes exactly) and its view to the storage in
// elements of the dtype the call names, and the call's other arguments to
// _rebuild_tensor_v3's signature, as for any tensor. Each case changes one
// thing in torch.save's output and must give the same status under both
// spellings. Falsification: check a v3 view in bytes rather than elements
// of its dtype, or treat torch.storage.UntypedStorage as an opaque key with
// no size, and the layout cases PASS under it.
func TestUntypedStorageLayout(t *testing.T) {
	type tcase struct {
		name    string
		tensor  func(class [2]string) v3
		records map[string][]byte
		want    checks.Status
		pattern string
	}
	b64 := map[string][]byte{"0": make([]byte, 64)}
	with := func(f func(*v3)) func([2]string) v3 {
		return func(class [2]string) v3 {
			t := uint16x32(class)
			f(&t)
			return t
		}
	}
	same := with(func(*v3) {})
	cases := []tcase{
		{"as torch.save writes it", same, b64, checks.Pass, ""},
		{"record shorter than the storage", same, map[string][]byte{"0": make([]byte, 62)}, checks.Fail, "pickle-storage-layout"},
		{"record longer than the storage", same, map[string][]byte{"0": make([]byte, 66)}, checks.Lead, "pickle-unaccounted-bytes"},
		{"record missing", same, nil, checks.Fail, "pickle-storage-layout"},
		{"storage smaller than the view in elements of its dtype", with(func(t *v3) { t.dtype[1] = "uint32" }), b64, checks.Fail, "pickle-storage-layout"},
		{"dtype that disagrees with the storage's size", with(func(t *v3) { t.dtype[1] = "uint64"; t.size = []int{8, 8} }), b64, checks.Fail, "pickle-storage-layout"},
		{"offset that runs the view past the storage", with(func(t *v3) { t.offset = 1 }), b64, checks.Fail, "pickle-storage-layout"},
		{"stride that runs the view past the storage", with(func(t *v3) { t.stride = []int{9, 1} }), b64, checks.Fail, "pickle-storage-layout"},
		{"untyped storage under _rebuild_tensor_v2", with(func(t *v3) { t.fn = "_rebuild_tensor_v2"; t.noDtype = true }), b64, checks.Lead, "pickle-grammar"},
		{"no dtype argument", with(func(t *v3) { t.noDtype = true }), b64, checks.Lead, "pickle-grammar"},
		{"a dtype argument that is a string", with(func(t *v3) { t.dtypeStr = true }), b64, checks.Lead, "pickle-grammar"},
		{"a dtype from another module", with(func(t *v3) { t.dtype[0] = "numpy" }), b64, checks.Lead, "pickle-unreviewed-global"},
		{"backward hooks", with(func(t *v3) { t.hooks = true }), b64, checks.Lead, "pickle-backward-hooks"},
	}
	for _, c := range cases {
		for _, sp := range spellings {
			r := Inspect(writeFixture(t, "pytorch_model.bin", v3Zip(t, c.tensor(sp), c.records)))
			if r.Status != c.want || (c.pattern != "" && !hasPattern(r, c.pattern)) {
				t.Errorf("%s, over %s.%s: status %s (%s), findings %+v; want %s %s", c.name, sp[0], sp[1], r.Status, r.Notes, r.Findings, c.want, c.pattern)
			}
		}
	}

	// A typed storage under _rebuild_tensor_v3, and one storage named both
	// untyped and typed (torch.save refuses to write either).
	typed := uint16x32([2]string{"torch", "ShortStorage"})
	typed.numel = 32
	if r := Inspect(writeFixture(t, "pytorch_model.bin", v3Zip(t, typed, b64))); r.Status != checks.Lead || !hasPattern(r, "pickle-grammar") {
		t.Errorf("a typed storage under _rebuild_tensor_v3: status %s, findings %+v; want LEAD", r.Status, r.Findings)
	}
	for _, sp := range spellings {
		pkl := newPK().raw("}").put().raw("(").str("a").v3(uint16x32(sp)).
			str("b").tensor("0", 16, 0, []int{16}, []int{1}, nil).raw("u").stop()
		if r := Inspect(writeFixture(t, "pytorch_model.bin", torchZip(t, pkl, b64))); r.Status != checks.Fail || !hasPattern(r, "pickle-storage-layout") {
			t.Errorf("one storage as %s.%s and as torch.FloatStorage: status %s, findings %+v; want FAIL", sp[0], sp[1], r.Status, r.Findings)
		}
	}
}

// legacyV3 is a legacy torch.save stream (_use_new_zipfile_serialization=False)
// of {"weight": t}: the legacy-stream vector's magic number, protocol
// version, and sys_info, then the object, its storage keys, and one record:
// an element count, then count x itemsize bytes.
func legacyV3(t *testing.T, tensor v3, count, itemsize int) []byte {
	t.Helper()
	v := loadVectors(t)["legacy-stream"].bytes(t)
	off := int64(0)
	for i := 0; i < 3; i++ {
		g := validateAt(bytes.NewReader(v), off, int64(len(v)), grammarOpts{pids: pidNone})
		if g.root == nil {
			t.Fatalf("the legacy-stream vector's pickle %d does not read", i+1)
		}
		off += g.end
	}
	tensor.legacy, tensor.key = true, "140234"
	var b bytes.Buffer
	b.Write(v[:off])
	b.Write(newPK().dict("weight", func(p *pk) { p.v3(tensor) }).stop())
	b.Write(newPK().raw("]").put().str("140234").raw("a").stop())
	_ = binary.Write(&b, binary.LittleEndian, int64(count))
	b.Write(make([]byte, count*itemsize))
	return b.Bytes()
}

// TestUntypedStorageInALegacyStream: torch.save writes a _new_dtypes() tensor
// over an untyped storage in the legacy format too, but torch's legacy loader
// takes the storage class's dtype, which UntypedStorage does not have, and
// stops (torch 2.2.2 and 2.14.1 both raise AttributeError). So under either
// spelling the row is a LEAD naming that, not a PASS, and the record is
// still matched: a record of the wrong size is still a FAIL. Falsification:
// drop the legacy rule in storageRef and the first case PASSes.
func TestUntypedStorageInALegacyStream(t *testing.T) {
	for _, sp := range spellings {
		r := Inspect(writeFixture(t, "pytorch_model.bin", legacyV3(t, uint16x32(sp), 64, 1)))
		if r.Status != checks.Lead || len(r.Findings) != 1 || !hasPattern(r, "pickle-grammar") || !strings.Contains(r.Findings[0].Detail, "legacy loader") {
			t.Errorf("legacy stream over %s.%s: status %s (%s), findings %+v; want one LEAD naming the legacy loader", sp[0], sp[1], r.Status, r.Notes, r.Findings)
		}
		if r := Inspect(writeFixture(t, "pytorch_model.bin", legacyV3(t, uint16x32(sp), 62, 1))); r.Status != checks.Fail || !hasPattern(r, "pickle-storage-layout") {
			t.Errorf("legacy stream over %s.%s, a record of 62 for 64: status %s, findings %+v; want FAIL", sp[0], sp[1], r.Status, r.Findings)
		}
	}
	// A typed storage in the same stream, which the legacy loader reads,
	// PASSes: the rule is about the untyped class, not the container.
	typed := v3{fn: "_rebuild_tensor_v2", class: [2]string{"torch", "FloatStorage"}, numel: 16, size: []int{16}, stride: []int{1}, noDtype: true}
	if r := Inspect(writeFixture(t, "pytorch_model.bin", legacyV3(t, typed, 16, 4))); r.Status != checks.Pass || !strings.Contains(r.Notes, "legacy") {
		t.Errorf("legacy stream over torch.FloatStorage: status %s (%s), findings %+v; want PASS", r.Status, r.Notes, r.Findings)
	}
}
