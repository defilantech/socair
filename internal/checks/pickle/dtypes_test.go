package pickle

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

// torch 2.14 adds bcomplex32 (c10::complex<c10::BFloat16>, 4 bytes; Python
// name "bcomplex32" with no alias, c10/core/ScalarType.cpp getDtypeNames) to
// torch.storage._new_dtypes(), so torch.save writes it with
// _rebuild_tensor_v3 over an untyped storage. A checkpoint holding one PASSes
// when its storage holds 4 bytes per element, and not when it is sized as a
// 2-byte type. Falsification: drop bcomplex32 from torchDtypes and the first
// case is a LEAD; give it 2 bytes and the second case PASSes.
func TestBComplex32AsTorchSavesIt(t *testing.T) {
	for _, sp := range spellings {
		tensor := v3{class: sp, numel: 32 * 4, size: []int{4, 8}, stride: []int{8, 1}, dtype: [2]string{"torch", "bcomplex32"}}
		r := Inspect(writeFixture(t, "pytorch_model.bin", v3Zip(t, tensor, map[string][]byte{"0": make([]byte, 32*4)})))
		if r.Status != checks.Pass || !strings.Contains(r.Notes, "bcomplex32 x1") {
			t.Errorf("bcomplex32 over %s.%s: status %s (%s), findings %+v; want PASS", sp[0], sp[1], r.Status, r.Notes, r.Findings)
		}
		half := tensor
		half.numel = 32 * 2
		if r := Inspect(writeFixture(t, "pytorch_model.bin", v3Zip(t, half, map[string][]byte{"0": make([]byte, 32*2)}))); r.Status == checks.Pass {
			t.Errorf("bcomplex32 over %s.%s sized at 2 bytes an element: PASS, want the view refused", sp[0], sp[1])
		}
	}
}

// torch.cuda defines twelve legacy typed storage classes (torch/cuda/__init__.py,
// class <X>Storage(_CudaLegacyStorage), the same twelve in v2.0.0 and v2.14.1)
// and no UntypedStorage or quantized storage. The grammar accepts a
// torch.cuda storage name only where torch.cuda defines one: a name that
// torch cannot resolve is not a storage the grammar can vouch for.
// Falsification: accept every storage name under torch.cuda again and the
// undefined names pass.
func TestCUDAStorageClassesAreTheOnesTorchDefines(t *testing.T) {
	defined := []string{"ByteStorage", "DoubleStorage", "FloatStorage", "HalfStorage", "LongStorage", "IntStorage",
		"ShortStorage", "CharStorage", "BoolStorage", "BFloat16Storage", "ComplexDoubleStorage", "ComplexFloatStorage"}
	for _, name := range defined {
		if class, _, _ := storageClass("torch.cuda." + name); class != "torch."+name {
			t.Errorf("torch.cuda.%s: storage class %q, want torch.%s", name, class, name)
		}
		if !valueGlobal("torch.cuda." + name) {
			t.Errorf("torch.cuda.%s: not admitted as a value", name)
		}
	}
	for _, name := range []string{"UntypedStorage", "QInt8Storage", "QInt32Storage", "QUInt8Storage", "QUInt4x2Storage", "QUInt2x4Storage"} {
		if class, _, _ := storageClass("torch.cuda." + name); class != "" {
			t.Errorf("torch.cuda.%s, which torch does not define: storage class %q, want none", name, class)
		}
		if valueGlobal("torch.cuda." + name) {
			t.Errorf("torch.cuda.%s, which torch does not define: admitted as a value", name)
		}
	}

	// End to end: a uint16 tensor over torch.cuda.UntypedStorage, which
	// passed before, is not a PASS; the same over a torch.cuda typed class
	// torch defines still is.
	if r := Inspect(writeFixture(t, "pytorch_model.bin", v3Zip(t, uint16x32([2]string{"torch.cuda", "UntypedStorage"}), map[string][]byte{"0": make([]byte, 64)}))); r.Status == checks.Pass {
		t.Errorf("a v3 tensor over torch.cuda.UntypedStorage: PASS (%s), want it refused", r.Notes)
	}
	cuda := newPK().dict("weight", func(p *pk) {
		p.global("torch._utils", "_rebuild_tensor_v2").raw("((")
		p.str("storage").global("torch.cuda", "FloatStorage").str("0").str("cuda:0").int(4).raw("t").put().raw("Q")
		p.int(0).ints(4).ints(1).raw("\x89")
		p.orderedDict()
		p.raw("t").put().raw("R").put()
	}).stop()
	if r := Inspect(writeFixture(t, "pytorch_model.bin", torchZip(t, cuda, map[string][]byte{"0": floats(4)}))); r.Status != checks.Pass {
		t.Errorf("a v2 tensor over torch.cuda.FloatStorage: status %s (%s), findings %+v; want PASS", r.Status, r.Notes, r.Findings)
	}
}
