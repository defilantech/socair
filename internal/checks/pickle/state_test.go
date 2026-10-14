package pickle

import (
	"archive/zip"
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/pickle/pickletest"
)

// TestPickletestWritesWhatCPythonWrites holds the shared fixture builder to
// the one this package's tests use, which TestBuilderWritesWhatCPythonWrites
// holds to CPython: a one-tensor state dict is the same bytes from both.
func TestPickletestWritesWhatCPythonWrites(t *testing.T) {
	c := pickletest.Checkpoint{
		Tensors:  []pickletest.Tensor{{Name: "w", Shape: []int{4}}},
		Storages: []pickletest.Storage{{Dtype: "float32", Data: floats(4)}},
	}
	if got := c.Pickle(); !bytes.Equal(got, stateDict()) {
		t.Fatalf("pickletest wrote\n %x\nthe package builder wrote\n %x", got, stateDict())
	}
}

func TestReadStateDict(t *testing.T) {
	c := pickletest.Checkpoint{
		Ordered: true,
		Tensors: []pickletest.Tensor{
			{Name: "embed.weight", Storage: 0, Shape: []int{2, 3}},
			{Name: "head.weight", Storage: 0, Shape: []int{2, 3}, Param: true},
			{Name: "fp8", Storage: 1, Shape: []int{2}, Offset: 2},
			{Name: "t", Storage: 2, Shape: []int{3, 2}, Stride: []int{1, 3}, Metadata: []string{"neg"}},
		},
		Storages: []pickletest.Storage{
			{Dtype: "bfloat16", Data: pickletest.Seq(12, 1)},
			{Dtype: "float8_e4m3fn", Data: pickletest.Seq(4, 2)},
			{Dtype: "float32", Data: pickletest.Seq(24, 3)},
		},
	}
	sd, err := ReadStateDict(writeFixture(t, "pytorch_model.bin", c.Zip()))
	if err != nil {
		t.Fatal(err)
	}
	if sd.Result.Status != checks.Pass || sd.Pickle != "archive/data.pkl" || sd.ByteOrder != "little" || !sd.HasByteOrder {
		t.Fatalf("result %s, pickle %q, byteorder %q %v", sd.Result.Status, sd.Pickle, sd.ByteOrder, sd.HasByteOrder)
	}
	if sd.Root != "collections.OrderedDict" || !reflect.DeepEqual(sd.RootAttributes, []string{"_metadata"}) {
		t.Errorf("root %q attributes %q", sd.Root, sd.RootAttributes)
	}
	want := []StateTensor{
		{Name: "embed.weight", Dtype: "bfloat16", Itemsize: 2, Shape: []int64{2, 3}, Stride: []int64{3, 1}, Storage: "0"},
		{Name: "head.weight", Dtype: "bfloat16", Itemsize: 2, Shape: []int64{2, 3}, Stride: []int64{3, 1}, Storage: "0", Parameter: true},
		{Name: "fp8", Dtype: "float8_e4m3fn", Itemsize: 1, Shape: []int64{2}, Stride: []int64{1}, Offset: 2, Storage: "1"},
		{Name: "t", Dtype: "float32", Itemsize: 4, Shape: []int64{3, 2}, Stride: []int64{1, 3}, Storage: "2", Metadata: true},
	}
	if !reflect.DeepEqual(sd.Tensors, want) {
		t.Errorf("tensors\n %+v\nwant\n %+v", sd.Tensors, want)
	}
	if st := sd.Storages["1"]; st.Class != "torch.UntypedStorage" || st.Numel != 4 || st.Itemsize != 1 || st.Record != "archive/data/1" {
		t.Errorf("storage 1: %+v", st)
	}
	if st := sd.Storages["0"]; st.Class != "torch.BFloat16Storage" || st.Numel != 6 || st.Dtype != "bfloat16" {
		t.Errorf("storage 0: %+v", st)
	}
}

// TestReadStateDictRefuses: anything the check does not PASS, any container
// other than a torch zip, and any root other than a dict of names to tensors
// is ErrNotStateDict, with the reason. Falsification: drop a case's test in
// ReadStateDict and its fixture reads as a state dict.
func TestReadStateDictRefuses(t *testing.T) {
	one := []pickletest.Storage{{Dtype: "float32", Data: floats(4)}}
	root := func(f func(*pickletest.Writer)) []byte {
		return pickletest.Checkpoint{Root: f}.Zip()
	}
	cases := map[string]struct {
		file []byte
		want string
	}{
		"a LEAD (a backward hook)": {pickletest.Checkpoint{
			Tensors: []pickletest.Tensor{{Name: "w", Shape: []int{4}, Hook: true}}, Storages: one}.Zip(), "row is LEAD"},
		"a FAIL (a view past its storage)": {pickletest.Checkpoint{
			Tensors: []pickletest.Tensor{{Name: "w", Shape: []int{4}, Stride: []int{2}}}, Storages: one}.Zip(), "row is FAIL"},
		"a list root": {root(func(p *pickletest.Writer) { p.Raw("]").Put() }), "not a dict of names to tensors"},
		"an int key":  {root(func(p *pickletest.Writer) { p.Raw("}").Put().Int(1).Int(2).Raw("s") }), "not a name"},
		"a value that is not a tensor": {root(func(p *pickletest.Writer) {
			p.Raw("}").Put().Str("epoch").Int(3).Raw("s")
		}), `"epoch" is an int, not a tensor`},
		"a legacy stream, not a zip": {legacyStream(t, 3, nil), "not a torch.save zip"},
		"an npz":                     {npzOf(t), "not a torch.save zip"},
	}
	for name, c := range cases {
		_, err := ReadStateDict(writeFixture(t, "model.bin", c.file))
		if !errors.Is(err, ErrNotStateDict) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrNotStateDict naming %q", name, err, c.want)
		}
	}
}

func npzOf(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("a.npy")
	_, _ = w.Write(npy("<f4", "(2,)", floats(2)))
	_ = zw.Close()
	return b.Bytes()
}
