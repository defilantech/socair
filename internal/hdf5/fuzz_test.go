package hdf5_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/defilantech/socair/internal/hdf5"
	"github.com/defilantech/socair/internal/hdf5/hdf5test"
)

// FuzzRead feeds arbitrary bytes to the reader and its layout check. They
// read untrusted artifacts, so neither may panic, a parse must be
// deterministic, and what it reports must hold together: every dataset has
// its type, shape, and layout, and no count is negative.
func FuzzRead(f *testing.F) {
	group := &hdf5test.Group{
		Attrs: []hdf5test.Attr{{Name: "layer_names", Strings: []string{"dense"}, Array: true}, {Name: "fixed", Strings: []string{"ab"}, Fixed: true}},
		Datasets: map[string]*hdf5test.Dataset{
			"w": hdf5test.Weights(4, 3),
			"c": {Type: hdf5test.Float32, Dims: []uint64{10}, Chunk: []uint64{4}},
			"z": {Type: hdf5test.Float32, Dims: []uint64{10}, Chunk: []uint64{5}, Deflate: true},
			"k": {Type: hdf5test.Int64, Compact: true},
		},
		Groups:       map[string]*hdf5test.Group{"sub": {Attrs: []hdf5test.Attr{{Name: "name", Strings: []string{"x"}}}}},
		Continuation: true,
	}
	f.Add((&hdf5test.File{Root: group}).Bytes())
	f.Add((&hdf5test.File{Root: group, Version2: true}).Bytes())
	f.Add((&hdf5test.File{UserBlock: 512, Root: &hdf5test.Group{Soft: map[string]string{"s": "/w"}, External: map[string][2]string{"e": {"f.h5", "/w"}}}}).Bytes())
	f.Add([]byte("\x89HDF\r\n\x1a\n\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, errA := hdf5.ReadFrom(bytes.NewReader(data), int64(len(data)))
		b, errB := hdf5.ReadFrom(bytes.NewReader(data), int64(len(data)))
		if (errA == nil) != (errB == nil) {
			t.Fatal("parse is not deterministic")
		}
		if errA != nil {
			return
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatal("two parses of the same bytes differ")
		}
		for _, o := range a.Objects {
			if o.Kind == hdf5.KindDataset && o.Dataset == nil || o.Kind != hdf5.KindDataset && o.Dataset != nil {
				t.Fatalf("object %s of kind %v with dataset %v", o.Path, o.Kind, o.Dataset)
			}
		}
		lc := a.Check()
		if lc.Datasets < 0 || lc.Chunks < 0 || lc.Contiguous+lc.Chunked+lc.Compact > lc.Datasets {
			t.Fatalf("check counts %+v", lc)
		}
	})
}
