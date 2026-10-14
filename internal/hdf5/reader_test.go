package hdf5_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/hdf5"
	"github.com/defilantech/socair/internal/hdf5/hdf5test"
)

func read(t *testing.T, f *hdf5test.File) *hdf5.File {
	t.Helper()
	b := f.Bytes()
	h, err := hdf5.ReadFrom(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func object(t *testing.T, h *hdf5.File, path string) *hdf5.Object {
	t.Helper()
	for _, o := range h.Objects {
		if o.Path == path {
			return o
		}
	}
	t.Fatalf("no object %s", path)
	return nil
}

func plain() *hdf5test.File {
	kernel := make([]byte, 48)
	for i := range kernel {
		kernel[i] = byte(i)
	}
	return &hdf5test.File{Root: &hdf5test.Group{
		Attrs: []hdf5test.Attr{
			{Name: "keras_version", Strings: []string{"2.9.0"}},
			{Name: "layer_names", Strings: []string{"dense", "head"}, Array: true},
			{Name: "fixed", Strings: []string{"abc", "de"}, Fixed: true, Array: true},
			{Name: "empty", IsFloat: true},
		},
		Groups: map[string]*hdf5test.Group{
			"dense": {
				Attrs: []hdf5test.Attr{{Name: "weight_names", Strings: []string{"dense/kernel:0", "dense/bias:0"}, Array: true}},
				Datasets: map[string]*hdf5test.Dataset{
					"kernel:0": {Type: hdf5test.Float32, Dims: []uint64{4, 3}, Data: kernel},
					"bias:0":   hdf5test.Weights(3),
					"step":     {Type: hdf5test.Int64},
					"half":     {Type: hdf5test.Float16, Dims: []uint64{5}},
				},
				Continuation: true,
			},
			"head": {},
		},
	}}
}

// The reader reads what h5py writes by default: groups through symbol
// tables, string attributes fixed and variable-length, and contiguous
// datasets, and its check finds every dataset's storage sound.
func TestReadsDefaultLayout(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		f := plain()
		f.Version2 = v2
		h := read(t, f)
		want := 0
		if v2 {
			want = 2
		}
		if h.SuperblockVersion != want || h.OffsetSize != 8 || h.LengthSize != 8 || len(h.Unread) != 0 {
			t.Fatalf("v2=%v: superblock %d, sizes %d/%d, unread %v", v2, h.SuperblockVersion, h.OffsetSize, h.LengthSize, h.Unread)
		}
		root := object(t, h, "/")
		if a := root.Attr("keras_version"); a == nil || !a.Type.VLenString || strings.Join(a.Strings, "") != "2.9.0" || a.Space.Kind != hdf5.SpaceScalar {
			t.Errorf("v2=%v: keras_version %+v", v2, a)
		}
		if a := root.Attr("layer_names"); a == nil || strings.Join(a.Strings, ",") != "dense,head" {
			t.Errorf("v2=%v: layer_names %+v", v2, a)
		}
		if a := root.Attr("fixed"); a == nil || a.Type.Class != hdf5.ClassString || strings.Join(a.Strings, ",") != "abc,de" {
			t.Errorf("v2=%v: fixed %+v", v2, a)
		}
		if a := root.Attr("empty"); a == nil || a.Type.Class != hdf5.ClassFloat || len(a.Strings) != 0 {
			t.Errorf("v2=%v: empty %+v", v2, a)
		}
		k := object(t, h, "/dense/kernel:0")
		if k.Kind != hdf5.KindDataset || k.Dataset.Type.Name() != "float32" || k.Dataset.Space.String() != "(4, 3)" ||
			k.Dataset.Layout.Class != hdf5.LayoutContiguous || k.Dataset.Layout.Size != 48 {
			t.Errorf("v2=%v: kernel %+v", v2, k.Dataset)
		}
		if s := object(t, h, "/dense/step").Dataset; s.Space.Kind != hdf5.SpaceScalar || s.Type.Name() != "int64" {
			t.Errorf("v2=%v: step %+v", v2, s)
		}
		if object(t, h, "/dense").Attr("weight_names") == nil {
			t.Errorf("v2=%v: the attributes in a continuation block were not read", v2)
		}
		lc := h.Check()
		if len(lc.Violations) != 0 || len(lc.Unchecked) != 0 || lc.Datasets != 4 || lc.Bytes != 48+12+8+10 {
			t.Errorf("v2=%v: check %+v", v2, lc)
		}
	}
}

// Jenkins' published values for lookup3's hashlittle with an initial value
// of 0, which every HDF5 checksum is.
func TestChecksumKnownAnswers(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
	}{{"", 0xdeadbeef}, {"Four score and seven years ago", 0x17770551}} {
		if got := hdf5.Checksum([]byte(c.in)); got != c.want {
			t.Errorf("Checksum(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

// A metadata checksum that does not match is malformed: the HDF5 library
// refuses the file. Falsification: skip the check and the file reads.
func TestBadChecksumIsUnparseable(t *testing.T) {
	f := plain()
	f.Version2 = true
	b := f.Bytes()
	b[44] ^= 0xff // the superblock's checksum
	if _, err := hdf5.ReadFrom(bytes.NewReader(b), int64(len(b))); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("a bad superblock checksum: %v", err)
	}
}

// The superblock is found after a user block, at the offsets the
// specification lists, and not elsewhere.
func TestSniffUserBlock(t *testing.T) {
	dir := t.TempDir()
	f := plain()
	f.UserBlock = 1024
	p := filepath.Join(dir, "u.h5")
	if err := os.WriteFile(p, f.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if off := hdf5.Sniff(p); off != 1024 {
		t.Fatalf("sniff %d", off)
	}
	h, err := hdf5.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if h.SuperblockOffset != 1024 || len(h.Check().Violations) != 0 {
		t.Errorf("user block: offset %d, %+v", h.SuperblockOffset, h.Check())
	}
	// The signature at 700, not a power-of-two offset, is not HDF5.
	odd := append(make([]byte, 700), plain().Bytes()...)
	if err := os.WriteFile(p, odd, 0o644); err != nil {
		t.Fatal(err)
	}
	if off := hdf5.Sniff(p); off != -1 {
		t.Errorf("signature at 700 sniffed at %d", off)
	}
}

func check(t *testing.T, f *hdf5test.File) hdf5.LayoutCheck {
	t.Helper()
	return read(t, f).Check()
}

func patterns(lc hdf5.LayoutCheck) string {
	var p []string
	for _, v := range lc.Violations {
		p = append(p, v.Pattern+" "+v.Where+": "+v.Detail)
	}
	return strings.Join(p, "\n")
}

// Storage the dataset's type and shape do not describe is a violation,
// each falsifiable by removing its rule.
func TestStorageViolations(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	cases := []struct {
		name, want string
		f          func() *hdf5test.File
	}{
		{"stored size larger than the shape", "tensor-size /d", func() *hdf5test.File {
			return one(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{3}, Data: make([]byte, 64), StoredSize: u(64)})
		}},
		{"stored size smaller than the shape", "tensor-size /d", func() *hdf5test.File {
			return one(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{3}, StoredSize: u(4)})
		}},
		{"storage past the end of the HDF5 data", "tensor-layout /d", func() *hdf5test.File {
			return one(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{1 << 20}, Data: make([]byte, 16), StoredSize: u(4 << 20)})
		}},
		{"storage over the superblock", "tensor-layout /d", func() *hdf5test.File {
			return one(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{3}, Addr: u(0)})
		}},
		{"two datasets over the same bytes", "tensor-layout /z", func() *hdf5test.File {
			// /d's data is the first allocated, right after the superblock.
			f := one(hdf5test.Weights(3))
			f.Root.Datasets["z"] = &hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{3}, Addr: u(96)}
			return f
		}},
		{"bytes after the HDF5 data", "tensor-layout after the HDF5 data", func() *hdf5test.File {
			f := one(hdf5test.Weights(3))
			f.Trailing = []byte("PK\x03\x04 a zip read from its end")
			return f
		}},
		{"a compact dataset of the wrong size", "tensor-size /d", func() *hdf5test.File {
			return one(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{3}, Data: make([]byte, 8), Compact: true})
		}},
	}
	for _, c := range cases {
		lc := check(t, c.f())
		if got := patterns(lc); !strings.Contains(got, c.want) {
			t.Errorf("%s: want %q in:\n%s", c.name, c.want, got)
		}
	}
}

func one(d *hdf5test.Dataset) *hdf5test.File {
	return &hdf5test.File{Root: &hdf5test.Group{Datasets: map[string]*hdf5test.Dataset{"d": d}}}
}

// A file shorter than its superblock says is truncated: not checked, not a
// violation.
func TestTruncatedIsUnchecked(t *testing.T) {
	f := one(hdf5test.Weights(3))
	f.EOFDelta = 4096
	lc := check(t, f)
	if len(lc.Violations) != 0 || len(lc.Unchecked) == 0 || !strings.Contains(lc.Unchecked[0], "truncated") {
		t.Errorf("truncated: %+v", lc)
	}
}

// Chunked storage is read through its B-tree; an unfiltered chunk is
// checked against its dimensions, a filtered one is named and not sized.
func TestChunkedStorage(t *testing.T) {
	data := make([]byte, 4*10*6)
	h := read(t, &hdf5test.File{Root: &hdf5test.Group{Datasets: map[string]*hdf5test.Dataset{
		"c": {Type: hdf5test.Float32, Dims: []uint64{10, 6}, Chunk: []uint64{4, 4}, Data: data},
		"z": {Type: hdf5test.Float32, Dims: []uint64{100}, Chunk: []uint64{10}, Deflate: true},
	}}})
	if c := object(t, h, "/c").Dataset; len(c.Layout.Chunks) != 6 {
		t.Errorf("chunks %+v", c.Layout)
	}
	if z := object(t, h, "/z").Dataset; len(z.Filters) != 1 || z.Filters[0].ID != 1 {
		t.Errorf("filters %+v", z.Filters)
	}
	lc := h.Check()
	if len(lc.Violations) != 0 || lc.Chunks != 16 || len(lc.Unchecked) != 1 || !strings.Contains(lc.Unchecked[0], "deflate") {
		t.Errorf("check %+v", lc)
	}
}

// What the reader does not model is named, never read past silently.
func TestUnmodelledIsNamed(t *testing.T) {
	cases := []struct {
		name, want string
		f          *hdf5test.File
	}{
		{"external link", "external links", &hdf5test.File{Root: &hdf5test.Group{External: map[string][2]string{"e": {"/etc/model.h5", "/w"}}}}},
		{"unknown message", "type 48, which this reader does not model, flagged so a reader that does not understand it must refuse", &hdf5test.File{Root: &hdf5test.Group{
			Extra: []hdf5test.Message{{Type: 48, Flags: 0x80, Data: []byte{1, 2, 3}}}}}},
	}
	for _, c := range cases {
		h := read(t, c.f)
		if got := strings.Join(h.Unread, "; "); !strings.Contains(got, c.want) {
			t.Errorf("%s: unread %q, want %q", c.name, got, c.want)
		}
	}
	h := read(t, one(&hdf5test.Dataset{Type: hdf5test.Float32, Dims: []uint64{4}, External: "/etc/passwd"}))
	if lc := h.Check(); len(lc.Unchecked) != 1 || !strings.Contains(lc.Unchecked[0], `"/etc/passwd"`) {
		t.Errorf("external storage: %+v", lc)
	}
	h = read(t, &hdf5test.File{Root: &hdf5test.Group{Soft: map[string]string{"alias": "/w"}}})
	if len(h.Links) != 1 || h.Links[0].Type != "soft" || h.Links[0].Target != "/w" || len(h.Unread) != 0 {
		t.Errorf("soft link %+v, unread %v", h.Links, h.Unread)
	}
}

// Malformed bytes are an error, not a partial result.
func TestMalformedIsAnError(t *testing.T) {
	b := plain().Bytes()
	for name, bad := range map[string][]byte{
		"no signature": append([]byte("not hdf5"), b[8:]...),
		"truncated":    b[:200],
		"bad heap":     bytes.Replace(b, []byte("HEAP"), []byte("HEAX"), 1),
		"bad node":     bytes.Replace(b, []byte("SNOD"), []byte("SNOX"), 1),
	} {
		_, err := hdf5.ReadFrom(bytes.NewReader(bad), int64(len(bad)))
		var pe *hdf5.ParseError
		if err == nil || !errors.As(err, &pe) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
