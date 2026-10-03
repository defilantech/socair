package gguf

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
)

// Sizes: F32 [8] is 32 bytes; Q4_K [256] is 144 bytes (one 256-element
// block); Q8_0 [32] is 34 bytes.
func valid() ([]gguftest.Tensor, int) {
	return []gguftest.Tensor{
		{Name: "a", Dims: []uint64{8}, Type: 0, Offset: 0},
		{Name: "b", Dims: []uint64{256}, Type: 12, Offset: 32},
		{Name: "c", Dims: []uint64{8}, Type: 0, Offset: 192}, // 32+144=176, aligned to 192
	}, 224
}

func layoutOf(t *testing.T, tensors []gguftest.Tensor, dataLen int) Layout {
	t.Helper()
	p := writeFixture(t, "t.gguf", gguftest.BuildWithTensors(gguftest.Clean(), tensors, dataLen))
	m, err := ReadHeader(p)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	return m.ValidateLayout()
}

func TestValidTensorLayout(t *testing.T) {
	ts, n := valid()
	if l := layoutOf(t, ts, n); len(l.Violations)+len(l.Unverified) != 0 || l.Truncated != "" {
		t.Fatalf("valid layout reported %+v", l)
	}
	// With b last, data ends at 176. Padding it to the 32-byte boundary (192)
	// is allowed; a byte beyond the boundary is not.
	for _, end := range []int{176, 192} {
		if l := layoutOf(t, ts[:2], end); len(l.Violations) != 0 {
			t.Fatalf("data of %d bytes: padding reported as a violation: %v", end, l.Violations)
		}
	}
	if l := layoutOf(t, ts[:2], 200); len(l.Violations) == 0 {
		t.Fatal("bytes past the alignment boundary must be a violation")
	}
}

// Each violation has its own fixture; removing a rule makes it validate.
func TestTensorLayoutViolations(t *testing.T) {
	ts, n := valid()
	cases := []struct {
		name    string
		tensors []gguftest.Tensor
		data    int
		want    string
	}{
		{"overlap", append(append([]gguftest.Tensor{}, ts...), gguftest.Tensor{Name: "d", Dims: []uint64{8}, Type: 0, Offset: 32}), n, "overlaps"},
		{"gap", []gguftest.Tensor{ts[0], {Name: "b", Dims: []uint64{256}, Type: 12, Offset: 96}, {Name: "c", Dims: []uint64{8}, Type: 0, Offset: 256}}, 288, "gap"},
		{"appended bytes", ts, n + 4096, "not covered"},
		{"misaligned", []gguftest.Tensor{ts[0], {Name: "b", Dims: []uint64{256}, Type: 12, Offset: 40}}, 224, "not aligned"},
		{"repeated name", []gguftest.Tensor{ts[0], {Name: "a", Dims: []uint64{8}, Type: 0, Offset: 32}}, 64, "repeated"},
		{"block mismatch", []gguftest.Tensor{{Name: "q", Dims: []uint64{100}, Type: 12, Offset: 0}}, 160, "not a multiple"},
	}
	for _, c := range cases {
		l := layoutOf(t, c.tensors, c.data)
		if !strings.Contains(strings.Join(l.Violations, "|"), c.want) {
			t.Errorf("%s: violations %q, want one mentioning %q", c.name, l.Violations, c.want)
		}
	}
}

func TestUnknownTypeAndTruncation(t *testing.T) {
	if l := layoutOf(t, []gguftest.Tensor{{Name: "x", Dims: []uint64{8}, Type: 250, Offset: 0}}, 32); len(l.Unverified) != 1 || len(l.Violations) != 0 {
		t.Fatalf("unknown type: %+v, want unverified only", l)
	}
	ts, n := valid()
	if l := layoutOf(t, ts, n-100); l.Truncated == "" {
		t.Fatalf("tensor data past the file end must be reported as truncated: %+v", l)
	}
}

// TestCountTableMismatch: a header that claims more tensors than its table
// holds (the audit's poly.gguf claimed 12,345) does not parse, so the layout is
// never passed on it.
func TestCountTableMismatch(t *testing.T) {
	ts, n := valid()
	b := gguftest.BuildWithTensors(gguftest.Clean(), ts, n)
	b[8] = 0x39 // tensor count 3 -> 57
	if _, err := ReadHeader(writeFixture(t, "lie.gguf", b)); err == nil {
		t.Fatal("a tensor count larger than the table must not parse")
	}
}

func TestHistogram(t *testing.T) {
	ts, n := valid()
	p := writeFixture(t, "h.gguf", gguftest.BuildWithTensors(gguftest.Clean(), ts, n))
	m, err := ReadHeader(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := HistogramString(m.TypeHistogram()); got != "Q4_K 69%, F32 31%" {
		t.Fatalf("histogram = %q", got)
	}
}

// TestClaimedTensorCountDoesNotAllocate: the table is grown from what is read,
// so a tiny file claiming the maximum count costs almost nothing.
func TestClaimedTensorCountDoesNotAllocate(t *testing.T) {
	b := gguftest.BuildWithTensors(gguftest.Clean(), nil, 0)
	b[8], b[9], b[10] = 0x00, 0x00, 0x10 // tensor count 1<<20
	p := writeFixture(t, "claim.gguf", b)
	allocs := testing.AllocsPerRun(3, func() { _, _ = ReadHeader(p) })
	var ms1, ms2 runtime.MemStats
	runtime.ReadMemStats(&ms1)
	_, _ = ReadHeader(p)
	runtime.ReadMemStats(&ms2)
	if grew := ms2.TotalAlloc - ms1.TotalAlloc; grew > 8<<20 {
		t.Fatalf("a 1M-tensor claim allocated %d bytes (%v allocs)", grew, allocs)
	}
}
