package safetensors

import (
	"strings"
	"testing"
)

// header builds a JSON header from tensor entries written as
// name:dtype:shape:begin:end, with shape dims separated by "x".
func header(entries ...string) []byte {
	var parts []string
	for _, e := range entries {
		f := strings.Split(e, ":")
		dims := "[]"
		if f[2] != "" {
			dims = "[" + strings.ReplaceAll(f[2], "x", ",") + "]"
		}
		parts = append(parts, `"`+f[0]+`":{"dtype":"`+f[1]+`","shape":`+dims+`,"data_offsets":[`+f[3]+`,`+f[4]+`]}`)
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

func parse(t *testing.T, raw []byte, dataBytes int64) *Manifest {
	t.Helper()
	m, err := parseHeader(raw, 8+int64(len(raw))+dataBytes)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	return m
}

// TestLayoutViolations: structure PASSed a file with two tensors at the same
// offsets, a bogus dtype, a negative shape, and a payload hidden in an
// unaccounted gap. Each rule has its own fixture; removing a rule makes its
// fixture parse clean and the test fail.
func TestLayoutViolations(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		data int64
		want string
	}{
		{"overlap", header("a:F32:2:0:8", "b:F32:2:0:8"), 8, "overlaps"},
		{"gap", header("a:F32:2:0:8", "b:F32:2:16:24"), 24, "gap"},
		{"trailing bytes", header("a:F32:2:0:8"), 64, "not covered"},
		{"size mismatch", header("a:F32:4:0:8"), 8, "holds 16 bytes"},
		{"negative dimension", header("a:F32:-5x2:0:8"), 8, "negative"},
		{"element count overflow", header("a:F64:4294967296x4294967296:0:8"), 8, "overflows"},
		{"not starting at zero", header("a:F32:2:8:16"), 16, "gap"},
	}
	for _, c := range cases {
		m := parse(t, c.raw, c.data)
		if !strings.Contains(strings.Join(m.Layout, "|"), c.want) {
			t.Errorf("%s: layout problems %q, want one mentioning %q", c.name, m.Layout, c.want)
		}
	}
}

func TestValidLayouts(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		data int64
	}{
		{"single tensor", header("a:F32:2x3:0:24"), 24},
		{"contiguous, out of name order", header("z:BF16:4:0:8", "a:I64:1:8:16"), 16},
		{"zero-sized tensors", header("e:F32:0:0:0", "f:F32:0x7:0:0", "a:U8:3:0:3"), 3},
		{"scalar", header("s:F64::0:8"), 8},
		{"no tensors, no data", []byte(`{"__metadata__":{"format":"pt"}}`), 0},
		{"sub-byte dtype", header("q:F4:8:0:4"), 4},
	}
	for _, c := range cases {
		m := parse(t, c.raw, c.data)
		if len(m.Layout) != 0 || len(m.Malformed) != 0 || len(m.Unverified) != 0 {
			t.Errorf("%s: layout %q malformed %q unverified %q, want clean", c.name, m.Layout, m.Malformed, m.Unverified)
		}
	}
}

// TestUnknownDtypeIsUnverified: safetensors keeps adding dtypes, so an unknown
// one means the layout cannot be checked, not that the file is malformed.
func TestUnknownDtypeIsUnverified(t *testing.T) {
	m := parse(t, header("a:EVIL:2:0:8"), 8)
	if len(m.Unverified) != 1 || len(m.Layout) != 0 {
		t.Fatalf("unverified %q layout %q, want one unverified dtype and no layout verdict", m.Unverified, m.Layout)
	}
}

func TestHeaderLimitMatchesReference(t *testing.T) {
	if maxHeaderBytes != 100_000_000 {
		t.Fatalf("maxHeaderBytes = %d, want the reference implementation's 100000000", maxHeaderBytes)
	}
}
