package safetensors

import (
	"testing"
)

// FuzzSafetensorsHeader feeds arbitrary JSON headers to the parser. It reads
// untrusted artifacts, so it may not panic, and its output must be
// deterministic: two parses of the same bytes agree.
func FuzzSafetensorsHeader(f *testing.F) {
	f.Add([]byte(`{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}`), int64(1024))
	f.Add([]byte(`{"__metadata__":{"a":"b"},"w":{"dtype":"F32","shape":[1],"data_offsets":[4,0]}}`), int64(64))
	f.Add([]byte(`{"w":{},"w":{"data_offsets":[0,1,2]}}`), int64(16))
	f.Fuzz(func(t *testing.T, raw []byte, size int64) {
		a, errA := parseHeader(raw, size)
		b, errB := parseHeader(raw, size)
		if (errA == nil) != (errB == nil) {
			t.Fatal("parse is not deterministic")
		}
		if errA != nil {
			return
		}
		if len(a.Malformed) != len(b.Malformed) || len(a.Duplicates) != len(b.Duplicates) {
			t.Fatal("findings are not deterministic")
		}
		for i := range a.Malformed {
			if a.Malformed[i] != b.Malformed[i] {
				t.Fatal("malformed order is not deterministic")
			}
		}
	})
}
