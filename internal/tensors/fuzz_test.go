package tensors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// FuzzLoad: a reference manifest is operator input; no input panics, and
// one that loads round-trips.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"schema":"socair.tensors/v1","artifact":{"name":"m","format":"GGUF"},"value_encoding":"float32-le-bits/v1","tensors":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Load(data)
		if err != nil {
			return
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Load(raw); err != nil {
			t.Fatalf("a loaded manifest does not load again: %v", err)
		}
	})
}

// FuzzFile: any bytes, as a GGUF or safetensors file, are fingerprinted or
// refused without a panic, and every fingerprinted tensor lies inside the
// file.
func FuzzFile(f *testing.F) {
	f.Add(safetensorstest.Clean())
	f.Add(gguftest.CleanQ5KM())
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "m")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := File(p, "")
		if err != nil {
			return
		}
		for _, x := range m.Tensors {
			if x.Bytes < 0 || x.Bytes > int64(len(data)) {
				t.Fatalf("tensor %q of %d bytes in a %d-byte file", x.Name, x.Bytes, len(data))
			}
		}
	})
}
