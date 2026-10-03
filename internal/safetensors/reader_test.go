package safetensors

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

func TestReadValidArtifact(t *testing.T) {
	data := safetensorstest.Clean()
	p := writeFixture(t, "model.safetensors", data)

	if !IsSafetensors(p) {
		t.Fatal("IsSafetensors should be true for a valid container")
	}

	m, err := ReadArtifact(p)
	if err != nil {
		t.Fatalf("ReadArtifact: %v", err)
	}
	if m.Format != "safetensors" {
		t.Errorf("format = %q", m.Format)
	}
	if m.TensorCount != 2 {
		t.Errorf("tensor count = %d, want 2", m.TensorCount)
	}
	if len(m.MetadataKeys) != 2 {
		t.Errorf("metadata keys = %v, want 2", m.MetadataKeys)
	}
	if len(m.Malformed) != 0 {
		t.Errorf("valid container reported malformed: %v", m.Malformed)
	}
	want := sha256.Sum256(data)
	if m.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %s, want %s", m.SHA256, hex.EncodeToString(want[:]))
	}
}

func TestNotSafetensors(t *testing.T) {
	p := writeFixture(t, "not.bin", []byte("GGUF\x00\x00\x00\x00random bytes here"))
	if IsSafetensors(p) {
		t.Fatal("IsSafetensors should be false")
	}
	if _, err := ReadArtifact(p); !errors.Is(err, ErrNotSafetensors) {
		t.Fatalf("err = %v, want ErrNotSafetensors", err)
	}
}

func TestOutOfRangeOffsetsAreMalformed(t *testing.T) {
	p := writeFixture(t, "bad.safetensors", safetensorstest.OutOfRangeOffsets())
	m, err := ReadArtifact(p)
	if err != nil {
		t.Fatalf("ReadArtifact: %v", err)
	}
	if len(m.Malformed) == 0 {
		t.Fatal("offsets that exceed the data section must be recorded as malformed")
	}
}

func TestHeaderLengthBeyondFile(t *testing.T) {
	// A header length larger than the file must be rejected, not allocated.
	var buf []byte
	buf = append(buf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f)
	buf = append(buf, []byte("{}")...)
	p := writeFixture(t, "huge.safetensors", buf)
	if _, err := ReadArtifact(p); err == nil {
		t.Fatal("expected an error on a header length beyond the file size")
	}
}

// TestMalformedIsDeterministic: the header is walked as a Go map, whose order
// is randomized, so Malformed came out in a different order on each run and the
// "byte-stable" report was not. Falsification: drop the sort and the forty
// reads below disagree.
func TestMalformedIsDeterministic(t *testing.T) {
	var specs []safetensorstest.TensorSpec
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		specs = append(specs, safetensorstest.TensorSpec{Name: n, Dtype: "F32", Shape: []int64{1}, Start: 0, End: 1 << 30})
	}
	p := writeFixture(t, "bad.safetensors", safetensorstest.BuildWithDataLen(nil, specs, 4))

	first, err := ReadHeader(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		m, err := ReadHeader(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(m.Malformed, "|") != strings.Join(first.Malformed, "|") {
			t.Fatalf("Malformed order changed between reads:\n%q\n%q", first.Malformed, m.Malformed)
		}
	}
}
