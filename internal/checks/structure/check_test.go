package structure

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf/gguftest"
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

func TestValidStructurePasses(t *testing.T) {
	p := writeFixture(t, "clean.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	r := Validate(p)
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS (notes: %s)", r.Status, r.Notes)
	}
}

func TestTruncatedDoesNotPass(t *testing.T) {
	full := gguftest.BuildGGUF(gguftest.Clean())
	p := writeFixture(t, "truncated.gguf", full[:6])
	r := Validate(p)
	if r.Status == checks.Pass {
		t.Fatalf("truncated artifact must not PASS, got %s", r.Status)
	}
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED (ambiguity, not malice)", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestSplitArtifactIsSurfaced(t *testing.T) {
	kvs := append(gguftest.Clean(),
		gguftest.U32("split.no", 1),
		gguftest.U32("split.count", 3),
	)
	p := writeFixture(t, "shard-00002-of-00003.gguf", gguftest.BuildGGUF(kvs))
	r := Validate(p)
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS", r.Status)
	}
	if !strings.Contains(r.Notes, "part 2 of 3") {
		t.Errorf("a shard must be surfaced in the notes, got: %s", r.Notes)
	}
}

func TestValidSafetensorsPasses(t *testing.T) {
	p := writeFixture(t, "model.safetensors", safetensorstest.Clean())
	r := Validate(p)
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS (notes: %s)", r.Status, r.Notes)
	}
	if !strings.Contains(r.Notes, "2 tensors") {
		t.Errorf("tensor count not surfaced: %s", r.Notes)
	}
}

func TestSafetensorsOffsetsOutOfRangeNotTested(t *testing.T) {
	p := writeFixture(t, "bad.safetensors", safetensorstest.OutOfRangeOffsets())
	r := Validate(p)
	if r.Status == checks.Pass {
		t.Fatal("a container with offsets beyond its data must not PASS")
	}
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestBadMagicDoesNotPass(t *testing.T) {
	body := append([]byte("NOPE"), gguftest.BuildGGUF(gguftest.Clean())...)
	p := writeFixture(t, "badmagic.gguf", body)
	r := Validate(p)
	if r.Status == checks.Pass {
		t.Fatalf("non-GGUF artifact must not PASS, got %s", r.Status)
	}
}

// TestDuplicateGGUFKeyFails: a repeated metadata key is a parser differential,
// since llama.cpp rejects the file, gguf-py keeps the first value, and other
// readers keep the last. That is positive evidence of a malformed container,
// so it FAILs and no acceptance clears it.
func TestDuplicateGGUFKeyFails(t *testing.T) {
	kvs := append(gguftest.Clean(), gguftest.Str("tokenizer.chat_template", "second"))
	p := writeFixture(t, "dup.gguf", gguftest.BuildGGUF(kvs))
	r := Validate(p)
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a duplicate key (notes: %s)", r.Status, r.Notes)
	}
	if len(r.Findings) == 0 || r.Findings[0].Pattern != "duplicate-key" {
		t.Fatalf("findings = %+v, want a duplicate-key finding", r.Findings)
	}
}

// safetensorsWithHeader wraps a raw JSON header in the safetensors framing,
// with dataLen zero bytes of tensor data.
func safetensorsWithHeader(header string, dataLen int) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(header)))
	b.WriteString(header)
	b.Write(make([]byte, dataLen))
	return b.Bytes()
}

// TestDuplicateSafetensorsKeyFails: the header decoded into a Go map, so a
// repeated tensor name collapsed to its last entry and the first was never
// checked. Falsification: decode straight into a map again and this PASSes.
func TestDuplicateSafetensorsKeyFails(t *testing.T) {
	h := `{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},` +
		`"w":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}`
	p := writeFixture(t, "dup.safetensors", safetensorsWithHeader(h, 8))
	r := Validate(p)
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a duplicate tensor name (notes: %s)", r.Status, r.Notes)
	}
}
