package gguf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/gguf/gguftest"
)

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

func TestReadArtifactValidFixture(t *testing.T) {
	data := gguftest.BuildGGUF(gguftest.Clean())
	p := writeFixture(t, "clean-Q5_K_M.gguf", data)

	m, err := ReadArtifact(p)
	if err != nil {
		t.Fatalf("ReadArtifact: %v", err)
	}

	if m.Name != "Fixture Model" {
		t.Errorf("name = %q, want %q", m.Name, "Fixture Model")
	}
	if m.Architecture != "llama" {
		t.Errorf("architecture = %q, want llama", m.Architecture)
	}
	if m.TokenizerModel != "llama" {
		t.Errorf("tokenizer model = %q, want llama", m.TokenizerModel)
	}
	if !m.ChatTemplatePresent || m.ChatTemplateBytes == 0 {
		t.Errorf("chat template not captured: present=%v bytes=%d", m.ChatTemplatePresent, m.ChatTemplateBytes)
	}
	if m.Version != 3 {
		t.Errorf("version = %d, want 3", m.Version)
	}
	if m.Quant.Declared != "Q5_K_M" {
		t.Errorf("declared quant = %q, want Q5_K_M", m.Quant.Declared)
	}
	if m.Quant.FileType == nil || *m.Quant.FileType != 17 {
		t.Errorf("file_type = %v, want 17", m.Quant.FileType)
	}
	if m.Quant.QuantVersion == nil || *m.Quant.QuantVersion != 2 {
		t.Errorf("quantization_version = %v, want 2", m.Quant.QuantVersion)
	}

	want := sha256.Sum256(data)
	if m.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %s, want %s", m.SHA256, hex.EncodeToString(want[:]))
	}
	if m.SizeBytes != int64(len(data)) {
		t.Errorf("size = %d, want %d", m.SizeBytes, len(data))
	}
}

func TestReadHeaderDoesNotHash(t *testing.T) {
	p := writeFixture(t, "clean.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	m, err := ReadHeader(p)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if m.SHA256 != "" {
		t.Errorf("ReadHeader must not set SHA256, got %q", m.SHA256)
	}
	if m.Name != "Fixture Model" {
		t.Errorf("name = %q, want Fixture Model", m.Name)
	}
}

func TestReadArtifactBadMagic(t *testing.T) {
	p := writeFixture(t, "bad.gguf", append([]byte("NOPE"), gguftest.BuildGGUF(gguftest.Clean())...))
	if _, err := ReadArtifact(p); !errors.Is(err, ErrNotGGUF) {
		t.Fatalf("err = %v, want ErrNotGGUF", err)
	}
}

func TestReadArtifactTruncatedHeader(t *testing.T) {
	full := gguftest.BuildGGUF(gguftest.Clean())
	p := writeFixture(t, "truncated.gguf", full[:6])
	if _, err := ReadArtifact(p); err == nil {
		t.Fatal("expected an error on a truncated header, got nil")
	}
}

func TestReadArtifactOversizeStringLength(t *testing.T) {
	// A key whose declared length is absurd must error, not allocate.
	var b bytes.Buffer
	b.WriteString("GGUF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	_ = binary.Write(&b, binary.LittleEndian, uint64(1))
	_ = binary.Write(&b, binary.LittleEndian, uint64(1<<40)) // 1 TiB string length
	b.WriteString("x")
	p := writeFixture(t, "oversize.gguf", b.Bytes())

	if _, err := ReadArtifact(p); err == nil {
		t.Fatal("expected an error on an oversize string length, got nil")
	}
}

func TestQuantFromFileName(t *testing.T) {
	cases := map[string]string{
		"google_gemma-3-12b-it-Q5_K_M.gguf":         "Q5_K_M",
		"model-Q4_K_S.gguf":                         "Q4_K_S",
		"deepseek-coder-33b-Q8_0.gguf":              "Q8_0",
		"Llama-3-8B-BF16.gguf":                      "BF16",
		"MiniMax-M2.7-UD-IQ3_S-00003-of-00003.gguf": "IQ3_S",
		"Qwen3.6-35B-A3B-UD-Q4_K_M.gguf":            "Q4_K_M",
		"ggml-vocab-qwen2.gguf":                     "", // a name starting with Q is not a quant
		"ggml-vocab-qwen35.gguf":                    "",
		"plain.gguf":                                "",
	}
	for name, want := range cases {
		if got := QuantFromFileName(name); got != want {
			t.Errorf("QuantFromFileName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestSplitMetadata(t *testing.T) {
	kvs := append(gguftest.Clean(),
		gguftest.U32("split.no", 1),
		gguftest.U32("split.count", 3),
		gguftest.U32("split.tensors.count", 809),
	)
	p := writeFixture(t, "shard-00002-of-00003-Q8_0.gguf", gguftest.BuildGGUF(kvs))

	m, err := ReadHeader(p)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !m.MultiPart() {
		t.Fatal("a shard must be reported as part of a split model")
	}
	if m.Split.No != 1 || m.Split.Count != 3 || m.Split.TensorCount != 809 {
		t.Errorf("split = %+v, want no=1 count=3 tensors=809", m.Split)
	}
}

// Real GGUF files store split metadata at mixed widths. The MiniMax shards on
// disk use uint16 for split.no and split.count and int32 for
// split.tensors.count. A reader that only decodes uint32 silently drops them.
func TestMixedWidthSplitMetadata(t *testing.T) {
	kvs := append(gguftest.Clean(),
		gguftest.U16("split.no", 1),
		gguftest.U16("split.count", 3),
		gguftest.I32("split.tensors.count", 809),
	)
	p := writeFixture(t, "shard-mixed-Q8_0.gguf", gguftest.BuildGGUF(kvs))

	m, err := ReadHeader(p)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !m.MultiPart() {
		t.Fatal("uint16 split metadata must be captured, not dropped")
	}
	if m.Split.No != 1 || m.Split.Count != 3 || m.Split.TensorCount != 809 {
		t.Errorf("split = %+v, want no=1 count=3 tensors=809", m.Split)
	}
}

func TestWholeModelIsNotMultiPart(t *testing.T) {
	p := writeFixture(t, "whole-Q8_0.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	m, err := ReadHeader(p)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if m.MultiPart() {
		t.Error("a model with no split metadata must not report as multi-part")
	}
}

// TestNestedArrayRejected: an ARRAY whose element type is ARRAY recursed with
// no bound, and a few megabytes of nested headers overflowed the goroutine
// stack, a fatal error that recover cannot catch. llama.cpp forbids nested
// arrays, so the reader rejects them at the first nested header, before any
// recursion. Falsification: allow element type ARRAY in skipArray and the
// reader recurses two million frames deep and fails with EOF, not the named
// rejection (at ~8M levels it is a fatal stack overflow instead).
func TestNestedArrayRejected(t *testing.T) {
	const depth = 2_000_000
	var b bytes.Buffer
	b.WriteString("GGUF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	_ = binary.Write(&b, binary.LittleEndian, uint64(1))
	_ = binary.Write(&b, binary.LittleEndian, uint64(1))
	b.WriteString("x")
	_ = binary.Write(&b, binary.LittleEndian, uint32(9)) // value type ARRAY
	for i := 0; i < depth; i++ {
		_ = binary.Write(&b, binary.LittleEndian, uint32(9)) // element type ARRAY
		_ = binary.Write(&b, binary.LittleEndian, uint64(1)) // one element
	}
	p := writeFixture(t, "nested.gguf", b.Bytes())

	_, err := ReadHeader(p)
	if err == nil {
		t.Fatal("expected an error on a nested array, got nil")
	}
	if !strings.Contains(err.Error(), "nested array") {
		t.Fatalf("expected a nested-array error, got %v", err)
	}
}

// bigArrayGGUF is a header with one uint8 array of n elements and a string key
// after it, so a reader that mis-skips the array misreads the next key.
func bigArrayGGUF(n uint64) []byte {
	var b bytes.Buffer
	b.WriteString("GGUF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	_ = binary.Write(&b, binary.LittleEndian, uint64(2))
	_ = binary.Write(&b, binary.LittleEndian, uint64(len("big")))
	b.WriteString("big")
	_ = binary.Write(&b, binary.LittleEndian, uint32(9)) // ARRAY
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // of UINT8
	_ = binary.Write(&b, binary.LittleEndian, n)
	b.Write(make([]byte, n))
	_ = binary.Write(&b, binary.LittleEndian, uint64(len("general.name")))
	b.WriteString("general.name")
	_ = binary.Write(&b, binary.LittleEndian, uint32(8)) // STRING
	_ = binary.Write(&b, binary.LittleEndian, uint64(len("after")))
	b.WriteString("after")
	return b.Bytes()
}

// TestLargeArrayParsesQuickly: the reader issued one unbuffered read syscall
// per array element, so a 64 MB uint8 array took about a minute and a
// multi-GB hostile header pinned the API for hours. Fixed-width arrays are now
// skipped in one bounded copy through a buffered reader. Falsification: go back
// to per-element unbuffered reads and this blows the budget by an order of
// magnitude.
func TestLargeArrayParsesQuickly(t *testing.T) {
	p := writeFixture(t, "bigarray.gguf", bigArrayGGUF(64<<20))

	start := time.Now()
	m, err := ReadHeader(p)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("a 64 MB array took %s to parse, want well under 5s", elapsed)
	}
	if m.Name != "after" {
		t.Fatalf("the key after the array read as %q; the array was mis-skipped", m.Name)
	}
	inv, err := Inventory(p)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(inv.Strings) != 1 || inv.Strings[0] != "after" {
		t.Fatalf("inventory strings = %q, want [after]", inv.Strings)
	}
}

// TestArrayCountPastEOF: an array that declares more elements than the file
// holds must error, not allocate or spin.
func TestArrayCountPastEOF(t *testing.T) {
	full := bigArrayGGUF(16)
	// Rewrite the element count to an absurd value.
	idx := bytes.Index(full, []byte("big")) + len("big") + 4 + 4
	binary.LittleEndian.PutUint64(full[idx:], 1<<62)
	p := writeFixture(t, "pasteof.gguf", full)
	if _, err := ReadHeader(p); err == nil {
		t.Fatal("expected an error for an array count past EOF")
	}
}
