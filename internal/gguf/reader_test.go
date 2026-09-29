package gguf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
		"google_gemma-3-12b-it-Q5_K_M.gguf": "Q5_K_M",
		"model-Q4_K_S.gguf":                 "Q4_K_S",
		"deepseek-coder-33b-Q8_0.gguf":      "Q8_0",
		"Llama-3-8B-BF16.gguf":              "BF16",
		"plain.gguf":                        "",
	}
	for name, want := range cases {
		if got := QuantFromFileName(name); got != want {
			t.Errorf("QuantFromFileName(%q) = %q, want %q", name, got, want)
		}
	}
}
