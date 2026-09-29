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
)

const (
	vString = typeString
	vU32    = typeUint32
)

type kvpair struct {
	key   string
	vtype uint32
	str   string
	u32   uint32
}

func strKV(key, val string) kvpair      { return kvpair{key: key, vtype: vString, str: val} }
func u32KV(key string, v uint32) kvpair { return kvpair{key: key, vtype: vU32, u32: v} }

func writeStr(b *bytes.Buffer, s string) {
	_ = binary.Write(b, binary.LittleEndian, uint64(len(s)))
	b.WriteString(s)
}

// buildGGUF assembles a minimal GGUF v3 container with the given metadata.
func buildGGUF(kvs []kvpair) []byte {
	var b bytes.Buffer
	b.WriteString("GGUF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	_ = binary.Write(&b, binary.LittleEndian, uint64(0)) // tensor count
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(kvs)))
	for _, p := range kvs {
		writeStr(&b, p.key)
		_ = binary.Write(&b, binary.LittleEndian, p.vtype)
		switch p.vtype {
		case vString:
			writeStr(&b, p.str)
		case vU32:
			_ = binary.Write(&b, binary.LittleEndian, p.u32)
		default:
			panic("fixture builder: unsupported type")
		}
	}
	return b.Bytes()
}

func cleanFixture() []kvpair {
	return []kvpair{
		strKV("general.name", "Fixture Model"),
		strKV("general.architecture", "llama"),
		strKV("general.size_label", "1B"),
		u32KV("general.file_type", 17),
		u32KV("general.quantization_version", 2),
		strKV("tokenizer.ggml.model", "llama"),
		strKV("tokenizer.chat_template", "{{ bos_token }}\n{{ messages }}"),
	}
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

func TestReadArtifactValidFixture(t *testing.T) {
	data := buildGGUF(cleanFixture())
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

func TestReadArtifactBadMagic(t *testing.T) {
	p := writeFixture(t, "bad.gguf", append([]byte("NOPE"), buildGGUF(cleanFixture())...))
	if _, err := ReadArtifact(p); !errors.Is(err, ErrNotGGUF) {
		t.Fatalf("err = %v, want ErrNotGGUF", err)
	}
}

func TestReadArtifactTruncatedHeader(t *testing.T) {
	full := buildGGUF(cleanFixture())
	p := writeFixture(t, "truncated.gguf", full[:6])
	_, err := ReadArtifact(p)
	if err == nil {
		t.Fatal("expected an error on a truncated header, got nil")
	}
	if !errors.Is(err, ErrNotGGUF) && !errors.Is(err, os.ErrClosed) {
		// any wrapped read error is acceptable; the point is no panic and a typed failure
		t.Logf("typed error: %v", err)
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
