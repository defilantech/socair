// Package gguf reads GGUF artifacts into an ArtifactManifest.
//
// The reader never executes artifact bytes. It parses the container header and
// metadata only, and streams the file once to hash it. Malformed input yields a
// typed error, never a panic.
package gguf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const magic = "GGUF"

// maxStringBytes caps a single metadata string so a malformed length cannot
// drive an unbounded allocation.
const maxStringBytes = 64 << 20

// GGUF metadata value types.
const (
	typeUint8   = 0
	typeInt8    = 1
	typeUint16  = 2
	typeInt16   = 3
	typeUint32  = 4
	typeInt32   = 5
	typeFloat32 = 6
	typeBool    = 7
	typeString  = 8
	typeArray   = 9
	typeUint64  = 10
	typeInt64   = 11
	typeFloat64 = 12
)

// Quant records the declared and observed quantization of the artifact.
type Quant struct {
	Declared     string  `json:"declared,omitempty"`
	FileType     *uint32 `json:"file_type,omitempty"`
	QuantVersion *uint32 `json:"quantization_version,omitempty"`
}

// Manifest is the identity and metadata of one GGUF artifact.
type Manifest struct {
	Path                string `json:"path"`
	FileName            string `json:"file_name"`
	SizeBytes           int64  `json:"size_bytes"`
	SHA256              string `json:"sha256"`
	Format              string `json:"format"`
	Version             uint32 `json:"gguf_version"`
	TensorCount         uint64 `json:"tensor_count"`
	KVCount             uint64 `json:"kv_count"`
	Name                string `json:"name,omitempty"`
	Architecture        string `json:"architecture,omitempty"`
	SizeLabel           string `json:"size_label,omitempty"`
	TokenizerModel      string `json:"tokenizer_model,omitempty"`
	ChatTemplatePresent bool   `json:"chat_template_present"`
	ChatTemplateBytes   int    `json:"chat_template_bytes"`
	Quant               Quant  `json:"quant"`
}

// ErrNotGGUF is returned when the file does not start with the GGUF magic.
var ErrNotGGUF = errors.New("gguf: not a GGUF file")

// wanted is the set of metadata keys we capture. The value type determines how
// each is decoded.
var wanted = map[string]struct{}{
	"general.name":                 {},
	"general.architecture":         {},
	"general.size_label":           {},
	"tokenizer.ggml.model":         {},
	"tokenizer.chat_template":      {},
	"general.file_type":            {},
	"general.quantization_version": {},
}

// ReadArtifact parses the GGUF header and metadata at path and returns its
// manifest, including a SHA256 of the exact file bytes.
func ReadArtifact(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	m := &Manifest{
		Path:      path,
		FileName:  filepath.Base(path),
		SizeBytes: info.Size(),
		Format:    "GGUF",
		Quant:     Quant{Declared: QuantFromFileName(filepath.Base(path))},
	}

	if err := readHeader(f, m); err != nil {
		return nil, err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	m.SHA256 = hex.EncodeToString(h.Sum(nil))

	return m, nil
}

func readHeader(f io.Reader, m *Manifest) error {
	var magicBuf [4]byte
	if _, err := io.ReadFull(f, magicBuf[:]); err != nil {
		return fmt.Errorf("gguf: reading magic: %w", err)
	}
	if string(magicBuf[:]) != magic {
		return ErrNotGGUF
	}

	version, err := readU32(f)
	if err != nil {
		return fmt.Errorf("gguf: reading version: %w", err)
	}
	m.Version = version

	if m.TensorCount, err = readU64(f); err != nil {
		return fmt.Errorf("gguf: reading tensor count: %w", err)
	}
	if m.KVCount, err = readU64(f); err != nil {
		return fmt.Errorf("gguf: reading kv count: %w", err)
	}

	for i := uint64(0); i < m.KVCount; i++ {
		key, err := readString(f)
		if err != nil {
			return fmt.Errorf("gguf: reading key %d: %w", i, err)
		}
		vtype, err := readU32(f)
		if err != nil {
			return fmt.Errorf("gguf: reading type for %q: %w", key, err)
		}

		_, isWanted := wanted[key]
		val, err := scanValue(f, vtype, isWanted)
		if err != nil {
			return fmt.Errorf("gguf: reading value for %q: %w", key, err)
		}
		if !isWanted {
			continue
		}
		applyWanted(m, key, val)
	}
	return nil
}

func applyWanted(m *Manifest, key string, val any) {
	switch key {
	case "general.name":
		m.Name = asString(val)
	case "general.architecture":
		m.Architecture = asString(val)
	case "general.size_label":
		m.SizeLabel = asString(val)
	case "tokenizer.ggml.model":
		m.TokenizerModel = asString(val)
	case "tokenizer.chat_template":
		s := asString(val)
		m.ChatTemplatePresent = s != ""
		m.ChatTemplateBytes = len(s)
	case "general.file_type":
		if v, ok := val.(uint32); ok {
			m.Quant.FileType = &v
		}
	case "general.quantization_version":
		if v, ok := val.(uint32); ok {
			m.Quant.QuantVersion = &v
		}
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// scanValue reads a metadata value of type t. When capture is true it returns
// the decoded string or uint32 value; otherwise it returns nil after skipping.
func scanValue(f io.Reader, t uint32, capture bool) (any, error) {
	switch t {
	case typeString:
		s, err := readString(f)
		if err != nil {
			return nil, err
		}
		if capture {
			return s, nil
		}
		return nil, nil
	case typeUint32:
		v, err := readU32(f)
		if err != nil {
			return nil, err
		}
		if capture {
			return v, nil
		}
		return nil, nil
	case typeUint64:
		return nil, skipN(f, 8)
	case typeInt64:
		return nil, skipN(f, 8)
	case typeFloat64:
		return nil, skipN(f, 8)
	case typeUint8, typeInt8, typeBool:
		return nil, skipN(f, 1)
	case typeUint16, typeInt16:
		return nil, skipN(f, 2)
	case typeInt32, typeFloat32:
		return nil, skipN(f, 4)
	case typeArray:
		return nil, skipArray(f)
	default:
		return nil, fmt.Errorf("unknown metadata value type %d", t)
	}
}

func skipArray(f io.Reader) error {
	elemType, err := readU32(f)
	if err != nil {
		return err
	}
	count, err := readU64(f)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		if _, err := scanValue(f, elemType, false); err != nil {
			return err
		}
	}
	return nil
}

func skipN(f io.Reader, n int64) error {
	_, err := io.CopyN(io.Discard, f, n)
	return err
}

func readU32(f io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readU64(f io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func readString(f io.Reader) (string, error) {
	n, err := readU64(f)
	if err != nil {
		return "", err
	}
	if n > maxStringBytes {
		return "", fmt.Errorf("string length %d exceeds cap %d", n, maxStringBytes)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// QuantFromFileName extracts a quantization label such as Q5_K_M from an
// artifact file name, for the declared-vs-observed comparison.
func QuantFromFileName(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	fields := strings.FieldsFunc(base, func(r rune) bool {
		return r == '-' || r == '.'
	})
	for _, f := range fields {
		up := strings.ToUpper(f)
		switch up {
		case "BF16", "F16", "F32", "Q8_0", "Q6_K", "Q5_K_M", "Q5_K_S", "Q5_0", "Q5_1",
			"Q4_K_M", "Q4_K_S", "Q4_0", "Q4_1", "Q3_K_M", "Q3_K_S", "Q2_K":
			return up
		}
	}
	// Fall back to any field that looks like a GGML quant tag.
	for _, f := range fields {
		up := strings.ToUpper(f)
		if strings.HasPrefix(up, "Q") || up == "BF16" {
			return up
		}
	}
	return ""
}
