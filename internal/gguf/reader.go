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
	"math"
	"os"
	"path/filepath"
	"regexp"
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
	ChatTemplateSHA256  string `json:"chat_template_sha256,omitempty"`

	// ChatTemplate is the raw template bytes, for the hero check. Not serialized
	// directly; the report carries only its hash.
	ChatTemplate string `json:"-"`

	Quant Quant  `json:"quant"`
	Split *Split `json:"split,omitempty"`
}

// Split records that an artifact is one shard of a multi-part model. A shard
// read as if it were a whole model is a real hazard, so this is surfaced, not
// inferred.
type Split struct {
	No          uint32 `json:"no"`
	Count       uint32 `json:"count"`
	TensorCount uint32 `json:"tensors"`
}

// MultiPart reports whether this artifact is one shard of a split model.
func (m *Manifest) MultiPart() bool {
	return m.Split != nil && m.Split.Count > 1
}

// ErrNotGGUF is returned when the file does not start with the GGUF magic.
var ErrNotGGUF = errors.New("gguf: not a GGUF file")

// IsGGUF reports whether the file starts with the GGUF magic. It reads four
// bytes and parses nothing, so a malformed GGUF is still GGUF here and its
// parse error surfaces from the reader.
func IsGGUF(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var b [4]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return false, nil
	}
	return string(b[:]) == magic, nil
}

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
	"split.no":                     {},
	"split.count":                  {},
	"split.tensors.count":          {},
}

// ReadHeader parses the GGUF header and metadata at path without hashing the
// file. Use it when only structure and metadata matter.
func ReadHeader(path string) (*Manifest, error) {
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
	return m, nil
}

// ReadArtifact parses the GGUF header and metadata at path and returns its
// manifest, including a SHA256 of the exact file bytes.
func ReadArtifact(path string) (*Manifest, error) {
	m, err := ReadHeader(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

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
		m.ChatTemplate = s
		m.ChatTemplatePresent = s != ""
		m.ChatTemplateBytes = len(s)
		sum := sha256.Sum256([]byte(s))
		m.ChatTemplateSHA256 = hex.EncodeToString(sum[:])
	case "general.file_type":
		if v, ok := asUint(val); ok {
			m.Quant.FileType = &v
		}
	case "general.quantization_version":
		if v, ok := asUint(val); ok {
			m.Quant.QuantVersion = &v
		}
	case "split.no":
		if v, ok := asUint(val); ok {
			m.ensureSplit().No = v
		}
	case "split.count":
		if v, ok := asUint(val); ok {
			m.ensureSplit().Count = v
		}
	case "split.tensors.count":
		if v, ok := asUint(val); ok {
			m.ensureSplit().TensorCount = v
		}
	}
}

func (m *Manifest) ensureSplit() *Split {
	if m.Split == nil {
		m.Split = &Split{}
	}
	return m.Split
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
	case typeUint8, typeInt8, typeBool:
		return readInt(f, 1, capture)
	case typeUint16, typeInt16:
		return readInt(f, 2, capture)
	case typeUint32, typeInt32, typeFloat32:
		return readInt(f, 4, capture)
	case typeUint64, typeInt64, typeFloat64:
		return readInt(f, 8, capture)
	case typeArray:
		return nil, skipArray(f)
	default:
		return nil, fmt.Errorf("unknown metadata value type %d", t)
	}
}

// readInt reads an n-byte little-endian integer. Real GGUF metadata stores the
// same field as different widths across writers (split.count is uint16 in
// some files), so all integer widths are decoded, not just uint32.
func readInt(f io.Reader, n int, capture bool) (any, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	if !capture {
		return nil, nil
	}
	var v uint64
	for i := n - 1; i >= 0; i-- {
		v = v<<8 | uint64(buf[i])
	}
	return v, nil
}

// asUint converts a decoded integer to uint32, rejecting values that would
// truncate.
func asUint(v any) (uint32, bool) {
	u, ok := v.(uint64)
	if !ok {
		return 0, false
	}
	if u > math.MaxUint32 {
		return 0, false
	}
	return uint32(u), true
}

func skipArray(f io.Reader) error {
	elemType, err := readU32(f)
	if err != nil {
		return err
	}
	// llama.cpp forbids nested arrays. Rejecting them here also bounds the
	// recursion: without this, nested headers recurse once per level and a
	// hostile file overflows the stack, a fatal error recover cannot catch.
	if elemType == typeArray {
		return errors.New("gguf: nested array in metadata is not valid GGUF")
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

// quantField matches a GGML quantization tag: a plain type (Q4_0, Q5_K_M), an
// IQ type (IQ3_S, IQ4_XS), or a float type. Deliberately strict, so a model
// name that merely starts with Q (for example a "qwen2" vocab file) is not
// mistaken for a quantization.
var quantField = regexp.MustCompile(`^(IQ[0-9][A-Z0-9_]*|Q[0-9][A-Z0-9_]*|BF16|F16|F32)$`)

// QuantFromFileName extracts a quantization label such as Q5_K_M or IQ3_S from
// an artifact file name, for the declared-vs-observed comparison. Prefix tags
// like UD- and shard parts are ignored because the label is a standalone field.
func QuantFromFileName(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	fields := strings.FieldsFunc(base, func(r rune) bool {
		return r == '-' || r == '.'
	})
	for _, f := range fields {
		up := strings.ToUpper(f)
		if quantField.MatchString(up) {
			return up
		}
	}
	return ""
}
