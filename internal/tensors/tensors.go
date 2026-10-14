// Package tensors fingerprints a model's tensors and compares two models
// tensor by tensor.
//
// A fingerprint names each tensor's dtype and logical shape, the SHA-256 of
// its raw bytes, and, for F32, F16, and BF16, the SHA-256 of its values
// widened exactly to float32. Two models whose tensors match one to one hold
// the same weights, even when one was converted losslessly to another float
// dtype or file format. A match says the weights are the same weights; it says
// nothing about whether those weights are safe.
package tensors

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/safetensors"
)

// Schema names the manifest format.
const Schema = "socair.tensors/v1"

// ValueEncoding names how values are hashed: each element widened exactly to
// IEEE 754 binary32 and written as its four little-endian bytes, in storage
// (row-major) order. F16 and BF16 widen without rounding, and a NaN keeps its
// payload, so the encoding is one-to-one for those dtypes.
const ValueEncoding = "float32-le-bits/v1"

// Manifest is a model's tensor fingerprints.
type Manifest struct {
	Schema        string   `json:"schema"`
	Artifact      Artifact `json:"artifact"`
	ValueEncoding string   `json:"value_encoding"`
	Tensors       []Tensor `json:"tensors"`
	// Unread names files or tensors that could not be fingerprinted, with the
	// reason, so a comparison cannot mistake a gap for a match.
	Unread []string `json:"unread,omitempty"`
}

// Artifact names the model a manifest describes: its subject digest as a
// Socair report gives it (the file's SHA-256, or a model directory's
// manifest digest), when it is known.
type Artifact struct {
	Name   string `json:"name"`
	Format string `json:"format"`
	SHA256 string `json:"sha256,omitempty"`
}

// Tensor is one tensor's fingerprint.
type Tensor struct {
	// File is the tensor's file within a model directory; empty for a
	// single file.
	File string `json:"file,omitempty"`
	Name string `json:"name"`
	// Dtype is the format's own name for the element type: F32, F16, BF16,
	// Q4_K, I64, and so on.
	Dtype string `json:"dtype"`
	// Shape is the logical shape, outermost dimension first, as safetensors
	// and PyTorch write it. GGUF lists dimensions innermost first, so its
	// dimensions are reversed.
	Shape []int64 `json:"shape"`
	Bytes int64   `json:"bytes"`
	// SHA256 is the hash of the tensor's raw bytes.
	SHA256 string `json:"sha256"`
	// Values is the hash of its values in ValueEncoding, for F32, F16, and
	// BF16 only.
	Values string `json:"values,omitempty"`
}

// Limits on what a manifest may hold, so a hostile manifest cannot drive
// memory: a manifest file's size, and its tensor count (GGUF's own limit).
const (
	MaxManifestBytes = 256 << 20
	maxTensors       = 1 << 20
)

// File fingerprints one GGUF or safetensors file. sha is the file's SHA-256
// if the caller has it (a scan does), or empty.
func File(path, sha string) (*Manifest, error) {
	m := &Manifest{Schema: Schema, ValueEncoding: ValueEncoding,
		Artifact: Artifact{Name: filepath.Base(path), SHA256: sha}}
	format, ts, unread, err := fileTensors(path, "")
	if err != nil {
		return nil, err
	}
	m.Artifact.Format = format
	m.Tensors, m.Unread = ts, unread
	m.sort()
	return m, nil
}

// Dir fingerprints the GGUF and safetensors files of a model directory,
// given its files relative to dir. digest is the directory's manifest digest
// if the caller has it, or empty. A file in another format holds no tensors
// this package reads, and is skipped; the caller names those files elsewhere.
func Dir(dir string, files []string, digest string) (*Manifest, error) {
	m := &Manifest{Schema: Schema, ValueEncoding: ValueEncoding,
		Artifact: Artifact{Name: filepath.Base(dir), Format: "model directory", SHA256: digest}}
	for _, rel := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if !isTensorFile(p) {
			continue
		}
		_, ts, unread, err := fileTensors(p, rel)
		if err != nil {
			m.Unread = append(m.Unread, rel+": "+err.Error())
			continue
		}
		m.Tensors = append(m.Tensors, ts...)
		m.Unread = append(m.Unread, unread...)
		if len(m.Tensors) > maxTensors {
			return nil, fmt.Errorf("more than %d tensors", maxTensors)
		}
	}
	m.sort()
	return m, nil
}

func (m *Manifest) sort() {
	sort.Slice(m.Tensors, func(i, j int) bool {
		if m.Tensors[i].File != m.Tensors[j].File {
			return m.Tensors[i].File < m.Tensors[j].File
		}
		return m.Tensors[i].Name < m.Tensors[j].Name
	})
	sort.Strings(m.Unread)
}

func isTensorFile(p string) bool {
	if ok, err := gguf.IsGGUF(p); err == nil && ok {
		return true
	}
	return safetensors.IsSafetensors(p)
}

// span is one tensor's place in its file.
type span struct {
	name, dtype   string
	shape         []int64
	offset, bytes int64
}

// fileTensors fingerprints every tensor of one file. A tensor whose range
// cannot be computed is listed in unread rather than failing the file.
func fileTensors(path, rel string) (format string, ts []Tensor, unread []string, err error) {
	var spans []span
	label := rel
	if label == "" {
		label = filepath.Base(path)
	}
	if ok, gerr := gguf.IsGGUF(path); gerr == nil && ok {
		format = "GGUF"
		h, err := gguf.ReadHeader(path)
		if err != nil {
			return "", nil, nil, err
		}
		if l := h.ValidateLayout(); len(l.Violations) > 0 || l.Truncated != "" {
			// Overlapping or gapped tensor data reads differently in
			// different loaders, as for safetensors below.
			return "", nil, nil, errors.New("the GGUF tensor layout is invalid, so its tensors were not read")
		}
		for _, t := range h.Tensors {
			off, n, err := h.Span(t)
			if err != nil {
				unread = append(unread, label+": "+err.Error())
				continue
			}
			shape := make([]int64, len(t.Dims))
			for i, d := range t.Dims {
				if d > math.MaxInt64 {
					unread = append(unread, fmt.Sprintf("%s: tensor %q dimension %d is out of range", label, t.Name, d))
					shape = nil
					break
				}
				shape[len(t.Dims)-1-i] = int64(d)
			}
			if shape == nil {
				continue
			}
			spans = append(spans, span{t.Name, gguf.TypeName(t.Type), shape, off, n})
		}
	} else if safetensors.IsSafetensors(path) {
		format = "safetensors"
		h, err := safetensors.ReadHeader(path)
		if err != nil {
			return "", nil, nil, err
		}
		if len(h.Malformed) > 0 || len(h.Layout) > 0 || len(h.Duplicates) > 0 {
			// A header whose entries overlap, repeat, or leave gaps reads
			// differently in different loaders, so its tensors are not
			// fingerprinted at all: Format and structure names why.
			return "", nil, nil, errors.New("the safetensors header is malformed or its layout is invalid, so its tensors were not read")
		}
		for _, e := range h.Entries {
			shape := append([]int64(nil), e.Shape...)
			spans = append(spans, span{e.Name, e.Dtype, shape, h.DataStart + e.Begin, e.End - e.Begin})
		}
	} else {
		return "", nil, nil, errors.New("not a GGUF or safetensors file")
	}

	f, err := os.Open(path)
	if err != nil {
		return "", nil, nil, err
	}
	defer f.Close()
	// One pair of buffers per file, sized to its largest tensor up to chunk.
	var most int64
	for _, sp := range spans {
		most = max(most, sp.bytes)
	}
	size := int(min(most, chunk))
	buf, out := make([]byte, size), make([]byte, 2*size)
	for _, sp := range spans {
		t, err := fingerprint(f, sp, buf, out)
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s: tensor %q: %v", label, sp.name, err))
			continue
		}
		t.File = rel
		ts = append(ts, t)
	}
	return format, ts, unread, nil
}

// widen returns the function that writes one element of dtype as float32
// little-endian bits, and the element's width in bytes, or nil for a dtype
// with no exact float32 encoding.
func widen(dtype string) (func(dst, src []byte), int) {
	switch dtype {
	case "F32":
		return func(dst, src []byte) { copy(dst, src[:4]) }, 4
	case "F16":
		return func(dst, src []byte) {
			binary.LittleEndian.PutUint32(dst, f16ToF32Bits(binary.LittleEndian.Uint16(src)))
		}, 2
	case "BF16":
		return func(dst, src []byte) {
			binary.LittleEndian.PutUint32(dst, uint32(binary.LittleEndian.Uint16(src))<<16)
		}, 2
	}
	return nil, 0
}

// f16ToF32Bits widens IEEE 754 binary16 bits to binary32 bits exactly:
// subnormals are normalized, and an infinity or NaN keeps its sign and its
// payload (shifted into the top of the wider mantissa), so distinct inputs
// give distinct outputs.
func f16ToF32Bits(h uint16) uint32 {
	sign := uint32(h>>15) << 31
	exp := uint32(h>>10) & 0x1f
	mant := uint32(h) & 0x3ff
	switch {
	case exp == 0 && mant == 0:
		return sign
	case exp == 0:
		// Subnormal: shift the mantissa up until its leading one reaches the
		// implicit bit, lowering the exponent once per shift.
		e := uint32(127 - 15 + 1)
		for mant&0x400 == 0 {
			mant <<= 1
			e--
		}
		return sign | e<<23 | (mant&0x3ff)<<13
	case exp == 0x1f:
		return sign | 0xff<<23 | mant<<13
	default:
		return sign | (exp+127-15)<<23 | mant<<13
	}
}

const chunk = 1 << 20 // a multiple of every element width

// fingerprint hashes one tensor's bytes, and its values when its dtype has a
// float32 encoding, in a single pass. buf is a read buffer whose length is a
// multiple of every element width, and out is twice its length.
func fingerprint(f *os.File, sp span, buf, out []byte) (Tensor, error) {
	t := Tensor{Name: sp.name, Dtype: sp.dtype, Shape: sp.shape, Bytes: sp.bytes}
	raw := sha256.New()
	var vals hash.Hash
	conv, width := widen(sp.dtype)
	if conv != nil {
		if sp.bytes%int64(width) != 0 {
			return Tensor{}, fmt.Errorf("%d bytes is not a whole number of %s elements", sp.bytes, sp.dtype)
		}
		vals = sha256.New()
	}
	r := io.NewSectionReader(f, sp.offset, sp.bytes)
	for read := int64(0); read < sp.bytes; {
		n := len(buf)
		if rest := sp.bytes - read; rest < int64(n) {
			n = int(rest)
		}
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return Tensor{}, fmt.Errorf("short read: %w", err)
		}
		raw.Write(buf[:n])
		if vals != nil {
			o := 0
			for i := 0; i < n; i += width {
				conv(out[o:o+4], buf[i:i+width])
				o += 4
			}
			vals.Write(out[:o])
		}
		read += int64(n)
	}
	t.SHA256 = hex.EncodeToString(raw.Sum(nil))
	if vals != nil {
		t.Values = hex.EncodeToString(vals.Sum(nil))
	}
	return t, nil
}
