// Package safetensors reads safetensors artifacts into a manifest.
//
// It reads the JSON header only and never reads or executes tensor data. The
// format is deliberately not pickle, so the pickle opcode scan does not apply
// to it; that check names the format it looked at.
package safetensors

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
)

// maxHeaderBytes caps the JSON header so a malformed length cannot drive an
// unbounded allocation. It is the reference implementation's limit, so a
// header the Rust loader accepts is not misread here as "not safetensors".
const maxHeaderBytes = 100_000_000

// dtypeBits is the element width of each safetensors dtype, from the
// reference implementation. A dtype outside this table is not malformed (the
// format keeps adding types) but its layout cannot be checked.
var dtypeBits = map[string]uint64{
	"BOOL": 8, "U8": 8, "I8": 8, "F8_E5M2": 8, "F8_E4M3": 8, "F8_E8M0": 8,
	"I16": 16, "U16": 16, "F16": 16, "BF16": 16,
	"I32": 32, "U32": 32, "F32": 32,
	"I64": 64, "U64": 64, "F64": 64, "C64": 64,
	"F4": 4, "F6_E2M3": 6, "F6_E3M2": 6,
}

// bodyHashes counts full-file hashes, so a test can hold a scan to one.
var bodyHashes atomic.Int64

// BodyHashes reports how many times ReadArtifact has hashed a whole file.
// It is instrumentation for tests that bound a scan's reads.
func BodyHashes() int64 { return bodyHashes.Load() }

// ErrNotSafetensors is returned when the file is not a safetensors container.
var ErrNotSafetensors = errors.New("safetensors: not a safetensors file")

// TensorInfo is one tensor's header entry.
type TensorInfo struct {
	Dtype string  `json:"dtype"`
	Shape []int64 `json:"shape"`
	Begin int64   `json:"-"`
	End   int64   `json:"-"`
}

// Manifest is the identity and header summary of one safetensors artifact.
type Manifest struct {
	Path         string   `json:"path"`
	FileName     string   `json:"file_name"`
	SizeBytes    int64    `json:"size_bytes"`
	SHA256       string   `json:"sha256"`
	Format       string   `json:"format"`
	TensorCount  int      `json:"tensor_count"`
	MetadataKeys []string `json:"metadata_keys,omitempty"`
	HeaderSHA256 string   `json:"header_sha256"`
	DataBytes    int64    `json:"data_bytes"`
	Malformed    []string `json:"malformed,omitempty"`
	// Layout lists violations of the tensor layout: overlapping or
	// non-contiguous ranges, data bytes no tensor accounts for, a range whose
	// size does not match its shape and dtype, or an impossible shape. The
	// reference loader rejects every one, and a gap is where a payload hides.
	Layout []string `json:"layout,omitempty"`
	// Unverified lists tensors whose layout could not be checked, such as a
	// dtype outside the known table.
	Unverified []string `json:"unverified,omitempty"`
	// Duplicates lists header keys that appear more than once. A JSON object
	// with a repeated key means different readers see different tensors.
	Duplicates []string `json:"duplicates,omitempty"`

	// Tensors names every tensor in the header, sorted, for checking a
	// sharded set against its index. Not serialized.
	Tensors []string `json:"-"`

	// Metadata holds the decoded __metadata__ values for the inventory check.
	// Not serialized: the report carries keys, not values.
	Metadata map[string]string `json:"-"`
}

type headerEntry struct {
	Dtype       string  `json:"dtype"`
	Shape       []int64 `json:"shape"`
	DataOffsets []int64 `json:"data_offsets"`
}

// IsSafetensors sniffs the header length and a JSON object start.
func IsSafetensors(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return false
	}
	var lenBuf [8]byte
	if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
		return false
	}
	n := int64(binary.LittleEndian.Uint64(lenBuf[:]))
	if n <= 0 || n > maxHeaderBytes || 8+n > info.Size() {
		return false
	}
	first := make([]byte, 1)
	if _, err := f.ReadAt(first, 8); err != nil {
		return false
	}
	return first[0] == '{'
}

// ReadArtifact parses the safetensors header at path and returns its manifest,
// including a SHA256 of the exact file bytes. It reads the header only.
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

	bodyHashes.Add(1)
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return nil, err
	}
	m.SHA256 = hex.EncodeToString(sum.Sum(nil))
	return m, nil
}

// ReadHeader parses the safetensors header at path without hashing the file.
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

	var lenBuf [8]byte
	if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
		return nil, ErrNotSafetensors
	}
	// An implausible length means this is not a safetensors container, rather
	// than a separate "header too large" case.
	n := int64(binary.LittleEndian.Uint64(lenBuf[:]))
	if n <= 0 || n > maxHeaderBytes || 8+n > info.Size() {
		return nil, ErrNotSafetensors
	}

	raw := make([]byte, n)
	if _, err := io.ReadFull(f, raw); err != nil {
		return nil, fmt.Errorf("safetensors: reading header: %w", err)
	}

	m, err := parseHeader(raw, info.Size())
	if err != nil {
		return nil, err
	}
	m.Path = path
	m.FileName = filepath.Base(path)
	return m, nil
}

// parseHeader parses a safetensors JSON header of a file of fileSize bytes.
// It touches no file, so it can be fuzzed directly.
func parseHeader(raw []byte, fileSize int64) (*Manifest, error) {
	n := int64(len(raw))
	headerSum := sha256.Sum256(raw)
	m := &Manifest{
		SizeBytes:    fileSize,
		Format:       "safetensors",
		HeaderSHA256: hex.EncodeToString(headerSum[:]),
		DataBytes:    fileSize - 8 - n,
	}

	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("safetensors: header is not valid JSON: %w", err)
	}
	// Decoding into a map keeps only the last of a repeated key, so the
	// repeats are found on the raw token stream.
	m.Duplicates = duplicateTopLevelKeys(raw)

	type span struct {
		name       string
		begin, end int64
	}
	var spans []span
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		rawEntry := entries[name]
		if name == "__metadata__" {
			var meta map[string]string
			if err := json.Unmarshal(rawEntry, &meta); err != nil {
				m.Malformed = append(m.Malformed, "__metadata__ is not a string map")
				continue
			}
			m.Metadata = meta
			for k := range meta {
				m.MetadataKeys = append(m.MetadataKeys, k)
			}
			sort.Strings(m.MetadataKeys)
			continue
		}

		var e headerEntry
		if err := json.Unmarshal(rawEntry, &e); err != nil {
			m.Malformed = append(m.Malformed, name+": entry is not a tensor header")
			continue
		}
		m.TensorCount++
		m.Tensors = append(m.Tensors, name)
		if e.Dtype == "" {
			m.Malformed = append(m.Malformed, name+": missing dtype")
		}
		if len(e.DataOffsets) != 2 {
			m.Malformed = append(m.Malformed, name+": data_offsets is not a pair")
			continue
		}
		begin, end := e.DataOffsets[0], e.DataOffsets[1]
		if begin < 0 || end < begin {
			m.Malformed = append(m.Malformed, fmt.Sprintf("%s: data_offsets [%d,%d] is not a valid range", name, begin, end))
			continue
		}
		if end > m.DataBytes {
			m.Malformed = append(m.Malformed, fmt.Sprintf("%s: data_offsets end %d exceeds the data section of %d bytes", name, end, m.DataBytes))
			continue
		}
		spans = append(spans, span{name, begin, end})

		if e.Dtype == "" {
			continue
		}
		width, known := dtypeBits[e.Dtype]
		if !known {
			m.Unverified = append(m.Unverified, fmt.Sprintf("%s: dtype %q is not in the known dtype table, so its size was not checked", name, e.Dtype))
			continue
		}
		if want, problem := tensorBytes(e.Shape, width); problem != "" {
			m.Layout = append(m.Layout, name+": "+problem)
		} else if want != uint64(end-begin) {
			m.Layout = append(m.Layout, fmt.Sprintf("%s: shape %v of %s holds %d bytes but data_offsets span %d", name, e.Shape, e.Dtype, want, end-begin))
		}
	}

	// The ranges must tile the data section exactly: start at 0, meet end to
	// start, and finish at its last byte. Checked only when every range is
	// sound, so one bad entry is not reported twice.
	if len(m.Malformed) == 0 {
		sort.Slice(spans, func(i, j int) bool {
			if spans[i].begin != spans[j].begin {
				return spans[i].begin < spans[j].begin
			}
			return spans[i].end < spans[j].end
		})
		var at int64
		last := ""
		for _, sp := range spans {
			switch {
			case sp.begin < at:
				m.Layout = append(m.Layout, fmt.Sprintf("%s [%d,%d] overlaps %s, which runs to %d", sp.name, sp.begin, sp.end, last, at))
			case sp.begin > at:
				m.Layout = append(m.Layout, fmt.Sprintf("gap of %d unaccounted bytes at [%d,%d] before %s", sp.begin-at, at, sp.begin, sp.name))
			}
			if sp.end > at {
				at, last = sp.end, sp.name
			}
		}
		if at < m.DataBytes {
			m.Layout = append(m.Layout, fmt.Sprintf("%d data bytes at [%d,%d] are not covered by any tensor", m.DataBytes-at, at, m.DataBytes))
		}
	}
	sort.Strings(m.Layout)
	sort.Strings(m.Unverified)

	// The entries were walked in map order, which Go randomizes. Sort so the
	// manifest, and every report built from it, is byte-stable.
	sort.Strings(m.Malformed)

	return m, nil
}

// duplicateTopLevelKeys returns the keys repeated in a JSON object, sorted. It
// walks tokens and skips each value whole, so nested objects are not mistaken
// for top-level keys.
func duplicateTopLevelKeys(raw []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	seen := make(map[string]bool)
	dup := make(map[string]bool)
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return sortedKeys(dup)
		}
		k, ok := t.(string)
		if !ok {
			return sortedKeys(dup)
		}
		if seen[k] {
			dup[k] = true
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return sortedKeys(dup)
		}
	}
	return sortedKeys(dup)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tensorBytes is the byte size of a tensor of the given shape and element
// width in bits, or a description of why the shape is impossible.
func tensorBytes(shape []int64, width uint64) (uint64, string) {
	n := uint64(1)
	for _, d := range shape {
		if d < 0 {
			return 0, fmt.Sprintf("shape %v has a negative dimension", shape)
		}
		hi, lo := bits.Mul64(n, uint64(d))
		if hi != 0 {
			return 0, fmt.Sprintf("shape %v overflows the element count", shape)
		}
		n = lo
	}
	hi, total := bits.Mul64(n, width)
	if hi != 0 {
		return 0, fmt.Sprintf("shape %v overflows the byte size", shape)
	}
	if total%8 != 0 {
		return 0, fmt.Sprintf("shape %v does not fill whole bytes at %d bits per element", shape, width)
	}
	return total / 8, ""
}
