// Package keras reads a Keras model for the structure and inventory checks:
// a legacy HDF5 file (.h5, .hdf5), which Keras 2, tf.keras, and Keras 3's
// legacy format write and Hugging Face transformers writes as tf_model.h5,
// or a .keras archive (Keras 3, and Keras 2.13 to 2.15): a zip of
// config.json, metadata.json, and model.weights.h5.
//
// It reads the HDF5 container with internal/hdf5, the model's config (the
// model_config and training_config attributes of an HDF5 file, or an
// archive's config.json) as Python's json module reads it, and lists what in
// the config makes a loader run code or reach outside the file (Analyze).
// It never deserializes the config, loads a weight, or runs anything; the
// checks grade what it finds. docs/keras.md gives the sources.
package keras

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/hdf5"
)

// Kind is what a file is, by its bytes.
type Kind int

const (
	// None is neither HDF5 nor a .keras archive.
	None Kind = iota
	// HDF5 is an HDF5 file: a Keras .h5 model or weights file, or HDF5
	// that is not Keras.
	HDF5
	// Archive is a .keras zip.
	Archive
)

// Archive members (keras/src/saving/saving_lib.py, Keras v3.15.1:
// _CONFIG_FILENAME, _METADATA_FILENAME, _VARS_FNAME_H5, _VARS_FNAME_NPZ,
// _ASSETS_DIRNAME).
const (
	ConfigEntry   = "config.json"
	MetadataEntry = "metadata.json"
	WeightsH5     = "model.weights.h5"
	WeightsNPZ    = "model.weights.npz"
	AssetsDir     = "assets/"
)

// Bounds.
const (
	maxEntries    = 1 << 16
	maxJSONBytes  = 64 << 20 // a config or metadata file
	maxAssetBytes = hdf5.MaxText
	maxTextTotal  = 64 << 20
	maxTextValues = 1 << 20
	// ArrayScanMin is the shortest element of a string-array attribute kept
	// as text, as for GGUF and ONNX string arrays: shorter elements, such as
	// weight names, cannot carry an executable or a long encoded blob.
	ArrayScanMin = 64
)

// Sniff reports what the file at path is by its bytes: HDF5 (its signature
// at offset 0 or after a user block, where the specification allows) or a
// .keras archive (a zip holding config.json and model.weights.h5 or
// model.weights.npz, the members Keras' loader requires). For HDF5 it
// returns the superblock's offset, which is 0 unless a user block precedes
// it.
func Sniff(path string) (Kind, int64) {
	f, err := os.Open(path)
	if err != nil {
		return None, -1
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return None, -1
	}
	return sniff(f, st.Size())
}

func sniff(r io.ReaderAt, size int64) (Kind, int64) {
	if off := hdf5.Find(r, size); off >= 0 {
		return HDF5, off
	}
	var head [4]byte
	if _, err := r.ReadAt(head[:], 0); err != nil || string(head[:]) != "PK\x03\x04" {
		return None, -1
	}
	zr, err := zip.NewReader(r, size)
	if err != nil || len(zr.File) > maxEntries {
		return None, -1
	}
	config, weights := false, false
	for _, zf := range zr.File {
		switch zf.Name {
		case ConfigEntry:
			config = true
		case WeightsH5, WeightsNPZ:
			weights = true
		}
	}
	if config && weights {
		return Archive, 0
	}
	return None, -1
}

// Model is what the reader found.
type Model struct {
	Kind Kind

	// H5 is the HDF5 file: the artifact, or an archive's model.weights.h5.
	// H5Unread says why it was not read, when it was not.
	H5       *hdf5.File
	H5Unread string
	// UserBlock is the size of a user block before the HDF5 superblock,
	// which HDF5 skips.
	UserBlock int64

	// Layout names what the HDF5 file holds, for the notes: a full model,
	// weights only, Keras 3 weights, or HDF5 that is not Keras.
	Layout       string
	KerasVersion string
	Backend      string

	// Configs are the model's configs: model_config and training_config in
	// an HDF5 file, config.json in an archive.
	Configs []Config

	// Entries are an archive's members; Unexpected names the ones Keras'
	// loader does not read, and Duplicates names repeated names.
	Entries    []Entry
	Unexpected []string
	Duplicates []string
	// Escapes are member names that leave the directory an archive is
	// extracted to: an absolute path, a drive, or a ".." component. Keras
	// extracts the whole archive when it has assets.
	Escapes  []string
	Comments int // archive and entry comments, scanned as text

	// Text is the free text, for the inventory: every string attribute
	// value (a string array's elements of ArrayScanMin bytes or more), the
	// keys and string values of the configs and metadata.json, object
	// comments, archive comments, each asset's bytes, and a user block's.
	Text          []string
	TextBytes     int64
	ShortElements int64
	TextTruncated bool
}

// Config is one config document.
type Config struct {
	Source string // "the model_config attribute", "config.json", ...
	Value  any    // decoded, or nil
	// Err says why it was not decoded, or "".
	Err string
}

// Entry is one archive member.
type Entry struct {
	Name   string
	Size   uint64
	Method uint16
}

// Read reads the Keras model at path, which Sniff identified.
func Read(path string) (*Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return ReadFrom(f, st.Size())
}

// ReadFrom reads a Keras model of size bytes through r.
func ReadFrom(r io.ReaderAt, size int64) (*Model, error) {
	kind, off := sniff(r, size)
	switch kind {
	case HDF5:
		return readHDF5(r, size, off)
	case Archive:
		return readArchive(r, size)
	}
	return nil, errors.New("neither HDF5 nor a .keras archive")
}

func readHDF5(f io.ReaderAt, size, off int64) (*Model, error) {
	h, err := hdf5.ReadFrom(f, size)
	if err != nil {
		return nil, err
	}
	m := &Model{Kind: HDF5, H5: h, UserBlock: off}
	if off > 0 {
		b := make([]byte, min(off, maxAssetBytes))
		if _, err := f.ReadAt(b, 0); err != nil {
			return nil, err
		}
		m.keep(string(b))
		if off > maxAssetBytes {
			m.TextTruncated = true
		}
	}
	m.fromHDF5(h, true)
	return m, nil
}

// fromHDF5 takes the Keras facts and the text from an HDF5 file. Configs
// come from the root attributes only when the file is the artifact itself:
// in an archive the config is config.json.
func (m *Model) fromHDF5(h *hdf5.File, configs bool) {
	if len(h.Objects) == 0 {
		return
	}
	root := h.Objects[0]
	for _, o := range h.Objects {
		for i := range o.Attrs {
			a := &o.Attrs[i]
			if a.Truncated {
				m.TextTruncated = true
			}
			isConfig := configs && o == root && (a.Name == "model_config" || a.Name == "training_config")
			for _, v := range a.Strings {
				switch {
				case isConfig:
					// Its keys and values are kept from the decoded config.
				case a.Space.Kind == hdf5.SpaceScalar || len(v) >= ArrayScanMin:
					m.keep(v)
				default:
					m.ShortElements++
				}
			}
		}
		if o.Comment != "" {
			m.keep(o.Comment)
		}
	}
	str := func(name string) string {
		if a := root.Attr(name); a != nil && len(a.Strings) == 1 {
			return a.Strings[0]
		}
		return ""
	}
	if v := str("keras_version"); v != "" {
		m.KerasVersion = v
	}
	if v := str("backend"); v != "" {
		m.Backend = v
	}
	hasConfig := root.Attr("model_config") != nil
	weights := root.Attr("layer_names") != nil || root.Attr("layer_names0") != nil
	keras3 := false
	for _, o := range h.Objects {
		if o.Path == "/layers" || o.Path == "/_layer_checkpoint_dependencies" || o.Path == "/vars" {
			keras3 = true
		}
	}
	switch {
	case hasConfig:
		m.Layout = "a full Keras model (model_config and model_weights)"
	case weights:
		m.Layout = "Keras weights only (layer_names and weight_names, as save_weights and Hugging Face transformers' tf_model.h5 write them), no model config"
	case keras3:
		m.Layout = "Keras 3 weights (layers/<name>/vars), no model config"
	default:
		m.Layout = "HDF5 with no Keras attributes (no model_config or layer_names, no Keras 3 layers group)"
	}
	if !configs {
		return
	}
	for _, name := range []string{"model_config", "training_config"} {
		a := root.Attr(name)
		if a == nil {
			continue
		}
		src := "the " + name + " attribute"
		switch {
		case !a.IsString():
			m.Configs = append(m.Configs, Config{Source: src, Err: "it is not a string (" + a.Type.Name() + ")"})
		case a.Unread != "":
			m.Configs = append(m.Configs, Config{Source: src, Err: a.Unread})
		case a.Truncated || len(a.Strings) != 1:
			m.Configs = append(m.Configs, Config{Source: src, Err: "it is not one string value the reader kept"})
		default:
			m.addConfig(src, []byte(a.Strings[0]))
		}
	}
}

// addConfig decodes a config document and keeps its text.
func (m *Model) addConfig(src string, raw []byte) {
	v, err := DecodeJSON(raw)
	if err != nil {
		m.Configs = append(m.Configs, Config{Source: src, Err: "it is not JSON Python's json module reads: " + err.Error()})
		m.keep(string(raw))
		return
	}
	m.Configs = append(m.Configs, Config{Source: src, Value: v})
	m.jsonText(v, 0)
}

// jsonText keeps a decoded document's object keys and string values.
func (m *Model) jsonText(v any, depth int) {
	if depth > maxJSONDepth {
		m.TextTruncated = true
		return
	}
	switch x := v.(type) {
	case string:
		m.keep(x)
	case []any:
		for _, e := range x {
			m.jsonText(e, depth+1)
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			m.keep(k)
			m.jsonText(x[k], depth+1)
		}
	}
}

// keep adds a value to the text, or marks the text truncated at a cap.
func (m *Model) keep(v string) {
	if v == "" {
		return
	}
	if m.TextBytes+int64(len(v)) > maxTextTotal || len(m.Text) >= maxTextValues {
		m.TextTruncated = true
		return
	}
	m.Text = append(m.Text, v)
	m.TextBytes += int64(len(v))
}

func readArchive(f io.ReaderAt, size int64) (*Model, error) {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, fmt.Errorf("the archive is not a zip Go's reader reads: %w", err)
	}
	if len(zr.File) > maxEntries {
		return nil, fmt.Errorf("the archive has %d entries, more than this reader's bound of %d", len(zr.File), maxEntries)
	}
	m := &Model{Kind: Archive}
	if zr.Comment != "" {
		m.keep(zr.Comment)
		m.Comments++
	}
	byName := map[string]*zip.File{}
	for _, zf := range zr.File {
		m.Entries = append(m.Entries, Entry{Name: zf.Name, Size: zf.UncompressedSize64, Method: zf.Method})
		if zf.Comment != "" {
			m.keep(zf.Comment)
			m.Comments++
		}
		if byName[zf.Name] != nil {
			m.Duplicates = append(m.Duplicates, zf.Name)
			continue
		}
		byName[zf.Name] = zf
		if escapes(zf.Name) {
			m.Escapes = append(m.Escapes, zf.Name)
			continue
		}
		switch {
		case zf.Name == ConfigEntry || zf.Name == MetadataEntry || zf.Name == WeightsH5:
		case zf.Name == WeightsNPZ:
			if byName[WeightsH5] != nil || hasEntry(zr, WeightsH5) {
				m.Unexpected = append(m.Unexpected, WeightsNPZ+" (Keras reads model.weights.h5 when both are present)")
			}
		case strings.HasPrefix(zf.Name, AssetsDir):
			if zf.FileInfo().IsDir() {
				continue
			}
			if err := m.asset(zf); err != nil {
				return nil, err
			}
		case zf.FileInfo().IsDir() && zf.UncompressedSize64 == 0:
			// A directory entry holds nothing; Keras writes none.
			m.Unexpected = append(m.Unexpected, zf.Name+" (a directory entry)")
		default:
			m.Unexpected = append(m.Unexpected, fmt.Sprintf("%s (%d bytes Keras' loader does not read)", zf.Name, zf.UncompressedSize64))
			// Its bytes go to the inventory as text, as an asset's do.
			if err := m.asset(zf); err != nil {
				return nil, err
			}
		}
	}
	sort.Strings(m.Unexpected)
	if zf := byName[MetadataEntry]; zf != nil {
		raw, err := readEntry(zf, maxJSONBytes)
		switch {
		case err != nil:
			m.Configs = append(m.Configs, Config{Source: MetadataEntry, Err: err.Error()})
		default:
			if v, err := DecodeJSON(raw); err == nil {
				m.jsonText(v, 0)
				if mv, ok := v.(map[string]any); ok {
					m.KerasVersion, _ = mv["keras_version"].(string)
				}
			} else {
				m.keep(string(raw))
			}
		}
	}
	if zf := byName[ConfigEntry]; zf != nil {
		raw, err := readEntry(zf, maxJSONBytes)
		if err != nil {
			m.Configs = append(m.Configs, Config{Source: ConfigEntry, Err: err.Error()})
		} else {
			m.addConfig(ConfigEntry, raw)
		}
	}
	zf := byName[WeightsH5]
	switch {
	case zf == nil:
		m.H5Unread = "the weights are in " + WeightsNPZ + ", a NumPy archive this reader does not read (Keras 3.0 to 3.8 load it with allow_pickle=True)"
	case zf.Method != zip.Store:
		m.H5Unread = fmt.Sprintf("%s is compressed in the archive (method %d); Keras writes it stored, and this reader reads it only stored", WeightsH5, zf.Method)
	default:
		at, err := zf.DataOffset()
		if err != nil {
			return nil, err
		}
		if zf.UncompressedSize64 > uint64(size) || at < 0 || at > size-int64(zf.UncompressedSize64) {
			return nil, fmt.Errorf("%s runs past the end of the archive", WeightsH5)
		}
		h, err := hdf5.ReadFrom(io.NewSectionReader(f, at, int64(zf.UncompressedSize64)), int64(zf.UncompressedSize64))
		if err != nil {
			m.H5Unread = WeightsH5 + " could not be parsed: " + err.Error()
			break
		}
		m.H5 = h
		if h.SuperblockOffset > 0 {
			m.UserBlock = h.SuperblockOffset
		}
		m.fromHDF5(h, false)
	}
	m.Layout = "a .keras archive"
	return m, nil
}

// escapes reports a member name that leaves the extraction directory, read
// with both separators: rooted, a Windows drive, or a ".." component.
func escapes(name string) bool {
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) || len(name) >= 2 && name[1] == ':' {
		return true
	}
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

func hasEntry(zr *zip.Reader, name string) bool {
	for _, zf := range zr.File {
		if zf.Name == name {
			return true
		}
	}
	return false
}

// asset keeps an asset's bytes as text, for the inventory.
func (m *Model) asset(zf *zip.File) error {
	raw, err := readEntry(zf, maxAssetBytes)
	if err != nil {
		var big *tooBig
		if errors.As(err, &big) {
			m.TextTruncated = true
			return nil
		}
		m.Unexpected = append(m.Unexpected, zf.Name+" (could not be read: "+err.Error()+")")
		return nil
	}
	m.keep(string(raw))
	return nil
}

type tooBig struct{ name string }

func (e *tooBig) Error() string { return e.name + " is past this reader's bound" }

// readEntry reads an archive member of at most max bytes, checking its
// CRC-32.
func readEntry(zf *zip.File, max int64) ([]byte, error) {
	if zf.UncompressedSize64 > uint64(max) {
		return nil, &tooBig{zf.Name}
	}
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var b bytes.Buffer
	if _, err := io.Copy(&b, io.LimitReader(rc, max+1)); err != nil {
		return nil, fmt.Errorf("%s: %w", zf.Name, err)
	}
	if int64(b.Len()) > max {
		return nil, &tooBig{zf.Name}
	}
	return b.Bytes(), nil
}

// maxJSONDepth bounds how deep a config is walked; encoding/json refuses
// nesting past 10000.
const maxJSONDepth = 512

// DecodeJSON decodes a config as Keras' json.loads does: a repeated key
// keeps its last value, trailing data is refused, and NaN, Infinity, and
// -Infinity, which Python's json module writes and reads, are read (as
// null: no rule reads a number).
func DecodeJSON(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(pythonConstants(raw)))
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON value")
	}
	return v, nil
}

// pythonConstants replaces NaN, Infinity, and -Infinity outside strings with
// null (as checks/remotecode reads Hugging Face configs).
func pythonConstants(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("NaN")) && !bytes.Contains(raw, []byte("Infinity")) {
		return raw
	}
	out := make([]byte, 0, len(raw))
	inString, escaped := false, false
next:
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			out = append(out, c)
			continue
		}
		if c == '"' {
			inString = true
		}
		for _, k := range [][]byte{[]byte("-Infinity"), []byte("Infinity"), []byte("NaN")} {
			if bytes.HasPrefix(raw[i:], k) {
				out = append(out, "null"...)
				i += len(k) - 1
				continue next
			}
		}
		out = append(out, c)
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
