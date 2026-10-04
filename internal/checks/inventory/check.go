// Package inventory answers the signed claim "no hidden files": does the
// artifact, or the repo mirror when one is provided, carry an embedded payload
// or an unexpected executable.
//
// The artifact side is high-confidence and can FAIL. The repo side is
// deliberately conservative: model repos legitimately ship config.py and
// tokenizer files, so those are inventoried, not failed. Only a native
// executable in the repo is a FAIL; an archive such as a zip-format PyTorch
// checkpoint is named as unscanned, which leaves the row NOT_TESTED.
package inventory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/safetensors"
)

// Options configures the inventory check.
type Options struct {
	// RepoMirror is a local directory holding the source repo listing. Empty
	// means the repo side is NOT_TESTED, not a pass.
	RepoMirror string
}

// payload patterns are high-confidence indicators of an embedded executable or
// archive inside artifact metadata.
var (
	scriptTag  = regexp.MustCompile(`(?i)<script\b|#!/bin/(sh|bash)|powershell\s+-|Invoke-Expression`)
	base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{512,}={0,2}`)
)

// strongMagics are four-byte executable and archive headers, distinctive
// enough to count anywhere inside a metadata value.
var strongMagics = []struct {
	name  string
	magic []byte
}{
	{"ELF", []byte{0x7f, 'E', 'L', 'F'}},
	{"zip", []byte{0x50, 0x4b, 0x03, 0x04}},
	{"Mach-O", []byte{0xfe, 0xed, 0xfa, 0xce}},
	{"Mach-O", []byte{0xce, 0xfa, 0xed, 0xfe}},
	{"Mach-O", []byte{0xfe, 0xed, 0xfa, 0xcf}},
	{"Mach-O", []byte{0xcf, 0xfa, 0xed, 0xfe}},
}

// containerIn names an executable or archive embedded in a metadata value.
// Two-byte magics ("MZ", gzip's 1f 8b) are ordinary byte pairs in text, as in
// "AMZ Corp", so they count only at the start of the value and only with the
// structure that confirms them: a PE signature at e_lfanew, or a gzip header
// with deflate and no reserved flags.
func containerIn(v []byte) string {
	for _, m := range strongMagics {
		if bytes.Contains(v, m.magic) {
			return m.name
		}
	}
	if isPE(v) {
		return "PE"
	}
	if len(v) >= 10 && v[0] == 0x1f && v[1] == 0x8b && v[2] == 0x08 && v[3]&0xe0 == 0 {
		return "gzip"
	}
	return ""
}

// isPE reports whether b starts with a DOS header whose e_lfanew points at a
// "PE\0\0" signature.
func isPE(b []byte) bool {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	off := int64(binary.LittleEndian.Uint32(b[0x3c:0x40]))
	return off >= 0x40 && off+4 <= int64(len(b)) && bytes.Equal(b[off:off+4], []byte("PE\x00\x00"))
}

// executableIn names a native executable at the start of a repo file. Only
// these are a FAIL on the repo side: an archive is not an executable.
func executableIn(head []byte) string {
	for _, m := range strongMagics {
		if m.name != "zip" && bytes.HasPrefix(head, m.magic) {
			return m.name
		}
	}
	if isPE(head) {
		return "PE"
	}
	return ""
}

// archiveIn names an archive at the start of a repo file. Its contents are not
// scanned here, so it makes the repo side NOT_TESTED rather than a pass.
func archiveIn(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte{0x50, 0x4b, 0x03, 0x04}):
		return "zip"
	case len(head) >= 3 && head[0] == 0x1f && head[1] == 0x8b && head[2] == 0x08:
		return "gzip"
	}
	return ""
}

// Inspect runs the inventory check over an artifact and an optional repo
// mirror.
func Inspect(path string, opts Options) checks.Result {
	r := checks.Result{
		Name:     "File inventory and payloads",
		LooksFor: "Hidden files, embedded payloads, unexpected executables",
	}

	var values []string
	var invNote string
	truncated := false
	switch {
	case safetensors.IsSafetensors(path):
		sm, err := safetensors.ReadHeader(path)
		if err != nil {
			r.Status = checks.NotTested
			r.Notes = "could not read safetensors header: " + err.Error()
			return r
		}
		for _, v := range sm.Metadata {
			values = append(values, v)
		}
		invNote = fmt.Sprintf("artifact: safetensors header, %d tensors, %d metadata keys", sm.TensorCount, len(sm.MetadataKeys))
	default:
		inv, err := gguf.Inventory(path)
		if err != nil {
			r.Status = checks.NotTested
			if errors.Is(err, gguf.ErrNotGGUF) {
				r.Notes = "not a GGUF or safetensors artifact; cannot inventory"
			} else {
				r.Notes = "could not read artifact metadata: " + err.Error()
			}
			return r
		}
		values = append(inv.Strings, inv.ArrayStrings...)
		invNote = fmt.Sprintf("artifact: %d metadata keys, %d string bytes, %d string-array elements (%d of %d+ bytes scanned)",
			len(inv.Keys), inv.TotalStrings, inv.ArrayElements, len(inv.ArrayStrings), gguf.ArrayScanMin)
		truncated = inv.Truncated
	}

	for _, s := range values {
		if m := scriptTag.FindString(s); m != "" {
			r.Findings = append(r.Findings, checks.Finding{
				Pattern: "embedded-script",
				Span:    excerpt(m),
				Detail:  "artifact metadata carries script or shell content",
			})
		}
		if m := base64Blob.FindString(s); m != "" {
			r.Findings = append(r.Findings, checks.Finding{
				Pattern: "embedded-base64-blob",
				Span:    excerpt(m),
				Detail:  "artifact metadata carries a large base64 blob",
			})
		}
		if kind := containerIn([]byte(s)); kind != "" {
			r.Findings = append(r.Findings, checks.Finding{
				Pattern: "embedded-binary",
				Detail:  "artifact metadata contains a " + kind + " container",
			})
		}
	}
	if len(r.Findings) > 0 {
		r.Status = checks.Fail
		r.Notes = fmt.Sprintf("%d embedded payload indicator(s) in artifact metadata (%s)", len(r.Findings), invNote)
		return r
	}

	// A FAIL above stands on its evidence; without one, an inventory cut off
	// at a cap did not see every value, so it cannot pass.
	if truncated {
		r.Status = checks.NotTested
		r.Notes = invNote + ". The metadata inventory reached its cap, so some values were not scanned."
		return r
	}

	artifactNote := invNote + ", no payload indicator"

	if opts.RepoMirror == "" {
		r.Status = checks.NotTested
		r.Notes = artifactNote + ". Repo mirror not provided, so the repo file listing was not inspected."
		return r
	}

	repoFindings, archives, repoNote, err := scanRepo(opts.RepoMirror)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = artifactNote + ". Could not read repo mirror: " + err.Error()
		return r
	}
	if len(repoFindings) > 0 {
		r.Status = checks.Fail
		r.Findings = repoFindings
		r.Notes = artifactNote + ". " + repoNote
		return r
	}
	if len(archives) > 0 {
		r.Status = checks.NotTested
		r.Notes = artifactNote + ". " + repoNote + ". Archive contents were not scanned: " + strings.Join(archives, ", ")
		return r
	}

	r.Status = checks.Pass
	r.Notes = artifactNote + ". " + repoNote
	return r
}

// scanRepo lists a repo mirror. A native executable is a FAIL. An archive,
// including every zip-format PyTorch checkpoint, is named as unscanned: it is
// not an executable, but its contents (a pickle, for a checkpoint) were not
// inspected. Scripts and config files are counted, not failed.
func scanRepo(root string) ([]checks.Finding, []string, string, error) {
	var findings []checks.Finding
	var archives []string
	var files, scripts int

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		files++
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".py", ".sh", ".js", ".rb":
			scripts++ // inventoried, not a failure: model repos ship these
			return nil
		}
		head := make([]byte, 4096)
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		n, _ := io.ReadFull(f, head)
		_ = f.Close()
		head = head[:n]
		rel, _ := filepath.Rel(root, path)
		if kind := executableIn(head); kind != "" {
			findings = append(findings, checks.Finding{
				Pattern: "repo-binary",
				Span:    rel,
				Detail:  fmt.Sprintf("repo file %q is a %s executable", rel, kind),
			})
			return nil
		}
		if kind := archiveIn(head); kind != "" {
			archives = append(archives, fmt.Sprintf("%s (%s)", rel, kind))
		}
		return nil
	})
	if err != nil {
		return nil, nil, "", err
	}
	sort.Strings(archives)
	return findings, archives, fmt.Sprintf("repo: %d files, %d scripts inventoried (scripts are expected, not a finding)", files, scripts), nil
}

func excerpt(s string) string {
	const max = 60
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// unparsedExt maps the extensions of model and serialization formats Socair
// does not parse to a format name. These are the files that can carry
// weights or code and that no check examined.
var unparsedExt = map[string]string{
	".onnx": "ONNX", ".h5": "Keras/HDF5", ".hdf5": "Keras/HDF5", ".keras": "Keras",
	".pb": "TensorFlow graph or SavedModel", ".tflite": "TensorFlow Lite", ".nemo": "NeMo archive",
	".npy": "NumPy", ".npz": "NumPy", ".joblib": "joblib", ".msgpack": "Flax msgpack",
	".pkl": "pickle (not this artifact)", ".pickle": "pickle (not this artifact)",
	".pt": "PyTorch checkpoint (not this artifact)", ".pth": "PyTorch checkpoint (not this artifact)",
	".bin": "binary weights or PyTorch checkpoint (not this artifact)", ".ckpt": "checkpoint (not this artifact)",
	".llamafile": "llamafile", ".mlmodel": "Core ML", ".engine": "TensorRT engine", ".plan": "TensorRT engine",
	".gguf": "GGUF (not this artifact)", ".safetensors": "safetensors (not this artifact)",
}

// UnparsedFormats lists the files in a repo mirror, other than the attested
// artifact, whose format can carry weights or code and that this scan did not
// parse, grouped by format and sorted. The attestation covers one artifact;
// this is what a reader needs to know sits beside it unexamined.
func UnparsedFormats(root, artifactName string) ([]string, error) {
	byFormat := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() == artifactName {
			return nil
		}
		if f, ok := unparsedExt[strings.ToLower(filepath.Ext(path))]; ok {
			rel, _ := filepath.Rel(root, path)
			byFormat[f] = append(byFormat[f], rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(byFormat))
	for f, files := range byFormat {
		sort.Strings(files)
		shown := files
		more := ""
		if len(files) > 5 {
			shown, more = files[:5], fmt.Sprintf(" and %d more", len(files)-5)
		}
		out = append(out, fmt.Sprintf("%s: %s%s", f, strings.Join(shown, ", "), more))
	}
	sort.Strings(out)
	return out, nil
}

// InspectRepo is the repo side alone: the file listing of a model directory,
// for a directory scan whose weights have no metadata to inventory (pickle
// checkpoints, for example). A native executable FAILs; an archive is named
// as unscanned.
func InspectRepo(root string) checks.Result {
	r := checks.Result{
		Name:     "File inventory and payloads",
		LooksFor: "Hidden files, embedded payloads, unexpected executables",
	}
	findings, archives, note, err := scanRepo(root)
	switch {
	case err != nil:
		r.Status = checks.NotTested
		r.Notes = "could not list the directory: " + err.Error()
	case len(findings) > 0:
		r.Status = checks.Fail
		r.Findings = findings
		r.Notes = note
	case len(archives) > 0:
		r.Status = checks.NotTested
		r.Notes = note + ". Archive contents were not scanned: " + strings.Join(archives, ", ")
	default:
		r.Status = checks.Pass
		r.Notes = note
	}
	return r
}
