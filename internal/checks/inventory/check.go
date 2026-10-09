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

	listing, err := scanRepo(opts.RepoMirror)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = artifactNote + ". Could not read repo mirror: " + err.Error()
		return r
	}
	return listing.grade(r, artifactNote+". ")
}

// repoListing is what scanRepo found in a repo mirror.
type repoListing struct {
	root           string
	findings       []checks.Finding
	archives       []string // archives whose contents were not scanned
	unread         []string // entries that could not be read, with the reason
	files, scripts int
}

func (l repoListing) note() string {
	return fmt.Sprintf("repo: %d files, %d scripts inventoried (scripts are expected, not a finding)", l.files, l.scripts)
}

// grade sets r from the listing. A native executable is a FAIL on its
// evidence, whatever else went unread. Otherwise a listing that saw no file,
// or left an archive or an entry unread, did not inspect the whole repo, so it
// is NOT_TESTED with each named.
func (l repoListing) grade(r checks.Result, prefix string) checks.Result {
	var unseen []string
	if len(l.archives) > 0 {
		unseen = append(unseen, "Archive contents were not scanned: "+strings.Join(l.archives, ", "))
	}
	if len(l.unread) > 0 {
		unseen = append(unseen, "Could not read: "+capped(l.unread, 10))
	}
	switch {
	case len(l.findings) > 0:
		r.Status = checks.Fail
		r.Findings = l.findings
		r.Notes = prefix + strings.Join(append([]string{l.note()}, unseen...), ". ")
	case l.files == 0 && len(l.unread) == 0:
		r.Status = checks.NotTested
		r.Notes = prefix + "Repo mirror " + l.root + " holds no files, so the repo file listing was not inspected"
	case len(unseen) > 0:
		r.Status = checks.NotTested
		r.Notes = prefix + strings.Join(append([]string{l.note()}, unseen...), ". ")
	default:
		r.Status = checks.Pass
		r.Notes = prefix + l.note()
	}
	return r
}

// capped joins items, naming at most max and counting the rest.
func capped(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, "; ")
	}
	return strings.Join(items[:max], "; ") + fmt.Sprintf("; and %d more", len(items)-max)
}

// scanRepo lists a repo mirror, reading the start of every file whatever its
// name: a script name says nothing about the bytes. A native executable is a
// FAIL. An archive, including every zip-format PyTorch checkpoint, is named as
// unscanned: it is not an executable, but its contents (a pickle, for a
// checkpoint) were not inspected. An entry that cannot be read is named, never
// skipped. Scripts and config files are counted, not failed. A root that is
// missing, unreadable, or not a directory is an error.
func scanRepo(root string) (repoListing, error) {
	l := repoListing{root: root}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return l, err
	}
	if fi, err := os.Stat(resolved); err != nil {
		return l, err
	} else if !fi.IsDir() {
		return l, fmt.Errorf("%s is not a directory", root)
	}

	err = filepath.WalkDir(resolved, func(path string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(resolved, path)
		if err != nil {
			if path == resolved {
				return err
			}
			l.unread = append(l.unread, rel+": "+reason(err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		head, err := readHead(path)
		if err != nil {
			l.unread = append(l.unread, rel+": "+reason(err))
			return nil
		}
		l.files++
		if kind := executableIn(head); kind != "" {
			l.findings = append(l.findings, checks.Finding{
				Pattern: "repo-binary",
				Span:    rel,
				Detail:  fmt.Sprintf("repo file %q is a %s executable", rel, kind),
			})
			return nil
		}
		if kind := archiveIn(head); kind != "" {
			l.archives = append(l.archives, fmt.Sprintf("%s (%s)", rel, kind))
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".py", ".sh", ".js", ".rb":
			l.scripts++ // inventoried, not a failure: model repos ship these
		}
		return nil
	})
	if err != nil {
		return l, err
	}
	sort.Strings(l.archives)
	sort.Strings(l.unread)
	return l, nil
}

// readHead reads the first 4 KiB of a regular file, following a symlink. A
// named pipe or device is not read: opening one can block, and it holds no
// file a loader would load.
func readHead(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return head[:n], nil
}

// reason is an error's cause without the path the note already names.
func reason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
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
	listing, err := scanRepo(root)
	if err != nil {
		r.Status = checks.NotTested
		r.Notes = "could not list the directory: " + err.Error()
		return r
	}
	return listing.grade(r, "")
}
