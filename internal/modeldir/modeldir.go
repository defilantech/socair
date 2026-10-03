// Package modeldir reads a model directory, such as a Hugging Face repo
// checkout or a cache snapshot, as one artifact.
//
// A transformers model is a set of files: weight shards, config.json, the
// tokenizer, the chat template, and sometimes Python code that
// trust_remote_code would execute. An attestation of one shard says nothing
// about the files that decide how it runs, so a directory scan covers every
// file.
//
// The directory's identity follows OpenSSF Model Signing: one digest over a
// canonical manifest of every file's SHA-256, size, and path. That digest is
// the attestation subject, and the per-file hashes travel in the report, so a
// verifier can recompute both. The canonical form is
//
//	socair.modeldir/v1\n
//	<sha256 hex> <size> <path>\n   (one line per file, sorted by path bytes)
//
// with paths relative to the directory, "/"-separated.
//
// Snapshot copies every file into a private read-only tree, hashing while
// copying, so the bytes hashed are the bytes the checks read.
package modeldir

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// MaxFiles bounds a directory scan. Real model repos hold tens to a few
// hundred files.
const MaxFiles = 10000

// Roles classify a file for the checks and the report.
const (
	RoleWeights   = "weights"
	RoleConfig    = "config"
	RoleTokenizer = "tokenizer"
	RoleTemplate  = "chat_template"
	RoleCode      = "code"
	RoleAdapter   = "adapter"
	RoleOther     = "other"
)

// Roles lists every role, in the order the schema enumerates them.
var Roles = []string{RoleWeights, RoleConfig, RoleTokenizer, RoleTemplate, RoleCode, RoleAdapter, RoleOther}

// File is one file in the directory.
type File struct {
	Path   string // relative, "/"-separated
	SHA256 string
	Size   int64
	Role   string
}

// Excluded names a path left out of the scan, and why.
type Excluded struct {
	Path   string
	Reason string
}

// skipDirs are tool metadata, not model files: nothing a loader reads.
var skipDirs = map[string]string{
	".git":               "git metadata; a loader does not read it",
	".cache":             "download-tool cache metadata; a loader does not read it",
	".huggingface":       "download-tool metadata; a loader does not read it",
	"__pycache__":        "compiled Python cache",
	".ipynb_checkpoints": "notebook autosave",
}

var weightExt = map[string]bool{
	".safetensors": true, ".gguf": true, ".bin": true, ".pt": true, ".pth": true,
	".ckpt": true, ".pkl": true, ".pickle": true, ".joblib": true, ".h5": true,
	".onnx": true, ".msgpack": true, ".npz": true, ".npy": true, ".mlmodel": true,
	".tflite": true, ".pb": true, ".keras": true,
}

// Classify gives a file its role from its path.
func Classify(rel string, adapter bool) string {
	base := strings.ToLower(path.Base(rel))
	ext := path.Ext(base)
	switch {
	case ext == ".py":
		return RoleCode
	case ext == ".jinja" || base == "chat_template.json":
		return RoleTemplate
	case strings.HasPrefix(base, "adapter_") || (adapter && weightExt[ext]):
		return RoleAdapter
	case weightExt[ext]:
		return RoleWeights
	case base == "tokenizer.json" || base == "tokenizer_config.json" || base == "tokenizer.model" ||
		base == "vocab.json" || base == "vocab.txt" || base == "merges.txt" || base == "special_tokens_map.json" ||
		base == "added_tokens.json" || strings.HasSuffix(base, ".tiktoken"):
		return RoleTokenizer
	case base == "config.json" || strings.HasSuffix(base, "_config.json") || strings.HasSuffix(base, ".index.json"):
		return RoleConfig
	}
	return RoleOther
}

// Snapshot copies every file under dir into a private read-only tree under a
// new temporary directory in tmpRoot (the system default when empty), hashing
// while copying. It returns the snapshot root, the files sorted by path, what
// was excluded, and a cleanup function.
//
// Symlinks to regular files are followed, as a Hugging Face cache snapshot is
// built of them; symlinked directories and other non-regular entries are
// excluded and named.
func Snapshot(dir, tmpRoot string) (string, []File, []Excluded, func(), error) {
	if err := isDir(dir); err != nil {
		return "", nil, nil, nil, err
	}
	snap, err := os.MkdirTemp(tmpRoot, "socair-dir-")
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("create scan snapshot directory (set SOCAIR_SCAN_TMP to a volume with room): %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(snap) }
	files, excluded, err := walk(dir, func(src, rel string) (string, int64, error) {
		sum, n, err := copyHashed(src, filepath.Join(snap, filepath.FromSlash(rel)))
		if err != nil {
			return "", 0, fmt.Errorf("snapshot %s (set SOCAIR_SCAN_TMP to a volume with room): %w", rel, err)
		}
		return sum, n, nil
	})
	if err != nil {
		cleanup()
		return "", nil, nil, nil, err
	}
	return snap, files, excluded, cleanup, nil
}

// Hash walks dir and returns its manifest digest and files, hashing in place,
// for a verifier checking a directory against an attestation.
func Hash(dir string) (string, []File, error) {
	if err := isDir(dir); err != nil {
		return "", nil, err
	}
	files, _, err := walk(dir, hashFile)
	if err != nil {
		return "", nil, err
	}
	return Digest(files), files, nil
}

func isDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// walk visits every file under dir in the scan's rules, calling read for
// each to get its digest and size, and returns the files sorted by path.
func walk(dir string, read func(src, rel string) (string, int64, error)) ([]File, []Excluded, error) {
	adapter := false
	if st, err := os.Stat(filepath.Join(dir, "adapter_config.json")); err == nil && st.Mode().IsRegular() {
		adapter = true
	}
	var files []File
	var excluded []Excluded
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if why, ok := skipDirs[d.Name()]; ok {
				excluded = append(excluded, Excluded{rel + "/", why})
				return fs.SkipDir
			}
			return nil
		}
		if !utf8.ValidString(rel) || strings.ContainsAny(rel, "\n\r") {
			return fmt.Errorf("file name %q cannot be named in a manifest", rel)
		}
		st, err := os.Stat(p) // follows symlinks
		if err != nil {
			excluded = append(excluded, Excluded{rel, "unreadable: " + err.Error()})
			return nil
		}
		if st.IsDir() {
			excluded = append(excluded, Excluded{rel + "/", "symlinked directory, not followed"})
			return nil
		}
		if !st.Mode().IsRegular() {
			excluded = append(excluded, Excluded{rel, "not a regular file"})
			return nil
		}
		if len(files) >= MaxFiles {
			return fmt.Errorf("more than %d files; not a model directory this scanner reads", MaxFiles)
		}
		sum, size, err := read(p, rel)
		if err != nil {
			return err
		}
		files = append(files, File{Path: rel, SHA256: sum, Size: size, Role: Classify(rel, adapter)})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(files) == 0 {
		return nil, nil, errors.New("the directory holds no files")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, excluded, nil
}

func hashFile(src, _ string) (string, int64, error) {
	f, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyHashed(src, dst string) (string, int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", 0, err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, err
	}
	if err := os.Chmod(dst, 0o400); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Digest is the SHA-256 of the canonical manifest of files, which must be
// sorted by path.
func Digest(files []File) string {
	h := sha256.New()
	io.WriteString(h, "socair.modeldir/v1\n")
	for _, f := range files {
		fmt.Fprintf(h, "%s %d %s\n", f.SHA256, f.Size, f.Path)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Diff names how actual differs from attested: files added, removed, or
// changed. It is empty when the two lists agree.
func Diff(attested, actual []File) []string {
	want := map[string]File{}
	for _, f := range attested {
		want[f.Path] = f
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range actual {
		seen[f.Path] = true
		w, ok := want[f.Path]
		switch {
		case !ok:
			out = append(out, "added: "+f.Path)
		case w.SHA256 != f.SHA256 || w.Size != f.Size:
			out = append(out, "changed: "+f.Path)
		}
	}
	for _, f := range attested {
		if !seen[f.Path] {
			out = append(out, "removed: "+f.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Skipped reports whether a directory of this name is left out of a scan, and
// why. A pull uses it so a fetched tree and a scanned tree agree on what the
// manifest covers.
func Skipped(name string) (string, bool) {
	why, ok := skipDirs[name]
	return why, ok
}
