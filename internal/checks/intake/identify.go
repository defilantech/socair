package intake

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/checks/pickle"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/safetensors"
)

// File is one model file and the format its bytes were identified as.
type File struct {
	// Path is the file's name, or its path within a model directory.
	Path string
	// Format is one of Formats, or "" when the bytes are none of them.
	Format string
	// How says what identified it, or what the bytes are when Format is "".
	How string
}

var npyMagic = []byte("\x93NUMPY")

// maxNPZEntries bounds the archive Identify opens to test for a NumPy .npz.
const maxNPZEntries = 4096

// Identify names the format of the file at path from its bytes, never from
// its name:
//
//   - gguf: the GGUF magic, whether or not the rest parses;
//   - safetensors: an 8-byte little-endian header length that fits the file,
//     then a JSON object (safetensors.IsSafetensors);
//   - numpy: the .npy magic, or a zip archive every entry of which is a .npy
//     array (an .npz);
//   - pickle: a protocol 2 to 5 pickle stream, or a zip archive holding a
//     pickle (the torch.save format), as pickle.Sniff recognises them.
//
// Anything else is "" with what the bytes are. A file that cannot be opened is
// "" too, and says so.
func Identify(p string) File {
	f := File{Path: filepath.Base(p)}
	if ok, err := gguf.IsGGUF(p); err != nil {
		f.How = "could not be read: " + err.Error()
		return f
	} else if ok {
		f.Format, f.How = GGUF, "the GGUF magic"
		return f
	}
	if safetensors.IsSafetensors(p) {
		f.Format, f.How = Safetensors, "a safetensors header"
		return f
	}
	head := readHead(p, len(npyMagic))
	if bytes.HasPrefix(head, npyMagic) {
		f.Format, f.How = NumPy, "the .npy magic"
		return f
	}
	if kind := pickle.Sniff(p); kind != "" {
		f.Format, f.How = Pickle, "a "+kind
		return f
	}
	if bytes.HasPrefix(head, []byte("PK\x03\x04")) {
		if isNPZ(p) {
			f.Format, f.How = NumPy, "a zip of .npy arrays (.npz)"
			return f
		}
		f.How = "a zip archive that holds no pickle Socair recognises and is not an .npz"
		return f
	}
	f.How = "its bytes are not GGUF, safetensors, NumPy, or a pickle Socair recognises"
	return f
}

func readHead(p string, n int) []byte {
	fh, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer fh.Close()
	b := make([]byte, n)
	k, _ := io.ReadFull(fh, b)
	return b[:k]
}

// isNPZ reports a zip archive whose every entry is a .npy array, by name and
// by its first bytes, as numpy.savez writes one.
func isNPZ(p string) bool {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return false
	}
	defer zr.Close()
	if len(zr.File) == 0 || len(zr.File) > maxNPZEntries {
		return false
	}
	for _, zf := range zr.File {
		if !strings.HasSuffix(zf.Name, ".npy") {
			return false
		}
		rc, err := zf.Open()
		if err != nil {
			return false
		}
		b := make([]byte, len(npyMagic))
		_, err = io.ReadFull(rc, b)
		rc.Close()
		if err != nil || !bytes.Equal(b, npyMagic) {
			return false
		}
	}
	return true
}

// DirFiles identifies a model directory's model files, read from the scan's
// snapshot at root: every file whose bytes are one of the formats, whatever
// its name, and every weight file (a weights extension, by its role), whether
// or not its bytes are identified. Config, tokenizer, and other files whose
// bytes are none of the formats are not model files and are left out.
func DirFiles(root string, files []modeldir.File) []File {
	var out []File
	for _, f := range files {
		id := Identify(filepath.Join(root, filepath.FromSlash(f.Path)))
		id.Path = f.Path
		weights := f.Role == modeldir.RoleWeights || f.Role == modeldir.RoleAdapter && modeldir.HasWeightExt(f.Path)
		switch {
		case id.Format != "":
			out = append(out, id)
		case weights:
			id.How = strings.ToLower(path.Ext(f.Path)) + " weights; " + id.How
			out = append(out, id)
		}
	}
	return out
}
