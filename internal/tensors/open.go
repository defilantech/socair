package tensors

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/defilantech/socair/internal/modeldir"
)

// Open reads a manifest or fingerprints a model. A file that begins with a
// JSON object is a socair.tensors/v1 manifest and is loaded strictly. A
// directory is fingerprinted as a model directory and named by its manifest
// digest, as a scan names it. Any other file is fingerprinted as one GGUF or
// safetensors file and named by its SHA-256.
func Open(path string) (*Manifest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		digest, files, err := modeldir.Hash(path)
		if err != nil {
			return nil, err
		}
		rel := make([]string, len(files))
		for i, f := range files {
			rel[i] = f.Path
		}
		return Dir(path, rel, digest)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	first, err := bufio.NewReader(f).Peek(1)
	if err == nil && first[0] == '{' {
		if info.Size() > MaxManifestBytes {
			return nil, fmt.Errorf("%s begins as JSON but is %d bytes, over the %d-byte manifest limit", path, info.Size(), MaxManifestBytes)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return Load(data)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return File(path, hex.EncodeToString(h.Sum(nil)))
}
