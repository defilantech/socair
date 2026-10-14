package tensors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Load decodes a manifest strictly: an unknown field, another schema or
// value encoding, a malformed hash, or a negative size or dimension is an
// error, since a reference that quietly lost a field could match what it
// should not.
func Load(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest is %d bytes, over the %d-byte limit", len(data), MaxManifestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("not a %s manifest: %w", Schema, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the manifest")
	}
	if m.Schema != Schema {
		return nil, fmt.Errorf("schema is %q, not %q", m.Schema, Schema)
	}
	if m.ValueEncoding != ValueEncoding {
		return nil, fmt.Errorf("value encoding is %q, not %q", m.ValueEncoding, ValueEncoding)
	}
	if len(m.Tensors) > maxTensors {
		return nil, fmt.Errorf("%d tensors, over the limit of %d", len(m.Tensors), maxTensors)
	}
	if m.Artifact.SHA256 != "" && !isHash(m.Artifact.SHA256) {
		return nil, fmt.Errorf("artifact sha256 %q is not a SHA-256", m.Artifact.SHA256)
	}
	for _, t := range m.Tensors {
		switch {
		case t.Name == "":
			return nil, errors.New("a tensor has no name")
		case t.Dtype == "":
			return nil, fmt.Errorf("tensor %q has no dtype", t.Name)
		case t.Bytes < 0:
			return nil, fmt.Errorf("tensor %q has a negative size", t.Name)
		case !isHash(t.SHA256):
			return nil, fmt.Errorf("tensor %q sha256 %q is not a SHA-256", t.Name, t.SHA256)
		case t.Values != "" && !isHash(t.Values):
			return nil, fmt.Errorf("tensor %q values %q is not a SHA-256", t.Name, t.Values)
		}
		if conv, _ := widen(t.Dtype); t.Values != "" && conv == nil {
			return nil, fmt.Errorf("tensor %q has a values hash, but %s has no %s encoding", t.Name, t.Dtype, ValueEncoding)
		}
		for _, d := range t.Shape {
			if d < 0 {
				return nil, fmt.Errorf("tensor %q has a negative dimension", t.Name)
			}
		}
	}
	m.sort()
	return &m, nil
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == lowerHex(s)
}

func lowerHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'F' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
