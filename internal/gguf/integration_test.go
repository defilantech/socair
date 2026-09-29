package gguf

import (
	"os"
	"testing"
)

// TestReadRealArtifact runs only when SOCAIR_TEST_MODEL points at a real GGUF.
// Example:
//
//	SOCAIR_TEST_MODEL=/path/to/model.gguf go test ./internal/gguf -run Real -v
func TestReadRealArtifact(t *testing.T) {
	path := os.Getenv("SOCAIR_TEST_MODEL")
	if path == "" {
		t.Skip("set SOCAIR_TEST_MODEL to run against a real artifact")
	}

	m, err := ReadArtifact(path)
	if err != nil {
		t.Fatalf("ReadArtifact(%s): %v", path, err)
	}
	if m.SHA256 == "" || len(m.SHA256) != 64 {
		t.Fatalf("sha256 = %q, want 64 hex chars", m.SHA256)
	}
	if m.Name == "" {
		t.Errorf("name is empty on a real artifact")
	}
	t.Logf("artifact: name=%q arch=%q format=%s tensors=%d kv=%d sha256=%s",
		m.Name, m.Architecture, m.Format, m.TensorCount, m.KVCount, m.SHA256)
}
