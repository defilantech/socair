package pickle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

func pickleStream(globals string) []byte {
	return append([]byte{protoOpcode, 0x04}, []byte(globals)...)
}

func TestPickleOsSystemFails(t *testing.T) {
	p := writeFixture(t, "evil.pt", pickleStream("cos\nsystem\nhttp://evil/x\n"))
	r := Inspect(p)
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL (notes: %s)", r.Status, r.Notes)
	}
	found := false
	for _, f := range r.Findings {
		if f.Span == "os.system" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an os.system finding, got %+v", r.Findings)
	}
}

func TestSubprocessFails(t *testing.T) {
	p := writeFixture(t, "evil.bin", pickleStream("csubprocess\nPopen\n"))
	if got := Inspect(p).Status; got != checks.Fail {
		t.Fatalf("status = %s, want FAIL", got)
	}
}

func TestBenignPicklePasses(t *testing.T) {
	p := writeFixture(t, "clean.pt", pickleStream("cjson\nloads\n"))
	if got := Inspect(p).Status; got != checks.Pass {
		t.Fatalf("status = %s, want PASS", got)
	}
}

func TestSafetensorsIsNotPickle(t *testing.T) {
	p := writeFixture(t, "model.safetensors", safetensorstest.Clean())
	r := Inspect(p)
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED (wrong format, not a false pass)", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestGgufIsNotPickle(t *testing.T) {
	p := writeFixture(t, "model-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	if got := Inspect(p).Status; got != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", got)
	}
}

func TestRawTensorFileIsNotScanned(t *testing.T) {
	// A .bin that is raw tensor data, not a pickle, must not be scanned as one.
	p := writeFixture(t, "raw.bin", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	r := Inspect(p)
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED for a non-pickle byte stream", r.Status)
	}
}
