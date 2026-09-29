package structure

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf/gguftest"
)

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

func TestValidStructurePasses(t *testing.T) {
	p := writeFixture(t, "clean.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	r := Validate(p)
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS (notes: %s)", r.Status, r.Notes)
	}
}

func TestTruncatedDoesNotPass(t *testing.T) {
	full := gguftest.BuildGGUF(gguftest.Clean())
	p := writeFixture(t, "truncated.gguf", full[:6])
	r := Validate(p)
	if r.Status == checks.Pass {
		t.Fatalf("truncated artifact must not PASS, got %s", r.Status)
	}
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED (ambiguity, not malice)", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestBadMagicDoesNotPass(t *testing.T) {
	body := append([]byte("NOPE"), gguftest.BuildGGUF(gguftest.Clean())...)
	p := writeFixture(t, "badmagic.gguf", body)
	r := Validate(p)
	if r.Status == checks.Pass {
		t.Fatalf("non-GGUF artifact must not PASS, got %s", r.Status)
	}
}
