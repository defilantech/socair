package structure

import (
	"os"
	"path/filepath"
	"strings"
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

func TestSplitArtifactIsSurfaced(t *testing.T) {
	kvs := append(gguftest.Clean(),
		gguftest.U32("split.no", 1),
		gguftest.U32("split.count", 3),
	)
	p := writeFixture(t, "shard-00002-of-00003.gguf", gguftest.BuildGGUF(kvs))
	r := Validate(p)
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS", r.Status)
	}
	if !strings.Contains(r.Notes, "part 2 of 3") {
		t.Errorf("a shard must be surfaced in the notes, got: %s", r.Notes)
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
