package pickle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

// FuzzPickleInspect feeds arbitrary files to the pickle check. It reads
// untrusted checkpoints, so it may not panic, and every result is one of the
// defined statuses with a reason.
func FuzzPickleInspect(f *testing.F) {
	f.Add([]byte("\x80\x02cposix\nsystem\nq\x00."))
	f.Add([]byte("\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94."))
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(dir, "x.pkl")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip(err)
		}
		r := Inspect(p)
		switch r.Status {
		case checks.Pass, checks.Fail, checks.Lead, checks.NotTested:
		default:
			t.Fatalf("undefined status %q", r.Status)
		}
		if r.Notes == "" {
			t.Fatal("a result must carry a reason")
		}
	})
}
