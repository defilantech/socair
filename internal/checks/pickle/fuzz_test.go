package pickle

import (
	"bytes"
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

// FuzzGrammar feeds arbitrary streams to the grammar in every persistent-id
// mode. It may not panic or loop, and a stream it accepts must have reached
// STOP within the bytes given and left its root.
func FuzzGrammar(f *testing.F) {
	f.Add(stateDict())
	f.Add([]byte("\x80\x02\x8a\x02\x05\x00."))
	f.Add([]byte("\x80\x02ccollections\nOrderedDict\nq\x00X\x03\x00\x00\x00abcq\x01\x85q\x02R."))
	f.Add([]byte("\x80\x03C\x02hi."))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, mode := range []pidMode{pidNone, pidZip, pidLegacy, pidTar} {
			g := validate(bytes.NewReader(data), grammarOpts{pids: mode, reviewed: map[string]bool{"x.Y": true}})
			if g.conforms() && (g.root == nil || g.end > int64(len(data)) || g.end < 3) {
				t.Fatalf("mode %d: conforms with root %v and end %d of %d bytes", mode, g.root, g.end, len(data))
			}
		}
	})
}
