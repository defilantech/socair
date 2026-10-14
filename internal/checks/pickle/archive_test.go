package pickle

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

// rewrite is how rezip changes a zip.
type rewrite struct {
	comment string                             // the archive comment
	header  func(*zip.FileHeader)              // edits each entry's header
	content func(name string, b []byte) []byte // edits each entry's bytes
	add     []string                           // entries to append, name then content
}

// rezip rewrites a zip, so a test can add what torch.save never writes.
func rezip(t *testing.T, z []byte, rw rewrite) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	write := func(h *zip.FileHeader, data []byte) {
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		var data bytes.Buffer
		if _, err := data.ReadFrom(rc); err != nil {
			t.Fatal(err)
		}
		_ = rc.Close()
		h := &zip.FileHeader{Name: zf.Name, Method: zip.Store}
		if rw.header != nil {
			rw.header(h)
		}
		out := data.Bytes()
		if rw.content != nil {
			out = rw.content(zf.Name, out)
		}
		write(h, out)
	}
	for i := 0; i+1 < len(rw.add); i += 2 {
		write(&zip.FileHeader{Name: rw.add[i], Method: zip.Store}, []byte(rw.add[i+1]))
	}
	if rw.comment != "" {
		if err := zw.SetComment(rw.comment); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestTorchZipReadEntryByEntry: a canonical torch.save zip the grammar
// PASSes is handed to File inventory as read, naming data.pkl, its storage
// record, and the metadata records torch.save writes, with nothing unread.
func TestTorchZipReadEntryByEntry(t *testing.T) {
	z := torchZip(t, stateDict(), map[string][]byte{"0": floats(4)},
		"archive/.data/serialization_id", "0123456789012345678901234567890123456789",
		"archive/.storage_alignment", "64")
	r, a := InspectArchive(writeFixture(t, "pytorch_model.bin", z), Options{})
	if r.Status != checks.Pass || a == nil {
		t.Fatalf("status %s (%s), archive %+v; want a PASS and what it read", r.Status, r.Notes, a)
	}
	if len(a.Unread) != 0 {
		t.Errorf("unread %q in a canonical torch zip", a.Unread)
	}
	for _, s := range []string{"archive/data.pkl", Grammar, "1 storage record", ".format_version", ".data/serialization_id", ".storage_alignment", "byteorder", "version"} {
		if !strings.Contains(a.Read, s) {
			t.Errorf("read %q does not name %q", a.Read, s)
		}
	}
	if a.By != r.Name {
		t.Errorf("by %q, want the row name %q", a.By, r.Name)
	}
}

// TestTorchZipUnreadEntriesAreNamed: what torch.save never writes, and the
// grammar does not read, is named as unread. Each case PASSes the grammar,
// so only the coverage keeps the archive unscanned. Falsification: drop any
// one rule in coverTorchZip and its case is handed on with nothing unread.
func TestTorchZipUnreadEntriesAreNamed(t *testing.T) {
	canonical := torchZip(t, stateDict(), map[string][]byte{"0": floats(4)})
	cases := map[string]struct {
		file []byte
		want string
	}{
		"a number record holding a command": {
			torchZip(t, stateDict(), map[string][]byte{"0": floats(4)}, "archive/.storage_alignment", "64; echo socair"),
			"archive/.storage_alignment (holds content"},
		"byteorder holding something else": {
			rezip(t, canonical, rewrite{content: func(name string, b []byte) []byte {
				if name == "archive/byteorder" {
					return []byte("middle")
				}
				return b
			}}),
			"archive/byteorder (holds content"},
		"a directory entry": {
			rezip(t, canonical, rewrite{add: []string{"archive/data/", ""}}),
			"archive/data/ (a directory entry"},
		"an archive comment": {
			rezip(t, canonical, rewrite{comment: "echo socair"}),
			"the archive comment (11 bytes)"},
		"an entry comment": {
			rezip(t, canonical, rewrite{header: func(h *zip.FileHeader) {
				if h.Name == "archive/version" {
					h.Comment = "echo socair"
				}
			}}),
			"archive/version (an entry comment of 11 bytes)"},
	}
	for name, c := range cases {
		r, a := InspectArchive(writeFixture(t, "pytorch_model.bin", c.file), Options{})
		if r.Status != checks.Pass {
			t.Errorf("%s: status %s (%s); the case needs a grammar PASS", name, r.Status, r.Notes)
			continue
		}
		if a == nil || !strings.Contains(strings.Join(a.Unread, "; "), c.want) {
			t.Errorf("%s: archive %+v, want %q named as unread", name, a, c.want)
		}
	}
}

// TestTorchZipCoverageNeedsAPass: an archive the grammar did not PASS is
// never handed on as read, so File inventory keeps it unscanned: a gadget in
// data.pkl (FAIL), an entry outside torch.save's layout (LEAD), and a
// TorchScript archive (NOT_TESTED). The coverage still names the extra
// entry, so keeping it unscanned does not rest on the LEAD alone.
func TestTorchZipCoverageNeedsAPass(t *testing.T) {
	gadget := torchZip(t, newPK().global("posix", "system").str("echo socair").raw("\x85").put().raw("R").stop(), nil)
	extra := torchZip(t, stateDict(), map[string][]byte{"0": floats(4)}, "archive/run.sh", "echo socair")
	script := torchZip(t, stateDict(), map[string][]byte{"0": floats(4)}, "archive/code/__torch__/m.py", "def forward(self): pass", "archive/constants.pkl", "\x80\x02).")
	for name, c := range map[string]struct {
		file []byte
		want checks.Status
	}{
		"gadget":      {gadget, checks.Fail},
		"extra entry": {extra, checks.Lead},
		"TorchScript": {script, checks.NotTested},
	} {
		r, a := InspectArchive(writeFixture(t, "pytorch_model.bin", c.file), Options{})
		if r.Status != c.want || a != nil {
			t.Errorf("%s: status %s, archive %+v; want %s and nothing handed on", name, r.Status, a, c.want)
		}
	}
	_, s := inspect(writeFixture(t, "pytorch_model.bin", extra), Options{})
	if s == nil || s.torch == nil || !strings.Contains(strings.Join(s.torch.unread, "; "), "archive/run.sh (") {
		t.Fatalf("the coverage does not name archive/run.sh: %+v", s)
	}
}
