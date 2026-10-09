package inventory

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

func TestCleanArtifactWithoutMirrorIsNotTested(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	r := Inspect(p, Options{})
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED with no repo mirror", r.Status)
	}
	if r.Notes == "" {
		t.Error("NOT_TESTED must carry a reason")
	}
}

func TestCleanArtifactWithCleanMirrorPasses(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))

	mirror := t.TempDir()
	_ = os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(filepath.Join(mirror, "tokenizer.py"), []byte("# model repo script"), 0o600)

	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS (scripts inventoried, not failed): %s", r.Status, r.Notes)
	}
}

// TestUnreadMirrorIsNotTested: walk errors were swallowed, so a mirror path
// that did not exist, or a directory with nothing in it, PASSed as "repo: 0
// files". A repo listing that was not read cannot pass. Falsification: return
// nil from the walk on an error again, or drop the empty check, and these
// PASS.
func TestUnreadMirrorIsNotTested(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	absent := filepath.Join(t.TempDir(), "no-such-mirror")
	empty := t.TempDir()
	file := writeFixture(t, "mirror.txt", []byte("not a directory"))
	for name, c := range map[string]struct{ mirror, want string }{
		"missing":         {absent, "no-such-mirror"},
		"empty":           {empty, "holds no files"},
		"not a directory": {file, "not a directory"},
	} {
		r := Inspect(p, Options{RepoMirror: c.mirror})
		if r.Status != checks.NotTested {
			t.Errorf("%s mirror: status = %s, want NOT_TESTED: %s", name, r.Status, r.Notes)
		}
		if !strings.Contains(r.Notes, c.want) {
			t.Errorf("%s mirror: notes must say %q, got %q", name, c.want, r.Notes)
		}
	}
}

// TestUnreadEntryIsNamed: an entry the walk could not read was skipped and
// the row still PASSed. It is now named, and the row is NOT_TESTED, as for an
// archive whose contents were not scanned. A FAIL elsewhere in the mirror
// still stands on its evidence. Falsification: skip unreadable entries
// silently and the first case PASSes.
func TestUnreadEntryIsNamed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file regardless of mode")
	}
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	mirror := t.TempDir()
	_ = os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600)
	locked := filepath.Join(mirror, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(locked, "hidden.bin"), []byte("unseen"), 0o600)
	secret := filepath.Join(mirror, "secret.bin")
	_ = os.WriteFile(secret, []byte("unseen"), 0o600)
	for _, q := range []string{locked, secret} {
		if err := os.Chmod(q, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755); _ = os.Chmod(secret, 0o600) })

	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED over unread entries: %s", r.Status, r.Notes)
	}
	for _, want := range []string{"locked", "secret.bin"} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("the unread entry %q must be named, got %q", want, r.Notes)
		}
	}

	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 16)...)
	_ = os.WriteFile(filepath.Join(mirror, "helper"), elf, 0o600)
	if r := Inspect(p, Options{RepoMirror: mirror}); r.Status != checks.Fail {
		t.Fatalf("an executable beside an unread entry must still FAIL, got %s: %s", r.Status, r.Notes)
	}
}

// TestScriptNamedExecutableFails: files named .py, .sh, .js, or .rb were
// counted as scripts without being read, so an ELF named setup.py PASSed.
// Every file is now read for an executable or archive signature, whatever
// its name. Falsification: skip script-named files before reading them and
// these PASS.
func TestScriptNamedExecutableFails(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	pe := make([]byte, 0x80)
	copy(pe, "MZ")
	pe[0x3c] = 0x40
	copy(pe[0x40:], "PE\x00\x00")
	for name, body := range map[string][]byte{
		"setup.py":       append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 16)...),
		"run.sh":         pe,
		"bin/install.js": append([]byte{0xcf, 0xfa, 0xed, 0xfe}, make([]byte, 16)...),
	} {
		mirror := t.TempDir()
		_ = os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600)
		target := filepath.Join(mirror, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(target), 0o755)
		if err := os.WriteFile(target, body, 0o600); err != nil {
			t.Fatal(err)
		}
		r := Inspect(p, Options{RepoMirror: mirror})
		if r.Status != checks.Fail {
			t.Errorf("%s: status = %s, want FAIL for an executable named like a script: %s", name, r.Status, r.Notes)
			continue
		}
		if len(r.Findings) != 1 || r.Findings[0].Span != name {
			t.Errorf("%s: the finding must name the file, got %+v", name, r.Findings)
		}
	}

	// An archive named like a script is not scanned inside, so it is named.
	mirror := t.TempDir()
	zip := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 60)...)
	_ = os.WriteFile(filepath.Join(mirror, "loader.py"), zip, 0o600)
	if r := Inspect(p, Options{RepoMirror: mirror}); r.Status != checks.NotTested || !strings.Contains(r.Notes, "loader.py (zip)") {
		t.Errorf("a zip named loader.py: status = %s, notes %q; want NOT_TESTED naming it", r.Status, r.Notes)
	}
}

// TestInspectRepoReadsScriptNamedFiles: a directory scan whose weights carry
// no metadata lists the directory alone, through the same reader.
func TestInspectRepoReadsScriptNamedFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "setup.py"), append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 16)...), 0o600)
	if r := InspectRepo(dir); r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL for an ELF named setup.py: %s", r.Status, r.Notes)
	}
}

func TestEmbeddedScriptInMetadataFails(t *testing.T) {
	kvs := gguftest.WithMeta("general.name", gguftest.Str("general.name", "<script>fetch('http://x')</script>"))
	p := writeFixture(t, "payload-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	r := Inspect(p, Options{})
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL", r.Status)
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected a finding on embedded script content")
	}
}

func TestEmbeddedBase64BlobFails(t *testing.T) {
	blob := ""
	for i := 0; i < 600; i++ {
		blob += "A"
	}
	kvs := gguftest.WithMeta("general.name", gguftest.Str("general.name", blob))
	p := writeFixture(t, "blob-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	if got := Inspect(p, Options{}).Status; got != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a large base64 blob", got)
	}
}

func TestRepoBinaryFails(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))

	mirror := t.TempDir()
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 16)...)
	if err := os.WriteFile(filepath.Join(mirror, "helper"), elf, 0o600); err != nil {
		t.Fatalf("writing elf: %v", err)
	}

	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a repo binary", r.Status)
	}
}

// TestShortMagicInTextDoesNotFail: metadata matching used bytes.Contains on
// two-byte magics, so ordinary text such as "Licensed by AMZ Corp" FAILed as an
// embedded PE. Two-byte magics now count only at the start of a value and only
// with confirming structure. Falsification: match "MZ" anywhere again and this
// FAILs.
func TestShortMagicInTextDoesNotFail(t *testing.T) {
	for _, v := range []string{"Licensed by AMZ Corp", "MZ is a common prefix", "\x1f\x8b but not gzip"} {
		p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(
			gguftest.WithMeta("general.license", gguftest.Str("general.license", v))))
		r := Inspect(p, Options{})
		if r.Status == checks.Fail {
			t.Errorf("metadata %q FAILed as an embedded binary: %+v", v, r.Findings)
		}
	}
}

// TestRealPEInMetadataFails: a value that really is a PE image still FAILs.
func TestRealPEInMetadataFails(t *testing.T) {
	pe := make([]byte, 0x80)
	copy(pe, "MZ")
	pe[0x3c] = 0x40
	copy(pe[0x40:], "PE\x00\x00")
	p := writeFixture(t, "pe-Q5_K_M.gguf", gguftest.BuildGGUF(
		gguftest.WithMeta("general.license", gguftest.Str("general.license", string(pe)))))
	r := Inspect(p, Options{})
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL on a PE image in metadata", r.Status)
	}
}

// TestRepoTorchCheckpointIsNotAFail: every PyTorch checkpoint since 1.6 is a
// zip, so the repo side FAILed any repo shipping pytorch_model.bin. An
// archive is not an executable; its contents were not scanned, so the row is
// NOT_TESTED with the checkpoint named. Falsification: treat zip as an
// executable magic again and this FAILs.
func TestRepoTorchCheckpointIsNotAFail(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	mirror := t.TempDir()
	zip := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 60)...)
	if err := os.WriteFile(filepath.Join(mirror, "pytorch_model.bin"), zip, 0o600); err != nil {
		t.Fatal(err)
	}
	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED for an unscanned checkpoint (notes: %s)", r.Status, r.Notes)
	}
	if !strings.Contains(r.Notes, "pytorch_model.bin") {
		t.Errorf("the unscanned checkpoint must be named, got %q", r.Notes)
	}
}

// TestRepoFileStartingMZIsNotAFail: a text file that happens to start "MZ" is
// not a PE.
func TestRepoFileStartingMZIsNotAFail(t *testing.T) {
	p := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	mirror := t.TempDir()
	if err := os.WriteFile(filepath.Join(mirror, "NOTES"), []byte("MZ-series notes for this model"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Inspect(p, Options{RepoMirror: mirror}); r.Status == checks.Fail {
		t.Fatalf("a text file starting MZ FAILed: %+v", r.Findings)
	}
}

func TestUnparsedFormatsGroupsAndCaps(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 7; i++ {
		if err := os.WriteFile(filepath.Join(root, "w"+string(rune('0'+i))+".npy"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := UnparsedFormats(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "NumPy: w0.npy") || !strings.HasSuffix(got[0], "and 2 more") {
		t.Fatalf("got %q, want one NumPy entry listing five files and 2 more", got)
	}
}

// TestPayloadInStringArrayFails: string arrays used to be skipped, so a
// payload in an array value passed (#135). Falsification: drop ArrayStrings
// from the scanned values and this passes.
func TestPayloadInStringArrayFails(t *testing.T) {
	blob := strings.Repeat("QUJD", 200) // 800 base64 characters
	kvs := append(gguftest.Clean(), gguftest.StrArray("general.tags", "chat", "instruct", blob))
	p := writeFixture(t, "array-payload-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	r := Inspect(p, Options{})
	if r.Status != checks.Fail {
		t.Fatalf("status = %s, want FAIL for a base64 blob in a string array: %s", r.Status, r.Notes)
	}
	found := false
	for _, f := range r.Findings {
		if f.Pattern == "embedded-base64-blob" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want an embedded-base64-blob finding, got %+v", r.Findings)
	}
}

// TestShortArrayElementsAreNotScanned: a vocabulary holds short tokens such as
// "<script" or "#!", which are not payloads. Elements under the scan minimum
// are counted, not kept, so they cannot FAIL a real model.
func TestShortArrayElementsAreNotScanned(t *testing.T) {
	kvs := append(gguftest.Clean(), gguftest.StrArray("tokenizer.ggml.extra", "<script", "#!/bin/sh", "PK\x03\x04"))
	p := writeFixture(t, "vocab-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	mirror := t.TempDir()
	_ = os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600)
	if r := Inspect(p, Options{RepoMirror: mirror}); r.Status != checks.Pass {
		t.Fatalf("status = %s, want PASS for short tokens: %+v %s", r.Status, r.Findings, r.Notes)
	}
}

// TestTruncatedInventoryIsNotTested: an inventory cut off at its cap did not
// scan every value, so it cannot PASS (#135). It used to PASS with a note.
// Falsification: ignore Truncated and this PASSes.
func TestTruncatedInventoryIsNotTested(t *testing.T) {
	big := strings.Repeat("plain notes. ", 5042) // about 64 KiB, no pattern
	vals := make([]string, 140)                  // 140 x 64 KiB: past the 8 MiB cap
	for i := range vals {
		vals[i] = big
	}
	kvs := append(gguftest.Clean(), gguftest.StrArray("general.notes", vals...))
	p := writeFixture(t, "big-Q5_K_M.gguf", gguftest.BuildGGUF(kvs))

	mirror := t.TempDir()
	_ = os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600)
	r := Inspect(p, Options{RepoMirror: mirror})
	if r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED for a truncated inventory: %s", r.Status, r.Notes)
	}
	if !strings.Contains(r.Notes, "cap") {
		t.Errorf("notes should name the cap: %s", r.Notes)
	}
}
