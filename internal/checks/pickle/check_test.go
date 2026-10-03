package pickle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// real holds pickles written by CPython 3.14 pickle.dumps, embedded so the
// tests need no Python. system_pN is an object whose __reduce__ returns
// (os.system, ('id',)), the canonical code-execution pickle; CPython emits the
// global as posix.system. benign_pN is an OrderedDict of a list, a set, and a
// string. getattr_p4 reduces to builtins.getattr; import_module_p4 to
// importlib.import_module.
var real = map[string][]byte{
	"system_p0":        []byte("\x63\x70\x6f\x73\x69\x78\x0a\x73\x79\x73\x74\x65\x6d\x0a\x70\x30\x0a\x28\x56\x69\x64\x0a\x70\x31\x0a\x74\x70\x32\x0a\x52\x70\x33\x0a\x2e"),
	"benign_p0":        []byte("\x63\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x0a\x4f\x72\x64\x65\x72\x65\x64\x44\x69\x63\x74\x0a\x70\x30\x0a\x28\x74\x52\x70\x31\x0a\x56\x77\x0a\x70\x32\x0a\x28\x6c\x70\x33\x0a\x46\x31\x2e\x35\x0a\x61\x49\x32\x0a\x61\x73\x56\x62\x0a\x70\x34\x0a\x63\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x5f\x5f\x0a\x73\x65\x74\x0a\x70\x35\x0a\x28\x28\x6c\x70\x36\x0a\x49\x33\x0a\x61\x49\x34\x0a\x61\x74\x70\x37\x0a\x52\x70\x38\x0a\x73\x56\x6e\x61\x6d\x65\x0a\x70\x39\x0a\x56\x6c\x61\x79\x65\x72\x0a\x70\x31\x30\x0a\x73\x2e"),
	"system_p1":        []byte("\x63\x70\x6f\x73\x69\x78\x0a\x73\x79\x73\x74\x65\x6d\x0a\x71\x00\x28\x58\x02\x00\x00\x00\x69\x64\x71\x01\x74\x71\x02\x52\x71\x03\x2e"),
	"benign_p1":        []byte("\x63\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x0a\x4f\x72\x64\x65\x72\x65\x64\x44\x69\x63\x74\x0a\x71\x00\x29\x52\x71\x01\x28\x58\x01\x00\x00\x00\x77\x71\x02\x5d\x71\x03\x28\x47\x3f\xf8\x00\x00\x00\x00\x00\x00\x4b\x02\x65\x58\x01\x00\x00\x00\x62\x71\x04\x63\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x5f\x5f\x0a\x73\x65\x74\x0a\x71\x05\x28\x5d\x71\x06\x28\x4b\x03\x4b\x04\x65\x74\x71\x07\x52\x71\x08\x58\x04\x00\x00\x00\x6e\x61\x6d\x65\x71\x09\x58\x05\x00\x00\x00\x6c\x61\x79\x65\x72\x71\x0a\x75\x2e"),
	"system_p2":        []byte("\x80\x02\x63\x70\x6f\x73\x69\x78\x0a\x73\x79\x73\x74\x65\x6d\x0a\x71\x00\x58\x02\x00\x00\x00\x69\x64\x71\x01\x85\x71\x02\x52\x71\x03\x2e"),
	"benign_p2":        []byte("\x80\x02\x63\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x0a\x4f\x72\x64\x65\x72\x65\x64\x44\x69\x63\x74\x0a\x71\x00\x29\x52\x71\x01\x28\x58\x01\x00\x00\x00\x77\x71\x02\x5d\x71\x03\x28\x47\x3f\xf8\x00\x00\x00\x00\x00\x00\x4b\x02\x65\x58\x01\x00\x00\x00\x62\x71\x04\x63\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x5f\x5f\x0a\x73\x65\x74\x0a\x71\x05\x5d\x71\x06\x28\x4b\x03\x4b\x04\x65\x85\x71\x07\x52\x71\x08\x58\x04\x00\x00\x00\x6e\x61\x6d\x65\x71\x09\x58\x05\x00\x00\x00\x6c\x61\x79\x65\x72\x71\x0a\x75\x2e"),
	"system_p3":        []byte("\x80\x03\x63\x70\x6f\x73\x69\x78\x0a\x73\x79\x73\x74\x65\x6d\x0a\x71\x00\x58\x02\x00\x00\x00\x69\x64\x71\x01\x85\x71\x02\x52\x71\x03\x2e"),
	"benign_p3":        []byte("\x80\x03\x63\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x0a\x4f\x72\x64\x65\x72\x65\x64\x44\x69\x63\x74\x0a\x71\x00\x29\x52\x71\x01\x28\x58\x01\x00\x00\x00\x77\x71\x02\x5d\x71\x03\x28\x47\x3f\xf8\x00\x00\x00\x00\x00\x00\x4b\x02\x65\x58\x01\x00\x00\x00\x62\x71\x04\x63\x62\x75\x69\x6c\x74\x69\x6e\x73\x0a\x73\x65\x74\x0a\x71\x05\x5d\x71\x06\x28\x4b\x03\x4b\x04\x65\x85\x71\x07\x52\x71\x08\x58\x04\x00\x00\x00\x6e\x61\x6d\x65\x71\x09\x58\x05\x00\x00\x00\x6c\x61\x79\x65\x72\x71\x0a\x75\x2e"),
	"system_p4":        []byte("\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05\x70\x6f\x73\x69\x78\x94\x8c\x06\x73\x79\x73\x74\x65\x6d\x94\x93\x94\x8c\x02\x69\x64\x94\x85\x94\x52\x94\x2e"),
	"benign_p4":        []byte("\x80\x04\x95\x52\x00\x00\x00\x00\x00\x00\x00\x8c\x0b\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x94\x8c\x0b\x4f\x72\x64\x65\x72\x65\x64\x44\x69\x63\x74\x94\x93\x94\x29\x52\x94\x28\x8c\x01\x77\x94\x5d\x94\x28\x47\x3f\xf8\x00\x00\x00\x00\x00\x00\x4b\x02\x65\x8c\x01\x62\x94\x8f\x94\x28\x4b\x03\x4b\x04\x90\x8c\x04\x6e\x61\x6d\x65\x94\x8c\x05\x6c\x61\x79\x65\x72\x94\x75\x2e"),
	"system_p5":        []byte("\x80\x05\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05\x70\x6f\x73\x69\x78\x94\x8c\x06\x73\x79\x73\x74\x65\x6d\x94\x93\x94\x8c\x02\x69\x64\x94\x85\x94\x52\x94\x2e"),
	"benign_p5":        []byte("\x80\x05\x95\x52\x00\x00\x00\x00\x00\x00\x00\x8c\x0b\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x94\x8c\x0b\x4f\x72\x64\x65\x72\x65\x64\x44\x69\x63\x74\x94\x93\x94\x29\x52\x94\x28\x8c\x01\x77\x94\x5d\x94\x28\x47\x3f\xf8\x00\x00\x00\x00\x00\x00\x4b\x02\x65\x8c\x01\x62\x94\x8f\x94\x28\x4b\x03\x4b\x04\x90\x8c\x04\x6e\x61\x6d\x65\x94\x8c\x05\x6c\x61\x79\x65\x72\x94\x75\x2e"),
	"getattr_p4":       []byte("\x80\x04\x95\x45\x00\x00\x00\x00\x00\x00\x00\x8c\x08\x62\x75\x69\x6c\x74\x69\x6e\x73\x94\x8c\x07\x67\x65\x74\x61\x74\x74\x72\x94\x93\x94\x8c\x0b\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x94\x8c\x0b\x4f\x72\x64\x65\x72\x65\x64\x44\x69\x63\x74\x94\x93\x94\x8c\x08\x66\x72\x6f\x6d\x6b\x65\x79\x73\x94\x86\x94\x52\x94\x2e"),
	"import_module_p4": []byte("\x80\x04\x95\x28\x00\x00\x00\x00\x00\x00\x00\x8c\x09\x69\x6d\x70\x6f\x72\x74\x6c\x69\x62\x94\x8c\x0d\x69\x6d\x70\x6f\x72\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x94\x93\x94\x8c\x02\x6f\x73\x94\x85\x94\x52\x94\x2e"),
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

func hasSpan(r checks.Result, span string) bool {
	for _, f := range r.Findings {
		if f.Span == span {
			return true
		}
	}
	return false
}

// TestSystemFailsAtEveryProtocol: the byte-pattern matcher found only the text
// GLOBAL of protocols 0 to 3, so a protocol 4 or 5 pickle (STACK_GLOBAL, the
// default since Python 3.8) of os.system PASSed. Falsification: go back to
// matching "c<module>\n<name>\n" and protocols 4 and 5 PASS.
func TestSystemFailsAtEveryProtocol(t *testing.T) {
	for p := 0; p <= 5; p++ {
		name := "system_p" + string(rune('0'+p))
		r := Inspect(writeFixture(t, "model.pt", real[name]))
		if r.Status != checks.Fail || !hasSpan(r, "posix.system") {
			t.Errorf("%s: status %s, findings %+v; want FAIL on posix.system", name, r.Status, r.Findings)
		}
	}
}

func TestBenignPassesAtEveryProtocol(t *testing.T) {
	for p := 0; p <= 5; p++ {
		name := "benign_p" + string(rune('0'+p))
		r := Inspect(writeFixture(t, "model.pt", real[name]))
		if r.Status != checks.Pass {
			t.Errorf("%s: status %s (%s), want PASS", name, r.Status, r.Notes)
		}
	}
}

func TestGadgetCallablesFail(t *testing.T) {
	cases := map[string]string{
		"getattr_p4":       "builtins.getattr",
		"import_module_p4": "importlib.import_module",
	}
	for fx, span := range cases {
		r := Inspect(writeFixture(t, "model.bin", real[fx]))
		if r.Status != checks.Fail || !hasSpan(r, span) {
			t.Errorf("%s: status %s, findings %+v; want FAIL on %s", fx, r.Status, r.Findings, span)
		}
	}
}

// Hand-built streams for forms CPython does not emit by default.
func TestOpcodeForms(t *testing.T) {
	cases := []struct {
		name   string
		stream string
		want   checks.Status
		span   string
	}{
		{"INST", "(S'id'\nios\nsystem\n.", checks.Fail, "os.system"},
		{"STACK_GLOBAL from memo", "\x80\x04\x8c\x02os\x94\x8c\x06system\x940" + "0h\x00h\x01\x93)R.", checks.Fail, "os.system"},
		{"submodule of a dangerous module", "\x80\x02casyncio.unix_events\n_UnixSubprocessTransport\n.", checks.Fail, "asyncio.unix_events._UnixSubprocessTransport"},
		{"__builtin__ alias", "\x80\x02c__builtin__\neval\n.", checks.Fail, "__builtin__.eval"},
		{"stream breaks after the import", "\x80\x02cos\nsystem\n", checks.Fail, "os.system"},
		{"unreviewed global", "\x80\x02cjson\nloads\n.", checks.Lead, "json.loads"},
		{"non-constant STACK_GLOBAL", "\x80\x04K\x01K\x02\x93.", checks.Lead, ""},
		{"extension registry", "\x80\x02\x82\x01.", checks.Lead, ""},
		{"torch tensor rebuild", "\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00(ctorch\nFloatStorage\nq\x01tR.", checks.Pass, ""},
	}
	for _, c := range cases {
		r := Inspect(writeFixture(t, "x.pkl", []byte(c.stream)))
		if r.Status != c.want {
			t.Errorf("%s: status %s (%s), want %s", c.name, r.Status, r.Notes, c.want)
			continue
		}
		if c.span != "" && !hasSpan(r, c.span) {
			t.Errorf("%s: no %s finding in %+v", c.name, c.span, r.Findings)
		}
	}
}

// TestLegacyTrailingDataIsNotMisread: a legacy torch.save file is pickles
// followed by raw storage bytes. Trailing bytes that happen to start with
// PROTO must not be reported as imports.
func TestLegacyTrailingDataIsNotMisread(t *testing.T) {
	stream := append(append(append([]byte{}, real["benign_p2"]...), real["benign_p2"]...), []byte("\x80\x02cfake\nmodule\n\x00\x01\x02")...)
	r := Inspect(writeFixture(t, "legacy.pt", stream))
	if r.Status != checks.Pass {
		t.Fatalf("status %s (%s), want PASS: trailing data is not a pickle", r.Status, r.Notes)
	}
}

func zipOf(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestZipCheckpoints: PyTorch has saved zips since 1.6, and the scanner never
// opened them. Entries are found by content, so a pickle stored under a
// non-.pkl name (a picklescan bypass) is still walked. Falsification: skip
// the zip branch and every zip is NOT_TESTED.
func TestZipCheckpoints(t *testing.T) {
	cases := []struct {
		name    string
		entries map[string][]byte
		want    checks.Status
	}{
		{"data.pkl gadget", map[string][]byte{"archive/data.pkl": real["system_p2"], "archive/version": []byte("3\n")}, checks.Fail},
		{"gadget under a tensor name", map[string][]byte{"archive/data.pkl": real["benign_p2"], "archive/data/0": real["system_p4"]}, checks.Fail},
		{"benign checkpoint", map[string][]byte{"archive/data.pkl": real["benign_p2"], "archive/data/0": {0x00, 0x00, 0x80, 0x3f}}, checks.Pass},
		{"no pickle at all", map[string][]byte{"README": []byte("hello")}, checks.NotTested},
	}
	for _, c := range cases {
		r := Inspect(writeFixture(t, "model.pt", zipOf(t, c.entries)))
		if r.Status != c.want {
			t.Errorf("%s: status %s (%s), want %s", c.name, r.Status, r.Notes, c.want)
		}
	}
}

func TestTarCheckpoint(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, data := range map[string][]byte{"sys_info": real["benign_p2"], "pickle": real["system_p2"]} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	r := Inspect(writeFixture(t, "legacy.tar", b.Bytes()))
	if r.Status != checks.Fail || !hasSpan(r, "posix.system") {
		t.Fatalf("status %s, findings %+v; want FAIL on posix.system", r.Status, r.Findings)
	}
}

// TestTruncationIsNotTested: a gadget past the scan budget used to PASS. Past
// the budget the result is NOT_TESTED, unless what was read already FAILs.
func TestTruncationIsNotTested(t *testing.T) {
	old := maxScanBytes
	t.Cleanup(func() { maxScanBytes = old })
	maxScanBytes = 16

	long := real["benign_p0"]
	if len(long) <= 16 {
		t.Fatalf("fixture too short: %d bytes", len(long))
	}
	if r := Inspect(writeFixture(t, "big.pt", long)); r.Status != checks.NotTested || !strings.Contains(r.Notes, "only in part") {
		t.Fatalf("status %s (%s), want NOT_TESTED for a stream past the budget", r.Status, r.Notes)
	}
	early := append([]byte("\x80\x02cos\nsystem\n"), bytes.Repeat([]byte("N0"), 64)...)
	if r := Inspect(writeFixture(t, "big.pt", early)); r.Status != checks.Fail {
		t.Fatalf("status %s, want FAIL: the gadget was inside the budget", r.Status)
	}
}

func TestSafetensorsIsNotPickle(t *testing.T) {
	r := Inspect(writeFixture(t, "model.safetensors", safetensorstest.Clean()))
	if r.Status != checks.NotTested || r.Notes == "" {
		t.Fatalf("status = %s (%q), want NOT_TESTED with a reason", r.Status, r.Notes)
	}
}

func TestGgufIsNotPickle(t *testing.T) {
	p := writeFixture(t, "model-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	if got := Inspect(p).Status; got != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED", got)
	}
}

func TestRawTensorFileIsNotScanned(t *testing.T) {
	p := writeFixture(t, "raw.bin", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	if r := Inspect(p); r.Status != checks.NotTested {
		t.Fatalf("status = %s, want NOT_TESTED for a non-pickle byte stream", r.Status)
	}
}
