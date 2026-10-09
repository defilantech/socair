package pickle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

// payload is the detection benchmark's defanged command.
const payload = "echo socair-benchmark"

func hasPattern(r checks.Result, pattern string) bool {
	for _, f := range r.Findings {
		if f.Pattern == pattern {
			return true
		}
	}
	return false
}

func floats(n int) []byte { return make([]byte, 4*n) }

// abuses are the issue's falsification fixtures: argument-level abuse of
// safe-listed callables, layout lies, and parse-differential shapes. Each
// starts from canonical torch.save output (see the builder) and changes one
// thing. needsGrammar marks those the import allowlist this grammar replaced
// let through.
func abuses(t *testing.T) []struct {
	name         string
	file         []byte
	want         checks.Status
	pattern      string
	needsGrammar bool
} {
	z := func(pkl []byte, records map[string][]byte) []byte { return torchZip(t, pkl, records) }
	one := map[string][]byte{"0": floats(4)}
	return []struct {
		name         string
		file         []byte
		want         checks.Status
		pattern      string
		needsGrammar bool
	}{
		{"OrderedDict handed a code string (ShadowPickle)", z(newPK().dict("w", func(p *pk) {
			p.global("collections", "OrderedDict").str(payload).raw("\x85").put().raw("R").put()
		}).stop(), nil), checks.Fail, "pickle-code-argument", true},
		{"tensor with backward hooks", z(newPK().dict("w", func(p *pk) {
			p.tensor("0", 4, 0, []int{4}, []int{1}, func(p *pk) { p.orderedDict().int(0).raw("Ns") })
		}).stop(), one), checks.Lead, "pickle-backward-hooks", true},
		{"tensor view past its storage (stride overrun)", z(newPK().dict("w", func(p *pk) {
			p.tensor("0", 4, 0, []int{4}, []int{2}, nil)
		}).stop(), one), checks.Fail, "pickle-storage-layout", true},
		{"storage larger than its record (oversize numel)", z(newPK().dict("w", func(p *pk) {
			p.tensor("0", 8, 0, []int{8}, []int{1}, nil)
		}).stop(), one), checks.Fail, "pickle-storage-layout", true},
		{"SETITEMS on a list", newPK().raw("]").put().int(0).raw("a(").int(0).int(7).raw("u").stop(),
			checks.Lead, "pickle-grammar", true},
		{"BUILD on an unlisted object", newPK().global("torch", "device").str("cpu").raw("\x85").put().raw("R").put().
			raw("}").put().str("x").int(1).raw("sb").stop(), checks.Lead, "pickle-grammar", true},
		{"non-canonical INT", []byte("\x80\x02I01\n."), checks.Lead, "pickle-noncanonical", true},
		{"NUL in a GLOBAL line", []byte("\x80\x02ccollections\x00x\nOrderedDict\nq\x00)Rq\x01."), checks.Lead, "pickle-noncanonical", false},
		{"memo slot written twice", []byte("\x80\x02X\x01\x00\x00\x00aq\x00X\x01\x00\x00\x00bq\x00h\x00\x87."), checks.Lead, "pickle-noncanonical", true},
		{"OBJ", []byte("\x80\x02(ccollections\nOrderedDict\nq\x00o."), checks.Lead, "pickle-noncanonical", true},
		{"INST", []byte("\x80\x02(icollections\nOrderedDict\n."), checks.Lead, "pickle-noncanonical", true},
		{"EXT1", []byte("\x80\x02\x82\x01."), checks.Lead, "pickle-noncanonical", false},
		{"NEWOBJ_EX", []byte("\x80\x02ccollections\nOrderedDict\nq\x00)}q\x01\x92."), checks.Lead, "pickle-noncanonical", true},
		{"payload before a broken stream (nullifAI)", append(newPK().global("posix", "system").str(payload).raw("\x85R").b.Bytes(), 0xff, 0xfe),
			checks.Fail, "pickle-dangerous-global", false},
		{"benign start, then a broken stream", append(newPK().raw("}").put().str("w").b.Bytes(), 0xff), checks.Lead, "pickle-unreadable", false},
		{"nested loader: torch.storage._load_from_bytes", newPK().global("torch.storage", "_load_from_bytes").
			global("_codecs", "encode").str("PK").str("latin1").raw("\x86").put().raw("R").put().raw("\x85").put().raw("R").stop(),
			checks.Fail, "pickle-nested-loader", false},
		{"Python 2 module name (cPickle.loads is pickle.loads)", newPK().global("cPickle", "loads").str("x").raw("\x85R").stop(),
			checks.Fail, "pickle-dangerous-global", false},
		{"Python 2 name (__builtin__.intern is sys.intern)", newPK().global("__builtin__", "intern").str("x").raw("\x85R").stop(),
			checks.Fail, "pickle-dangerous-global", false},
	}
}

// TestGrammarCatchesAbuse: each abuse FAILs or LEADs with its pattern.
// Falsification: TestStrictModeFalsification switches the grammar off.
func TestGrammarCatchesAbuse(t *testing.T) {
	for _, c := range abuses(t) {
		r := Inspect(writeFixture(t, "model.bin", c.file))
		if r.Status != c.want || !hasPattern(r, c.pattern) {
			t.Errorf("%s: status %s, findings %+v; want %s with %s", c.name, r.Status, r.Findings, c.want, c.pattern)
		}
	}
}

// TestStrictModeFalsification: with the grammar off, the check is the import
// allowlist it replaced, and every abuse marked needsGrammar PASSes. So each
// of those is caught by the grammar and nothing else, and neutering the
// grammar fails TestGrammarCatchesAbuse.
func TestStrictModeFalsification(t *testing.T) {
	t.Cleanup(func() { strictGrammar = true })
	strictGrammar = false
	n := 0
	for _, c := range abuses(t) {
		if !c.needsGrammar {
			continue
		}
		n++
		if r := Inspect(writeFixture(t, "model.bin", c.file)); r.Status != checks.Pass {
			t.Errorf("%s: with the grammar off, status %s (%s); the fixture must test the grammar alone", c.name, r.Status, r.Notes)
		}
	}
	if n < 10 {
		t.Fatalf("only %d grammar-dependent fixtures", n)
	}
}

// TestCanonicalCheckpointPasses: a protocol 2 state dict with its storage
// record earns the proof-style PASS, naming the grammar and what it built.
// Falsification: drop the record size check and the oversize-numel abuse
// above PASSes.
func TestCanonicalCheckpointPasses(t *testing.T) {
	for name, file := range map[string][]byte{
		"builder":                  torchZip(t, stateDict(), map[string][]byte{"0": floats(4)}),
		"CPython torch-one-tensor": torchZip(t, loadVectors(t)["torch-one-tensor"].bytes(t), map[string][]byte{"0": floats(4)}),
	} {
		r := Inspect(writeFixture(t, "pytorch_model.bin", file))
		if r.Status != checks.Pass || !strings.Contains(r.Notes, Grammar) || !strings.Contains(r.Notes, "1 tensor") {
			t.Errorf("%s: status %s (%s), want a PASS naming %s and 1 tensor", name, r.Status, r.Notes, Grammar)
		}
	}
}

func TestTorchZipLayout(t *testing.T) {
	sd := stateDict()
	cases := []struct {
		name    string
		file    []byte
		want    checks.Status
		pattern string
	}{
		{"storage record missing", torchZip(t, sd, nil), checks.Fail, "pickle-storage-layout"},
		{"record longer than its storage", torchZip(t, sd, map[string][]byte{"0": floats(5)}), checks.Lead, "pickle-unaccounted-bytes"},
		{"record no tensor references", torchZip(t, sd, map[string][]byte{"0": floats(4), "1": []byte(payload)}), checks.Lead, "pickle-unaccounted-bytes"},
		{"record outside torch's layout", torchZip(t, sd, map[string][]byte{"0": floats(4)}, "archive/run.sh", payload), checks.Lead, "pickle-unaccounted-bytes"},
		{"bytes after STOP in data.pkl", torchZip(t, append(append([]byte{}, sd...), payload...), map[string][]byte{"0": floats(4)}), checks.Lead, "pickle-unaccounted-bytes"},
		{"storage referenced with two sizes", torchZip(t, newPK().raw("}").put().raw("(").str("a").
			tensor("0", 4, 0, []int{4}, []int{1}, nil).str("b").tensor("0", 2, 0, []int{2}, []int{1}, nil).raw("u").stop(),
			map[string][]byte{"0": floats(4)}), checks.Fail, "pickle-storage-layout"},
	}
	for _, c := range cases {
		r := Inspect(writeFixture(t, "pytorch_model.bin", c.file))
		if r.Status != c.want || !hasPattern(r, c.pattern) {
			t.Errorf("%s: status %s, findings %+v; want %s with %s", c.name, r.Status, r.Findings, c.want, c.pattern)
		}
	}
}

// TestOutsideTheGrammarIsNotTested: a stream in another protocol, a callable
// the grammar does not model, and a container it does not match are gaps,
// not passes and not leads.
func TestOutsideTheGrammarIsNotTested(t *testing.T) {
	cases := map[string][]byte{
		"protocol 0":          real["benign_p0"],
		"protocol 4":          real["benign_p4"],
		"protocol 5":          real["benign_p5"],
		"unmodeled callable":  newPK().global("__builtin__", "range").int(3).raw("\x85").put().raw("R").stop(),
		"TorchScript archive": torchZip(t, stateDict(), map[string][]byte{"0": floats(4)}, "archive/code/__torch__/m.py", "def forward(self): pass", "archive/constants.pkl", "\x80\x02)."),
	}
	for name, file := range cases {
		r := Inspect(writeFixture(t, "model.bin", file))
		if r.Status != checks.NotTested || r.Notes == "" {
			t.Errorf("%s: status %s (%s), want NOT_TESTED with a reason", name, r.Status, r.Notes)
		}
	}
}

// legacyStream builds a legacy torch.save file (the stream format before
// zips): magic number, protocol version, sys_info, the object, the storage
// keys, then each storage as an 8-byte element count and its bytes.
func legacyStream(t *testing.T, count int64, tail []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	v := loadVectors(t)["legacy-stream"].bytes(t)
	// The vector ends with one storage record: an element count of 3, then
	// three float32 values.
	b.Write(v[:len(v)-8-12])
	_ = binary.Write(&b, binary.LittleEndian, count)
	b.Write(v[len(v)-12:])
	b.Write(tail)
	return b.Bytes()
}

func TestLegacyStream(t *testing.T) {
	r := Inspect(writeFixture(t, "pytorch_model.bin", legacyStream(t, 3, nil)))
	if r.Status != checks.Pass || !strings.Contains(r.Notes, "legacy") {
		t.Fatalf("legacy stream: status %s (%s), want PASS", r.Status, r.Notes)
	}
	if r := Inspect(writeFixture(t, "pytorch_model.bin", legacyStream(t, 2, nil))); r.Status != checks.Fail || !hasPattern(r, "pickle-storage-layout") {
		t.Errorf("record count that disagrees with its storage id: status %s, findings %+v; want FAIL", r.Status, r.Findings)
	}
	if r := Inspect(writeFixture(t, "pytorch_model.bin", legacyStream(t, 3, []byte(payload)))); r.Status != checks.Lead || !hasPattern(r, "pickle-unaccounted-bytes") {
		t.Errorf("bytes after the last record: status %s, findings %+v; want LEAD", r.Status, r.Findings)
	}
}

// TestReviewedClassTier: a reviewed class (delivered as reference data, empty
// by default) built with a default __new__ and a dict of plain values
// conforms; the same class with other state, or unreviewed, LEADs.
func TestReviewedClassTier(t *testing.T) {
	args := func(state func(*pk)) []byte {
		p := newPK().global("transformers.training_args", "TrainingArguments").raw(")\x81").put()
		state(p)
		return p.raw("b").stop()
	}
	plainState := args(func(p *pk) { p.raw("}").put().raw("(").str("output_dir").str("out").str("seed").int(42).raw("u") })
	withObject := args(func(p *pk) {
		p.raw("}").put().str("cb").global("collections", "OrderedDict").raw(")R").put().raw("s")
	})
	reviewed := Options{Reviewed: map[string]bool{"transformers.training_args.TrainingArguments": true}}
	if r := InspectWith(writeFixture(t, "training_args.bin", plainState), reviewed); r.Status != checks.Pass || !strings.Contains(r.Notes, "TrainingArguments") {
		t.Errorf("reviewed class with plain state: status %s (%s), want PASS naming the class", r.Status, r.Notes)
	}
	if r := InspectWith(writeFixture(t, "training_args.bin", withObject), reviewed); r.Status != checks.Lead || !hasPattern(r, "pickle-reviewed-class-state") {
		t.Errorf("reviewed class with an object in its state: status %s, findings %+v; want LEAD", r.Status, r.Findings)
	}
	if r := Inspect(writeFixture(t, "training_args.bin", plainState)); r.Status != checks.Lead || !hasPattern(r, "pickle-unreviewed-global") {
		t.Errorf("no review list: status %s, findings %+v; want LEAD on the unreviewed class", r.Status, r.Findings)
	}
}

func npy(descr, shape string, data []byte) []byte {
	h := "{'descr': '" + descr + "', 'fortran_order': False, 'shape': " + shape + ", }"
	pad := 64 - (10+len(h)+1)%64
	h += strings.Repeat(" ", pad) + "\n"
	b := append([]byte("\x93NUMPY\x01\x00"), byte(len(h)), byte(len(h)>>8))
	return append(append(b, h...), data...)
}

func TestNumPy(t *testing.T) {
	objectPayload := newPK().raw("]").put().str("a").raw("a").stop()
	cases := []struct {
		name    string
		file    []byte
		want    checks.Status
		pattern string
	}{
		{"float32 array", npy("<f4", "(2, 3)", floats(6)), checks.Pass, ""},
		{"scalar", npy("<f8", "()", make([]byte, 8)), checks.Pass, ""},
		{"data shorter than the shape", npy("<f4", "(2, 3)", floats(5)), checks.Fail, "pickle-storage-layout"},
		{"data longer than the shape", npy("<f4", "(2, 3)", append(floats(6), payload...)), checks.Lead, "pickle-unaccounted-bytes"},
		{"object array with a gadget", npy("|O", "(1,)", newPK().global("posix", "system").str(payload).raw("\x85R").stop()), checks.Fail, "pickle-dangerous-global"},
		{"object array, protocol 2 (inside the grammar)", npy("|O", "(1,)", objectPayload), checks.Pass, ""},
		{"object array, protocol 4 (as numpy writes it)", npy("|O", "(1,)", real["benign_p4"]), checks.NotTested, ""},
		{"header over numpy's limit", append([]byte("\x93NUMPY\x02\x00"), 0x20, 0x4e, 0, 0), checks.NotTested, ""},
	}
	for _, c := range cases {
		r := Inspect(writeFixture(t, "array.npy", c.file))
		if r.Status != c.want || (c.pattern != "" && !hasPattern(r, c.pattern)) {
			t.Errorf("%s: status %s (%s), findings %+v; want %s %s", c.name, r.Status, r.Notes, r.Findings, c.want, c.pattern)
		}
	}

	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range map[string][]byte{"a.npy": npy("<i8", "(3,)", make([]byte, 24)), "b.npy": npy("|b1", "(2,)", []byte{0, 1})} {
		w, _ := zw.Create(name)
		_, _ = w.Write(data)
	}
	_ = zw.Close()
	if r := Inspect(writeFixture(t, "arrays.npz", b.Bytes())); r.Status != checks.Pass || !strings.Contains(r.Notes, "2 array") {
		t.Errorf("npz: status %s (%s), want PASS over 2 arrays", r.Status, r.Notes)
	}
}

// TestLegacyTarIsAGap: the grammar runs on a legacy tar's pickles, but its
// storage records are not matched, so a clean tar is NOT_TESTED.
func TestLegacyTarIsAGap(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range []struct {
		name string
		data []byte
	}{{"sys_info", newPK().raw("}").put().stop()}, {"pickle", newPK().raw("}").put().stop()}} {
		_ = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(e.data)
	}
	_ = tw.Close()
	if r := Inspect(writeFixture(t, "model.tar", b.Bytes())); r.Status != checks.NotTested || !strings.Contains(r.Notes, "tar") {
		t.Fatalf("status %s (%s), want NOT_TESTED naming the tar layout", r.Status, r.Notes)
	}
}
