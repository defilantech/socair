package engine

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

var hubSource = PreviewSource{Hub: PreviewHub, Repo: "org/tiny", Commit: strings.Repeat("c0ffee12", 5)}

// stated returns each file's true SHA-256, as a hub would state it.
func stated(t *testing.T, dir string) map[string]string {
	t.Helper()
	_, files, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, f := range files {
		m[f.Path] = f.SHA256
	}
	return m
}

func previewRow(p *Preview, name string) report.CheckResult {
	for _, c := range p.Checks {
		if c.Name == name {
			return c
		}
	}
	return report.CheckResult{}
}

// The preview reads in place and reports each hash as its source states
// it. Falsification: a snapshot needs SOCAIR_SCAN_TMP, set here to a volume
// that does not exist, so a preview that copied would fail; and the stated
// weight hash is wrong on purpose, so a preview that hashed would report
// another.
func TestPreviewReadsInPlaceWithStatedHashes(t *testing.T) {
	dir := modelRepo(t, nil)
	hashes := stated(t, dir)
	hashes["model.safetensors"] = strings.Repeat("ab", 32)
	t.Setenv("SOCAIR_SCAN_TMP", filepath.Join(t.TempDir(), "missing"))

	p, err := PreviewDir(dir, hubSource, hashes)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range p.Model.Files {
		if f.StatedSHA256 != hashes[f.Path] {
			t.Errorf("%s: %s, want the stated %s", f.Path, f.StatedSHA256, hashes[f.Path])
		}
	}
	for name, want := range map[string]report.Status{
		"Format and structure": report.StatusPass, "Chat template": report.StatusPass,
		"Remote code": report.StatusPass, "Tokenizer config": report.StatusPass,
	} {
		if got := previewRow(p, name).Status; got != want {
			t.Errorf("%s = %s (%s), want %s", name, got, previewRow(p, name).Notes, want)
		}
	}
	if p.Model.Name != "org/tiny" || p.Source.Commit != hubSource.Commit {
		t.Errorf("model %q at %q, want the source's repo and commit", p.Model.Name, p.Source.Commit)
	}
	if p.Kind != PreviewKind || p.Notice != PreviewNotice || p.Hashes != PreviewHashes {
		t.Error("a preview carries its kind and its fixed statements")
	}
}

func TestPreviewNeedsEveryFilesHash(t *testing.T) {
	dir := modelRepo(t, nil)
	for name, edit := range map[string]func(map[string]string){
		"missing":   func(h map[string]string) { delete(h, "config.json") },
		"malformed": func(h map[string]string) { h["config.json"] = "a git blob id" },
	} {
		hashes := stated(t, dir)
		edit(hashes)
		if _, err := PreviewDir(dir, hubSource, hashes); err == nil || !strings.Contains(err.Error(), "config.json") {
			t.Errorf("%s: a file with no stated SHA-256 must stop the preview, naming it: %v", name, err)
		}
	}
	if _, err := PreviewDir(dir, hubSource, nil); err == nil {
		t.Error("a preview with no stated hashes must stop")
	}
}

// Every preview names the full commit it read, on the hub it reads.
func TestPreviewNamesTheCommit(t *testing.T) {
	dir := modelRepo(t, nil)
	for name, src := range map[string]PreviewSource{
		"a branch":        {Hub: PreviewHub, Repo: "org/tiny", Commit: "main"},
		"a short commit":  {Hub: PreviewHub, Repo: "org/tiny", Commit: "c0ffee12"},
		"an upper commit": {Hub: PreviewHub, Repo: "org/tiny", Commit: strings.ToUpper(hubSource.Commit)},
		"another hub":     {Hub: "example.com", Repo: "org/tiny", Commit: hubSource.Commit},
		"no repo":         {Hub: PreviewHub, Repo: "tiny", Commit: hubSource.Commit},
		"a path":          {Hub: PreviewHub, Repo: "org/../tiny", Commit: hubSource.Commit},
	} {
		if _, err := PreviewDir(dir, src, stated(t, dir)); err == nil {
			t.Errorf("%s: a preview must name a full commit on %s", name, PreviewHub)
		}
	}
	p, err := PreviewDir(dir, hubSource, stated(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != hubSource {
		t.Errorf("source %+v, want %+v", p.Source, hubSource)
	}
}

// The preview finds what a full scan finds, for the checks it runs.
func TestPreviewFindsWhatAScanFinds(t *testing.T) {
	dir := modelRepo(t, map[string]string{"modeling_tiny.py": "import os\n", "config.json": `{"auto_map":{"AutoModel":"modeling_tiny.TinyModel"}}`})
	full, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PreviewDir(dir, hubSource, stated(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if p.Model.StatedDigest != full.Artifact.SHA256 {
		t.Errorf("digest %s, a full scan's %s", p.Model.StatedDigest, full.Artifact.SHA256)
	}
	for _, c := range full.Checks {
		if got := previewRow(p, c.Name); got.Status != c.Status {
			t.Errorf("%s: preview %s, full scan %s", c.Name, got.Status, c.Status)
		}
	}
	if previewRow(p, "Remote code").Status != report.StatusLead {
		t.Errorf("remote code = %s, want LEAD", previewRow(p, "Remote code").Status)
	}
}

// A check that reads a whole file is NOT_TESTED in a preview, named as the
// preview's, never a PASS. Falsification: the full scan of the same files
// runs the pickle check and FAILs it, so the fixture is one the check reads.
func TestPreviewLeavesWholeFileChecksNotTested(t *testing.T) {
	dir := modelRepo(t, map[string]string{"pytorch_model.bin": string(posixSystemPickle)})
	full, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := row(full, "Pickle opcode scan").Status; got != report.StatusFail {
		t.Fatalf("full scan pickle row = %s, want FAIL; the fixture does not exercise the check", got)
	}
	p, err := PreviewDir(dir, hubSource, stated(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	r := previewRow(p, "Pickle opcode scan")
	if r.Status != report.StatusNotTested || !strings.Contains(r.Notes, PreviewHeadersOnly) {
		t.Errorf("preview pickle row = %s (%s), want NOT_TESTED naming the preview", r.Status, r.Notes)
	}

	onnx := modelRepo(t, map[string]string{"model.onnx": "not read"})
	p, err = PreviewDir(onnx, hubSource, stated(t, onnx))
	if err != nil {
		t.Fatal(err)
	}
	if r := previewRow(p, "Format and structure"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, PreviewHeadersOnly) {
		t.Errorf("an ONNX file's structure = %s (%s), want NOT_TESTED naming the preview", r.Status, r.Notes)
	}
}

// A preview carries no verdict: none of the fields an attestation has, at
// any depth of its type, and none in its JSON. Falsification: the same
// detector finds them in a report.Document.
func TestPreviewCarriesNoVerdict(t *testing.T) {
	forbidden := []string{"promotion", "assurance", "issuer", "signature", "signer", "bounded_statement",
		"verification", "authorized", "document_hash", "attestation"}
	hit := func(s string) string {
		s = strings.ToLower(s)
		for _, f := range forbidden {
			if strings.Contains(s, f) {
				return f
			}
		}
		return ""
	}
	var walk func(t reflect.Type, seen map[reflect.Type]bool, found *[]string)
	walk = func(t reflect.Type, seen map[reflect.Type]bool, found *[]string) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if h := hit(f.Name + " " + f.Tag.Get("json") + " " + f.Type.Name()); h != "" {
				*found = append(*found, t.Name()+"."+f.Name)
			}
			walk(f.Type, seen, found)
		}
	}
	var inDoc []string
	walk(reflect.TypeOf(report.Document{}), map[reflect.Type]bool{}, &inDoc)
	if len(inDoc) == 0 {
		t.Fatal("the detector finds nothing in a report.Document, so it detects nothing")
	}
	var inPreview []string
	walk(reflect.TypeOf(Preview{}), map[reflect.Type]bool{}, &inPreview)
	if len(inPreview) != 0 {
		t.Errorf("a preview must carry no verdict, signature, or issuer: %v", inPreview)
	}

	dir := modelRepo(t, nil)
	p, err := PreviewDir(dir, hubSource, stated(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	for k := range keys {
		if h := hit(k); h != "" {
			t.Errorf("preview JSON key %q (%s)", k, h)
		}
	}
}

// A GGUF on its own previews its metadata rows, with its stated hash.
func TestPreviewGGUF(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tiny-Q4_K_M.gguf")
	if err := os.WriteFile(file, gguftest.BuildGGUF(gguftest.Clean()), 0o644); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("cd", 32)
	p, err := PreviewGGUF(file, hubSource, want)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Model.Files) != 1 || p.Model.Files[0].StatedSHA256 != want || p.Model.StatedDigest != want {
		t.Errorf("files %+v digest %s, want the stated %s", p.Model.Files, p.Model.StatedDigest, want)
	}
	if got := previewRow(p, "Chat template").Status; got == "" {
		t.Error("a GGUF preview grades its chat template")
	}
	if _, err := PreviewGGUF(file, hubSource, ""); err == nil {
		t.Error("a GGUF preview needs the file's stated hash")
	}
	if _, err := PreviewGGUF(filepath.Join(dir, "model.safetensors"), hubSource, want); err == nil {
		t.Error("PreviewGGUF previews a .gguf file only")
	}
}

// No scan takes a stated hash. A directory scan reads its files in full, and
// only the preview passes scanDir stated hashes: every other call in this
// package passes nil. Falsification: pass anything else from scan.go and
// the source check fails; a header-only directory scan is refused.
func TestScanNeverTakesStatedHashes(t *testing.T) {
	dir := modelRepo(t, nil)
	if _, err := ScanMode(dir, ModeHeaders); err == nil {
		t.Error("a header-only directory scan must be refused")
	}
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.SHA256 != digest {
		t.Errorf("a scan's subject %s, the computed digest %s", d.Artifact.SHA256, digest)
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn, ok := call.Fun.(*ast.Ident)
				if !ok || fn.Name != "scanDir" && fn.Name != "scanFile" {
					return true
				}
				calls++
				last := call.Args[len(call.Args)-1]
				isNil := false
				if id, ok := last.(*ast.Ident); ok && id.Name == "nil" {
					isNil = true
				}
				// scanFile has no stated-hash parameter: its last argument is
				// Tier 2's config, nil in a preview, and a header-only file
				// scan has no subject (attest.Sign refuses it).
				if fn.Name == "scanDir" && !isNil && filepath.Base(name) != "preview.go" {
					t.Errorf("%s: scanDir is passed stated hashes outside preview.go", fset.Position(call.Pos()))
				}
				if fn.Name == "scanDir" && isNil && filepath.Base(name) == "preview.go" {
					t.Errorf("%s: the preview passes scanDir no stated hashes", fset.Position(call.Pos()))
				}
				return true
			})
		}
	}
	if calls < 3 {
		t.Fatalf("found %d calls to scanDir and scanFile; the source check reads nothing", calls)
	}
}
