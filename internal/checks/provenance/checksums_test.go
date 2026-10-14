package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

func sumOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hA and hB are two well-formed hashes for parser cases.
var (
	hA = sumOf("a")
	hB = sumOf("b")
)

type entry struct {
	name, sum string
}

// parseCases are lists and what `sha256sum --check` reads from each
// (coreutils 9.12, src/cksum.c), save the cases with bareFor set: a sidecar's
// bare hash is a convention sha256sum does not read.
var parseCases = []struct {
	name      string
	list      string
	bareFor   string
	want      []entry
	malformed []int
}{
	{"text mode", hA + "  model.gguf\n", "", []entry{{"model.gguf", hA}}, nil},
	{"binary mode", hA + " *model.gguf\n", "", []entry{{"model.gguf", hA}}, nil},
	{"dot slash kept as listed", hA + "  ./model.gguf\n", "", []entry{{"./model.gguf", hA}}, nil},
	{"upper-case hash", strings.ToUpper(hA) + "  m\n", "", []entry{{"m", hA}}, nil},
	{"no final newline", hA + "  m", "", []entry{{"m", hA}}, nil},
	{"CRLF", hA + "  m\r\n" + hB + "  n\r\n", "", []entry{{"m", hA}, {"n", hB}}, nil},
	{"comments and blank lines", "# made by sha256sum\n\n" + hA + "  m\n\r\n", "", []entry{{"m", hA}}, nil},
	{"a comment only at column one", " # not a comment\n", "", nil, []int{1}},
	{"leading blanks", " \t" + hA + "  m\n", "", []entry{{"m", hA}}, nil},
	{"tab separator", hA + "\t*m\n", "", []entry{{"m", hA}}, nil},
	{"name keeps its blanks", hA + "   spaced name \n", "", []entry{{" spaced name ", hA}}, nil},
	{"escaped newline", `\` + hA + `  a\nb` + "\n", "", []entry{{"a\nb", hA}}, nil},
	{"escaped backslash and CR", `\` + hA + `  a\\b\rc` + "\n", "", []entry{{"a\\b\rc", hA}}, nil},
	{"unknown escape", `\` + hA + `  a\tb` + "\n", "", nil, []int{1}},
	{"trailing lone backslash", `\` + hA + `  a\` + "\n", "", nil, []int{1}},
	{"unescaped backslash is literal", hA + `  a\b` + "\n", "", []entry{{`a\b`, hA}}, nil},
	{"tagged", "SHA256 (model.gguf) = " + hA + "\n", "", []entry{{"model.gguf", hA}}, nil},
	{"tagged, OpenSSL spacing", "SHA256(model.gguf)= " + hA + "\n", "", []entry{{"model.gguf", hA}}, nil},
	{"tagged, name with a parenthesis", "SHA256 (a (1).gguf) = " + hA + "\n", "", []entry{{"a (1).gguf", hA}}, nil},
	{"tagged, escaped", `\SHA256 (a\nb) = ` + hA + "\n", "", []entry{{"a\nb", hA}}, nil},
	{"tagged, trailing blank", "SHA256 (m) = " + hA + " \n", "", nil, []int{1}},
	{"tagged, another algorithm", "SHA512 (m) = " + hA + "\n" + "MD5 (m) = 0cc175b9c0f1b6a831c399e269772661\n", "", nil, []int{1, 2}},
	{"short hash", hA[:63] + "  m\n", "", nil, []int{1}},
	{"long hash", hA + "0  m\n", "", nil, []int{1}},
	{"not hex", strings.Repeat("g", 64) + "  m\n", "", nil, []int{1}},
	{"hash alone", hA + "\n", "", nil, []int{1}},
	{"hash and one blank", hA + " \n", "", nil, []int{1}},
	{"NUL in the line", hA + "  m\x00n\n", "", nil, []int{1}},
	{"BSD reversed", hA + " m\n" + hB + " n\n", "", []entry{{"m", hA}, {"n", hB}}, nil},
	{"BSD reversed, then a flag is part of the name", hA + " m\n" + hB + "  n\n", "", []entry{{"m", hA}, {" n", hB}}, nil},
	{"standard, then reversed does not mix", hA + "  m\n" + hB + " n\n", "", []entry{{"m", hA}}, []int{2}},
	{"a sidecar's bare hash", hA + "\n", "model.gguf", []entry{{"model.gguf", hA}}, nil},
	{"a sidecar in the list form", hA + "  other.gguf\n", "model.gguf", []entry{{"other.gguf", hA}}, nil},
	{"a sidecar with a hash and a size", hA + " 1234\n", "model.gguf", []entry{{"1234", hA}}, nil},
	{"a sidecar whose hash is short", hA[:40] + "\n", "model.gguf", nil, []int{1}},
}

// TestParseChecksumList holds the parser to the forms `sha256sum --check`
// reads and to the lines it refuses. Falsification: accept a hash that is not
// 64 hex digits, drop the mode flag handling, or stop unescaping, and a case
// here fails.
func TestParseChecksumList(t *testing.T) {
	for _, c := range parseCases {
		p := parseChecksumList([]byte(c.list), c.bareFor)
		var got []entry
		for _, e := range p.entries {
			got = append(got, entry{e.name, e.sum})
		}
		if !reflect.DeepEqual(got, c.want) || !reflect.DeepEqual(p.malformed, c.malformed) {
			t.Errorf("%s: entries %q malformed %v, want %q malformed %v", c.name, got, p.malformed, c.want, c.malformed)
		}
	}
}

// Which files are read as lists: the conventional names, and a sidecar
// beside the file it is named for. Falsification: read any .sha256 file and
// the versioned and orphaned names here are read.
func TestIsChecksumList(t *testing.T) {
	held := map[string]bool{"model.safetensors": true, "sub/model.gguf": true}
	exists := func(p string) bool { return held[p] }
	for name, want := range map[string]bool{
		"SHA256SUMS": true, "sha256sums": true, "SHA256SUMS.txt": true, "sub/sha256sums.txt": true,
		"checksums.sha256": true, "CHECKSUMS.sha256": true,
		"model.safetensors.sha256": true, "model.safetensors.SHA256": true, "sub/model.gguf.sha256": true,
		"model.gguf.sha256": false, "hashes/model.safetensors.sha256": false, "checksums-v4.5.0.sha256": false,
		".sha256": false, "SHA256SUMS.json": false, "SHA256SUMS.sig": false, "SHA256SUMS.v3": false, "checklist.chk": false,
		"MD5SUMS": false, "SOURCE_SHA256SUMS": false, "sha256.txt": false, "model.sha256.json": false,
	} {
		if isChecksumList(name, exists) != want {
			t.Errorf("isChecksumList(%q) = %v, want %v", name, !want, want)
		}
	}
}

// dirFixture writes files under a new directory and returns it with the
// files as a directory scan lists them.
func dirFixture(t *testing.T, files map[string]string) (string, []modeldir.File) {
	t.Helper()
	root := t.TempDir()
	var out []modeldir.File
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, body)
		out = append(out, modeldir.File{Path: rel, SHA256: sumOf(body), Size: int64(len(body))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return root, out
}

// TestChecksumMismatchIsALead is the falsification test: a directory whose
// model.safetensors was replaced after its SHA256SUMS was written is a LEAD
// naming the file and both hashes, and the same directory with a list that
// matches is not. Neuter the comparison (treat every held file as agreeing,
// or drop the status change) and this fails.
func TestChecksumMismatchIsALead(t *testing.T) {
	sums := sumOf("weights v1") + "  model.safetensors\n" + sumOf("{}") + "  config.json\n"
	root, files := dirFixture(t, map[string]string{
		"model.safetensors": "weights v2, swapped in",
		"config.json":       "{}",
		"SHA256SUMS":        sums,
	})
	r := Inspect(Options{ArtifactPath: root, Root: root, Files: files})
	if r.Status != checks.Lead {
		t.Fatalf("status %s, want LEAD: %s", r.Status, r.Notes)
	}
	if len(r.Findings) != 1 || r.Findings[0].Pattern != "checksum-mismatch" || r.Findings[0].Span != "model.safetensors" ||
		!strings.Contains(r.Findings[0].Detail, sumOf("weights v1")) || !strings.Contains(r.Findings[0].Detail, sumOf("weights v2, swapped in")) ||
		!strings.Contains(r.Findings[0].Detail, "SHA256SUMS line 1") {
		t.Fatalf("the finding must name the file, the list's line, and both hashes: %+v", r.Findings)
	}
	if !strings.Contains(r.Notes, "Agree with the bytes the scan hashed: 1 (config.json)") {
		t.Errorf("the agreeing file must be noted: %s", r.Notes)
	}

	root, files = dirFixture(t, map[string]string{
		"model.safetensors": "weights v1",
		"config.json":       "{}",
		"SHA256SUMS":        sums,
	})
	r = Inspect(Options{ArtifactPath: root, Root: root, Files: files})
	if r.Status != checks.NotTested || len(r.Findings) != 0 {
		t.Fatalf("a matching list is noted, never a PASS and never a LEAD: %s %+v", r.Status, r.Findings)
	}
	for _, want := range []string{"Agree with the bytes the scan hashed: 2 (config.json, model.safetensors)", "not that they are safe",
		"Not covered by any list, the lists themselves included: 1 (SHA256SUMS)"} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("notes must say %q: %s", want, r.Notes)
		}
	}
}

// Agreement never moves the row: with a bound manifest it PASSes for its own
// reason, and without one it stays NOT_TESTED. A disagreement makes a PASS a
// LEAD, and a FAIL stays a FAIL with the finding added.
func TestChecksumsNeverPassAndOnlyWithhold(t *testing.T) {
	root, files := dirFixture(t, map[string]string{"model.gguf": "x"})
	writeFile(t, filepath.Join(root, "SHA256SUMS"), artSHA+"  model.gguf\n")
	files = append(files, modeldir.File{Path: "SHA256SUMS", SHA256: sumOf(artSHA + "  model.gguf\n")})
	if r := Inspect(Options{ArtifactPath: root, Root: root, Files: files}); r.Status != checks.NotTested {
		t.Fatalf("an agreeing list alone must leave the row NOT_TESTED, got %s", r.Status)
	}

	dirSHA := strings.Repeat("cd", 32)
	m := writeFile(t, filepath.Join(t.TempDir(), "m.json"),
		`{"artifact_sha256":"`+dirSHA+`","repo_url":"https://huggingface.co/a/b","commit_or_tag":"main","commit_sha":"`+commit+`"}`)
	r := Inspect(Options{ArtifactPath: root, ArtifactSHA256: dirSHA, ManifestPath: m, Root: root, Files: files})
	if r.Status != checks.Pass {
		t.Fatalf("a bound manifest PASSes, agreeing list or not: %s (%s)", r.Status, r.Notes)
	}

	writeFile(t, filepath.Join(root, "SHA256SUMS"), hB+"  model.gguf\n")
	files[len(files)-1].SHA256 = sumOf(hB + "  model.gguf\n")
	if r := Inspect(Options{ArtifactPath: root, ArtifactSHA256: dirSHA, ManifestPath: m, Root: root, Files: files}); r.Status != checks.Lead {
		t.Fatalf("a disagreeing list must make a PASS a LEAD, got %s", r.Status)
	}
	sig := &Signature{State: SignatureInvalid, Format: "OMS", Signer: "k", Detail: "bad"}
	r = Inspect(Options{ArtifactPath: root, Signature: sig, Root: root, Files: files})
	if r.Status != checks.Fail || len(r.Findings) != 2 {
		t.Fatalf("a FAIL stays a FAIL, with both findings: %s %+v", r.Status, r.Findings)
	}
}

// What a list says of files the scan cannot compare is noted, never graded:
// a listed file the scan does not hold (a selected pull), a rename, the list
// listing itself, names outside the directory, a skipped directory, and lines
// that do not parse.
func TestChecksumNotes(t *testing.T) {
	list := strings.Join([]string{
		sumOf("w") + "  model-00002-of-00002.safetensors", // not held: a selected pull
		sumOf("r") + "  old-name.bin",                     // held as new-name.bin
		sumOf("") + "  SHA256SUMS",                        // the list itself, as `sha256sum * > SHA256SUMS` writes it
		hA + "  ../escape",                                // outside
		hA + "  /etc/passwd",                              // outside
		hA + "  .git/config",                              // under a directory the scan skips
		"not a checksum line",
		sumOf("c") + "  config.json",
	}, "\n") + "\n"
	root, files := dirFixture(t, map[string]string{
		"new-name.bin": "r",
		"config.json":  "c",
		"SHA256SUMS":   list,
	})
	r := Inspect(Options{ArtifactPath: root, Root: root, Files: files})
	if r.Status != checks.NotTested || len(r.Findings) != 0 {
		t.Fatalf("nothing here disagrees with a held file: %s %+v (%s)", r.Status, r.Findings, r.Notes)
	}
	for _, want := range []string{
		"Agree with the bytes the scan hashed: 1 (config.json)",
		"Listed but not in the scan, so not compared (a selected pull or a partial download leaves files out): 1 (model-00002-of-00002.safetensors)",
		"Listed under another name with the same hash: old-name.bin (listed in SHA256SUMS) is held as new-name.bin",
		"Lists itself, an entry not compared, as no list can hold its own hash: SHA256SUMS",
		"Names outside the directory, not compared: SHA256SUMS line 4 (a path that leaves the directory); SHA256SUMS line 5 (an absolute path)",
		"Listed, not compared: .git/config (under .git/, which the scan does not read)",
		"Lines that are not SHA-256 checksum lines, not compared: SHA256SUMS line 7",
		"Not covered by any list, the lists themselves included: 2 (SHA256SUMS, new-name.bin)",
	} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("notes must say %q:\n%s", want, r.Notes)
		}
	}
}

// A list resolves names from its own directory, as `sha256sum --check` run
// there does, and nowhere else. A list none of whose names is a file beside
// it is named and not compared: which tree it describes is a guess, and a
// wrong guess is a false LEAD. Falsification: resolve such a list from the
// top and checksums/SHA256SUMS below disagrees with model.gguf, a LEAD.
func TestChecksumListDirectory(t *testing.T) {
	root, files := dirFixture(t, map[string]string{
		"model.gguf":                  "top",
		"sub/model.gguf":              "sub",
		"sub/SHA256SUMS":              sumOf("sub") + "  model.gguf\n",
		"checksums/SHA256SUMS":        sumOf("a bundle's model.gguf") + "  model.gguf\n" + sumOf("sub") + "  sub/model.gguf\n",
		"other/x/SHA256SUMS":          sumOf("nothing") + "  absent.bin\n",
		"part/a.bin":                  "a",
		"part/SHA256SUMS":             sumOf("a") + "  a.bin\n" + sumOf("gone") + "  gone.bin\n",
		"weights.bin":                 "w",
		"weights.bin.sha256":          sumOf("w") + "\n",
		"sidecars/weights.bin.sha256": sumOf("w") + "\n",
	})
	r := Inspect(Options{ArtifactPath: root, Root: root, Files: files})
	if r.Status != checks.NotTested || len(r.Findings) != 0 {
		t.Fatalf("no list disagrees with a file beside it: %s %+v (%s)", r.Status, r.Findings, r.Notes)
	}
	for _, want := range []string{
		"Uploader checksum lists: checksums/SHA256SUMS, 2 entries; other/x/SHA256SUMS, 1 entry; part/SHA256SUMS, 2 entries; sub/SHA256SUMS, 1 entry; weights.bin.sha256, 1 entry.",
		"Agree with the bytes the scan hashed: 3 (part/a.bin, sub/model.gguf, weights.bin)",
		"Listed but not in the scan, so not compared (a selected pull or a partial download leaves files out): 1 (part/gone.bin)",
		"Not compared, as none of their names is a file beside them (a list of another tree, or written from another directory; not guessed at): " +
			"checksums/SHA256SUMS (2 entries); other/x/SHA256SUMS (1 entry)",
		"Not covered by any list, the lists themselves included: 7 (checksums/SHA256SUMS, model.gguf, ",
	} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("notes must say %q:\n%s", want, r.Notes)
		}
	}
}

// A Markdown file that disagrees with its list is named and not graded: no
// loader reads it, and a model card edited on the Hub after the list was
// written is the most common disagreement in real repositories. Any other
// file is graded. Falsification: grade Markdown and the first scan is a LEAD;
// exempt more and the second is not.
func TestMarkdownDisagreementIsNotGraded(t *testing.T) {
	list := sumOf("card v1") + "  README.md\n" + sumOf("w") + "  model.safetensors\n"
	root, files := dirFixture(t, map[string]string{"README.md": "card v2", "model.safetensors": "w", "SHA256SUMS": list})
	r := Inspect(Options{ArtifactPath: root, Root: root, Files: files})
	if r.Status != checks.NotTested || len(r.Findings) != 0 ||
		!strings.Contains(r.Notes, "Disagree, named and not graded, as Markdown no loader reads and a model card is edited in place after a list is written: README.md (SHA256SUMS line 1)") {
		t.Fatalf("a disagreeing model card is named, not graded: %s %+v (%s)", r.Status, r.Findings, r.Notes)
	}
	if strings.Contains(r.Notes, "Agree with the bytes the scan hashed: 2") {
		t.Fatalf("a file that disagrees must not be counted as agreeing: %s", r.Notes)
	}

	list = sumOf("{}") + "  config.json\n" + sumOf("card") + "  docs/USAGE.MD\n"
	root, files = dirFixture(t, map[string]string{"config.json": `{"x":1}`, "docs/USAGE.MD": "card", "SHA256SUMS": list})
	if r := Inspect(Options{ArtifactPath: root, Root: root, Files: files}); r.Status != checks.Lead || len(r.Findings) != 1 || r.Findings[0].Span != "config.json" {
		t.Fatalf("a config that disagrees is a LEAD: %s %+v", r.Status, r.Findings)
	}
}

// A single file's lists sit beside it, outside the attested bytes, so each is
// named with the hash of what was read; only what they say of this file
// counts.
func TestChecksumsBesideASingleFile(t *testing.T) {
	dir := t.TempDir()
	art := writeFile(t, filepath.Join(dir, "model.gguf"), "x")
	writeFile(t, filepath.Join(dir, "other.gguf"), "y")
	list := artSHA + "  model.gguf\n" + sumOf("y") + "  other.gguf\n"
	writeFile(t, filepath.Join(dir, "SHA256SUMS"), list)
	r := Inspect(Options{ArtifactPath: art, ArtifactSHA256: artSHA})
	if r.Status != checks.NotTested {
		t.Fatalf("agreement is noted, not graded: %s (%s)", r.Status, r.Notes)
	}
	for _, want := range []string{
		"Uploader checksum lists beside the artifact, not among the attested bytes: SHA256SUMS (sha256 " + sumOf(list) + "), 2 entries",
		"Agree with the bytes the scan hashed: 1 (model.gguf)",
		"1 entry names another file, which a single-file scan does not hold",
	} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("notes must say %q:\n%s", want, r.Notes)
		}
	}

	writeFile(t, filepath.Join(dir, "model.gguf.sha256"), hB+"\n")
	r = Inspect(Options{ArtifactPath: art, ArtifactSHA256: artSHA})
	if r.Status != checks.Lead || len(r.Findings) != 1 || r.Findings[0].Span != "model.gguf" ||
		!strings.Contains(r.Findings[0].Detail, "model.gguf.sha256 (sha256 "+sumOf(hB+"\n")+", beside the artifact) line 1 lists "+hB) {
		t.Fatalf("a sidecar that disagrees is a LEAD naming it: %s %+v", r.Status, r.Findings)
	}

	// Renamed: the list names this file's bytes under another name.
	dir = t.TempDir()
	art = writeFile(t, filepath.Join(dir, "renamed.gguf"), "x")
	writeFile(t, filepath.Join(dir, "SHA256SUMS"), artSHA+"  original.gguf\n")
	r = Inspect(Options{ArtifactPath: art, ArtifactSHA256: artSHA})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "SHA256SUMS lists original.gguf with this artifact's hash") {
		t.Fatalf("a rename is noted: %s (%s)", r.Status, r.Notes)
	}

	// A header-only scan hashes nothing, so nothing is compared.
	r = Inspect(Options{ArtifactPath: art})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "Not compared: the artifact was not hashed") {
		t.Fatalf("a header-only scan compares nothing: %s (%s)", r.Status, r.Notes)
	}
}

// Every read is bounded, and a list past a bound is named, never read in
// part. A list with no checksum line is named too.
func TestChecksumListBounds(t *testing.T) {
	big := strings.Repeat(hA+"  m\n", MaxChecksumListBytes/68+1)
	many := strings.Repeat("\n", MaxChecksumListLines+1)
	root, files := dirFixture(t, map[string]string{
		"m":                  "a",
		"SHA256SUMS":         big,
		"sub/sha256sums.txt": many,
		"x/SHA256SUMS.txt":   "this file is prose, not a list\n",
	})
	r := Inspect(Options{ArtifactPath: root, Root: root, Files: files})
	if r.Status != checks.NotTested {
		t.Fatalf("lists past a bound compare nothing: %s (%s)", r.Status, r.Notes)
	}
	for _, want := range []string{
		"SHA256SUMS (" + strconv.Itoa(len(big)) + " bytes, over the 4 MiB bound for one list)",
		"sub/sha256sums.txt (" + strconv.Itoa(MaxChecksumListLines+1) + " lines, over the 50000-line bound for one list)",
		"x/SHA256SUMS.txt (no SHA-256 checksum line in it (line 1 not in a checksum format))",
	} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("notes must say %q:\n%s", want, r.Notes)
		}
	}
	if strings.Contains(r.Notes, "Agree") {
		t.Errorf("a list past its bound must not be read in part: %s", r.Notes)
	}
}

// A listed name is quoted in the notes when it would break the report's
// text.
func TestChecksumNamesAreDisplayedSafely(t *testing.T) {
	list := sumOf("m") + "  m\n" + `\` + sumOf("q") + `  evil\nname` + "\n"
	root, files := dirFixture(t, map[string]string{"m": "m", "SHA256SUMS": list})
	r := Inspect(Options{ArtifactPath: root, Root: root, Files: files})
	if strings.Contains(r.Notes, "evil\nname") || !strings.Contains(r.Notes, `"evil\nname"`) {
		t.Fatalf("a name with a newline must be quoted: %s", r.Notes)
	}
}

// A file a selected pull left out is listed and not held; with a bound
// manifest that records the selection, the note says so.
func TestChecksumSelectedPull(t *testing.T) {
	list := sumOf("w1") + "  model-00001-of-00002.safetensors\n" + sumOf("w2") + "  model-00002-of-00002.safetensors\n"
	root, files := dirFixture(t, map[string]string{"model-00001-of-00002.safetensors": "w1", "SHA256SUMS": list})
	dirSHA := strings.Repeat("cd", 32)
	m := writeFile(t, filepath.Join(t.TempDir(), "m.json"),
		`{"artifact_sha256":"`+dirSHA+`","repo_url":"https://huggingface.co/a/b","commit_or_tag":"`+commit+`","commit_sha":"`+commit+`",`+
			`"selection":{"include":["*00001*"],"left_out":["model-00002-of-00002.safetensors"]}}`)
	r := Inspect(Options{ArtifactPath: root, ArtifactSHA256: dirSHA, ManifestPath: m, Root: root, Files: files})
	if r.Status != checks.Pass {
		t.Fatalf("a selection still binds, and a left-out file is not a disagreement: %s (%s)", r.Status, r.Notes)
	}
	want := "Listed but not in the scan, so not compared (a selected pull or a partial download leaves files out): 1 (model-00002-of-00002.safetensors), " +
		"1 of them left out by the selection the bound provenance manifest records"
	if !strings.Contains(r.Notes, want) {
		t.Fatalf("notes must say %q:\n%s", want, r.Notes)
	}
}
