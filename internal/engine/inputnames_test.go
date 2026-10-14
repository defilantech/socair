package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// hostPaths are the forms a temp directory can take in a report: as given,
// and with symlinks resolved (macOS's /var is /private/var).
func hostPaths(t *testing.T, dir string) []string {
	t.Helper()
	out := []string{dir}
	if r, err := filepath.EvalSymlinks(dir); err == nil && r != dir {
		out = append(out, r)
	}
	return out
}

// TestReportNamesLocalInputsByNameAndHash: a filed report travels, so it
// names each local reference input by its base name and the SHA-256 of the
// bytes the scan read, never by its path on the scanning host, which can
// carry a username and directory layout (#170). Every input lives under this
// test's temp directory, as do the artifacts and the scan snapshots, and the
// report must not contain that directory anywhere. Falsification: name the
// denylist, a reference, the license policy, or the provenance manifest by
// its path again, and this fails.
func TestReportNamesLocalInputsByNameAndHash(t *testing.T) {
	root := filepath.Dir(t.TempDir()) // every t.TempDir of this test is under it
	inputs := filepath.Join(t.TempDir(), "operator", "inputs")
	if err := os.MkdirAll(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	type input struct{ name, body string }
	tokens := make([]string, 300)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("tok%d", i)
	}
	table, _ := json.Marshal(tokenizer.Table{Format: tokenizer.TableFormat, Name: "canon", Tokens: tokens})
	files := map[string]input{
		"SOCAIR_DENYLIST":            {"denylist.txt", strings.Repeat("0", 64) + "  known-bad\n"},
		"SOCAIR_TOKENIZER_REFERENCE": {"canon.json", string(table)},
		"SOCAIR_TEMPLATE_REFERENCE":  {"org-model.jinja", reviewedTemplate},
		"SOCAIR_LICENSE_POLICY":      {"licenses.txt", "apache-2.0\n"},
	}
	for env, in := range files {
		p := filepath.Join(inputs, in.name)
		if err := os.WriteFile(p, []byte(in.body), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(env, p)
	}
	signedFeed(t, map[string]string{"denylist.txt": strings.Repeat("aa", 32) + "  unrelated\n"})
	t.Setenv("SOCAIR_SCAN_TMP", t.TempDir())
	t.Setenv("SOCAIR_ACCEPTED_BY", "")
	mirror := filepath.Join(t.TempDir(), "mirror")
	if err := os.MkdirAll(mirror, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	gg := gguftest.BuildGGUF(gguftest.Clean())
	single := writeFixture(t, "clean-Q5_K_M.gguf", gg)
	dir := modelRepo(t, map[string]string{"README.md": card("apache-2.0")})
	digest, _, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path, sha string
		mirror    bool
	}{
		"single file":     {single, sha(string(gg)), true},
		"model directory": {dir, digest, false},
	} {
		manifest := fmt.Sprintf(`{"artifact_sha256":%q,"repo_url":"https://huggingface.co/example/model","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`, c.sha)
		prov := filepath.Join(inputs, "provenance.json")
		if err := os.WriteFile(prov, []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SOCAIR_PROVENANCE", prov)
		t.Setenv("SOCAIR_REPO_MIRROR", "")
		if c.mirror {
			t.Setenv("SOCAIR_REPO_MIRROR", mirror)
		}
		d, err := Scan(c.path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Fatalf("%s: %v", name, problems)
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		js := string(raw)
		for _, p := range hostPaths(t, root) {
			if i := strings.Index(js, p); i >= 0 {
				t.Errorf("%s: the report names a path on the scanning host: ...%s...", name, js[max(0, i-80):min(len(js), i+len(p)+60)])
			}
		}
		for _, in := range files {
			if want := in.name + " (sha256 " + sha(in.body) + ")"; !strings.Contains(js, want) {
				t.Errorf("%s: the report does not name %q", name, want)
			}
		}
		if want := "provenance.json (sha256 " + sha(manifest) + ")"; !strings.Contains(row(d, "Hash, provenance, lineage").Notes, want) {
			t.Errorf("%s: the provenance row does not name %q: %s", name, want, row(d, "Hash, provenance, lineage").Notes)
		}
		if !strings.Contains(d.Scope.ReferenceData, "feed Example Intel 2026.10.1") {
			t.Errorf("%s: the feed is no longer named by issuer and version: %s", name, d.Scope.ReferenceData)
		}
	}
}

// TestDirectoryInputListsEachFile: a reference input given as a directory is
// named by the directory's base name and each file it read, by name and hash,
// in order; files without the input's extension are not read or named.
func TestDirectoryInputListsEachFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "operator", "refs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"b.jinja": "B", "a.jinja": "A", "notes.txt": "not a template"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	refs, files, err := loadTemplateReferences(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := "from refs/: a.jinja (sha256 " + sha("A") + "), b.jinja (sha256 " + sha("B") + ")"
	if files != want || len(refs) != 2 || refs[0].Label != "a" {
		t.Fatalf("named %q (%d refs), want %q", files, len(refs), want)
	}
}

// TestReportErrorsNameNoHostPath: an input the scan could not read is named
// in the report too, and an operating-system error names the path it failed
// on. A local denylist that is missing or refused, a provenance manifest that
// is missing, a repo mirror that is missing or a file, and a model directory
// with a dangling symlink each name the input by base name, never by its path
// on the host. Falsification: put err.Error() back in any of these notes and
// this fails.
func TestReportErrorsNameNoHostPath(t *testing.T) {
	root := filepath.Dir(t.TempDir())
	for _, k := range []string{"SOCAIR_FEED", "SOCAIR_TOKENIZER_REFERENCE", "SOCAIR_TEMPLATE_REFERENCE", "SOCAIR_LICENSE_POLICY", "SOCAIR_ACCEPTED_BY"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_SCAN_TMP", t.TempDir())
	inputs := filepath.Join(t.TempDir(), "operator", "inputs")
	if err := os.MkdirAll(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(inputs, "refused.txt")
	if err := os.WriteFile(garbage, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(inputs, "mirror-file")
	if err := os.WriteFile(notDir, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	single := writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()))
	dangling := modelRepo(t, nil)
	if err := os.Symlink(filepath.Join(inputs, "no-such-blob"), filepath.Join(dangling, "pytorch_model.bin")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, path string
		env        map[string]string
		row, want  string
	}{
		{"missing denylist", single, map[string]string{"SOCAIR_DENYLIST": filepath.Join(inputs, "absent.txt")},
			"Known-bad hash match", "could not read denylist absent.txt: no such file or directory"},
		{"refused denylist", single, map[string]string{"SOCAIR_DENYLIST": garbage},
			"Known-bad hash match", "could not read denylist refused.txt (sha256 " + sha("garbage\n") + "): line 1"},
		{"missing provenance manifest", single, map[string]string{"SOCAIR_PROVENANCE": filepath.Join(inputs, "absent.json")},
			"Hash, provenance, lineage", "could not read provenance manifest absent.json: no such file or directory"},
		{"missing repo mirror", single, map[string]string{"SOCAIR_REPO_MIRROR": filepath.Join(inputs, "absent-mirror")},
			"File inventory and payloads", "Could not read repo mirror absent-mirror: no such file or directory"},
		{"repo mirror that is a file", single, map[string]string{"SOCAIR_REPO_MIRROR": notDir},
			"File inventory and payloads", "Could not read repo mirror mirror-file: not a directory"},
		{"dangling symlink in a model directory", dangling, nil,
			"", "pytorch_model.bin: excluded (unreadable: no such file or directory)"},
	}
	for _, c := range cases {
		for _, k := range []string{"SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_REPO_MIRROR"} {
			t.Setenv(k, c.env[k])
		}
		d, err := Scan(c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		js := string(raw)
		for _, p := range hostPaths(t, root) {
			if i := strings.Index(js, p); i >= 0 {
				t.Errorf("%s: the report names a path on the scanning host: ...%s...", c.name, js[max(0, i-80):min(len(js), i+len(p)+60)])
			}
		}
		got := strings.Join(d.OutOfScope.UnparsedFormats, "; ")
		if c.row != "" {
			got = row(d, c.row).Notes
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not say %q", c.name, got, c.want)
		}
	}
}
