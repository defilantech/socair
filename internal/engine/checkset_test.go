package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ruleRoots are the packages whose code decides what a check detects and how
// it grades: the checks themselves and the parsers that feed them. A change
// here can change a verdict, so it must be visible in CheckSetVersion.
var ruleRoots = []string{"../checks", "../gguf", "../safetensors"}

// changelog records every check-set version and the rule fingerprints it
// covers.
const changelog = "../../docs/check-set.md"

// ruleFingerprint hashes the rule-bearing sources. Go files are parsed and
// printed without comments, so a comment or formatting edit leaves it
// unchanged; any code or embedded-data change moves it. Tests, test helpers,
// and testdata are excluded.
func ruleFingerprint(t *testing.T) string {
	t.Helper()
	var files []string
	for _, root := range ruleRoots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if name == "testdata" || strings.HasSuffix(name, "test") && p != root {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(name, "_test.go") {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(files)

	h := sha256.New()
	for _, p := range files {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(p, ".go") {
			if src, err = normalizeGo(src); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
		}
		h.Write([]byte(filepath.ToSlash(p)))
		h.Write([]byte{0})
		h.Write(src)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeGo prints a Go file without its comments, so only code remains.
func normalizeGo(src []byte) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0) // mode 0 drops comments
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TestCheckSetVersionTracksRules fails when the rules change without the
// changelog saying which check-set version they belong to, so two reports
// that carry the same version were produced by the same rules.
func TestCheckSetVersionTracksRules(t *testing.T) {
	fp := ruleFingerprint(t)
	log, err := os.ReadFile(changelog)
	if err != nil {
		t.Fatal(err)
	}
	want := "| `" + CheckSetVersion + "` | `" + fp + "` |"
	for _, line := range strings.Split(string(log), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), want) {
			return
		}
	}
	t.Fatalf(`the check rules changed (fingerprint %s) and docs/check-set.md has no row for it under %s.

If the change can alter what a check detects or how it grades (a pattern,
threshold, allowlist, status mapping, or parser behaviour), bump
CheckSetVersion in internal/engine/scan.go and add a row:

  | `+"`<new version>`"+` | `+"`%s`"+` | <date> | <what changed> |

If it cannot (a refactor or a performance change), add a row for the same
version with the new fingerprint and say so:

  | `+"`%s`"+` | `+"`%s`"+` | <date> | No rule change: <what changed> |`,
		fp, CheckSetVersion, fp, CheckSetVersion, fp)
}

// TestRuleFingerprintIgnoresComments pins the property the test above relies
// on: a comment-only edit must not move the fingerprint, and a code edit must.
func TestRuleFingerprintIgnoresComments(t *testing.T) {
	norm := func(s string) string {
		b, err := normalizeGo([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	base := norm("package x\n\n// a\nconst Limit = 512 // b\n")
	if base != norm("package x\n\n// changed\nconst Limit = 512\n") {
		t.Fatal("a comment edit moved the normalized source")
	}
	if base == norm("package x\n\nconst Limit = 160\n") {
		t.Fatal("a threshold change did not move the normalized source")
	}
}
