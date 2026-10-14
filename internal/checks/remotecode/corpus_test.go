package remotecode

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

// TestRealRepos is the false-positive gate for this row: it inspects every
// repository directory under the directories SOCAIR_REMOTECODE_CORPUS names
// (space-separated; each holds one repository per subdirectory, such as the
// configs and .py files fetched without weights) and prints each row. It
// fails if a repository with a non-empty auto_map in any JSON file is not a
// LEAD: the narrowing in #254 must never clear real remote code.
//
//	SOCAIR_REMOTECODE_CORPUS="<dirs>" go test ./internal/checks/remotecode -run RealRepos -v
func TestRealRepos(t *testing.T) {
	env := os.Getenv("SOCAIR_REMOTECODE_CORPUS")
	if env == "" {
		t.Skip("set SOCAIR_REMOTECODE_CORPUS to directories of model repositories")
	}
	tally := map[checks.Status]int{}
	for _, corpus := range strings.Fields(env) {
		entries, err := os.ReadDir(corpus)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(corpus, e.Name())
			_, files, err := modeldir.Hash(dir)
			if err != nil || len(files) == 0 {
				t.Logf("SKIP %s: %v", e.Name(), err)
				continue
			}
			r := Inspect(dir, files)
			tally[r.Status]++
			var pats []string
			for _, f := range r.Findings {
				pats = append(pats, f.Pattern)
			}
			sort.Strings(pats)
			t.Logf("%-10s %s [%s] %s", r.Status, e.Name(), strings.Join(uniq(pats), ","), r.Notes)
			if hasAutoMap(dir, files) && r.Status != checks.Lead {
				t.Errorf("%s has an auto_map and is %s: real remote code must stay a LEAD", e.Name(), r.Status)
			}
		}
	}
	t.Logf("PASS %d, LEAD %d, NOT_TESTED %d, FAIL %d", tally[checks.Pass], tally[checks.Lead], tally[checks.NotTested], tally[checks.Fail])
}

// hasAutoMap reports whether any JSON file holds a non-empty top-level
// auto_map object or list, by a decode independent of the check's own
// reader (it replaces Python's Infinity, which real configs hold, by null).
func hasAutoMap(dir string, files []modeldir.File) bool {
	for _, f := range files {
		if filepath.Ext(f.Path) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil || !bytes.Contains(raw, []byte(`"auto_map"`)) {
			continue
		}
		raw = bytes.ReplaceAll(raw, []byte("-Infinity"), []byte("null"))
		raw = bytes.ReplaceAll(raw, []byte("Infinity"), []byte("null"))
		var top map[string]json.RawMessage
		if json.Unmarshal(raw, &top) != nil {
			continue
		}
		if am := bytes.TrimSpace(top["auto_map"]); len(am) > 2 && (am[0] == '{' || am[0] == '[') {
			return true
		}
	}
	return false
}
