package provenance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/modeldir"
)

// hubListing is a repository as the Hugging Face Hub lists it at one commit,
// with the checksum lists fetched under files/: the shape of the corpus the
// false-positive measurement in docs/false-positive-baseline.md fetched.
type hubListing struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	// Notes are the fetch's failures, such as a gated repository's lists
	// refused; a repository with one is not measured.
	Notes []string `json:"notes"`
	Files []struct {
		Path   string  `json:"path"`
		Size   int64   `json:"size"`
		SHA256 *string `json:"sha256"` // the LFS oid, or the hash of the fetched bytes; null when not fetched
	} `json:"files"`
}

// TestRealChecksumLists compares the checksum lists real repositories ship
// with the Hub's own hash of every file, through the same comparison a
// directory scan runs, with no weights downloaded. Each directory under
// SOCAIR_CHECKSUM_CORPUS holds hub.json (every file's path and size, with its
// LFS SHA-256 or the SHA-256 of the fetched bytes) and the fetched lists, and
// the non-LFS files they name, under files/. It prints every repository whose
// lists do not simply agree, and fails only when the corpus is incomplete: a
// list names a file whose hash was not fetched.
//
//	SOCAIR_CHECKSUM_CORPUS=<dir> go test ./internal/checks/provenance -run RealChecksumLists -v
func TestRealChecksumLists(t *testing.T) {
	corpus := os.Getenv("SOCAIR_CHECKSUM_CORPUS")
	if corpus == "" {
		t.Skip("set SOCAIR_CHECKSUM_CORPUS to a directory of fetched repositories")
	}
	dirs, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatal(err)
	}
	type total struct{ repos, unfetched, lists, notRead, malformedLists, lead, agreeOnly, entriesAgree, disagree, notHeld, renamed, unplaced, notGraded, mdOnly, selfListed, outside, noneCompared int }
	var tot total
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(corpus, d.Name(), "hub.json"))
		if err != nil {
			continue
		}
		var h hubListing
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatalf("%s: %v", d.Name(), err)
		}
		if len(h.Notes) > 0 {
			t.Logf("%s @ %s: not measured, the fetch failed: %s", h.Repo, h.Commit, strings.Join(h.Notes, "; "))
			tot.unfetched++
			continue
		}
		var files []modeldir.File
		unhashed := map[string]bool{}
		for _, f := range h.Files {
			if skippedDir(f.Path) != "" {
				continue // a directory scan's walk does not read it either
			}
			sum := "unhashed:" + f.Path
			if f.SHA256 != nil {
				sum = *f.SHA256
			} else {
				unhashed[f.Path] = true
			}
			files = append(files, modeldir.File{Path: f.Path, SHA256: sum, Size: f.Size})
		}
		if len(h.Files) >= modeldir.MaxFiles {
			// A directory scan refuses it, and the Hub's listing may stop here.
			t.Logf("%s @ %s: not measured, %d files listed, and a directory scan reads at most %d", h.Repo, h.Commit, len(h.Files), modeldir.MaxFiles)
			tot.unfetched++
			continue
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		s := dirChecksums(filepath.Join(corpus, d.Name(), "files"), files)
		if len(s.lists) == 0 {
			continue
		}
		s.compare()
		for _, f := range s.findings {
			if unhashed[f.Span] {
				t.Errorf("%s: the corpus did not fetch %s, which a list names", h.Repo, f.Span)
			}
		}
		tot.repos++
		tot.lists += len(s.lists)
		for _, l := range s.lists {
			if l.notRead != "" {
				tot.notRead++
			} else if len(l.malformed) > 0 {
				tot.malformedLists++
			}
		}
		tot.entriesAgree += len(s.agree)
		tot.disagree += s.disagreed
		tot.notHeld += len(s.notHeld)
		tot.renamed += len(s.renamed)
		tot.unplaced += len(s.unplaced)
		tot.notGraded += len(s.notGraded)
		if s.disagreed == 0 && len(s.notGraded) > 0 {
			tot.mdOnly++ // a LEAD if Markdown were graded
		}
		tot.selfListed += len(s.selfListed)
		tot.outside += len(s.outside)
		switch {
		case s.disagreed > 0:
			tot.lead++
		case len(s.agree) > 0 && len(s.notHeld) == 0 && len(s.renamed) == 0 && len(s.unplaced) == 0 && len(s.notGraded) == 0 && len(s.outside) == 0 && !hasUnread(s):
			tot.agreeOnly++
			continue
		case len(s.agree) == 0:
			tot.noneCompared++
		}
		status := "noted"
		if s.disagreed > 0 {
			status = "LEAD"
		}
		evidence := ""
		for _, f := range s.findings {
			evidence += "\n      " + f.Span + ": " + f.Detail
		}
		t.Logf("%s @ %s: %s\n    %s%s", h.Repo, h.Commit, status, s.note(), evidence)
	}
	t.Logf("%d repositories (%d more not measured), %d lists (%d not read, %d with malformed lines): %d LEAD (%d more if Markdown were graded), %d agree with nothing else noted, %d compared no entry; "+
		"entries: %d files agree, %d disagree, %d listed files not held, %d renames, %d lists not placed, %d Markdown files that disagree (not graded), %d lists that list themselves, %d names outside",
		tot.repos, tot.unfetched, tot.lists, tot.notRead, tot.malformedLists, tot.lead, tot.mdOnly, tot.agreeOnly, tot.noneCompared,
		tot.entriesAgree, tot.disagree, tot.notHeld, tot.renamed, tot.unplaced, tot.notGraded, tot.selfListed, tot.outside)
	if tot.repos == 0 {
		t.Fatal("no repository with a checksum list in the corpus")
	}
}

func hasUnread(s *checksumScan) bool {
	for _, l := range s.lists {
		if l.notRead != "" || len(l.malformed) > 0 {
			return true
		}
	}
	return false
}
