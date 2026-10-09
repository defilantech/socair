package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
)

// TestRealLicenses measures license identification on real model repos. It
// runs only when SOCAIR_LICENSE_CORPUS names a directory whose subdirectories
// are model repos (their README.md and LICENSE files, and any GGUF headers),
// and logs one line per repo: the identified license, a disagreement, and
// every statement the catalogue did not recognize. With SOCAIR_LICENSE_POLICY
// set it also tallies the License policy row:
//
//	SOCAIR_LICENSE_CORPUS=<dir> [SOCAIR_LICENSE_POLICY=<file>] go test ./internal/engine -run RealLicenses -v
//
// Results are recorded in docs/false-positive-baseline.md.
func TestRealLicenses(t *testing.T) {
	dir := os.Getenv("SOCAIR_LICENSE_CORPUS")
	if dir == "" {
		t.Skip("set SOCAIR_LICENSE_CORPUS to a directory of model repos")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	tally := map[string]int{}
	rows := map[report.Status]int{}
	for _, name := range names {
		d, err := Scan(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		l := d.Artifact.License
		state := "identified"
		switch {
		case l.Disagreement != "":
			state = "disagreement"
		case l.ID == "" && len(l.Sources) == 0:
			state = "none stated"
		case l.ID == "":
			state = "not identified"
		}
		tally[state]++
		var unrec []string
		for _, s := range l.Sources {
			if s.ID == "" {
				unrec = append(unrec, s.Source+" \""+s.Value+"\": "+s.Note)
			}
		}
		line := name + " | " + state + " | " + l.ID
		if l.Disagreement != "" {
			line += " | " + l.Disagreement
		}
		if len(unrec) > 0 {
			line += " | unrecognized or pointer: " + strings.Join(unrec, "; ")
		}
		for _, c := range d.Checks {
			if c.Name == "License policy" {
				rows[c.Status]++
				line += " | policy " + string(c.Status)
			}
		}
		t.Log(line)
	}
	t.Logf("%d repos: %d identified, %d disagreement, %d not identified, %d none stated", len(names),
		tally["identified"], tally["disagreement"], tally["not identified"], tally["none stated"])
	if len(rows) > 0 {
		t.Logf("License policy: %d PASS, %d FAIL, %d LEAD, %d NOT_TESTED", rows[report.StatusPass], rows[report.StatusFail],
			rows[report.StatusLead], rows[report.StatusNotTested])
	}
}
