package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The published detection ceiling is the public claim about what Socair does
// not detect. It is the source of truth for the socair.ai ceiling page, and it
// must agree with the engine. If the two disagree, this test fails rather than
// letting the attestation drift from what the world is told.

type ceilingDoc struct {
	Version   string   `json:"version"`
	Statement string   `json:"statement"`
	Bullets   []string `json:"bullets"`
	Notes     []string `json:"notes"`
}

func loadCeiling(t *testing.T) ceilingDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "detection-ceiling.json"))
	if err != nil {
		t.Fatalf("read the published ceiling: %v", err)
	}
	var d ceilingDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("parse the published ceiling: %v", err)
	}
	if d.Version == "" {
		t.Error("the published ceiling needs a version")
	}
	return d
}

func TestCeilingMatchesTheEngine(t *testing.T) {
	d := loadCeiling(t)

	if !reflect.DeepEqual(d.Bullets, DefaultCeiling()) {
		t.Fatalf("the published ceiling and the engine disagree; they are one list:\n engine: %v\n page:   %v",
			DefaultCeiling(), d.Bullets)
	}
	if d.Statement != DoesNotCertify {
		t.Errorf("statement = %q, want the fixed sentence %q", d.Statement, DoesNotCertify)
	}
}

// absenceClaims are phrases that assert safety rather than bound it. The
// ceiling is the one place we state our limits, so a claim of absence here is
// a defect, not a wording preference.
var absenceClaims = []string{
	"no backdoors",
	"backdoor-free",
	"guaranteed",
	"proven safe",
	"virus-free",
	"certified safe",
	"cannot contain",
	"free of",
}

func TestCeilingMakesNoAbsenceClaim(t *testing.T) {
	d := loadCeiling(t)

	lines := append([]string{d.Statement}, d.Bullets...)
	lines = append(lines, d.Notes...)
	for _, line := range lines {
		low := strings.ToLower(line)
		for _, claim := range absenceClaims {
			if strings.Contains(low, claim) {
				t.Errorf("the ceiling must not claim absence: %q contains %q", line, claim)
			}
		}
	}
}
