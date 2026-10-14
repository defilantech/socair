package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
)

// TestFingerprintKnownAnswer pins the computation docs/sarif.md describes: a
// SHA-256 over netstrings, written out here by hand, so a change to the inputs
// or their encoding fails instead of silently reopening every alert.
func TestFingerprintKnownAnswer(t *testing.T) {
	d := &report.Document{Artifact: report.ArtifactIdentity{
		SHA256: "13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444"}}
	c := report.CheckResult{Name: "Chat template", Status: report.StatusFail,
		Evidence: "dunder-reach: ''.__class__ (attribute reach into Python internals)"}
	in := "20:socairFindingHash/v1," +
		"64:13d44e37860489806f575deb0b219c6058c9421fe1982a9311a0e367c4e8f444," +
		"13:Chat template," +
		"4:FAIL," +
		"66:dunder-reach: ''.__class__ (attribute reach into Python internals),"
	sum := sha256.Sum256([]byte(in))
	if got, want := Fingerprint(d, c), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("Fingerprint = %s, want %s", got, want)
	}
}

// TestFingerprintIgnoresClockAndHost: everything a rescan of the same bytes
// changes (the document id, the times, the input path, the host, versions,
// notes) and every row field a release may reword, other than evidence, leave
// the fingerprint unchanged.
func TestFingerprintIgnoresClockAndHost(t *testing.T) {
	base := loadGolden(t)
	d := loadGolden(t)
	d.Header.DocumentID, d.Header.IssuedUTC, d.Header.RescanDue = "SOC-OTHER", "2031-01-01T00:00:00Z", "2031-04-01"
	d.Scope.ScanStartUTC, d.Scope.ScanEndUTC = "2031-01-01T00:00:00Z", "2031-01-01T00:01:00Z"
	d.Scope.InputPath, d.Scope.ExecutionContext = "/other/host/models/x.gguf", "another host"
	d.Scope.ToolVersions, d.Scope.CheckSetVersion = "socair 9.9.9", "tier1/9.9"
	d.Artifact.FileName, d.Artifact.Name = "renamed.gguf", "Renamed"
	d.PromotionAuthorization.State = report.StateAuthorized
	for i := range d.Checks {
		d.Checks[i].Notes += " (reworded)"
		d.Checks[i].LooksFor += " (reworded)"
		d.Checks[i].PassMeans += " (reworded)"
		d.Checks[i].MapsTo = nil
	}
	for i, c := range base.Checks {
		if got, want := Fingerprint(d, d.Checks[i]), Fingerprint(base, c); got != want || got == "" {
			t.Errorf("%s: fingerprint %q moved to %q with nothing about the finding changed", c.Name, want, got)
		}
	}
}

// TestFingerprintSeparatesFindings: a different artifact, row, status, or
// evidence is a different finding, so it gets a different fingerprint.
func TestFingerprintSeparatesFindings(t *testing.T) {
	d := loadGolden(t)
	c := report.CheckResult{Name: "Chat template", Status: report.StatusFail, Evidence: "dunder-reach: ''.__class__"}
	base := Fingerprint(d, c)

	revision := loadGolden(t)
	revision.Artifact.SHA256 = "0000000000000000000000000000000000000000000000000000000000000001"
	other := map[string]string{"new revision": Fingerprint(revision, c)}
	for name, mod := range map[string]func(*report.CheckResult){
		"other row":      func(c *report.CheckResult) { c.Name = "Tokenizer config" },
		"other status":   func(c *report.CheckResult) { c.Status = report.StatusLead },
		"other evidence": func(c *report.CheckResult) { c.Evidence = "template-name-path: \"../x\"" },
		"no evidence":    func(c *report.CheckResult) { c.Evidence = "" },
		// The netstring keeps a boundary between fields: moving bytes from
		// one field into the next is a different input.
		"shifted boundary": func(c *report.CheckResult) { c.Name, c.Status = "Chat templateF", "AIL" },
	} {
		x := c
		mod(&x)
		other[name] = Fingerprint(d, x)
	}
	seen := map[string]string{base: "base"}
	for name, fp := range other {
		if fp == "" {
			t.Errorf("%s: no fingerprint", name)
			continue
		}
		if prev, ok := seen[fp]; ok {
			t.Errorf("%s gives the same fingerprint as %s", name, prev)
		}
		seen[fp] = name
	}

	// Every row of one report is its own finding.
	rows := map[string]string{}
	for _, row := range d.Checks {
		fp := Fingerprint(d, row)
		if prev, ok := rows[fp]; ok {
			t.Errorf("%s and %s share a fingerprint", row.Name, prev)
		}
		rows[fp] = row.Name
	}
}

// TestEveryResultCarriesTheFingerprint is the falsification: drop the partial
// fingerprints, or let either key carry anything but Fingerprint, and it
// fails. A header-only report names no bytes and carries none.
func TestEveryResultCarriesTheFingerprint(t *testing.T) {
	d := loadGolden(t)
	d.Checks[1].Status, d.Checks[1].Evidence = report.StatusFail, "embedded-script: offset 12"
	d.Checks[2].Status, d.Checks[2].Evidence = report.StatusLead, "token-instruction: token 7"
	results := Build(d).Runs[0].Results
	if len(results) != len(d.Checks) {
		t.Fatalf("%d results for %d rows", len(results), len(d.Checks))
	}
	for i, r := range results {
		want := Fingerprint(d, d.Checks[i])
		if want == "" {
			t.Fatalf("%s: no fingerprint for a report with an artifact hash", d.Checks[i].Name)
		}
		for _, k := range []string{FingerprintKey, "primaryLocationLineHash"} {
			if got := r.PartialFingerprints[k]; got != want {
				t.Errorf("%s: partialFingerprints[%q] = %q, want %q", d.Checks[i].Name, k, got, want)
			}
		}
		if len(r.PartialFingerprints) != 2 {
			t.Errorf("%s: partialFingerprints = %v, want exactly the two keys", d.Checks[i].Name, r.PartialFingerprints)
		}
	}

	d.Artifact.SHA256 = ""
	for _, r := range Build(d).Runs[0].Results {
		if r.PartialFingerprints != nil {
			t.Errorf("%s: a report without an artifact hash carries fingerprints %v", r.RuleID, r.PartialFingerprints)
		}
	}
}

// TestTwoScansShareFingerprints runs the engine. The same fixture scanned
// twice, from two directories, gives every row the same fingerprint. A
// different finding gives the FAILing row a different one, whether it comes
// from other bytes (another hostile template) or from the same bytes (a
// denylist entry with another label). The same finding in a new revision of
// the model (other bytes, the same evidence) is a new finding too.
func TestTwoScansShareFingerprints(t *testing.T) {
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_ACCEPTED_BY",
		"SOCAIR_FEED", "SOCAIR_FEED_KEYS", "SOCAIR_TOKENIZER_REFERENCE", "SOCAIR_TEMPLATE_REFERENCE",
		"SOCAIR_LICENSE_POLICY", "SOCAIR_INTAKE_POLICY", "SOCAIR_TIER2_HELPER", "SOCAIR_TIER2_ENDPOINT",
		"SOCAIR_PUBLISHER_KEYS", "SOCAIR_PUBLISHER_ROOTS", "SOCAIR_OMS_SIGNATURE", "SOCAIR_SIGSTORE_VERIFIER"} {
		t.Setenv(k, "")
	}
	// build is the clean fixture with its chat template and name replaced.
	build := func(template, name string) []byte {
		kvs := gguftest.WithMeta("tokenizer.chat_template", gguftest.Str("tokenizer.chat_template", template))
		for i, kv := range kvs {
			if kv.Key() == "general.name" {
				kvs[i] = gguftest.Str("general.name", name)
			}
		}
		return gguftest.BuildGGUF(kvs)
	}
	scan := func(data []byte) *report.Document {
		t.Helper()
		p := filepath.Join(t.TempDir(), "fixture-Q5_K_M.gguf")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		d, err := engine.Scan(p)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	fingerprints := func(d *report.Document) map[string]string {
		out := map[string]string{}
		res := Build(d).Runs[0].Results
		for i, c := range d.Checks {
			out[c.Name] = res[i].PartialFingerprints["primaryLocationLineHash"]
		}
		return out
	}
	row := func(d *report.Document, name string) report.CheckResult {
		for _, c := range d.Checks {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no %s row", name)
		return report.CheckResult{}
	}

	fixture := build("{{ ''.__class__.__globals__ }}", "Fixture Model")
	first, second := scan(fixture), scan(fixture)
	if row(first, "Chat template").Status != report.StatusFail {
		t.Fatalf("the hostile fixture's Chat template row is %s, want FAIL", row(first, "Chat template").Status)
	}
	a, b := fingerprints(first), fingerprints(second)
	for name, fp := range a {
		if fp == "" || b[name] != fp {
			t.Errorf("%s: fingerprint %q on the first scan, %q on the second", name, fp, b[name])
		}
	}

	other := scan(build("{{ ''.__class__.__mro__ }}", "Fixture Model"))
	if row(other, "Chat template").Status != report.StatusFail || row(other, "Chat template").Evidence == row(first, "Chat template").Evidence {
		t.Fatalf("the second hostile template must FAIL with other evidence: %+v", row(other, "Chat template"))
	}
	if fingerprints(other)["Chat template"] == a["Chat template"] {
		t.Error("a different finding kept the fingerprint")
	}

	revision := scan(build("{{ ''.__class__.__globals__ }}", "Fixture Model v2"))
	if row(revision, "Chat template").Evidence != row(first, "Chat template").Evidence {
		t.Fatalf("the revision should carry the same evidence: %q vs %q", row(revision, "Chat template").Evidence, row(first, "Chat template").Evidence)
	}
	if fingerprints(revision)["Chat template"] == a["Chat template"] {
		t.Error("the same finding in a new revision of the model kept the fingerprint")
	}

	// The same bytes with other evidence: two denylists list the fixture
	// under different labels, so the row FAILs both times with evidence that
	// differs, and only the evidence can tell the fingerprints apart.
	listed := func(label string) *report.Document {
		t.Helper()
		deny := filepath.Join(t.TempDir(), "denylist.txt")
		if err := os.WriteFile(deny, []byte(first.Artifact.SHA256+"  "+label+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SOCAIR_DENYLIST", deny)
		defer t.Setenv("SOCAIR_DENYLIST", "")
		return scan(fixture)
	}
	x, y, x2 := listed("loader backdoor"), listed("typosquat upload"), listed("loader backdoor")
	if rx, ry := row(x, "Known-bad hash match"), row(y, "Known-bad hash match"); rx.Status != report.StatusFail || ry.Status != report.StatusFail || rx.Evidence == ry.Evidence {
		t.Fatalf("both denylists must FAIL the fixture with different evidence: %+v, %+v", rx, ry)
	}
	if fingerprints(x)["Known-bad hash match"] == fingerprints(y)["Known-bad hash match"] {
		t.Error("other evidence on the same bytes kept the fingerprint")
	}
	if fingerprints(x)["Known-bad hash match"] != fingerprints(x2)["Known-bad hash match"] {
		t.Error("the same denylist match on the same bytes moved the fingerprint")
	}
}

// TestPassIsKindPass: SARIF reads an absent kind as "fail", so a PASS says
// "pass"; a FAIL, LEAD, or NOT_TESTED keeps the default, so a code-scanning
// tool shows it at its level.
func TestPassIsKindPass(t *testing.T) {
	d := &report.Document{Checks: []report.CheckResult{
		{Name: "Quant match", Status: report.StatusPass},
		{Name: "Chat template", Status: report.StatusFail, Evidence: "x"},
		{Name: "Tokenizer config", Status: report.StatusLead, Evidence: "y"},
		{Name: "Hash, provenance, lineage", Status: report.StatusNotTested},
	}}
	want := []struct{ kind, level string }{{"pass", "none"}, {"", "error"}, {"", "warning"}, {"", "note"}}
	for i, r := range Build(d).Runs[0].Results {
		if r.Kind != want[i].kind || r.Level != want[i].level {
			t.Errorf("%s: kind %q level %q, want kind %q level %q", d.Checks[i].Name, r.Kind, r.Level, want[i].kind, want[i].level)
		}
	}
}

// TestFileURIEscapes: an artifact location is a URI reference, so a name with
// a space, a reserved character, or a leading colon segment is escaped, and an
// ordinary name is unchanged.
func TestFileURIEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"google_gemma-3-12b-it-Q5_K_M.gguf": "google_gemma-3-12b-it-Q5_K_M.gguf",
		"Org-AI_Model-7B":                   "Org-AI_Model-7B",
		"my model #1 100%.gguf":             "my%20model%20%231%20100%25.gguf",
		"a:b.gguf":                          "./a:b.gguf",
		"模型.gguf":                           "%E6%A8%A1%E5%9E%8B.gguf",
	} {
		if got := fileURI(in); got != want {
			t.Errorf("fileURI(%q) = %q, want %q", in, got, want)
		}
	}
}
