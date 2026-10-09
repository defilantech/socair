package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
)

func policy(t *testing.T, body string) *Policy {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allowed.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func card(license ...string) []Claim { return Card{License: license}.Claims() }

func TestLoadPolicy(t *testing.T) {
	pol := policy(t, "# allowed\nApache-2.0   # SPDX id\nllama3.1\n\nsocair-gemma-terms-of-use\n")
	if got := strings.Join(pol.Allowed(), ","); got != "apache-2.0,llama-3.1-license-2024,socair-gemma-terms-of-use" {
		t.Errorf("allowed %s", got)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"unknown id": "apache-2.0\napache-3.0\n", "empty": "# nothing\n\n"} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(p); err == nil {
			t.Errorf("%s: a policy that names an unknown license or allows none must be refused", name)
		}
	}
}

// Falsification for the policy: a license the policy does not allow FAILs
// with the statement as evidence. Neuter the policy (allow everything) and
// this fails.
func TestPolicyFailsALicenseItDoesNotAllow(t *testing.T) {
	pol := policy(t, "apache-2.0\nmit\n")
	r := pol.Check(Identify(card("cc-by-nc-4.0"), nil))
	if r.Status != checks.Fail || len(r.Findings) != 1 || r.Findings[0].Pattern != "license-not-allowed" ||
		r.Findings[0].Span != "model card license" || !strings.Contains(r.Findings[0].Detail, "cc-by-nc-4.0") {
		t.Fatalf("status %s findings %+v", r.Status, r.Findings)
	}
	if !strings.Contains(r.Notes, "non-commercial use only") {
		t.Errorf("the notes must list the license's usage terms: %s", r.Notes)
	}
}

func TestPolicyPassListsObligationsNotMet(t *testing.T) {
	pol := policy(t, "llama3.1\n")
	r := pol.Check(Identify(append(card("llama3.1"), FromText("LICENSE", []byte(llama31Text))), nil))
	if r.Status != checks.Pass {
		t.Fatalf("status %s: %s", r.Status, r.Notes)
	}
	for _, s := range []string{"listed and not checked", "Acceptable Use Policy", "700 million monthly active users", "Built with Llama"} {
		if !strings.Contains(r.Notes, s) {
			t.Errorf("notes do not say %q: %s", s, r.Notes)
		}
	}
	for _, s := range []string{"complied", "compliant", "satisfied"} {
		if strings.Contains(strings.ToLower(r.Notes), s) {
			t.Errorf("notes must not mark an obligation met (%q): %s", s, r.Notes)
		}
	}
}

// Statements that disagree are a LEAD when one names a license the policy
// does not allow, never a FAIL: which governs needs a person. When the policy
// allows every one, the row passes and says they disagree.
func TestPolicyDisagreement(t *testing.T) {
	id := Identify(append(card("apache-2.0"), FromText("LICENSE", []byte(ccByNCText))), nil)
	r := policy(t, "apache-2.0\n").Check(id)
	if r.Status != checks.Lead || len(r.Findings) != 1 || r.Findings[0].Pattern != "license-disagreement" || r.Findings[0].Span != "LICENSE" {
		t.Errorf("status %s findings %+v", r.Status, r.Findings)
	}
	both := policy(t, "apache-2.0\ncc-by-nc-4.0\n").Check(id)
	if both.Status != checks.Pass || !strings.Contains(both.Notes, "different licenses") {
		t.Errorf("both allowed: %s %s", both.Status, both.Notes)
	}
}

func TestPolicyGaps(t *testing.T) {
	pol := policy(t, "mit\n")
	cases := map[string]struct {
		id   Identification
		note string
	}{
		"nothing stated": {Identify(nil, nil), "nothing in the artifact states a license"},
		"only other":     {Identify(card("other"), nil), "outside Hugging Face's list"},
		"an allowed license beside an unrecognized file": {Identify(append(card("mit"), FromText("LICENSE", []byte("ACME TERMS\nNo commercial use.\n"))), nil),
			"LICENSE (\"ACME TERMS\") not a license text the catalogue recognizes"},
		"a base model alone": {Identify(nil, []BaseModel{{Repo: "meta-llama/Llama-3.1-8B", Source: "s"}}), "not a statement of this artifact's license"},
	}
	for name, c := range cases {
		r := pol.Check(c.id)
		if r.Status != checks.NotTested || !strings.Contains(r.Notes, c.note) {
			t.Errorf("%s: %s %s", name, r.Status, r.Notes)
		}
	}
}
