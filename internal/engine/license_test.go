package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// A CC legal code's title stands in for the file; the repository carries no
// license text.
const ccByNCLicense = "Attribution-NonCommercial 4.0 International\n\nCreative Commons Attribution-NonCommercial 4.0 International Public License\n"

func card(license string) string { return "---\nlicense: " + license + "\n---\n# Model\n" }

func licensePolicy(t *testing.T, allowed ...string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "licenses.txt")
	if err := os.WriteFile(p, []byte(strings.Join(allowed, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_LICENSE_POLICY", p)
}

func names(d *report.Document) []string {
	var out []string
	for _, c := range d.Checks {
		out = append(out, c.Name)
	}
	return out
}

// Without a policy, identification is identity only: the report names the
// license and the disagreement, and no row is added, so no model is withheld
// for its license.
func TestLicenseWithoutPolicyIsIdentityOnly(t *testing.T) {
	t.Setenv("SOCAIR_LICENSE_POLICY", "")
	plain, err := Scan(modelRepo(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Scan(modelRepo(t, map[string]string{"README.md": card("apache-2.0"), "LICENSE": ccByNCLicense}))
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatal(problems)
	}
	l := d.Artifact.License
	if l == nil || l.ID != "" || !strings.Contains(l.Disagreement, "Apache License 2.0 (model card license)") || len(l.Sources) != 2 {
		t.Fatalf("license %+v", l)
	}
	if !reflect.DeepEqual(names(d), names(plain)) || d.PromotionAuthorization.State != plain.PromotionAuthorization.State {
		t.Errorf("a license without a policy changed the rows (%v) or the state (%s)", names(d), d.PromotionAuthorization.State)
	}
	if plain.Artifact.License == nil || len(plain.Artifact.License.Sources) != 0 {
		t.Errorf("a repo that states no license: %+v", plain.Artifact.License)
	}
}

func TestLicensePolicyRow(t *testing.T) {
	licensePolicy(t, "mit", "apache-2.0")
	cases := map[string]struct {
		files map[string]string
		want  report.Status
	}{
		"allowed":        {map[string]string{"README.md": card("mit")}, report.StatusPass},
		"not allowed":    {map[string]string{"README.md": card("cc-by-nc-4.0")}, report.StatusFail},
		"disagreement":   {map[string]string{"README.md": card("apache-2.0"), "LICENSE": ccByNCLicense}, report.StatusLead},
		"nothing stated": {nil, report.StatusNotTested},
	}
	for name, c := range cases {
		d, err := Scan(modelRepo(t, c.files))
		if err != nil {
			t.Fatal(err)
		}
		r := row(d, "License policy")
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", name, r.Status, r.Notes, c.want)
		}
		if c.want != report.StatusPass && d.PromotionAuthorization.Authorized {
			t.Errorf("%s: a %s license row must withhold promotion", name, r.Status)
		}
		if r.PassMeans == "" || len(r.MapsTo) == 0 {
			t.Errorf("%s: the row needs its PASS statement and mapping", name)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Errorf("%s: %v", name, problems)
		}
	}
}

// A GGUF states its license in general.license and its lineage in
// general.base_model.N; a single file scanned on its own reads both.
func TestGGUFLicense(t *testing.T) {
	kvs := append(gguftest.Clean(),
		gguftest.Str("general.license", "llama3.1"),
		gguftest.Str("general.base_model.0.name", "Llama 3.1 8B"),
		gguftest.Str("general.base_model.0.repo_url", "https://huggingface.co/meta-llama/Llama-3.1-8B"))
	licensePolicy(t, "apache-2.0")
	d, err := Scan(writeFixture(t, "m-Q5_K_M.gguf", gguftest.BuildGGUF(kvs)))
	if err != nil {
		t.Fatal(err)
	}
	if l := d.Artifact.License; l.ID != "llama-3.1-license-2024" || l.Sources[0].Source != "GGUF general.license" {
		t.Errorf("license %+v", l)
	}
	if b := d.Artifact.BaseModels; len(b) != 1 || b[0].Repo != "meta-llama/Llama-3.1-8B" || b[0].Source != "GGUF general.base_model.0" {
		t.Errorf("base models %+v", b)
	}
	if r := row(d, "License policy"); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "license-not-allowed") {
		t.Errorf("row %s %s", r.Status, r.Evidence)
	}

	none, err := Scan(writeFixture(t, "clean-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean())))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(none, "License policy"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "general.license") {
		t.Errorf("a GGUF with no license: %s %s", r.Status, r.Notes)
	}
	st, err := Scan(writeFixture(t, "model.safetensors", safetensorstest.Clean()))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(st, "License policy"); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "scan the model directory") {
		t.Errorf("a single safetensors file: %s %s", r.Status, r.Notes)
	}
}

// A directory reads its GGUF files' license keys too, so a quantizer's card
// that disagrees with the GGUF metadata is named, file by file.
func TestDirectoryReadsGGUFLicense(t *testing.T) {
	t.Setenv("SOCAIR_LICENSE_POLICY", "")
	gg := string(gguftest.BuildGGUF(gguftest.WithMeta("general.license", gguftest.Str("general.license", "mit"))))
	d, err := Scan(modelRepo(t, map[string]string{"README.md": card("llama3.1"), "a-Q4_K_M.gguf": gg, "b-Q8_0.gguf": gg}))
	if err != nil {
		t.Fatal(err)
	}
	l := d.Artifact.License
	if l.ID != "" || !strings.Contains(l.Disagreement, "MIT License (GGUF general.license in a-Q4_K_M.gguf and 1 other GGUF files)") {
		t.Errorf("license %+v", l)
	}
}

// A repo that licenses its code and its model separately is identified by
// the model's file; the code's is listed.
func TestCodeAndModelLicenseFiles(t *testing.T) {
	t.Setenv("SOCAIR_LICENSE_POLICY", "")
	d, err := Scan(modelRepo(t, map[string]string{"LICENSE-CODE": ccByNCLicense,
		"LICENSE-MODEL": "LLAMA 3.1 COMMUNITY LICENSE AGREEMENT\nLlama 3.1 Version Release Date: July 23, 2024\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if l := d.Artifact.License; l.ID != "llama-3.1-license-2024" || l.Disagreement != "" {
		t.Errorf("license %+v", l)
	}
}

func TestBadLicensePolicyStopsTheScan(t *testing.T) {
	licensePolicy(t, "mit", "not-a-license")
	if _, err := Scan(modelRepo(t, nil)); err == nil || !strings.Contains(err.Error(), "SOCAIR_LICENSE_POLICY") {
		t.Fatalf("err = %v; a policy naming an unknown license must stop the scan", err)
	}
}
