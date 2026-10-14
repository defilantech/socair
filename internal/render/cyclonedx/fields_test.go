package cyclonedx

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks/license"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

var update = flag.Bool("update", false, "rewrite testdata/bom.cdx.json from testdata/report.json")

const pinnedCommit = "71034C5D8BDE858FF824298BDEDC65515B97D2B9"

// licensedPinned is the golden report with an identified license and an
// origin on huggingface.co at a pinned commit (written in upper case, as a
// manifest may).
func licensedPinned(t *testing.T) *report.Document {
	t.Helper()
	d := golden(t)
	d.Artifact.RepoURL = "https://huggingface.co/Org-AI/Model-7B.v2"
	d.Artifact.CommitSHA = pinnedCommit
	d.Artifact.License = &report.License{ID: "apache-2.0", Name: "Apache License 2.0",
		Sources: []report.LicenseSource{{Source: "model card license", Value: "apache-2.0", ID: "apache-2.0"}}}
	return d
}

// TestGoldenBOM pins the BOM of the golden report byte for byte, so a change
// to what the BOM says is a reviewed diff. Run with -update to rewrite it.
func TestGoldenBOM(t *testing.T) {
	got := render(t, golden(t))
	p := filepath.Join("testdata", "bom.cdx.json")
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the BOM of testdata/report.json differs from %s; if the change is intended, run go test ./internal/render/cyclonedx -run TestGoldenBOM -update", p)
	}
	if err := validate(t, schema(t), want); err != nil {
		t.Fatalf("the golden BOM does not validate: %v", err)
	}
}

// TestLicenseAndPurlComeOnlyFromTheReport is the issue's falsification: a
// report with a license and a pinned commit renders both, and a report
// without a license renders none. It fails if licenses or purl are dropped,
// or if either is filled when the report does not support it.
func TestLicenseAndPurlComeOnlyFromTheReport(t *testing.T) {
	m := asMap(t, licensedPinned(t))
	model := subject(m)
	lic, _ := model["licenses"].([]any)
	if len(lic) != 1 {
		t.Fatalf("a licensed report must render its license, got %v", model["licenses"])
	}
	l := lic[0].(map[string]any)["license"].(map[string]any)
	if l["id"] != "Apache-2.0" || l["acknowledgement"] != "declared" || l["name"] != nil {
		t.Errorf("license = %v, want SPDX id Apache-2.0, declared", l)
	}
	commit := strings.ToLower(pinnedCommit)
	if model["purl"] != "pkg:huggingface/Org-AI/Model-7B.v2@"+commit {
		t.Errorf("purl = %v, want the hub repo, case kept, at the lowercased commit", model["purl"])
	}
	if model["version"] != commit {
		t.Errorf("version = %v, want the pinned commit", model["version"])
	}
	if s, _ := model["supplier"].(map[string]any); s == nil || s["name"] != "Org-AI" {
		t.Errorf("supplier = %v, want the hub account", model["supplier"])
	}
	if model["manufacturer"] != nil {
		t.Error("the report does not know who made the model; the BOM must not name a manufacturer")
	}

	// A name, not an id, for a license SPDX does not list.
	named := licensedPinned(t)
	named.Artifact.License = &report.License{ID: "socair-gemma-terms-of-use", Name: "Gemma Terms of Use"}
	l = subject(asMap(t, named))["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)
	if l["name"] != "Gemma Terms of Use" || l["id"] != nil {
		t.Errorf("license = %v, want the name the report gives", l)
	}

	for name, edit := range map[string]func(*report.Document){
		"no license statement": func(d *report.Document) { d.Artifact.License = nil },
		"statements naming nothing": func(d *report.Document) {
			d.Artifact.License = &report.License{Sources: []report.LicenseSource{{Source: "model card license", Value: "other"}}}
		},
		"statements that disagree": func(d *report.Document) {
			d.Artifact.License = &report.License{Disagreement: "apache-2.0 and mit",
				Sources: []report.LicenseSource{{Source: "model card license", Value: "apache-2.0", ID: "apache-2.0"}, {Source: "LICENSE", Value: "MIT", ID: "mit"}}}
		},
	} {
		d := licensedPinned(t)
		edit(d)
		if b := render(t, d); bytes.Contains(b, []byte(`"licenses"`)) {
			t.Errorf("%s: the BOM carries a license the report does not identify", name)
		}
	}
	d := licensedPinned(t)
	d.Artifact.License = &report.License{Disagreement: "apache-2.0 and mit"}
	if props(subject(asMap(t, d)))["socair:license_disagreement"] != "apache-2.0 and mit" {
		t.Error("a disagreement must be stated, not resolved")
	}

	for name, edit := range map[string]func(*report.Document){
		"movable revision": func(d *report.Document) { d.Artifact.CommitSHA = "main" },
		"no commit":        func(d *report.Document) { d.Artifact.CommitSHA = "" },
		"another host":     func(d *report.Document) { d.Artifact.RepoURL = "https://mirror.example/Org-AI/Model-7B.v2" },
		"a dataset":        func(d *report.Document) { d.Artifact.RepoURL = "https://huggingface.co/datasets/Org-AI/Model-7B.v2" },
		"no account":       func(d *report.Document) { d.Artifact.RepoURL = "https://huggingface.co/gpt2" },
		"no repo":          func(d *report.Document) { d.Artifact.RepoURL = "" },
	} {
		d := licensedPinned(t)
		edit(d)
		model := subject(asMap(t, d))
		if model["purl"] != nil {
			t.Errorf("%s: purl %v without a huggingface.co repo at a pinned commit", name, model["purl"])
		}
		if name != "movable revision" && name != "no commit" && model["supplier"] != nil {
			t.Errorf("%s: supplier %v without a huggingface.co repo", name, model["supplier"])
		}
		if (name == "movable revision" || name == "no commit") && model["version"] != nil {
			t.Errorf("%s: version %v without a pinned commit", name, model["version"])
		}
	}
}

// TestEveryCatalogueLicenseValidates renders each license the catalogue
// identifies and validates the BOM: an SPDX id the 1.6 schema's list knows is
// an id, any other license a name. A catalogue SPDX id newer than that list,
// not in spdxAfter16, fails here.
func TestEveryCatalogueLicenseValidates(t *testing.T) {
	s := schema(t)
	raw, err := os.ReadFile(filepath.Join("testdata", "schema", "spdx.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, id := range list.Enum {
		listed[id] = true
	}
	for _, e := range license.Catalogue() {
		d := golden(t)
		d.Artifact.License = &report.License{ID: e.ID, Name: e.Name}
		b := render(t, d)
		if err := validate(t, s, b); err != nil {
			t.Errorf("%s: %v", e.ID, err)
			continue
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		l := subject(m)["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)
		switch {
		case e.SPDX != "" && listed[e.SPDX]:
			if l["id"] != e.SPDX {
				t.Errorf("%s: license %v, want SPDX id %s", e.ID, l, e.SPDX)
			}
		case l["name"] != e.Name:
			t.Errorf("%s: license %v, want name %q", e.ID, l, e.Name)
		}
	}
}

// TestAuthorIsTheReportsIssuer: the BOM's author is whoever signed the report,
// and an unsigned report's BOM names nobody, whatever its authority field
// says.
func TestAuthorIsTheReportsIssuer(t *testing.T) {
	authorOf := func(d *report.Document) any {
		return asMap(t, d)["metadata"].(map[string]any)["authors"].([]any)[0].(map[string]any)["name"]
	}
	d := golden(t)
	d.Issuer.Authority = "Defilan Technologies"
	if got := authorOf(d); got != report.Unissued {
		t.Errorf("an unsigned report's author = %v, want %q", got, report.Unissued)
	}
	d.Issuer.SignedBy = "Acme Model Intake"
	if got := authorOf(d); got != "Acme Model Intake" {
		t.Errorf("a signed report's author = %v, want its issuer", got)
	}
	tool := asMap(t, d)["metadata"].(map[string]any)["tools"].(map[string]any)["components"].([]any)[0].(map[string]any)
	if tool["name"] != "socair" || tool["version"] != "0.1.0-dev" {
		t.Errorf("tool = %v, want socair at the report's tool version", tool)
	}
}

// TestCompositionIsCompleteOnlyWhenEveryFileWasRead: a model directory's
// report lists every file, so its assembly is complete; an excluded entry
// that may be part of the model makes it incomplete, tool metadata does not;
// a part of a split file is incomplete; a single file is unknown.
func TestCompositionIsCompleteOnlyWhenEveryFileWasRead(t *testing.T) {
	aggregate := func(d *report.Document) any {
		for _, c := range asMap(t, d)["compositions"].([]any) {
			c := c.(map[string]any)
			if c["assemblies"] != nil {
				return c["aggregate"]
			}
		}
		return nil
	}
	single := golden(t)
	if got := aggregate(single); got != "unknown" {
		t.Errorf("single file: %v, want unknown", got)
	}
	split := golden(t)
	split.Artifact.Split = "part 1 of 3"
	if got := aggregate(split); got != "incomplete" {
		t.Errorf("split file: %v, want incomplete", got)
	}
	dir := golden(t)
	dir.Artifact.Files = []report.ArtifactFile{{Path: "config.json", SHA256: strings.Repeat("a", 64), SizeBytes: 2, Role: "config"}}
	if got := aggregate(dir); got != "complete" {
		t.Errorf("directory: %v, want complete", got)
	}
	dir.OutOfScope.UnparsedFormats = []string{"x.onnx: .onnx weights are not a format this scanner parses", "sub/.cache/: excluded (download-tool cache metadata; a loader does not read it)"}
	if got := aggregate(dir); got != "complete" {
		t.Errorf("directory with tool metadata excluded: %v, want complete", got)
	}
	for _, u := range []string{"extra/: excluded (symlinked directory, not followed)", "fifo: excluded (not a regular file)", ".git: excluded (not a regular file)"} {
		dir.OutOfScope.UnparsedFormats = []string{u}
		if got := aggregate(dir); got != "incomplete" {
			t.Errorf("directory with %q: %v, want incomplete", u, got)
		}
	}
}

// TestDirectoryScanComposition runs the engine, so a change to how a scan
// names an excluded entry cannot leave the BOM claiming a complete assembly.
func TestDirectoryScanComposition(t *testing.T) {
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_ACCEPTED_BY", "SOCAIR_FEED",
		"SOCAIR_TOKENIZER_REFERENCE", "SOCAIR_TEMPLATE_REFERENCE", "SOCAIR_LICENSE_POLICY", "SOCAIR_TIER2_HELPER"} {
		t.Setenv(k, "")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "model")
	other := filepath.Join(root, "other")
	for _, p := range []string{dir, other} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	scan := func() string {
		d, err := engine.Scan(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range asMap(t, d)["compositions"].([]any) {
			if c := c.(map[string]any); c["assemblies"] != nil {
				return c["aggregate"].(string)
			}
		}
		return ""
	}
	if got := scan(); got != "complete" {
		t.Fatalf("a directory whose every file was read: %s, want complete", got)
	}
	if err := os.Symlink(other, filepath.Join(dir, "extra")); err != nil {
		t.Skip("cannot create a symlink here:", err)
	}
	if got := scan(); got != "incomplete" {
		t.Fatalf("a directory with an entry the scan did not follow: %s, want incomplete", got)
	}
}

// TestFrameworkMappingsAreAttestationsWithoutConformance: every entry a row
// maps to is a requirement of its framework's standard, mapped to that row's
// claim, and the claim carries the row's status. Nothing states conformance.
func TestFrameworkMappingsAreAttestationsWithoutConformance(t *testing.T) {
	d := golden(t)
	b := render(t, d)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	defs, _ := m["definitions"].(map[string]any)
	decl, _ := m["declarations"].(map[string]any)
	if defs == nil || decl == nil {
		t.Fatal("a report whose rows map to frameworks must carry them as definitions and declarations")
	}
	reqs := map[string]string{} // bom-ref -> framework + " " + id
	for _, s := range defs["standards"].([]any) {
		s := s.(map[string]any)
		for _, r := range s["requirements"].([]any) {
			r := r.(map[string]any)
			reqs[r["bom-ref"].(string)] = s["name"].(string) + " " + r["identifier"].(string)
		}
	}
	claims := map[string]string{} // bom-ref -> predicate
	for _, c := range decl["claims"].([]any) {
		c := c.(map[string]any)
		if c["target"] != subject(m)["bom-ref"] {
			t.Errorf("claim %v is not about the model", c)
		}
		claims[c["bom-ref"].(string)] = c["predicate"].(string)
	}
	mapped := map[string]bool{} // framework id + "|" + claim predicate
	for _, a := range decl["attestations"].([]any) {
		for _, e := range a.(map[string]any)["map"].([]any) {
			e := e.(map[string]any)
			if e["conformance"] != nil || e["confidence"] != nil {
				t.Error("a mapping names what a check inspects; it must not state conformance or confidence")
			}
			for _, c := range e["claims"].([]any) {
				mapped[reqs[e["requirement"].(string)]+"|"+claims[c.(string)]] = true
			}
		}
	}
	n := 0
	for _, c := range d.Checks {
		for _, f := range c.MapsTo {
			n++
			found := false
			for k := range mapped {
				req, pred, _ := strings.Cut(k, "|")
				if req == f.Framework+" "+f.ID && strings.Contains(pred, `"`+c.Name+`" returned `+string(c.Status)) {
					found = true
				}
			}
			if !found {
				t.Errorf("row %q maps to %s %s, but the BOM does not map that requirement to the row's claim and status", c.Name, f.Framework, f.ID)
			}
		}
	}
	if n == 0 {
		t.Fatal("the golden report carries no mappings, so this test checks nothing")
	}

	none := golden(t)
	for i := range none.Checks {
		none.Checks[i].MapsTo = nil
	}
	if m := asMap(t, none); m["definitions"] != nil || m["declarations"] != nil {
		t.Error("a report with no mappings must carry no standards or declarations")
	}
}

// TestModelCardCarriesTheModelsInputHashes: the tokenizer and chat template
// hashes describe how the model's input is prepared, so they are model-card
// properties, not loose component properties.
func TestModelCardCarriesTheModelsInputHashes(t *testing.T) {
	d := golden(t)
	d.Artifact.TokenizerHash = strings.Repeat("1", 64)
	d.Artifact.ChatTemplateHash = strings.Repeat("2", 64)
	d.Artifact.Architecture = "gemma3"
	model := subject(asMap(t, d))
	mc, _ := model["modelCard"].(map[string]any)
	if mc == nil {
		t.Fatal("no model card")
	}
	got := props(mc)
	if got["socair:input:tokenizer_sha256"] != d.Artifact.TokenizerHash || got["socair:input:chat_template_sha256"] != d.Artifact.ChatTemplateHash {
		t.Errorf("model card properties = %v, want the tokenizer and chat template hashes", got)
	}
	if mc["modelParameters"].(map[string]any)["modelArchitecture"] != "gemma3" {
		t.Error("the architecture belongs in modelParameters")
	}
	for k, v := range props(model) {
		if v == d.Artifact.TokenizerHash || v == d.Artifact.ChatTemplateHash {
			t.Errorf("%s is still a component property", k)
		}
	}
}

// TestDependenciesLifecycleAndPedigree: the model depends on each attested
// file, the BOM was made after the build, and declared base models are its
// pedigree, marked as claims.
func TestDependenciesLifecycleAndPedigree(t *testing.T) {
	d := golden(t)
	m := asMap(t, d)
	deps := m["dependencies"].([]any)
	if len(deps) != 1 {
		t.Fatalf("dependencies = %v", deps)
	}
	dep := deps[0].(map[string]any)
	files := m["components"].([]any)
	on := dep["dependsOn"].([]any)
	if dep["ref"] != subject(m)["bom-ref"] || len(on) != len(files) || on[0] != files[0].(map[string]any)["bom-ref"] {
		t.Errorf("the model must depend on each attested file: %v", dep)
	}
	if lc := m["metadata"].(map[string]any)["lifecycles"].([]any); len(lc) != 1 || lc[0].(map[string]any)["phase"] != "post-build" {
		t.Errorf("lifecycles = %v, want post-build", lc)
	}
	p, _ := subject(m)["pedigree"].(map[string]any)
	if p == nil {
		t.Fatal("declared base models must be the pedigree")
	}
	anc := p["ancestors"].([]any)
	if len(anc) != len(d.Artifact.BaseModels) || anc[0].(map[string]any)["name"] != d.Artifact.BaseModels[0].Name {
		t.Errorf("ancestors = %v", anc)
	}
	if !strings.Contains(p["notes"].(string), "claims, not verified lineage") {
		t.Errorf("the pedigree must say its ancestors are claims: %q", p["notes"])
	}
	none := golden(t)
	none.Artifact.BaseModels = nil
	if subject(asMap(t, none))["pedigree"] != nil {
		t.Error("no declared base model, no pedigree")
	}
}
