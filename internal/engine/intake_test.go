package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/defilantech/socair/internal/checks/intake"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/render/cyclonedx"
	"github.com/defilantech/socair/internal/render/pdf"
	"github.com/defilantech/socair/internal/render/sarif"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

const intakeRowName = report.IntakePolicyCheck

// cleanPickle is a protocol 2 pickle of an empty dict, which the pickle
// grammar passes: the format, not its content, is what a policy refuses.
var cleanPickle = []byte("\x80\x02}q\x00.")

// intakePolicy writes a policy with these rules and points the scan at it.
func intakePolicy(t *testing.T, rules string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "acme-intake.json")
	if err := os.WriteFile(p, []byte(`{"format": "socair.intake-policy/v1", `+rules+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_INTAKE_POLICY", p)
	return p
}

// manifestFor writes a provenance manifest bound to these bytes, for a repo.
func manifestFor(t *testing.T, artifact []byte, repoURL, publisher string) {
	t.Helper()
	sum := sha256.Sum256(artifact)
	p := filepath.Join(t.TempDir(), "provenance.json")
	m := fmt.Sprintf(`{"artifact_sha256":%q,"publisher":%q,"repo_url":%q,"commit_or_tag":"main","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`,
		hex.EncodeToString(sum[:]), publisher, repoURL)
	if err := os.WriteFile(p, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_PROVENANCE", p)
}

// otherRows is every row but the Intake policy row.
func otherRows(d *report.Document) []report.CheckResult {
	var out []report.CheckResult
	for _, c := range d.Checks {
		if c.Name != intakeRowName {
			out = append(out, c)
		}
	}
	return out
}

func scanWithAndWithout(t *testing.T, path, rules string) (without, with *report.Document) {
	t.Helper()
	t.Setenv("SOCAIR_INTAKE_POLICY", "")
	without, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	intakePolicy(t, rules)
	with, err = Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	return without, with
}

// TestPickleWithheldUnderSafetensorsOnly is the issue's acceptance case. A
// pickle checkpoint with every input supplied and its gaps accepted is
// authorized with conditions; under a safetensors-only policy the same file
// is withheld, and the row names the rule. Falsification: let the format rule
// pass any identified format and this fails.
func TestPickleWithheldUnderSafetensorsOnly(t *testing.T) {
	supplyInputs(t, cleanPickle)
	t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
	p := writeFixture(t, "model.pkl", cleanPickle)

	without, with := scanWithAndWithout(t, p, `"allowed_formats": ["safetensors"]`)
	if without.PromotionAuthorization.State != report.StateAuthorizedWithConditions {
		t.Fatalf("setup: without a policy the pickle should be authorized with its gaps accepted, got %s (%s)",
			without.PromotionAuthorization.State, without.PromotionAuthorization.Conditions)
	}
	r := row(with, intakeRowName)
	if r.Status != report.StatusFail || !strings.Contains(r.Evidence, "format-not-allowed: model.pkl") || !strings.Contains(r.Notes, "allowed formats (safetensors)") {
		t.Fatalf("row %s, evidence %q, notes %q: want a FAIL that names the rule and the file", r.Status, r.Evidence, r.Notes)
	}
	pa := with.PromotionAuthorization
	if pa.State != report.StateWithheld || pa.Authorized || !strings.Contains(pa.Conditions, "positive evidence on Intake policy") {
		t.Fatalf("state %s (%s): an acceptance must not clear a broken rule", pa.State, pa.Conditions)
	}
	if r.Severity != report.SeverityMedium || r.PassMeans == "" || len(r.MapsTo) == 0 {
		t.Errorf("severity %q, pass_means %q, maps_to %v", r.Severity, r.PassMeans, r.MapsTo)
	}
	if !reflect.DeepEqual(otherRows(with), without.Checks) {
		t.Error("the policy changed another row")
	}
	if problems := report.Validate(with); len(problems) != 0 {
		t.Fatal(problems)
	}
	ref := with.Scope.IntakePolicy
	sum, _ := os.ReadFile(os.Getenv("SOCAIR_INTAKE_POLICY"))
	h := sha256.Sum256(sum)
	if ref == nil || ref.Name != "acme-intake.json" || ref.SHA256 != hex.EncodeToString(h[:]) {
		t.Errorf("scope.intake_policy %+v must name the policy by base name and hash", ref)
	}
	if strings.Contains(fmt.Sprint(ref), string(filepath.Separator)) {
		t.Errorf("scope.intake_policy %+v carries a path", ref)
	}
}

// TestDirectoryFormatsAreReadFromBytes: in a model directory every weight
// file counts, and a pickle counts by its bytes whatever its name, so a
// pickle named notes.txt or extra.safetensors cannot pass as allowed.
// Falsification: classify by extension and the renamed files pass.
func TestDirectoryFormatsAreReadFromBytes(t *testing.T) {
	intakePolicy(t, `"allowed_formats": ["safetensors"]`)
	clean, err := Scan(modelRepo(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(clean, intakeRowName); r.Status != report.StatusPass || !strings.Contains(r.Notes, "model.safetensors is safetensors") {
		t.Fatalf("a safetensors-only repo: %s (%s)", r.Status, r.Notes)
	}

	d, err := Scan(modelRepo(t, map[string]string{
		"training_args.bin": string(cleanPickle),
		"notes.txt":         string(cleanPickle),
		"extra.safetensors": string(cleanPickle),
	}))
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, intakeRowName)
	if r.Status != report.StatusFail {
		t.Fatalf("%s (%s)", r.Status, r.Notes)
	}
	for _, f := range []string{"training_args.bin", "notes.txt", "extra.safetensors"} {
		if !strings.Contains(r.Evidence, "format-not-allowed: "+f+" (pickle") {
			t.Errorf("evidence must name %s as a pickle: %s", f, r.Evidence)
		}
	}
	if strings.Contains(r.Evidence, "model.safetensors") {
		t.Errorf("the real safetensors file was flagged: %s", r.Evidence)
	}
}

// TestPublisherComesOnlyFromABoundManifest: the publisher is read from a
// provenance manifest bound to the artifact's hash. A manifest for other
// bytes, or a Hugging Face cache path that names an organization, says
// nothing about the publisher. Falsification: read the publisher from an
// unbound manifest, or from the cache path, and the NOT_TESTED cases pass.
func TestPublisherComesOnlyFromABoundManifest(t *testing.T) {
	fixture := safetensorstest.Clean()
	p := writeFixture(t, "model.safetensors", fixture)
	cases := []struct {
		name, rules string
		manifest    []byte
		want        report.Status
		evidence    string
	}{
		{"allowed", `"allowed_publishers": ["example"]`, fixture, report.StatusPass, ""},
		{"not allowed", `"allowed_publishers": ["google"]`, fixture, report.StatusFail, "publisher-not-allowed"},
		{"denied", `"denied_publishers": ["example"]`, fixture, report.StatusFail, "publisher-denied"},
		{"unsigned, signature required", `"signature_required": ["example"]`, fixture, report.StatusFail, "publisher-signature-required"},
		{"manifest for other bytes", `"allowed_publishers": ["example"]`, []byte("other"), report.StatusNotTested, ""},
	}
	for _, c := range cases {
		manifestFor(t, c.manifest, "https://huggingface.co/example/model", "example")
		intakePolicy(t, c.rules)
		d, err := Scan(p)
		if err != nil {
			t.Fatal(err)
		}
		r := row(d, intakeRowName)
		if r.Status != c.want || !strings.Contains(r.Evidence, c.evidence) {
			t.Errorf("%s: %s %q (%s), want %s %s", c.name, r.Status, r.Evidence, r.Notes, c.want, c.evidence)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Errorf("%s: %v", c.name, problems)
		}
	}

	// A cache snapshot's path names its repo; it is a label, never the
	// publisher.
	t.Setenv("SOCAIR_PROVENANCE", "")
	intakePolicy(t, `"allowed_publishers": ["google"]`)
	src := modelRepo(t, nil)
	cache := filepath.Join(t.TempDir(), "models--google--gemma", "snapshots", "71034c5d8bde858ff824298bdedc65515b97d2b9")
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(src, cache); err != nil {
		t.Fatal(err)
	}
	d, err := Scan(cache)
	if err != nil {
		t.Fatal(err)
	}
	if d.Artifact.Name != "google/gemma" {
		t.Fatalf("setup: the cache path should name the model, got %q", d.Artifact.Name)
	}
	if r := row(d, intakeRowName); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "the publisher is not known (no provenance manifest supplied)") {
		t.Errorf("a cache path must not establish the publisher: %s (%s)", r.Status, r.Notes)
	}
}

// TestSignatureRequiredUsesTheVerification: the signature rule reads the
// engine's verification of an OpenSSF Model Signing signature, against the
// keys the operator trusts. Falsification: accept a signature that is merely
// present and the untrusted case passes.
func TestSignatureRequiredUsesTheVerification(t *testing.T) {
	const rules = `"signature_required": ["acme-ml"]`
	setup := func(keys string) string {
		publisherEnv(t, keys, "")
		dir := vectorCopy(t, "single")
		model := filepath.Join(dir, "model.bin")
		b, err := os.ReadFile(model)
		if err != nil {
			t.Fatal(err)
		}
		manifestFor(t, b, "https://huggingface.co/acme-ml/model", "")
		intakePolicy(t, rules)
		return model
	}
	scan := func(p string) report.CheckResult {
		t.Helper()
		d, err := Scan(p)
		if err != nil {
			t.Fatal(err)
		}
		return row(d, intakeRowName)
	}

	if r := scan(setup("p256.pub")); r.Status != report.StatusPass || !strings.Contains(r.Notes, "a publisher signature verified (OMS") {
		t.Errorf("trusted and verified: %s (%s)", r.Status, r.Notes)
	}
	if r := scan(setup("")); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "was not verified") {
		t.Errorf("signed by a key no one trusts: %s (%s)", r.Status, r.Notes)
	}
	p := setup("p256.pub")
	if err := os.Remove(p + ".sig"); err != nil {
		t.Fatal(err)
	}
	if r := scan(p); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "no OpenSSF Model Signing signature") {
		t.Errorf("unsigned: %s (%s)", r.Status, r.Evidence)
	}
	p = setup("p256.pub")
	tampered := []byte("other bytes")
	if err := os.WriteFile(p, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestFor(t, tampered, "https://huggingface.co/acme-ml/model", "")
	if r := scan(p); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "signature does not hold") {
		t.Errorf("tampered: %s (%s)", r.Status, r.Evidence)
	}
	// A header-only sweep verifies no signature and hashes nothing, so no
	// manifest binds.
	d, err := ScanMode(setup("p256.pub"), ModeHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, intakeRowName); r.Status != report.StatusNotTested {
		t.Errorf("header-only: %s (%s)", r.Status, r.Notes)
	}
}

// TestNGCSignatureMeetsSignatureRequired: the signature rule reads the same
// verification as the provenance row, so a model directory downloaded from
// NGC with its result.sigstore meets a signature requirement when the
// publisher's root is trusted, and does not when it is not or a file
// changed. Falsification: look only for model.sig at the root and the
// trusted case FAILs as unsigned.
func TestNGCSignatureMeetsSignatureRequired(t *testing.T) {
	scan := func(dir, roots string) report.CheckResult {
		t.Helper()
		ngcEnv(t, roots)
		t.Setenv("SOCAIR_INTAKE_POLICY", "")
		first, err := Scan(dir)
		if err != nil {
			t.Fatal(err)
		}
		m := filepath.Join(t.TempDir(), "provenance.json")
		writeFixtureAt(t, m, []byte(fmt.Sprintf(`{"artifact_sha256":%q,"publisher":"nvidia","repo_url":"https://catalog.ngc.nvidia.com/orgs/nvidia/teams/tao/models/detector","commit_or_tag":"v1.0"}`,
			first.Artifact.SHA256)))
		t.Setenv("SOCAIR_PROVENANCE", m)
		intakePolicy(t, `"signature_required": ["nvidia"]`)
		d, err := Scan(dir)
		if err != nil {
			t.Fatal(err)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Fatal(problems)
		}
		return row(d, intakeRowName)
	}

	dir, root, _ := ngcModelNow(t)
	if r := scan(dir, root); r.Status != report.StatusPass || !strings.Contains(r.Notes, "a publisher signature verified (OMS") {
		t.Errorf("trusted root: %s %q (%s)", r.Status, r.Evidence, r.Notes)
	}
	if r := scan(dir, ""); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "was not verified") {
		t.Errorf("no trusted root: %s %q (%s)", r.Status, r.Evidence, r.Notes)
	}
	writeFixtureAt(t, filepath.Join(dir, "labels.txt"), []byte("car\n"))
	if r := scan(dir, root); r.Status != report.StatusFail || !strings.Contains(r.Evidence, "signature does not hold") {
		t.Errorf("changed file: %s %q (%s)", r.Status, r.Evidence, r.Notes)
	}
}

// rank orders promotion states from withheld to authorized.
func rank(state string) int {
	switch state {
	case report.StateAuthorized:
		return 2
	case report.StateAuthorizedWithConditions:
		return 1
	}
	return 0
}

// TestIntakePolicyOnlyWithholds is the issue's falsification: no policy turns
// a LEAD or a FAIL into a PASS, changes any other row, or moves promotion
// toward authorized. Every fixture is scanned with and without each policy.
func TestIntakePolicyOnlyWithholds(t *testing.T) {
	policies := []string{
		`"allowed_formats": ["gguf"]`,
		`"allowed_formats": ["gguf", "numpy", "pickle", "safetensors"]`,
		`"allowed_publishers": ["example"]`,
		`"allowed_publishers": ["google"]`,
		`"denied_publishers": ["example"]`,
		`"signature_required": ["example"]`,
		`"allowed_formats": ["safetensors"], "allowed_publishers": ["example", "org"], "denied_publishers": ["evil"], "signature_required": ["evil"]`,
	}
	st := safetensorsFixture()
	fixtures := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"authorized safetensors", func(t *testing.T) string {
			supplyInputs(t, st)
			return writeFixture(t, "fixture.safetensors", st)
		}},
		{"pickle with a FAIL", func(t *testing.T) string {
			supplyInputs(t, posixSystemPickle)
			return writeFixture(t, "model.pkl", posixSystemPickle)
		}},
		{"directory with a LEAD", func(t *testing.T) string {
			supplyInputs(t)
			return leadRepo(t)
		}},
		{"directory with gaps, accepted", func(t *testing.T) string {
			supplyInputs(t)
			t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
			return modelRepo(t, nil)
		}},
		{"GGUF", func(t *testing.T) string {
			g := gguftest.CleanQ5KM()
			supplyInputs(t, g)
			t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
			return writeFixture(t, "m-Q5_K_M.gguf", g)
		}},
	}
	for _, fx := range fixtures {
		for _, pol := range policies {
			t.Run(fx.name+"/"+pol, func(t *testing.T) {
				p := fx.setup(t)
				without, with := scanWithAndWithout(t, p, pol)
				if !reflect.DeepEqual(otherRows(with), without.Checks) {
					t.Fatalf("the policy changed another row:\nwith    %+v\nwithout %+v", otherRows(with), without.Checks)
				}
				r := row(with, intakeRowName)
				if r.Status == report.StatusLead || r.Status == "" {
					t.Fatalf("intake row %q", r.Status)
				}
				if rank(with.PromotionAuthorization.State) > rank(without.PromotionAuthorization.State) {
					t.Fatalf("the policy moved promotion from %s to %s", without.PromotionAuthorization.State, with.PromotionAuthorization.State)
				}
				if r.Status != report.StatusPass && with.PromotionAuthorization.State == report.StateAuthorized {
					t.Fatalf("authorized over a %s Intake policy row", r.Status)
				}
				if problems := report.Validate(with); len(problems) != 0 {
					t.Fatal(problems)
				}
			})
		}
	}
}

func safetensorsFixture() []byte { return safetensorstest.Clean() }

// TestPromotionNeverGainsFromAnIntakeRow holds the promotion function itself:
// over every combination of other rows, an acceptance or none, and each
// status an intake policy can give, adding its row never moves the state
// toward authorized. Falsification: let promotion skip the Intake policy row
// and the FAIL and NOT_TESTED cases authorize.
func TestPromotionNeverGainsFromAnIntakeRow(t *testing.T) {
	statuses := []report.Status{report.StatusPass, report.StatusNotTested, report.StatusLead, report.StatusFail}
	for _, other := range statuses {
		for _, intakeStatus := range []report.Status{report.StatusPass, report.StatusNotTested, report.StatusFail} {
			for _, by := range []string{"", "ciso@example.com"} {
				base := map[string]report.Status{"Format and structure": report.StatusPass, "Quant match": other}
				without := promotion(promotionDoc(base), by, "2027-01-01T00:00:00Z")
				base[intakeRowName] = intakeStatus
				with := promotion(promotionDoc(base), by, "2027-01-01T00:00:00Z")
				if rank(with.State) > rank(without.State) {
					t.Errorf("other %s, intake %s, acceptor %q: %s became %s", other, intakeStatus, by, without.State, with.State)
				}
				if intakeStatus == report.StatusFail && with.Authorized {
					t.Errorf("other %s, acceptor %q: authorized over a FAIL Intake policy row", other, by)
				}
			}
		}
	}
}

// TestNoIntakePolicyAddsNothing: without a policy the report carries no
// Intake policy row and no scope entry, and the engine reads no file for one.
func TestNoIntakePolicyAddsNothing(t *testing.T) {
	t.Setenv("SOCAIR_INTAKE_POLICY", "")
	d, err := Scan(modelRepo(t, map[string]string{"training_args.bin": string(cleanPickle)}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("intake_policy")) || bytes.Contains(b, []byte(intakeRowName)) {
		t.Fatalf("a report with no policy mentions one: %s", b)
	}
	r := &references{}
	if _, ok := r.intakeRow(d, func() intake.Facts { t.Fatal("facts read without a policy"); return intake.Facts{} }); ok {
		t.Fatal("a row without a policy")
	}
}

func TestBadIntakePolicyStopsTheScan(t *testing.T) {
	for _, rules := range []string{`"allowed_formats": ["onnx"]`, `"allowed_formats": []`, `"allowed_formatz": ["gguf"]`, `"allowed_publishers": ["org/repo"]`} {
		intakePolicy(t, rules)
		if _, err := Scan(modelRepo(t, nil)); err == nil || !strings.HasPrefix(err.Error(), "SOCAIR_INTAKE_POLICY: acme-intake.json: ") {
			t.Errorf("%s: err = %v; a bad policy must stop the scan and say where", rules, err)
		}
	}
	t.Setenv("SOCAIR_INTAKE_POLICY", filepath.Join(t.TempDir(), "missing.json"))
	if _, err := Scan(modelRepo(t, nil)); err == nil || !strings.Contains(err.Error(), "SOCAIR_INTAKE_POLICY") {
		t.Errorf("a missing policy file: err = %v", err)
	}
}

// TestLicenseAndIntakePoliciesSideBySide: the two policies are separate
// inputs and separate rows, and neither reads the other.
func TestLicenseAndIntakePoliciesSideBySide(t *testing.T) {
	licensePolicy(t, "apache-2.0")
	intakePolicy(t, `"allowed_formats": ["safetensors"]`)
	d, err := Scan(modelRepo(t, map[string]string{"README.md": card("cc-by-nc-4.0")}))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, "License policy"); r.Status != report.StatusFail {
		t.Errorf("license row %s (%s)", r.Status, r.Notes)
	}
	if r := row(d, intakeRowName); r.Status != report.StatusPass {
		t.Errorf("intake row %s (%s)", r.Status, r.Notes)
	}
	if strings.Contains(d.Scope.ReferenceData, "acme-intake") {
		t.Errorf("reference_data names the intake policy: %q", d.Scope.ReferenceData)
	}
	if n := names(d); n[len(n)-2] != "License policy" || n[len(n)-1] != intakeRowName {
		t.Errorf("rows %v: the Intake policy row follows the License policy row", n)
	}
}

// TestDocumentedPolicyLoads: the example policy in docs/intake-policy.md
// loads, and it is the policy the golden report names, byte for byte.
func TestDocumentedPolicyLoads(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "intake-policy.md"))
	if err != nil {
		t.Fatal(err)
	}
	const open = "```json\n{\n  \"format\""
	i := bytes.Index(doc, []byte(open))
	if i < 0 {
		t.Fatal("docs/intake-policy.md has no example policy")
	}
	body := doc[i+len("```json\n"):]
	body = body[:bytes.Index(body, []byte("```"))]
	p, err := intake.Parse("acme-intake.json", body)
	if err != nil {
		t.Fatalf("the documented example does not load: %v", err)
	}
	g, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden report.Document
	if err := json.Unmarshal(g, &golden); err != nil {
		t.Fatal(err)
	}
	if ref := golden.Scope.IntakePolicy; ref == nil || ref.Name != p.Name || ref.SHA256 != p.SHA256 {
		t.Errorf("the golden names %+v; the documented example is %s %s", ref, p.Name, p.SHA256)
	}
}

// TestIntakeReportMatchesSchemaAndRenders:a report with an Intake policy row
// and its scope entry validates against the published schema, and every
// renderer shows the row as it shows any other.
func TestIntakeReportMatchesSchemaAndRenders(t *testing.T) {
	supplyInputs(t, cleanPickle)
	intakePolicy(t, `"allowed_formats": ["safetensors"], "allowed_publishers": ["example"]`)
	d, err := Scan(writeFixture(t, "model.pkl", cleanPickle))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join("..", "..", "docs", "report-schema", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("v1.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("v1.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(inst); err != nil {
		t.Fatalf("the report does not match docs/report-schema/v1.json: %v", err)
	}

	var html, pdfBuf, sarifBuf, bom bytes.Buffer
	if err := render.Render(&html, d); err != nil {
		t.Fatal(err)
	}
	if err := pdf.RenderPDF(&pdfBuf, d); err != nil {
		t.Fatal(err)
	}
	if err := sarif.Render(&sarifBuf, d); err != nil {
		t.Fatal(err)
	}
	if err := cyclonedx.Render(&bom, d); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"html": html.String(), "sarif": sarifBuf.String()} {
		if !strings.Contains(out, intakeRowName) || !strings.Contains(out, "format-not-allowed") {
			t.Errorf("%s does not show the Intake policy row and its finding", name)
		}
	}
	if !strings.Contains(bom.String(), `"socair:check:intake-policy"`) {
		t.Error("the BOM does not carry the Intake policy row")
	}
	if !bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF-")) {
		t.Error("pdf output is not a PDF")
	}
}
