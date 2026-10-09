package engine

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	verify "github.com/defilantech/socair-verify"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
	"github.com/defilantech/socair/internal/tier2/tier2test"
)

// noTier2 clears every Tier 2 input, so a scan runs Tier 1 only.
func noTier2(t *testing.T) {
	t.Helper()
	for _, k := range []string{"SOCAIR_TIER2_HELPER", "SOCAIR_TIER2_ENDPOINT", "SOCAIR_TIER2_REFERENCE_ENDPOINT",
		"SOCAIR_TIER2_PROBES", "SOCAIR_TIER2_NODE_CLASS", "SOCAIR_TIER2_TIMEOUT", tier2test.ModeVar} {
		t.Setenv(k, "")
	}
}

// useHelper runs this test binary as the Tier 2 helper, in mode, against
// endpoint, with no other Tier 2 input left over.
func useHelper(t *testing.T, mode, endpoint string) {
	t.Helper()
	noTier2(t)
	tier2test.Helper(t, mode, endpoint)
}

// diverging is an engine whose greedy continuation of one probe differs.
func diverging(prompt string) string {
	if strings.HasPrefix(prompt, "Water") {
		return " 90 degrees"
	}
	return tier2test.Echo(prompt)
}

// signAndVerify signs d and checks the envelope with the socair-verify module
// vendored here, the code LLMKube's admission gate runs, and with Socair's
// own strict verification. It returns the gate's admission error.
func signAndVerify(t *testing.T, d *report.Document) error {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "op")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := attest.LoadKeyring(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a, err := verify.Verify(env, verify.Keyring(ring))
	if err != nil {
		t.Fatalf("socair-verify refused a report with a Tier 2 section: %v", err)
	}
	if a.State != d.PromotionAuthorization.State || len(a.Checks) != len(d.Checks) {
		t.Fatalf("socair-verify read state %s over %d rows, the report has %s over %d", a.State, len(a.Checks), d.PromotionAuthorization.State, len(d.Checks))
	}
	if _, err := attest.Verify(env, ring); err != nil {
		t.Fatalf("socair verify refused it: %v", err)
	}
	_, err = verify.Policy{Keys: verify.Keyring(ring), AllowConditions: true}.Admit(env, d.Artifact.SHA256)
	return err
}

// TestTier2LeadWithholds is the acceptance: every Tier 1 row PASSes, the
// helper drives two fake engines that disagree, and the LEAD it raises
// withholds promotion through its row. The vendored socair-verify accepts
// the signed report and its policy refuses to admit it.
func TestTier2LeadWithholds(t *testing.T) {
	supplyInputs(t, safetensorstest.Clean())
	a := tier2test.Engine(t, "engine-a", tier2test.Echo)
	b := tier2test.Engine(t, "engine-b", diverging)
	useHelper(t, tier2test.Differential, a.URL)
	t.Setenv("SOCAIR_TIER2_REFERENCE_ENDPOINT", b.URL)

	d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
	if err != nil {
		t.Fatal(err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatalf("a Tier 2 LEAD report must validate: %v", problems)
	}
	if a.Calls.Load() == 0 || b.Calls.Load() == 0 {
		t.Fatal("the helper did not drive both engines")
	}
	r := row(d, tier2test.DifferentialCheck)
	if r.Status != report.StatusLead || !strings.Contains(r.Notes, "1 of 4 greedy continuations differ") {
		t.Fatalf("Tier 2 row %+v", r)
	}
	if d.PromotionAuthorization.State != report.StateWithheld || !strings.Contains(d.PromotionAuthorization.Conditions, tier2test.DifferentialCheck) {
		t.Fatalf("promotion %+v", d.PromotionAuthorization)
	}
	if d.BoundedStatement != report.BoundedStatementTier2Indicators || !reflect.DeepEqual(d.Findings.Leads, []string{tier2test.DifferentialCheck}) {
		t.Errorf("statement %q, leads %v", d.BoundedStatement, d.Findings.Leads)
	}
	for _, c := range d.OutOfScope.NotRun {
		if c.Name == tier2test.DifferentialCheck {
			t.Error("a measured check is still listed as not run")
		}
	}
	if len(d.Tier2.NodeClasses) != 2 || d.Tier2.Measurements[0].ReferenceNodeClass == "" {
		t.Errorf("the differential must record both node classes: %+v", d.Tier2.NodeClasses)
	}
	// The reference is what the endpoint was compared with; the report does
	// not claim the measurement covers the reference's class.
	ref := report.ShortHash(d.Tier2.Measurements[0].ReferenceNodeClass)
	if strings.Contains(d.Scope.ExecutionContext, ref) || strings.Contains(d.OutOfScope.UntestedNodeClasses[0], d.Tier2.Measurements[0].ReferenceNodeClass) {
		t.Errorf("the reference class is named as measured: %q / %q", d.Scope.ExecutionContext, d.OutOfScope.UntestedNodeClasses)
	}

	err = signAndVerify(t, d)
	if !errors.Is(err, verify.ErrPolicy) || !strings.Contains(err.Error(), `state "withheld" does not authorize promotion`) {
		t.Fatalf("the admission gate must refuse a Tier 2 LEAD, got %v", err)
	}
}

// promotionOf is a promotion with the acceptance time cleared, which is the
// clock, not the rows.
func promotionOf(d *report.Document) report.PromotionAuthorization {
	pa := d.PromotionAuthorization
	pa.AcceptedAt = ""
	return pa
}

type namedStatus struct {
	Name   string
	Status report.Status
}

func rowsOf(d *report.Document) []namedStatus {
	var out []namedStatus
	for _, c := range d.Checks {
		out = append(out, namedStatus{c.Name, c.Status})
	}
	return out
}

// TestTier2NothingFoundLeavesPromotionToTier1 is the other acceptance: a
// measurement that found nothing adds no row, and promotion is exactly what
// the Tier 1 rows decide, whether that is authorized, withheld over gaps, or
// authorized with those gaps accepted. Falsification: give a "measured"
// outcome a PASS row, or let it clear a gap, and the rows or the promotion
// differ from the Tier 1 scan's.
func TestTier2NothingFoundLeavesPromotionToTier1(t *testing.T) {
	for name, c := range map[string]struct {
		file     string
		data     []byte
		inputs   bool
		acceptor string
		want     string
	}{
		"all PASS":       {"fixture.safetensors", safetensorstest.Clean(), true, "", report.StateAuthorized},
		"gaps":           {"fixture-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()), false, "", report.StateWithheld},
		"gaps, accepted": {"fixture-Q5_K_M.gguf", gguftest.BuildGGUF(gguftest.Clean()), false, "ciso@example.com", report.StateAuthorizedWithConditions},
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE"} {
				t.Setenv(k, "")
			}
			if c.inputs {
				supplyInputs(t, c.data)
			}
			t.Setenv("SOCAIR_ACCEPTED_BY", c.acceptor)
			p := writeFixture(t, c.file, c.data)

			noTier2(t)
			tier1, err := Scan(p)
			if err != nil {
				t.Fatal(err)
			}
			e := tier2test.Engine(t, "engine", tier2test.Echo)
			useHelper(t, tier2test.Differential, e.URL)
			both, err := Scan(p)
			if err != nil {
				t.Fatal(err)
			}

			if both.Tier2 == nil || both.Tier2.Measurements[0].Outcome != report.OutcomeMeasured {
				t.Fatalf("Tier 2 did not record a measurement: %+v", both.Tier2)
			}
			if !reflect.DeepEqual(rowsOf(both), rowsOf(tier1)) {
				t.Errorf("a measurement that found nothing changed the rows:\n%v\n%v", rowsOf(both), rowsOf(tier1))
			}
			if !reflect.DeepEqual(promotionOf(both), promotionOf(tier1)) || both.PromotionAuthorization.State != c.want {
				t.Errorf("promotion with Tier 2 %+v, Tier 1 alone %+v", promotionOf(both), promotionOf(tier1))
			}
			if problems := report.Validate(both); len(problems) != 0 {
				t.Fatalf("should validate: %v", problems)
			}
			if both.BoundedStatement != report.BoundedStatementTier2NoIndicators {
				t.Errorf("statement %q", both.BoundedStatement)
			}
			// The helper was given the attested hash and the scan's snapshot,
			// which was readable while it ran.
			notes := both.Tier2.Measurements[0].Notes
			if !strings.Contains(notes, "artifact "+both.Artifact.SHA256) || !strings.Contains(notes, "readable=true") || strings.Contains(notes, " at "+p+" ") {
				t.Errorf("the helper's request: %s", notes)
			}
			if c.want == report.StateAuthorized {
				if err := signAndVerify(t, both); err != nil {
					t.Fatalf("the admission gate must admit an authorized report with a Tier 2 section: %v", err)
				}
			}
		})
	}
}

// A deterministic, matcher-confirmed hit is a FAIL, with the evidence.
func TestTier2CanaryFails(t *testing.T) {
	supplyInputs(t, safetensorstest.Clean())
	e := tier2test.Engine(t, "engine", func(p string) string {
		if strings.HasPrefix(p, "def add") {
			return " " + tier2test.CanaryText
		}
		return tier2test.Echo(p)
	})
	useHelper(t, tier2test.Canary, e.URL)
	d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, tier2test.CanaryCheck)
	if r.Status != report.StatusFail || !strings.Contains(r.Evidence, tier2test.CanaryText) || r.Severity != report.SeverityHigh {
		t.Fatalf("row %+v", r)
	}
	if d.PromotionAuthorization.State != report.StateWithheld || len(report.Validate(d)) != 0 {
		t.Fatalf("state %s, problems %v", d.PromotionAuthorization.State, report.Validate(d))
	}
}

// A helper that fails leaves Tier 2 not run, says why, and changes nothing
// else: Tier 2 can only withhold, so its absence is not a gap.
func TestTier2HelperFailureIsNotAGap(t *testing.T) {
	supplyInputs(t, safetensorstest.Clean())
	e := tier2test.Engine(t, "engine", tier2test.Echo)
	useHelper(t, tier2test.UnknownField, e.URL)
	d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
	if err != nil {
		t.Fatal(err)
	}
	if d.Tier2 != nil || d.PromotionAuthorization.State != report.StateAuthorized || len(report.Validate(d)) != 0 {
		t.Fatalf("tier2 %+v, state %s, problems %v", d.Tier2, d.PromotionAuthorization.State, report.Validate(d))
	}
	for _, c := range d.OutOfScope.NotRun {
		if !strings.Contains(c.Reason, "configured (SOCAIR_TIER2_HELPER) but did not run") || !strings.Contains(c.Reason, `unknown field "verdict"`) {
			t.Errorf("not-run reason %q must say why Tier 2 did not run", c.Reason)
		}
	}
	if d.AssuranceLevel.Tier2Note != report.Tier1Assurance().Tier2Note || d.BoundedStatement != report.BoundedStatementNoIndicators {
		t.Errorf("a report whose Tier 2 did not run must not say it did: %q / %q", d.AssuranceLevel.Tier2Note, d.BoundedStatement)
	}
}

func TestTier2ConfigurationErrorStopsTheScan(t *testing.T) {
	noTier2(t)
	t.Setenv("SOCAIR_TIER2_ENDPOINT", "http://127.0.0.1:8000")
	if _, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean())); err == nil || !strings.Contains(err.Error(), "SOCAIR_TIER2_HELPER") {
		t.Fatalf("an endpoint with no helper must stop the scan, got %v", err)
	}
}

// A header-only sweep attests nothing, so it runs no Tier 2.
func TestTier2NotRunInHeaderMode(t *testing.T) {
	e := tier2test.Engine(t, "engine", tier2test.Echo)
	useHelper(t, tier2test.Differential, e.URL)
	d, err := ScanMode(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()), ModeHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if d.Tier2 != nil || e.Calls.Load() != 0 {
		t.Fatal("a header-only sweep must not run Tier 2")
	}
}

// The node class the operator declares reaches the report as the helper's
// account of it, and a changed field is a different class. A directory scan
// hands the helper its snapshot root.
func TestTier2NodeClassFollowsTheDeclaration(t *testing.T) {
	e := tier2test.Engine(t, "vllm", tier2test.Echo)
	dir := modelRepo(t, nil)
	scan := func(driver string) *report.Document {
		nc := filepath.Join(t.TempDir(), "node-class.json")
		if err := os.WriteFile(nc, []byte(`{"gpu_model":"NVIDIA B200","gpu_count":8,"driver":"`+driver+`","cuda_graphs":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		useHelper(t, tier2test.Differential, e.URL)
		t.Setenv("SOCAIR_TIER2_NODE_CLASS", nc)
		d, err := Scan(dir)
		if err != nil {
			t.Fatal(err)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Fatalf("should validate: %v", problems)
		}
		return d
	}
	a, b := scan("570.86.15"), scan("575.51.03")
	nc := a.Tier2.NodeClasses[0]
	if nc.Facts.GPUModel != "NVIDIA B200" || nc.Facts.EngineName != "vllm" || nc.ReportedBy != report.NodeClassReportedByHelper {
		t.Fatalf("node class %+v", nc)
	}
	if nc.Hash == b.Tier2.NodeClasses[0].Hash || a.OutOfScope.UntestedNodeClasses[0] == b.OutOfScope.UntestedNodeClasses[0] {
		t.Fatal("a different driver must be a different node class")
	}
	if !strings.Contains(a.Scope.ExecutionContext, report.ShortHash(nc.Hash)) || !strings.Contains(a.Scope.InferenceBudget, "Tier 2: 1 measurement(s)") {
		t.Errorf("scope %+v", a.Scope)
	}
	if notes := a.Tier2.Measurements[0].Notes; !strings.Contains(notes, "model directory") || !strings.Contains(notes, "readable=true") {
		t.Errorf("the helper's request: %s", notes)
	}
}

// Opt-in: SOCAIR_TEST_PROBE_HELPER=<tools/socair-probe/socair-probe> runs the
// real Python helper against a fake engine, end to end.
func TestRealProbeHelper(t *testing.T) {
	helper := os.Getenv("SOCAIR_TEST_PROBE_HELPER")
	if helper == "" {
		t.Skip("set SOCAIR_TEST_PROBE_HELPER to the socair-probe helper to run this")
	}
	supplyInputs(t, safetensorstest.Clean())
	noTier2(t)
	e := tier2test.Engine(t, "fake-engine", tier2test.Echo)
	t.Setenv("SOCAIR_TIER2_HELPER", helper)
	t.Setenv("SOCAIR_TIER2_ENDPOINT", e.URL)
	d, err := Scan(writeFixture(t, "fixture.safetensors", safetensorstest.Clean()))
	if err != nil {
		t.Fatal(err)
	}
	if d.Tier2 == nil {
		t.Fatalf("Tier 2 did not run: %+v", d.OutOfScope.NotRun)
	}
	if problems := report.Validate(d); len(problems) != 0 || e.Calls.Load() == 0 {
		t.Fatalf("problems %v, %d completions", problems, e.Calls.Load())
	}
	if m := d.Tier2.Measurements[0]; m.Outcome != report.OutcomeMeasured || *m.Score != 1 || d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("measurement %+v, state %s", m, d.PromotionAuthorization.State)
	}
	if err := signAndVerify(t, d); err != nil {
		t.Fatal(err)
	}
}
