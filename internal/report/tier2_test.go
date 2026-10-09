package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func boolp(b bool) *bool        { return &b }
func f64p(f float64) *float64   { return &f }
func int64p(i int64) *int64     { return &i }
func digest(fill string) string { return "sha256:" + strings.Repeat(fill, 32) }

func sampleNodeClass() NodeClass {
	return NodeClass{
		Schema: NodeClassSchema, GPUModel: "NVIDIA H100 80GB HBM3", ComputeCapability: "9.0", GPUCount: 8,
		Interconnect: "NVLink 4 via NVSwitch", Driver: "570.86.15", VBIOS: "96.00.99.00.01", ECC: boolp(true), MIG: "disabled", CCMode: "off",
		CUDA: "12.8", CuBLAS: "12.8.4.1", CuDNN: "9.7.1", NCCL: "2.25.1",
		ContainerImageDigest: digest("ab"), EngineName: "vllm", EngineVersion: "0.11.0", EngineCommit: "0123456789abcdef0123456789abcdef01234567",
		DType: "bfloat16", WeightQuantization: "fp8", KVCacheQuantization: "fp8_e4m3",
		TensorParallelSize: 8, PipelineParallelSize: 1, ExpertParallelSize: 1, AttentionBackend: "FLASH_ATTN",
		CUDAGraphs: boolp(true), TorchCompile: boolp(true), Eager: boolp(false), BatchInvariant: boolp(false),
		PrefixCaching: boolp(true), ChunkedPrefill: boolp(true), SpeculativeDecoding: "off",
		Env: map[string]string{"CUBLAS_WORKSPACE_CONFIG": ":4096:8"},
	}
}

func sampleMeasurement(check, outcome string) Measurement {
	m := Measurement{
		Check: check, Suite: "socair/quant-diff", SuiteVersion: "0.1.0", DatasetDigest: digest("cd"),
		Scorer: ScorerDeterministic, N: 64, Score: f64p(0.97), CI95: []float64{0.89, 0.99},
		Decoding: Decoding{Temperature: 0, TopP: 1, MaxTokens: 32, Seed: int64p(0)},
		Engine:   "vllm 0.11.0", NodeClass: sampleNodeClass().Hash(),
		StartedUTC: "2026-10-09T10:00:00Z", EndedUTC: "2026-10-09T10:05:00Z", Outcome: outcome,
	}
	if outcome == OutcomeFail {
		m.Evidence = "probe 12: continuation matched the canary"
	}
	return m
}

const quantCheck = "Quantization differential (Tier 2)"

// tier2Doc is the golden with every Tier 1 row PASS, so the Tier 2 rows alone
// decide promotion, and a Tier 2 section filled the way the engine fills it.
func tier2Doc(t *testing.T, ms ...Measurement) *Document {
	t.Helper()
	d, _ := loadGolden(t)
	for i := range d.Checks {
		d.Checks[i].Status = StatusPass
	}
	d.OutOfScope.NotRun = Tier2NotRun()
	nc := sampleNodeClass()
	d.RecordTier2(&Tier2{
		Statement:    Tier2Statement,
		Helper:       "fake-helper 1.0",
		NodeClasses:  []NodeClassRecord{{Hash: nc.Hash(), ReportedBy: NodeClassReportedByHelper, Facts: nc}},
		Measurements: ms,
	})
	d.Checks = append(d.Checks, Tier2Rows(d.Tier2)...)
	settle(d)
	return d
}

// settle re-derives what follows from the rows, as the engine does: the
// bounded statement, and a state that is authorized only over all-PASS rows.
func settle(d *Document) {
	d.BoundedStatement = BoundedStatementOf(d)
	pass := true
	for _, c := range d.Checks {
		pass = pass && c.Status == StatusPass
	}
	d.PromotionAuthorization = PromotionAuthorization{State: StateWithheld, Level: "Tier 1 only"}
	if pass {
		d.PromotionAuthorization = PromotionAuthorization{State: StateAuthorized, Authorized: true, Level: "Tier 1 only"}
	}
}

func hasProblem(problems []string, part string) bool {
	for _, p := range problems {
		if strings.Contains(p, part) {
			return true
		}
	}
	return false
}

func rowOf(d *Document, name string) *CheckResult {
	for i := range d.Checks {
		if d.Checks[i].Name == name {
			return &d.Checks[i]
		}
	}
	return nil
}

// TestNodeClassHashIsTheDocumentedCanonicalForm pins the canonical form, so a
// third party (or LLMKube) can recompute a node-class hash from docs/tier2.md
// alone: every field, keys sorted, no whitespace, no HTML escaping.
func TestNodeClassHashIsTheDocumentedCanonicalForm(t *testing.T) {
	n := NodeClass{Schema: NodeClassSchema, GPUModel: "H100 <SXM>", GPUCount: 8, ECC: boolp(true), Env: map[string]string{"Z": "1", "A": "2"}}
	want := `{"attention_backend":"","batch_invariant":null,"cc_mode":"","chunked_prefill":null,"compute_capability":"",` +
		`"container_image_digest":"","cublas":"","cuda":"","cuda_graphs":null,"cudnn":"","driver":"","dtype":"","eager":null,` +
		`"ecc":true,"engine_commit":"","engine_name":"","engine_version":"","env":{"A":"2","Z":"1"},"expert_parallel_size":0,` +
		`"gpu_count":8,"gpu_model":"H100 <SXM>","interconnect":"","kv_cache_quantization":"","mig":"","nccl":"",` +
		`"pipeline_parallel_size":0,"prefix_caching":null,"schema":"socair.nodeclass/v1","speculative_decoding":"",` +
		`"tensor_parallel_size":0,"torch_compile":null,"vbios":"","weight_quantization":""}`
	if got := string(n.Canonical()); got != want {
		t.Fatalf("canonical form\n got %s\nwant %s", got, want)
	}
	sum := sha256.Sum256([]byte(want))
	if got := n.Hash(); got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("hash %s is not sha256 over the canonical form", got)
	}
}

// TestEveryNodeClassFieldMovesTheHash: any difference in any field is a
// different node class. It walks the struct, so a field added later is
// covered too. Falsification: leave any field out of Canonical (or give it
// omitempty) and this names it.
func TestEveryNodeClassFieldMovesTheHash(t *testing.T) {
	base := sampleNodeClass()
	typ := reflect.TypeOf(base)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		changed := sampleNodeClass()
		f := reflect.ValueOf(&changed).Elem().Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString(f.String() + "x")
		case reflect.Int:
			f.SetInt(f.Int() + 1)
		case reflect.Pointer:
			f.Set(reflect.ValueOf(boolp(!f.Elem().Bool())))
		case reflect.Map:
			f.SetMapIndex(reflect.ValueOf("VLLM_ATTENTION_BACKEND"), reflect.ValueOf("XFORMERS"))
		default:
			t.Fatalf("field %s has kind %s; teach this test to change it", name, f.Kind())
		}
		if changed.Hash() == base.Hash() {
			t.Errorf("changing %s does not change the node-class hash", name)
		}
	}
}

// An unreported switch is unknown, not off, so the two are different classes;
// a missing env and an empty one are the same.
func TestNodeClassUnknownIsNotOff(t *testing.T) {
	unknown, off := sampleNodeClass(), sampleNodeClass()
	unknown.CUDAGraphs, off.CUDAGraphs = nil, boolp(false)
	if unknown.Hash() == off.Hash() {
		t.Error("cuda_graphs unknown and cuda_graphs off hash the same")
	}
	a, b := sampleNodeClass(), sampleNodeClass()
	a.Env, b.Env = nil, map[string]string{}
	if a.Hash() != b.Hash() {
		t.Error("a missing env and an empty env must be the same class")
	}
}

func TestNodeClassFactsNameTheUnreported(t *testing.T) {
	n := NodeClass{Schema: NodeClassSchema, GPUModel: "H100", Eager: boolp(false)}
	reported, unreported := n.Facts()
	if !reflect.DeepEqual(reported, []Fact{{"gpu_model", "H100"}, {"eager", "false"}}) {
		t.Errorf("reported %v", reported)
	}
	if len(unreported) != reflect.TypeOf(n).NumField()-3 || unreported[0] != "compute_capability" {
		t.Errorf("unreported %v", unreported)
	}
}

// TestTier2LeadWithholdsAndValidates is the acceptance: an advisory LEAD
// withholds promotion through its row, and the document validates.
func TestTier2LeadWithholdsAndValidates(t *testing.T) {
	d := tier2Doc(t, sampleMeasurement(quantCheck, OutcomeLead))
	if problems := Validate(d); len(problems) != 0 {
		t.Fatalf("a Tier 2 LEAD report should validate, got %v", problems)
	}
	r := rowOf(d, quantCheck)
	if r == nil || r.Status != StatusLead || r.Severity != SeverityMedium {
		t.Fatalf("the LEAD measurement must raise a LEAD row, got %+v", r)
	}
	if d.PromotionAuthorization.State != StateWithheld || d.BoundedStatement != BoundedStatementTier2Indicators {
		t.Fatalf("state %s, statement %q", d.PromotionAuthorization.State, d.BoundedStatement)
	}
}

// TestTier2NothingFoundAddsNoRow: a measurement that found nothing, or did
// not complete, adds no row. Promotion is what the Tier 1 rows decide: here
// authorized, because they all PASS, and a gap stays a gap.
func TestTier2NothingFoundAddsNoRow(t *testing.T) {
	for _, outcome := range []string{OutcomeMeasured, OutcomeError} {
		d := tier2Doc(t, sampleMeasurement(quantCheck, outcome))
		if rowOf(d, quantCheck) != nil || len(Tier2Rows(d.Tier2)) != 0 {
			t.Fatalf("%s: a measurement that raised nothing must add no row", outcome)
		}
		if problems := Validate(d); len(problems) != 0 {
			t.Fatalf("%s: should validate, got %v", outcome, problems)
		}
		if d.BoundedStatement != BoundedStatementTier2NoIndicators {
			t.Errorf("%s: statement %q", outcome, d.BoundedStatement)
		}
	}

	d := tier2Doc(t, sampleMeasurement(quantCheck, OutcomeMeasured))
	d.Checks[1].Status = StatusNotTested
	settle(d)
	if d.PromotionAuthorization.State != StateWithheld {
		t.Fatal("a Tier 1 gap must still withhold beside a measurement that found nothing")
	}
	d.PromotionAuthorization = PromotionAuthorization{State: StateAuthorized, Authorized: true}
	if !hasProblem(Validate(d), "NOT_TESTED row") {
		t.Fatal("a measurement that found nothing must not clear a NOT_TESTED gap")
	}
}

// TestTier2RowCannotBePassOrGap is the issue's falsification: edit an
// advisory row's result to PASS (or to a gap someone could accept) and it
// cannot move promotion, because the document no longer validates.
// Falsification: drop the LEAD-or-FAIL rule in validateTier2 and the
// problem it names disappears.
func TestTier2RowCannotBePassOrGap(t *testing.T) {
	for _, s := range []Status{StatusPass, StatusNotTested} {
		d := tier2Doc(t, sampleMeasurement(quantCheck, OutcomeLead))
		rowOf(d, quantCheck).Status = s
		settle(d)
		problems := Validate(d)
		if !hasProblem(problems, "a Tier 2 row is only ever LEAD or FAIL") {
			t.Errorf("a Tier 2 row edited to %s must be refused, got %v", s, problems)
		}
	}
}

// TestTier2LeadWithoutItsRowIsRefused: removing the LEAD measurement's row
// would let the Tier 1 rows authorize; Validate refuses the document.
// Falsification: skip the "has no row" rule and this passes the forgery.
func TestTier2LeadWithoutItsRowIsRefused(t *testing.T) {
	for _, outcome := range []string{OutcomeLead, OutcomeFail} {
		d := tier2Doc(t, sampleMeasurement(quantCheck, outcome))
		d.Checks = d.Checks[:len(d.Checks)-1]
		settle(d)
		if d.PromotionAuthorization.State != StateAuthorized {
			t.Fatal("setup: without the row the Tier 1 rows authorize")
		}
		if !hasProblem(Validate(d), "but checks has no row for it") {
			t.Errorf("a %s measurement without its row must be refused", outcome)
		}
	}
}

// A Tier 2 row needs a measurement that raised it, with its status.
// Falsification: drop either binding and the matching case validates.
func TestTier2RowNeedsItsMeasurement(t *testing.T) {
	lead := CheckResult{Name: quantCheck, LooksFor: "x", Status: StatusLead}

	d, _ := loadGolden(t)
	d.Checks = append(d.Checks, lead)
	d.BoundedStatement = BoundedStatementOf(d)
	if !hasProblem(Validate(d), "has no tier2 section") {
		t.Error("a Tier 2 row in a report with no tier2 section must be refused")
	}

	d = tier2Doc(t, sampleMeasurement(quantCheck, OutcomeMeasured))
	d.Checks = append(d.Checks, lead)
	settle(d)
	if !hasProblem(Validate(d), "is not backed by a LEAD or FAIL measurement") {
		t.Error("a Tier 2 row over a measurement that found nothing must be refused")
	}

	d = tier2Doc(t, sampleMeasurement(quantCheck, OutcomeFail))
	rowOf(d, quantCheck).Status = StatusLead
	settle(d)
	if !hasProblem(Validate(d), "but its measurements raise FAIL") {
		t.Error("a FAIL measurement's row downgraded to LEAD must be refused")
	}
}

// A FAIL needs deterministic, matcher-confirmed evidence; a judge or a
// statistic raises at most a LEAD. Falsification: drop either rule.
func TestTier2FailNeedsDeterministicEvidence(t *testing.T) {
	judged := sampleMeasurement(quantCheck, OutcomeFail)
	judged.Scorer = ScorerLLMJudgePrefix + digest("ef")
	if !hasProblem(tier2Doc(t, judged).Tier2.Problems(), "needs a deterministic, matcher-confirmed scorer") {
		t.Error("a judged FAIL must be refused")
	}
	bare := sampleMeasurement(quantCheck, OutcomeFail)
	bare.Evidence = ""
	if !hasProblem(tier2Doc(t, bare).Tier2.Problems(), "a FAIL names the output it matched") {
		t.Error("a FAIL with no evidence must be refused")
	}
	judgedLead := sampleMeasurement(quantCheck, OutcomeLead)
	judgedLead.Scorer = ScorerLLMJudgePrefix + digest("ef")
	if problems := Validate(tier2Doc(t, judgedLead)); len(problems) != 0 {
		t.Errorf("a judged LEAD is allowed, got %v", problems)
	}
}

// Validate recomputes each node class's hash from its facts, so a record
// whose facts were edited no longer names its class. Falsification: trust
// the recorded hash and this validates.
func TestTier2NodeClassHashIsRecomputed(t *testing.T) {
	d := tier2Doc(t, sampleMeasurement(quantCheck, OutcomeMeasured))
	d.Tier2.NodeClasses[0].Facts.Driver = "550.54.15"
	if !hasProblem(Validate(d), "is not the hash") {
		t.Fatal("a node class whose facts do not hash to its hash must be refused")
	}
}

func TestTier2SectionIsWellFormed(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(*Tier2)
		want string
	}{
		"a pass outcome":       {func(s *Tier2) { s.Measurements[0].Outcome = "pass" }, `outcome "pass" is not one of`},
		"no suffix":            {func(s *Tier2) { s.Measurements[0].Check = "Quantization differential" }, "must name a Tier 2 check"},
		"bare suffix":          {func(s *Tier2) { s.Measurements[0].Check = Tier2Suffix }, "must name a Tier 2 check"},
		"dataset digest":       {func(s *Tier2) { s.Measurements[0].DatasetDigest = "abc" }, "dataset_digest"},
		"scorer":               {func(s *Tier2) { s.Measurements[0].Scorer = "llm-judge:gpt" }, "scorer"},
		"unknown node class":   {func(s *Tier2) { s.Measurements[0].NodeClass = digest("00") }, "is not one of tier2.node_classes"},
		"unknown reference":    {func(s *Tier2) { s.Measurements[0].ReferenceNodeClass = digest("00") }, "reference_node_class"},
		"ended before started": {func(s *Tier2) { s.Measurements[0].EndedUTC = "2026-10-09T09:00:00Z" }, "is before started_utc"},
		"not RFC 3339":         {func(s *Tier2) { s.Measurements[0].StartedUTC = "yesterday" }, "must be RFC 3339"},
		"inverted ci":          {func(s *Tier2) { s.Measurements[0].CI95 = []float64{0.9, 0.1} }, "ci95"},
		"top_p 0":              {func(s *Tier2) { s.Measurements[0].Decoding.TopP = 0 }, "decoding"},
		"no score":             {func(s *Tier2) { s.Measurements[0].Score = nil }, "neither a score nor metrics"},
		"no probes":            {func(s *Tier2) { s.Measurements[0].N = 0 }, "at least one probe"},
		"no engine":            {func(s *Tier2) { s.Measurements[0].Engine = "" }, "engine is empty"},
		"edited statement":     {func(s *Tier2) { s.Statement = "Tier 2 found the model safe." }, "fixed Tier 2 statement"},
		"no measurements":      {func(s *Tier2) { s.Measurements = nil }, "measurements is empty"},
		"self-observed claim":  {func(s *Tier2) { s.NodeClasses[0].ReportedBy = "observed by Socair" }, "reported_by"},
		"repeated node class":  {func(s *Tier2) { s.NodeClasses = append(s.NodeClasses, s.NodeClasses[0]) }, "repeats"},
		"wrong node schema":    {func(s *Tier2) { s.NodeClasses[0].Facts.Schema = "other/v9" }, "facts.schema"},
		"anonymous helper":     {func(s *Tier2) { s.Helper = " " }, "helper is empty"},
		"metrics without score": {func(s *Tier2) {
			s.Measurements[0].Score = nil
			s.Measurements[0].Metrics = map[string]float64{"kl": 0.01}
		}, ""},
	} {
		d := tier2Doc(t, sampleMeasurement(quantCheck, OutcomeMeasured))
		c.edit(d.Tier2)
		problems := d.Tier2.Problems()
		if c.want == "" {
			if len(problems) != 0 {
				t.Errorf("%s: should be well formed, got %v", name, problems)
			}
			continue
		}
		if !hasProblem(problems, c.want) {
			t.Errorf("%s: want a problem naming %q, got %v", name, c.want, problems)
		}
	}
}

// A check cannot be both measured and listed as not run, and the untested
// node classes are every class but the ones measured on.
func TestTier2OutOfScopeFollowsTheSection(t *testing.T) {
	d := tier2Doc(t, sampleMeasurement("Serving-stack differential (Tier 2)", OutcomeMeasured))
	for _, c := range d.OutOfScope.NotRun {
		if c.Name == "Serving-stack differential (Tier 2)" {
			t.Fatal("RecordTier2 must drop a measured check from not_run")
		}
		if c.Reason != Tier2NotMeasured {
			t.Errorf("not-run reason %q", c.Reason)
		}
	}
	if problems := Validate(d); len(problems) != 0 {
		t.Fatalf("should validate, got %v", problems)
	}
	if !strings.Contains(d.OutOfScope.UntestedNodeClasses[0], sampleNodeClass().Hash()) {
		t.Errorf("untested node classes %q must name the measured class", d.OutOfScope.UntestedNodeClasses)
	}

	d.OutOfScope.NotRun = append(d.OutOfScope.NotRun, NotRunCheck{Name: "Serving-stack differential (Tier 2)", LooksFor: "x", Reason: "y"})
	if !hasProblem(Validate(d), "which tier2 measured") {
		t.Error("a measured check listed as not run must be refused")
	}
	d = tier2Doc(t, sampleMeasurement(quantCheck, OutcomeMeasured))
	d.OutOfScope.UntestedNodeClasses = []string{Tier1UntestedNodeClasses}
	if !hasProblem(Validate(d), "untested_node_classes") {
		t.Error("a Tier 2 report claiming it ran on no hardware must be refused")
	}
	d = tier2Doc(t, sampleMeasurement(quantCheck, OutcomeMeasured))
	d.AssuranceLevel.Tier2Note = Tier1Assurance().Tier2Note
	if !hasProblem(Validate(d), "tier2_note") {
		t.Error("a Tier 2 report saying Tier 2 did not run must be refused")
	}
}

// The Tier 2 pair is picked only for a report with a Tier 2 section, and it
// never credits a Tier 2 indicator to the Tier 1 checks. Falsification:
// return the Tier 1 pair for every document and the first case fails.
func TestBoundedStatementOfTier2(t *testing.T) {
	d := tier2Doc(t, sampleMeasurement(quantCheck, OutcomeLead))
	if BoundedStatementOf(d) != BoundedStatementTier2Indicators {
		t.Error("a Tier 2 LEAD report takes the Tier 2 indicators sentence")
	}
	d.BoundedStatement = BoundedStatementIndicators
	if !hasProblem(Validate(d), "bounded_statement") {
		t.Error("the Tier 1 sentence over a Tier 2 report must be refused")
	}
	if strings.Contains(BoundedStatementTier2NoIndicators, "no model behavior was tested") ||
		strings.Contains(BoundedStatementTier2Indicators, "the Tier 1 checks found") {
		t.Error("the Tier 2 pair must not repeat the Tier 1 pair's claims")
	}
	g, _ := loadGolden(t)
	if BoundedStatementOf(g) != BoundedStatementFor(g.Checks) {
		t.Error("a Tier 1 report keeps the Tier 1 pair")
	}
}

// A report from a scan where Tier 2 did not run carries no tier2 key, so
// every Tier 1 report, and its document hash, is what it was.
func TestTier1ReportCarriesNoTier2Key(t *testing.T) {
	g, _ := loadGolden(t)
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"tier2"`) {
		t.Fatal("a report without Tier 2 must not carry a tier2 key")
	}
}
