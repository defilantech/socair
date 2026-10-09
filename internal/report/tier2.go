package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tier 2 runs the model, on the site's own GPUs, through a probe helper
// (internal/tier2, docs/tier2.md). What it produces is a measurement, never a
// verdict: a measurement can raise a LEAD, or a FAIL on deterministic,
// matcher-confirmed evidence, and either reaches promotion only through an
// ordinary check row (Tier2Rows), which withholds it. A measurement that
// found nothing adds no row, so it cannot authorize a model, clear a gap, or
// move promotion at all. Validate enforces this.

// Tier2Suffix ends the name of every check that runs the model, so a Tier 2
// row is recognisable wherever a report is read, including by verifiers that
// know nothing of the Tier 2 section.
const Tier2Suffix = " (Tier 2)"

// IsTier2Check reports whether a check name is a Tier 2 check.
func IsTier2Check(name string) bool {
	return strings.HasSuffix(name, Tier2Suffix) && strings.TrimSpace(strings.TrimSuffix(name, Tier2Suffix)) != ""
}

// Measurement outcomes. There is no pass: "measured" means the measurement
// completed and raised nothing, which is not evidence of absence.
const (
	OutcomeMeasured = "measured"
	OutcomeLead     = "lead"
	OutcomeFail     = "fail"
	OutcomeError    = "error"
)

// Scorers. A deterministic scorer matches outputs by rule; an LLM judge is a
// model, named by its digest, and can raise at most a LEAD.
const (
	ScorerDeterministic  = "deterministic"
	ScorerLLMJudgePrefix = "llm-judge:"
)

// Tier2Statement is the fixed account of what a Tier 2 section is. Like the
// bounded statement it is not edited per artifact.
const Tier2Statement = "Tier 2 measurements ran the model through the endpoints the operator named, on the node classes listed here as the probe helper reported them; " +
	"Socair did not observe the hardware or verify that an endpoint served the bytes identified by the artifact hash. " +
	"A measurement is not a verdict: a LEAD or FAIL it raises is a check row and withholds promotion, " +
	"and a measurement that found nothing adds no row, is not a PASS, and authorizes nothing."

// Tier2RanNote is the assurance section's Tier 2 note when Tier 2 ran. No
// Tier 2 level is awarded: a measurement can only withhold.
const Tier2RanNote = "Tier 2 measurements ran (see Tier 2 measurements). They can withhold promotion through the LEAD or FAIL rows they raise, " +
	"but never authorize it, and no Tier 2 level is awarded."

// Tier2NotMeasured is the not-run reason of a Tier 2 check the helper did not
// measure when Tier 2 ran.
const Tier2NotMeasured = "Tier 2 ran, but the probe helper returned no measurement for this check"

// NodeClassSchema names the canonical node-class record (NodeClass.Canonical).
const NodeClassSchema = "socair.nodeclass/v1"

// NodeClassReportedByHelper labels a node class whose facts came from the
// probe helper. Socair records them; it does not observe the hardware.
const NodeClassReportedByHelper = "probe helper (not observed by Socair)"

// Tier2 is the report section for measurements made by running the model. It
// is absent when Tier 2 did not run.
type Tier2 struct {
	// Statement is Tier2Statement.
	Statement string `json:"statement"`
	// Helper is the probe helper's name and version, as it reports them.
	Helper       string            `json:"helper"`
	NodeClasses  []NodeClassRecord `json:"node_classes"`
	Measurements []Measurement     `json:"measurements"`
}

// NodeClassRecord is one node class a measurement ran on, keyed by the hash
// of its facts and labelled with who stated them.
type NodeClassRecord struct {
	// Hash is Facts.Hash(); Validate recomputes it.
	Hash       string    `json:"hash"`
	ReportedBy string    `json:"reported_by"`
	Facts      NodeClass `json:"facts"`
}

// NodeClass is what decides a model's numerics on a node. Two nodes that
// differ in any field are different classes, because each can change the
// arithmetic the model runs, and a behavior measured on one is not measured
// on the other. An unreported text field is empty, an unreported count is 0,
// and an unreported switch is null (unknown, not off). No field is omitted
// from the canonical form, so the hash covers every one.
type NodeClass struct {
	Schema string `json:"schema"`

	GPUModel          string `json:"gpu_model"`
	ComputeCapability string `json:"compute_capability"`
	GPUCount          int    `json:"gpu_count"`
	// Interconnect is the links and topology, e.g. "NVLink 4 via NVSwitch".
	Interconnect string `json:"interconnect"`
	Driver       string `json:"driver"`
	VBIOS        string `json:"vbios"`
	ECC          *bool  `json:"ecc"`
	// MIG is "disabled" or the instance profile, e.g. "1g.10gb".
	MIG string `json:"mig"`
	// CCMode is the confidential-computing mode: "off", "on", or "devtools".
	CCMode string `json:"cc_mode"`

	CUDA   string `json:"cuda"`
	CuBLAS string `json:"cublas"`
	CuDNN  string `json:"cudnn"`
	NCCL   string `json:"nccl"`

	ContainerImageDigest string `json:"container_image_digest"`
	EngineName           string `json:"engine_name"`
	EngineVersion        string `json:"engine_version"`
	EngineCommit         string `json:"engine_commit"`

	DType                string `json:"dtype"`
	WeightQuantization   string `json:"weight_quantization"`
	KVCacheQuantization  string `json:"kv_cache_quantization"`
	TensorParallelSize   int    `json:"tensor_parallel_size"`
	PipelineParallelSize int    `json:"pipeline_parallel_size"`
	ExpertParallelSize   int    `json:"expert_parallel_size"`
	AttentionBackend     string `json:"attention_backend"`
	CUDAGraphs           *bool  `json:"cuda_graphs"`
	TorchCompile         *bool  `json:"torch_compile"`
	Eager                *bool  `json:"eager"`
	BatchInvariant       *bool  `json:"batch_invariant"`
	PrefixCaching        *bool  `json:"prefix_caching"`
	ChunkedPrefill       *bool  `json:"chunked_prefill"`
	// SpeculativeDecoding is "off", or the method and draft model.
	SpeculativeDecoding string `json:"speculative_decoding"`

	// Env holds the numerically relevant environment variables the engine
	// ran with (e.g. CUBLAS_WORKSPACE_CONFIG, VLLM_ATTENTION_BACKEND).
	Env map[string]string `json:"env"`
}

// Canonical is the node class's canonical JSON, the bytes Hash covers: every
// field present, object keys sorted (env included), no insignificant
// whitespace, and no HTML escaping. A missing env is written {}.
func (n NodeClass) Canonical() []byte {
	if n.Env == nil {
		n.Env = map[string]string{}
	}
	// Marshalling a struct of strings, ints, bools, and a string map cannot
	// fail; re-decoding into a map is what sorts the keys.
	b, _ := json.Marshal(n)
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	_ = dec.Decode(&m)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m)
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}

// Hash identifies a node class: sha256 over Canonical, written
// "sha256:<hex>". Any change to any field changes it.
func (n NodeClass) Hash() string {
	sum := sha256.Sum256(n.Canonical())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Fact is one reported node-class field, for display.
type Fact struct {
	Name  string
	Value string
}

// Facts lists the reported fields in record order, and names the fields that
// were not reported, so a reader sees how complete the class is.
func (n NodeClass) Facts() (reported []Fact, unreported []string) {
	v := reflect.ValueOf(n)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if name == "schema" {
			continue
		}
		val := ""
		switch f := v.Field(i); f.Kind() {
		case reflect.String:
			val = f.String()
		case reflect.Int:
			if f.Int() != 0 {
				val = strconv.FormatInt(f.Int(), 10)
			}
		case reflect.Pointer:
			if !f.IsNil() {
				val = strconv.FormatBool(f.Elem().Bool())
			}
		case reflect.Map:
			keys := make([]string, 0, f.Len())
			for _, k := range f.MapKeys() {
				keys = append(keys, k.String()+"="+f.MapIndex(k).String())
			}
			sort.Strings(keys)
			val = strings.Join(keys, ", ")
		}
		if val == "" {
			unreported = append(unreported, name)
			continue
		}
		reported = append(reported, Fact{Name: name, Value: val})
	}
	return reported, unreported
}

// Measurement is one Tier 2 measurement: what was run, how it was scored,
// where it ran, and what came out. It is never a pass or fail of the model.
type Measurement struct {
	// Check names the Tier 2 check measured; it ends in Tier2Suffix.
	Check         string `json:"check"`
	Suite         string `json:"suite"`
	SuiteVersion  string `json:"suite_version"`
	DatasetDigest string `json:"dataset_digest"`
	// Scorer is ScorerDeterministic or "llm-judge:sha256:<hex>".
	Scorer  string             `json:"scorer"`
	N       int                `json:"n"`
	Score   *float64           `json:"score,omitempty"`
	Metrics map[string]float64 `json:"metrics,omitempty"`
	// CI95 is the score's 95% confidence interval, [low, high].
	CI95     []float64 `json:"ci95,omitempty"`
	Decoding Decoding  `json:"decoding"`
	// Engine is the serving engine as the helper names it.
	Engine string `json:"engine"`
	// NodeClass is the hash of the class the model ran on; for a
	// differential, ReferenceNodeClass is the class it was compared with.
	NodeClass          string `json:"node_class"`
	ReferenceNodeClass string `json:"reference_node_class,omitempty"`
	StartedUTC         string `json:"started_utc"`
	EndedUTC           string `json:"ended_utc"`
	Outcome            string `json:"outcome"`
	// Evidence is the matched output behind a FAIL, which needs it.
	Evidence string `json:"evidence,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// Decoding is how the model was sampled for a measurement.
type Decoding struct {
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	MaxTokens   int     `json:"max_tokens"`
	Seed        *int64  `json:"seed,omitempty"`
}

// String states the decoding in one line.
func (dc Decoding) String() string {
	s := "temperature " + num(dc.Temperature) + ", top_p " + num(dc.TopP) + ", max_tokens " + strconv.Itoa(dc.MaxTokens)
	if dc.Seed != nil {
		s += ", seed " + strconv.FormatInt(*dc.Seed, 10)
	} else {
		s += ", no seed"
	}
	return s
}

// Summary states a measurement's numbers in one line, for renderers.
func (m Measurement) Summary() string {
	var parts []string
	if m.Score != nil {
		s := "score " + num(*m.Score)
		if len(m.CI95) == 2 {
			s += " (95% CI " + num(m.CI95[0]) + " to " + num(m.CI95[1]) + ")"
		}
		parts = append(parts, s)
	}
	parts = append(parts, "n="+strconv.Itoa(m.N))
	if len(m.Metrics) > 0 {
		keys := make([]string, 0, len(m.Metrics))
		for k := range m.Metrics {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+" "+num(m.Metrics[k]))
		}
	}
	return strings.Join(parts, ", ")
}

func num(f float64) string { return strconv.FormatFloat(f, 'g', 6, 64) }

// ShortHash abbreviates a "sha256:<hex>" digest for prose.
func ShortHash(h string) string {
	if digest, ok := strings.CutPrefix(h, "sha256:"); ok && len(digest) > 12 {
		return "sha256:" + digest[:12]
	}
	return h
}

// Tier2Rows are the check rows a Tier 2 section raises: one per check with a
// LEAD or FAIL measurement, FAIL when any of its measurements failed. A
// measurement that found nothing, or did not complete, raises no row, so it
// never reaches promotion and never clears a gap.
func Tier2Rows(t *Tier2) []CheckResult {
	if t == nil {
		return nil
	}
	var order []string
	rows := map[string]*CheckResult{}
	for _, m := range t.Measurements {
		var s Status
		switch m.Outcome {
		case OutcomeLead:
			s = StatusLead
		case OutcomeFail:
			s = StatusFail
		default:
			continue
		}
		r, ok := rows[m.Check]
		if !ok {
			r = &CheckResult{Name: m.Check, LooksFor: "A measurement made by running the model", Status: s}
			rows[m.Check] = r
			order = append(order, m.Check)
		}
		if s == StatusFail {
			r.Status = StatusFail
		}
		if m.Evidence != "" {
			r.Evidence = joinNonEmpty(r.Evidence, m.Evidence)
		}
		note := fmt.Sprintf("%s %s raised a %s (%s) on node class %s", m.Suite, m.SuiteVersion, strings.ToUpper(m.Outcome), m.Summary(), ShortHash(m.NodeClass))
		if m.Notes != "" {
			note += ": " + m.Notes
		}
		r.Notes = joinNonEmpty(r.Notes, note)
	}
	out := make([]CheckResult, 0, len(order))
	for _, name := range order {
		r := *rows[name]
		r.Severity = RowSeverity(r.Status, nil)
		out = append(out, r)
	}
	return out
}

func joinNonEmpty(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// Tier2UntestedNodeClasses is the node-class statement of a report whose
// Tier 2 section ran: every class but the ones its measurements ran on.
func Tier2UntestedNodeClasses(t *Tier2) string {
	var tested []string
	seen := map[string]bool{}
	for _, m := range t.Measurements {
		if !seen[m.NodeClass] {
			seen[m.NodeClass] = true
			tested = append(tested, m.NodeClass)
		}
	}
	return "every node class other than " + strings.Join(tested, ", ") +
		": Tier 1 is static, and Tier 2 measured only the node classes its measurements name; a change to any field of a node class makes a different class"
}

// RecordTier2 adds a Tier 2 section to a document and states what it
// changes: the Tier 2 note, the node classes still untested, the Tier 2
// checks still not run, and the execution context. Its rows (Tier2Rows) are
// added with the check rows, so the bounded statement, findings, and
// promotion are computed over both.
func (d *Document) RecordTier2(t *Tier2) {
	d.Tier2 = t
	d.AssuranceLevel.Tier2Note = Tier2RanNote
	d.OutOfScope.UntestedNodeClasses = []string{Tier2UntestedNodeClasses(t)}
	measured := map[string]bool{}
	n := 0
	for _, m := range t.Measurements {
		measured[m.Check] = true
		n += m.N
	}
	var notRun []NotRunCheck
	for _, c := range d.OutOfScope.NotRun {
		if measured[c.Name] {
			continue
		}
		if IsTier2Check(c.Name) {
			c.Reason = Tier2NotMeasured
		}
		notRun = append(notRun, c)
	}
	d.OutOfScope.NotRun = notRun
	var classes []string
	for _, c := range t.NodeClasses {
		classes = append(classes, ShortHash(c.Hash))
	}
	d.Scope.ExecutionContext = "Tier 1 static, portable; Tier 2 on node class " + strings.Join(classes, ", ") + ", as the probe helper reported it"
	d.Scope.InferenceBudget = fmt.Sprintf("Tier 2: %d measurement(s) over %d probe(s)", len(t.Measurements), n)
}

// Tier2DidNotRun states why a configured Tier 2 run produced nothing. It is
// not a gap: Tier 2 can only withhold, so its absence changes no promotion.
func (d *Document) Tier2DidNotRun(reason string) {
	for i, c := range d.OutOfScope.NotRun {
		if IsTier2Check(c.Name) {
			d.OutOfScope.NotRun[i].Reason = reason
		}
	}
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Problems reports what is wrong with a Tier 2 section on its own: fixed
// wording, node classes whose hash is not their facts', references that do
// not resolve, and measurements that are not well formed. A FAIL needs a
// deterministic scorer and the evidence it matched. Validate adds the rules
// that bind the section to the check rows.
func (t *Tier2) Problems() []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf("tier2."+format, args...)) }
	if t.Statement != Tier2Statement {
		add("statement must be the fixed Tier 2 statement")
	}
	if strings.TrimSpace(t.Helper) == "" {
		add("helper is empty")
	}
	if len(t.NodeClasses) == 0 {
		add("node_classes is empty")
	}
	if len(t.Measurements) == 0 {
		add("measurements is empty; a Tier 2 section records at least one")
	}
	classes := map[string]bool{}
	for i, c := range t.NodeClasses {
		if c.Facts.Schema != NodeClassSchema {
			add("node_classes[%d].facts.schema %q, want %q", i, c.Facts.Schema, NodeClassSchema)
		}
		if h := c.Facts.Hash(); c.Hash != h {
			add("node_classes[%d].hash %s is not the hash %s of its facts", i, c.Hash, h)
		}
		if c.ReportedBy != NodeClassReportedByHelper {
			add("node_classes[%d].reported_by %q, want %q", i, c.ReportedBy, NodeClassReportedByHelper)
		}
		if classes[c.Hash] {
			add("node_classes[%d] repeats %s", i, c.Hash)
		}
		classes[c.Hash] = true
	}
	for i, m := range t.Measurements {
		for _, p := range m.problems(classes) {
			add("measurements[%d] %s", i, p)
		}
	}
	return problems
}

func (m Measurement) problems(classes map[string]bool) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if !IsTier2Check(m.Check) {
		add("check %q must name a Tier 2 check, ending %q", m.Check, Tier2Suffix)
	}
	if strings.TrimSpace(m.Suite) == "" || strings.TrimSpace(m.SuiteVersion) == "" {
		add("needs a suite and a suite_version")
	}
	if !digestRE.MatchString(m.DatasetDigest) {
		add("dataset_digest %q is not sha256:<64 hex>", m.DatasetDigest)
	}
	judge, isJudge := strings.CutPrefix(m.Scorer, ScorerLLMJudgePrefix)
	if m.Scorer != ScorerDeterministic && !(isJudge && digestRE.MatchString(judge)) {
		add("scorer %q is not %q or %q", m.Scorer, ScorerDeterministic, ScorerLLMJudgePrefix+"sha256:<64 hex>")
	}
	switch m.Outcome {
	case OutcomeMeasured, OutcomeLead, OutcomeFail:
		if m.N < 1 {
			add("n is %d; a completed measurement scored at least one probe", m.N)
		}
		if m.Score == nil && len(m.Metrics) == 0 {
			add("has neither a score nor metrics")
		}
	case OutcomeError:
		if m.N < 0 {
			add("n is negative")
		}
	default:
		add("outcome %q is not one of measured, lead, fail, error", m.Outcome)
	}
	if m.Outcome == OutcomeFail {
		if m.Scorer != ScorerDeterministic {
			add("is a fail scored by %q; a FAIL needs a deterministic, matcher-confirmed scorer, and anything else raises at most a LEAD", m.Scorer)
		}
		if strings.TrimSpace(m.Evidence) == "" {
			add("is a fail with no evidence; a FAIL names the output it matched")
		}
	}
	if len(m.CI95) != 0 && (len(m.CI95) != 2 || m.CI95[0] > m.CI95[1]) {
		add("ci95 %v is not [low, high]", m.CI95)
	}
	if dc := m.Decoding; dc.Temperature < 0 || dc.TopP <= 0 || dc.TopP > 1 || dc.MaxTokens < 1 {
		add("decoding (%s) is out of range", dc)
	}
	if strings.TrimSpace(m.Engine) == "" {
		add("engine is empty")
	}
	if !classes[m.NodeClass] {
		add("node_class %q is not one of tier2.node_classes", m.NodeClass)
	}
	if m.ReferenceNodeClass != "" && !classes[m.ReferenceNodeClass] {
		add("reference_node_class %q is not one of tier2.node_classes", m.ReferenceNodeClass)
	}
	start, err1 := time.Parse(time.RFC3339, m.StartedUTC)
	end, err2 := time.Parse(time.RFC3339, m.EndedUTC)
	switch {
	case err1 != nil || err2 != nil:
		add("started_utc %q and ended_utc %q must be RFC 3339", m.StartedUTC, m.EndedUTC)
	case end.Before(start):
		add("ended_utc %s is before started_utc %s", m.EndedUTC, m.StartedUTC)
	}
	return problems
}

// validateTier2 binds the Tier 2 section to the check rows. A Tier 2 row is
// only ever LEAD or FAIL, and only when a measurement raised it; every LEAD or
// FAIL measurement has its row. So a measurement reaches promotion only
// through a row that withholds it, and validateStateAgainstChecks, which reads
// the rows, needs no Tier 2 rule of its own.
func validateTier2(d *Document) []string {
	var problems []string
	rows := map[string][]Status{}
	for i, c := range d.Checks {
		if !IsTier2Check(c.Name) {
			continue
		}
		rows[c.Name] = append(rows[c.Name], c.Status)
		if c.Status != StatusLead && c.Status != StatusFail {
			problems = append(problems, fmt.Sprintf(
				"checks[%d] %q is a Tier 2 row with status %s; a Tier 2 row is only ever LEAD or FAIL, because a measurement that found nothing adds no row", i, c.Name, c.Status))
		}
	}
	names := make([]string, 0, len(rows))
	for name := range rows {
		names = append(names, name)
	}
	sort.Strings(names)

	if d.Tier2 == nil {
		for _, name := range names {
			problems = append(problems, fmt.Sprintf("checks row %q is a Tier 2 row, but the report has no tier2 section with a measurement that raised it", name))
		}
		if d.AssuranceLevel.Tier2Note == Tier2RanNote {
			problems = append(problems, "assurance_level.tier2_note says Tier 2 ran, but the report has no tier2 section")
		}
		return problems
	}

	problems = append(problems, d.Tier2.Problems()...)
	want := map[string]Status{}
	for _, r := range Tier2Rows(d.Tier2) {
		want[r.Name] = r.Status
		switch got := rows[r.Name]; {
		case len(got) == 0:
			problems = append(problems, fmt.Sprintf(
				"tier2: a measurement of %q raised a %s, but checks has no row for it; a LEAD or FAIL measurement reaches promotion only through its row", r.Name, r.Status))
		case len(got) > 1:
			problems = append(problems, fmt.Sprintf("checks has %d rows named %q", len(got), r.Name))
		case got[0] != r.Status:
			problems = append(problems, fmt.Sprintf("checks row %q is %s, but its measurements raise %s", r.Name, got[0], r.Status))
		}
	}
	for _, name := range names {
		if _, ok := want[name]; !ok {
			problems = append(problems, fmt.Sprintf("checks row %q is not backed by a LEAD or FAIL measurement in tier2.measurements", name))
		}
	}
	measured := map[string]bool{}
	for _, m := range d.Tier2.Measurements {
		measured[m.Check] = true
	}
	for _, c := range d.OutOfScope.NotRun {
		if measured[c.Name] {
			problems = append(problems, fmt.Sprintf("out_of_scope.not_run names %q, which tier2 measured", c.Name))
		}
	}
	if want := Tier2UntestedNodeClasses(d.Tier2); len(d.OutOfScope.UntestedNodeClasses) != 1 || d.OutOfScope.UntestedNodeClasses[0] != want {
		problems = append(problems, "out_of_scope.untested_node_classes must name every class but the ones the Tier 2 measurements ran on (Tier2UntestedNodeClasses)")
	}
	if d.AssuranceLevel.Tier2Note != Tier2RanNote {
		problems = append(problems, "assurance_level.tier2_note must be the fixed note that Tier 2 ran")
	}
	return problems
}
