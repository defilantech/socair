package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/gguf"
)

func loadGolden(t *testing.T) (*Document, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report.json"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	var d Document
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	return &d, raw
}

func TestGoldenValidates(t *testing.T) {
	d, _ := loadGolden(t)
	if problems := Validate(d); len(problems) != 0 {
		t.Fatalf("golden has validation problems: %v", problems)
	}
	// The golden is hand-written, so it is held to the fixed wording here.
	if d.AssuranceLevel != Tier1Assurance() {
		t.Errorf("golden assurance level %+v is not the fixed Tier 1 wording", d.AssuranceLevel)
	}
}

// TestGoldenMatchesSchemaRequired checks the golden carries every top-level key
// the published schema marks required, without pulling a schema library.
func TestGoldenMatchesSchemaRequired(t *testing.T) {
	d, raw := loadGolden(t)
	_ = d

	schemaRaw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema", "v1.json"))
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}
	var schema struct {
		Required []string `json:"required"`
		ID       string   `json:"$id"`
	}
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if schema.ID == "" {
		t.Error("schema has no $id")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("golden is not valid JSON: %v", err)
	}
	for _, key := range schema.Required {
		if _, ok := doc[key]; !ok {
			t.Errorf("golden is missing schema-required key %q", key)
		}
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	d, _ := loadGolden(t)
	a, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("marshaling the same document twice produced different bytes")
	}
}

// TestValidateCatchesRemovedRequiredField is the A2a falsification: removing a
// required field must fail validation, not render silently.
func TestValidateCatchesRemovedRequiredField(t *testing.T) {
	d, _ := loadGolden(t)
	d.Header.DocumentID = ""
	problems := Validate(d)
	if len(problems) == 0 {
		t.Fatal("blanking header.document_id must fail validation, but it passed")
	}
	found := false
	for _, p := range problems {
		if p == "missing: header.document_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a header.document_id problem, got %v", problems)
	}
}

func TestValidateCatchesAlteredBoundedStatement(t *testing.T) {
	d, _ := loadGolden(t)
	d.BoundedStatement = "This attestation certifies the model is free of malicious code."
	if len(Validate(d)) == 0 {
		t.Fatal("replacing the bounded statement with an absence claim must fail validation")
	}
}

// TestBoundedStatementFollowsTheRows: one fixed sentence was printed on every
// report, so a report with a FAIL said its checks "found no indicators". The
// sentence is now picked from the rows. Falsification: return the
// no-indicators sentence whatever the rows say and this fails.
func TestBoundedStatementFollowsTheRows(t *testing.T) {
	rows := func(ss ...Status) []CheckResult {
		var out []CheckResult
		for i, s := range ss {
			out = append(out, CheckResult{Name: fmt.Sprintf("c%d", i), Status: s})
		}
		return out
	}
	for _, c := range []struct {
		rows []CheckResult
		want string
	}{
		{rows(StatusPass), BoundedStatementNoIndicators},
		{rows(StatusPass, StatusNotTested), BoundedStatementNoIndicators},
		{rows(StatusNotTested), BoundedStatementNoIndicators},
		{rows(StatusPass, StatusFail), BoundedStatementIndicators},
		{rows(StatusNotTested, StatusLead), BoundedStatementIndicators},
		{rows(StatusFail, StatusLead, StatusNotTested), BoundedStatementIndicators},
	} {
		if got := BoundedStatementFor(c.rows); got != c.want {
			t.Errorf("%v: got %q, want %q", c.rows, got, c.want)
		}
	}
	if strings.Contains(BoundedStatementIndicators, "found no indicators") {
		t.Error("the indicators sentence must not say no indicators were found")
	}
	if strings.Contains(BoundedStatementNoIndicators, "node class") || strings.Contains(BoundedStatementIndicators, "node class") {
		t.Error("Tier 1 runs on no node class; the bounded statement must not name one")
	}
}

// TestValidateBindsTheBoundedStatementToTheRows: Validate re-derives the
// sentence from the check rows, so the clean sentence over a FAIL or LEAD, or
// the indicators sentence over clean rows, is refused even though each is one
// of the fixed sentences. Falsification: accept either fixed sentence in
// Validate and a report claiming "no indicators" over a FAIL validates.
func TestValidateBindsTheBoundedStatementToTheRows(t *testing.T) {
	boundedProblem := func(problems []string) bool {
		for _, p := range problems {
			if strings.Contains(p, "bounded_statement") {
				return true
			}
		}
		return false
	}
	for _, s := range []Status{StatusFail, StatusLead} {
		d, _ := loadGolden(t)
		d.Checks[0].Status = s
		d.BoundedStatement = BoundedStatementNoIndicators
		if !boundedProblem(Validate(d)) {
			t.Errorf("the no-indicators sentence over a %s row must fail validation", s)
		}
		d.BoundedStatement = BoundedStatementIndicators
		if problems := Validate(d); boundedProblem(problems) {
			t.Errorf("the indicators sentence over a %s row should validate, got %v", s, problems)
		}
	}
	d, _ := loadGolden(t)
	d.BoundedStatement = BoundedStatementIndicators
	if !boundedProblem(Validate(d)) {
		t.Error("the indicators sentence over rows with no FAIL or LEAD must fail validation")
	}
}

func TestPromotionStateRules(t *testing.T) {
	t.Run("unknown state", func(t *testing.T) {
		d, _ := loadGolden(t)
		d.PromotionAuthorization.State = "bogus"
		if len(Validate(d)) == 0 {
			t.Fatal("an unknown promotion state must fail validation")
		}
	})
	t.Run("authorized bool must agree with state", func(t *testing.T) {
		d, _ := loadGolden(t)
		d.PromotionAuthorization.State = StateAuthorized
		d.PromotionAuthorization.Authorized = false
		if len(Validate(d)) == 0 {
			t.Fatal("a mismatched authorized bool must fail validation")
		}
	})
	t.Run("authorized must not carry accepted surfaces", func(t *testing.T) {
		d, _ := loadGolden(t)
		d.PromotionAuthorization.State = StateAuthorized
		d.PromotionAuthorization.Authorized = true
		d.PromotionAuthorization.AcceptedSurfaces = []string{"File inventory and payloads"}
		if len(Validate(d)) == 0 {
			t.Fatal("an authorized report with accepted surfaces must fail validation")
		}
	})
	// A withheld report used to carry its gaps as accepted_surfaces, which
	// every renderer printed as "Accepted, not tested" when nobody had
	// accepted anything. Only authorized_with_conditions accepts.
	// Falsification: refuse accepted_surfaces on authorized alone and the
	// withheld and escalated cases validate.
	t.Run("only conditions carry an acceptance", func(t *testing.T) {
		for _, state := range []string{StateWithheld, StateEscalated} {
			for field, set := range map[string]func(*PromotionAuthorization){
				"accepted_surfaces":  func(pa *PromotionAuthorization) { pa.AcceptedSurfaces = []string{"File inventory and payloads"} },
				"accepted_by":        func(pa *PromotionAuthorization) { pa.AcceptedBy = "ciso@example.com" },
				"accepted_at":        func(pa *PromotionAuthorization) { pa.AcceptedAt = "2026-09-29T00:00:00Z" },
				"acceptance_expires": func(pa *PromotionAuthorization) { pa.AcceptanceExpires = "2027-01-31T00:00:00Z" },
			} {
				d, _ := loadGolden(t)
				d.PromotionAuthorization.State = state
				if problems := Validate(d); len(problems) != 0 {
					t.Fatalf("the golden in state %s should validate before the edit, got %v", state, problems)
				}
				set(&d.PromotionAuthorization)
				if len(Validate(d)) == 0 {
					t.Errorf("a report in state %s carrying %s must fail validation", state, field)
				}
			}
		}
	})
	t.Run("conditions need a named acceptance", func(t *testing.T) {
		d, _ := loadGolden(t)
		d.PromotionAuthorization.State = StateAuthorizedWithConditions
		d.PromotionAuthorization.Authorized = true
		d.PromotionAuthorization.AcceptedSurfaces = d.Findings.NotTested
		d.PromotionAuthorization.AcceptedBy = ""
		if len(Validate(d)) == 0 {
			t.Fatal("authorized_with_conditions without accepted_by must fail validation")
		}
		d.PromotionAuthorization.AcceptedBy = "ciso@example.com"
		if len(Validate(d)) == 0 {
			t.Fatal("an acceptance with no expiry cannot be enforced and must fail validation")
		}
		d.PromotionAuthorization.AcceptanceExpires = "end of quarter"
		if len(Validate(d)) == 0 {
			t.Fatal("a free-text acceptance expiry must fail validation")
		}
		d.PromotionAuthorization.AcceptanceExpires = "2027-01-31T00:00:00Z"
		if problems := Validate(d); len(problems) != 0 {
			t.Fatalf("a named acceptance with an RFC 3339 expiry should validate, got %v", problems)
		}
	})
}

// TestPromotionStateBoundToChecks holds the promotion state to the check rows.
// The airlock trusts a validating document as its ticket, so a document whose
// state was edited to "authorized" over a FAIL or an unaccepted gap must not
// validate. Falsification: drop the binding in validatePromotion and a forged
// report crosses into the clean store.
func TestPromotionStateBoundToChecks(t *testing.T) {
	// setStatus keeps the bounded statement in step with the rows, so the
	// only thing wrong with each forged document is its promotion state.
	setStatus := func(d *Document, name string, s Status) {
		for i := range d.Checks {
			if d.Checks[i].Name == name {
				d.Checks[i].Status = s
				d.BoundedStatement = BoundedStatementFor(d.Checks)
				return
			}
		}
		t.Fatalf("golden has no check %q", name)
	}
	authorize := func(d *Document) {
		d.PromotionAuthorization.State = StateAuthorized
		d.PromotionAuthorization.Authorized = true
		d.PromotionAuthorization.AcceptedSurfaces = nil
	}

	t.Run("authorized over a FAIL", func(t *testing.T) {
		d, _ := loadGolden(t)
		setStatus(d, "File inventory and payloads", StatusPass)
		setStatus(d, "Hash, provenance, lineage", StatusPass)
		setStatus(d, "Format and structure", StatusFail)
		authorize(d)
		if len(Validate(d)) == 0 {
			t.Fatal("an authorized state over a FAIL row must fail validation")
		}
	})
	t.Run("authorized over a NOT_TESTED", func(t *testing.T) {
		d, _ := loadGolden(t)
		authorize(d)
		if len(Validate(d)) == 0 {
			t.Fatal("an authorized state over NOT_TESTED rows must fail validation")
		}
	})
	t.Run("authorized with no checks", func(t *testing.T) {
		d, _ := loadGolden(t)
		d.Checks = nil
		authorize(d)
		if len(Validate(d)) == 0 {
			t.Fatal("an authorized state with no check rows must fail validation")
		}
	})
	t.Run("conditions over a FAIL", func(t *testing.T) {
		d, _ := loadGolden(t)
		setStatus(d, "Format and structure", StatusFail)
		d.PromotionAuthorization.State = StateAuthorizedWithConditions
		d.PromotionAuthorization.Authorized = true
		d.PromotionAuthorization.AcceptedBy = "ciso@example.com"
		if len(Validate(d)) == 0 {
			t.Fatal("authorized_with_conditions over a FAIL must fail validation; no acceptance clears a FAIL")
		}
	})
	t.Run("conditions must accept every gap", func(t *testing.T) {
		d, _ := loadGolden(t)
		d.PromotionAuthorization.State = StateAuthorizedWithConditions
		d.PromotionAuthorization.Authorized = true
		d.PromotionAuthorization.AcceptedBy = "ciso@example.com"
		d.PromotionAuthorization.AcceptedSurfaces = []string{"File inventory and payloads"}
		if len(Validate(d)) == 0 {
			t.Fatal("an acceptance that omits a NOT_TESTED row must fail validation")
		}
	})
	t.Run("conditions over a LEAD", func(t *testing.T) {
		d, _ := loadGolden(t)
		setStatus(d, "Format and structure", StatusLead)
		d.PromotionAuthorization.State = StateAuthorizedWithConditions
		d.PromotionAuthorization.Authorized = true
		d.PromotionAuthorization.AcceptedBy = "ciso@example.com"
		d.PromotionAuthorization.AcceptedSurfaces = append(d.Findings.NotTested, "Format and structure")
		if len(Validate(d)) == 0 {
			t.Fatal("an acceptance over a LEAD must fail validation; no acceptance clears a LEAD")
		}
	})
	t.Run("all PASS authorizes", func(t *testing.T) {
		d, _ := loadGolden(t)
		setStatus(d, "File inventory and payloads", StatusPass)
		setStatus(d, "Hash, provenance, lineage", StatusPass)
		authorize(d)
		if problems := Validate(d); len(problems) != 0 {
			t.Fatalf("an all-PASS authorized report should validate, got %v", problems)
		}
	})
}

func TestNewFromManifest(t *testing.T) {
	ft := uint32(17)
	m := &gguf.Manifest{
		Name:      "Fixture Model",
		FileName:  "fixture-Q5_K_M.gguf",
		SHA256:    "0000000000000000000000000000000000000000000000000000000000000000",
		Format:    "GGUF",
		SizeBytes: 12345,
		Quant:     gguf.Quant{Declared: "Q5_K_M", FileType: &ft},
	}
	d := NewFromManifest(m)

	if len(d.Checks) != 0 {
		t.Fatalf("a seeded document runs no checks yet, got %d rows", len(d.Checks))
	}
	if d.BoundedStatement != BoundedStatementNoIndicators {
		t.Error("a seeded document has no FAIL or LEAD, so it carries the no-indicators sentence")
	}
	if d.Artifact.SHA256 != m.SHA256 {
		t.Error("artifact hash not carried into the report")
	}
	if d.PromotionAuthorization.State != StateWithheld {
		t.Errorf("a freshly seeded document must withhold promotion, got %q", d.PromotionAuthorization.State)
	}

	// The seeded document is not fileable: no document id, no issue date, and no
	// checks have run.
	if len(Validate(d)) == 0 {
		t.Error("a seeded document must not validate")
	}

	// Once the engine fills the header and the checks, it validates.
	d.Header.DocumentID = "SOCAIR-TEST-0001"
	d.Header.IssuedUTC = "2026-09-29T00:00:00Z"
	d.Checks = []CheckResult{{Name: "Format and structure", LooksFor: "x", Status: StatusPass}}
	if problems := Validate(d); len(problems) != 0 {
		t.Fatalf("a filled document should validate, got %v", problems)
	}
}
