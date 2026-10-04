// Package sarif emits a SARIF 2.1.0 log from a report document.
//
// One run, one result per check. The level mapping is deliberate: a FAIL is an
// error, a LEAD is a warning (a suspicious signal for escalation), a
// NOT_TESTED is a note (we did not look; it is not a finding), and a PASS is
// none.
package sarif

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/defilantech/socair/internal/report"
)

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool       tool              `json:"tool"`
	Results    []result          `json:"results"`
	Properties map[string]string `json:"properties,omitempty"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription text            `json:"shortDescription"`
	Properties       *ruleProperties `json:"properties,omitempty"`
}

// ruleProperties carries what code-scanning tools read from a rule: tags,
// including the framework entries the check addresses, and the numeric
// security-severity of a FAIL or LEAD (GitHub's 0.1 to 10 scale).
type ruleProperties struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

// securitySeverity maps a row severity onto the CVSS-like scale code-scanning
// tools sort by: critical 9.0+, high 7.0+, medium 4.0+, low below.
var securitySeverity = map[string]string{
	report.SeverityCritical: "9.5",
	report.SeverityHigh:     "8.0",
	report.SeverityMedium:   "5.5",
	report.SeverityLow:      "3.0",
}

// tags names a check's framework entries as external/<framework>/<id>.
func tags(c report.CheckResult) []string {
	if len(c.MapsTo) == 0 {
		return nil
	}
	out := []string{"security"}
	for _, m := range c.MapsTo {
		fw := "atlas"
		if strings.HasPrefix(m.Framework, "OWASP") {
			fw = "owasp-llm"
		}
		out = append(out, "external/"+fw+"/"+m.ID)
	}
	return out
}

type text struct {
	Text string `json:"text"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   text       `json:"message"`
	Locations []location `json:"locations,omitempty"`
}

type location struct {
	PhysicalLocation physical `json:"physicalLocation"`
}

type physical struct {
	ArtifactLocation artifact `json:"artifactLocation"`
}

type artifact struct {
	URI string `json:"uri"`
}

var slug = regexp.MustCompile(`[^a-z0-9]+`)

func ruleID(name string) string {
	s := strings.ToLower(name)
	s = slug.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// level maps a check status to a SARIF level.
func level(s report.Status) string {
	switch s {
	case report.StatusFail:
		return "error"
	case report.StatusLead:
		return "warning"
	case report.StatusNotTested:
		return "note"
	default:
		return "none"
	}
}

// Build assembles the SARIF log for a document.
func Build(d *report.Document) log {
	rules := make([]rule, 0, len(d.Checks))
	results := make([]result, 0, len(d.Checks))

	for _, c := range d.Checks {
		r := rule{
			ID:               ruleID(c.Name),
			Name:             c.Name,
			ShortDescription: text{Text: c.LooksFor},
		}
		if t, sev := tags(c), securitySeverity[c.Severity]; t != nil || sev != "" {
			r.Properties = &ruleProperties{Tags: t, SecuritySeverity: sev}
		}
		rules = append(rules, r)

		msg := string(c.Status)
		if c.Evidence != "" {
			msg += ": " + c.Evidence
		} else if c.Notes != "" {
			msg += ": " + c.Notes
		}
		res := result{
			RuleID:  ruleID(c.Name),
			Level:   level(c.Status),
			Message: text{Text: msg},
		}
		if d.Artifact.FileName != "" {
			res.Locations = []location{{
				PhysicalLocation: physical{
					ArtifactLocation: artifact{URI: d.Artifact.FileName},
				},
			}}
		}
		results = append(results, res)
	}

	return log{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "Socair",
				InformationURI: "https://socair.ai",
				Rules:          rules,
			}},
			Results: results,
			Properties: map[string]string{
				"socairPromotionState": d.PromotionAuthorization.State,
				"socairArtifactSHA256": d.Artifact.SHA256,
			},
		}},
	}
}

// Render writes the SARIF log for d to w.
func Render(w io.Writer, d *report.Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(Build(d))
}
