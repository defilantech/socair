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
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription text   `json:"shortDescription"`
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
		rules = append(rules, rule{
			ID:               ruleID(c.Name),
			Name:             c.Name,
			ShortDescription: text{Text: c.LooksFor},
		})

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
