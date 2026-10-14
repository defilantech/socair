// Package sarif emits a SARIF 2.1.0 log from a report document.
//
// One run, one result per check. The level mapping is deliberate: a FAIL is an
// error, a LEAD is a warning (a suspicious signal that needs review), a
// NOT_TESTED is a note (we did not look; it is not a finding), and a PASS is
// none, with kind "pass". Each result of a report that names its artifact's
// SHA-256 carries a fingerprint (Fingerprint), so a code-scanning tool tracks
// one finding across scans of the same bytes. docs/sarif.md says what each
// property holds.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strconv"
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
	RuleID              string            `json:"ruleId"`
	Kind                string            `json:"kind,omitempty"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
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

// kind is "pass" for a PASS. SARIF 2.1.0 reads an absent kind as "fail"
// (section 3.27.9), and level "none" means a kind other than "fail" (section
// 3.27.10), so a PASS without it reads as a failure with no severity. FAIL,
// LEAD, and NOT_TESTED keep the default, "fail", with their level as the
// severity. SARIF's kinds for an undecided result, "open" and "review", require
// level "none", and GitHub code scanning reads the level, not the kind, so a
// NOT_TESTED written that way could pass for a PASS there.
func kind(s report.Status) string {
	if s == report.StatusPass {
		return "pass"
	}
	return ""
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

// FingerprintKey names Socair's partial fingerprint. SARIF asks a producer to
// name a partial fingerprint for what it hashes and to version the name
// (section 3.27.17): a different computation gets a new version, and this one
// keeps its name.
const FingerprintKey = "socairFindingHash/v1"

// githubFingerprintKey is the one partial fingerprint GitHub code scanning
// reads. Its upload-sarif action computes one from a source line, which a
// model file or a directory does not have, and keeps a value already there.
const githubFingerprintKey = "primaryLocationLineHash"

// Fingerprint identifies a check row's finding on the artifact the document
// names. It is the SHA-256, in lower-case hex, of these values in order, each
// written as a netstring (its length in bytes in decimal, ":", the bytes,
// ","):
//
//	FingerprintKey
//	the artifact's SHA-256 as the document records it (for a model
//	directory, the digest of its manifest)
//	the row's name
//	the row's status
//	the row's evidence (each finding's pattern, span, and detail; empty for
//	a row without findings)
//
// Nothing else goes in: not the document id, the issue or scan times, the
// input path, the execution context, the tool or check-set version, the file
// name, the notes, the severity, or the framework mappings. So two scans of the same
// bytes that find the same thing give the same fingerprint, and a new revision
// of the model, another status, or other evidence gives a new one. A document
// without the artifact's SHA-256 (a header-only sweep) names no exact bytes
// and gets none: Fingerprint returns "".
func Fingerprint(d *report.Document, c report.CheckResult) string {
	if d.Artifact.SHA256 == "" {
		return ""
	}
	h := sha256.New()
	for _, v := range []string{FingerprintKey, d.Artifact.SHA256, c.Name, string(c.Status), c.Evidence} {
		h.Write([]byte(strconv.Itoa(len(v)) + ":" + v + ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fileURI writes a file name as a relative URI reference (RFC 3986, which
// SARIF 2.1.0 section 3.10.1 requires): spaces, reserved characters, and
// non-ASCII are percent-encoded, and a first segment holding a colon is
// preceded by "./" so it cannot read as a scheme.
func fileURI(name string) string {
	return (&url.URL{Path: name}).String()
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
			Kind:    kind(c.Status),
			Level:   level(c.Status),
			Message: text{Text: msg},
		}
		if d.Artifact.FileName != "" {
			res.Locations = []location{{
				PhysicalLocation: physical{
					ArtifactLocation: artifact{URI: fileURI(d.Artifact.FileName)},
				},
			}}
		}
		if fp := Fingerprint(d, c); fp != "" {
			res.PartialFingerprints = map[string]string{FingerprintKey: fp, githubFingerprintKey: fp}
		}
		results = append(results, res)
	}

	props := map[string]string{
		"socairPromotionState": d.PromotionAuthorization.State,
		"socairArtifactSHA256": d.Artifact.SHA256,
	}
	// The editions the external/ tags' IDs are from, as the document names
	// them.
	if e := report.FrameworkEditions(d.Checks); len(e) > 0 {
		props["socairFrameworkEditions"] = strings.Join(e, ", ")
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
			Results:    results,
			Properties: props,
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
