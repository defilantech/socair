// Package cyclonedx emits a CycloneDX 1.6 ML-BOM from a report document.
//
// The BOM is derived from socair.report/v1 and adds nothing the report does
// not say. Its subject (metadata.component) is the model, and its one
// component is the file the report attested, by name, format, size, and
// SHA-256. The model carries its upstream origin when the report recorded one
// bound to that hash. Each check row travels as a property carrying its
// status, so a NOT_TESTED row reads NOT_TESTED in the BOM too and never as an
// absence of findings. The report itself is referenced by its document hash as
// the artifact's static-analysis report, and as its attestation once signed.
//
// Output is deterministic for a fixed document: the timestamp is the report's
// issue time and the serial number is derived from the document, not from the
// clock or a random source.
package cyclonedx

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/defilantech/socair/internal/report"
)

// SpecVersion is the CycloneDX version emitted.
const SpecVersion = "1.6"

// MediaType is the CycloneDX JSON media type for this version.
const MediaType = "application/vnd.cyclonedx+json; version=1.6"

type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

type metadata struct {
	Timestamp  string     `json:"timestamp,omitempty"`
	Tools      tools      `json:"tools"`
	Component  *component `json:"component,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type tools struct {
	Components []component `json:"components"`
}

type component struct {
	Type               string        `json:"type"`
	BOMRef             string        `json:"bom-ref,omitempty"`
	Name               string        `json:"name"`
	Version            string        `json:"version,omitempty"`
	Publisher          string        `json:"publisher,omitempty"`
	Description        string        `json:"description,omitempty"`
	Hashes             []hash        `json:"hashes,omitempty"`
	ExternalReferences []externalRef `json:"externalReferences,omitempty"`
	Properties         []property    `json:"properties,omitempty"`
	ModelCard          *modelCard    `json:"modelCard,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type externalRef struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
	Hashes  []hash `json:"hashes,omitempty"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type modelCard struct {
	ModelParameters *modelParameters `json:"modelParameters,omitempty"`
	Properties      []property       `json:"properties,omitempty"`
}

type modelParameters struct {
	ModelArchitecture string `json:"modelArchitecture,omitempty"`
}

var (
	slug  = regexp.MustCompile(`[^a-z0-9]+`)
	hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func checkKey(name string) string {
	return strings.Trim(slug.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// serial derives an RFC 4122 version 5 style UUID from the document, so the
// same report always yields the same BOM serial number.
func serial(d *report.Document) string {
	sum := sha256.Sum256([]byte("socair.report/v1\x00" + d.Header.DocumentID + "\x00" + d.Artifact.SHA256 + "\x00" + d.Header.IssuedUTC))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Render writes the BOM for d as JSON.
func Render(w io.Writer, d *report.Document) error {
	b, err := Build(d)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// Build returns the BOM for d. A document with no artifact hash (a header-only
// scan) describes no exact bytes, so it has no BOM.
func Build(d *report.Document) (any, error) {
	a := d.Artifact
	sha := strings.ToLower(a.SHA256)
	if !hex64.MatchString(sha) {
		return nil, fmt.Errorf("cyclonedx: the report has no artifact SHA-256 (a header-only scan), so there are no exact bytes to describe")
	}

	model := component{
		Type:      "machine-learning-model",
		BOMRef:    "model:" + sha,
		Name:      firstNonEmpty(a.Name, a.FileName),
		Version:   a.CommitSHA,
		Publisher: a.Publisher,
		Hashes:    []hash{{Alg: "SHA-256", Content: sha}},
	}
	props := []property{
		{"socair:file_name", a.FileName},
		{"socair:format", a.Format},
		{"socair:size_bytes", fmt.Sprint(a.SizeBytes)},
	}
	add := func(name, value string) {
		if value != "" {
			props = append(props, property{name, value})
		}
	}
	add("socair:split", a.Split)
	add("socair:quant_declared", a.QuantDeclared)
	add("socair:quant_observed", a.QuantObserved)
	add("socair:chat_template_sha256", a.ChatTemplateHash)
	add("socair:tokenizer_hash", a.TokenizerHash)
	add("socair:commit_or_tag", a.CommitOrTag)
	add("socair:publisher_signing_status", a.PublisherSigningState)
	model.Properties = props

	if a.RepoURL != "" {
		model.ExternalReferences = append(model.ExternalReferences, externalRef{
			Type: "vcs", URL: a.RepoURL, Comment: commitComment(a.CommitSHA),
		})
	}
	// The report is the artifact's static-analysis report. It is named by its
	// document id and, once signed, its document hash, which also identifies
	// the attestation that carries it.
	reportRef := externalRef{
		Type:    "static-analysis-report",
		URL:     "urn:socair:report:" + d.Header.DocumentID,
		Comment: "socair.report/v1, Tier 1 static; state " + d.PromotionAuthorization.State,
	}
	if h := d.Verification.DocumentHash; hex64.MatchString(h) {
		reportRef.Hashes = []hash{{Alg: "SHA-256", Content: h}}
		model.ExternalReferences = append(model.ExternalReferences, reportRef, externalRef{
			Type:    "attestation",
			URL:     "urn:socair:attestation:" + h,
			Comment: "in-toto Statement v1 in DSSE, predicate https://socair.ai/attestation/v1, signer key " + d.Verification.SignerKeyID,
			Hashes:  []hash{{Alg: "SHA-256", Content: h}},
		})
	} else {
		model.ExternalReferences = append(model.ExternalReferences, reportRef)
	}

	if a.Architecture != "" {
		model.ModelCard = &modelCard{ModelParameters: &modelParameters{ModelArchitecture: a.Architecture}}
	}

	// Results, every row with its status, so a gap is visible in the BOM.
	results := []property{
		{"socair:promotion_state", d.PromotionAuthorization.State},
		{"socair:assurance_level", d.Header.AssuranceLevelAwarded},
		{"socair:check_set_version", d.Scope.CheckSetVersion},
	}
	if pa := d.PromotionAuthorization; pa.State == report.StateAuthorizedWithConditions {
		results = append(results,
			property{"socair:accepted_by", pa.AcceptedBy},
			property{"socair:accepted_surfaces", strings.Join(pa.AcceptedSurfaces, "; ")})
		if pa.AcceptanceExpires != "" {
			results = append(results, property{"socair:acceptance_expires", pa.AcceptanceExpires})
		}
	}
	for _, c := range d.Checks {
		results = append(results, property{"socair:check:" + checkKey(c.Name), string(c.Status)})
	}
	results = append(results, property{"socair:does_not_certify", d.OutOfScope.DoesNotCertify})
	model.Properties = append(model.Properties, results...)

	return bom{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: serial(d),
		Version:      1,
		Metadata: metadata{
			Timestamp: d.Header.IssuedUTC,
			Tools: tools{Components: []component{{
				Type: "application", Name: "socair", Version: toolVersion(d.Scope.ToolVersions),
			}}},
			Component: &model,
		},
		Components: []component{{
			Type:   "file",
			BOMRef: "file:" + sha,
			Name:   a.FileName,
			Hashes: []hash{{Alg: "SHA-256", Content: sha}},
			Properties: []property{
				{"socair:format", a.Format},
				{"socair:size_bytes", fmt.Sprint(a.SizeBytes)},
			},
		}},
	}, nil
}

func commitComment(commit string) string {
	if commit == "" {
		return "revision not pinned to a commit"
	}
	return "commit " + commit
}

// toolVersion extracts the socair version from "socair <version>, ...".
func toolVersion(s string) string {
	for _, part := range strings.Split(s, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "socair "); ok {
			return v
		}
	}
	return ""
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
