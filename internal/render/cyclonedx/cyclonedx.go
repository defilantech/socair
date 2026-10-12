// Package cyclonedx emits a CycloneDX 1.6 ML-BOM from a report document, and
// signs it.
//
// The BOM is derived from socair.report/v1 and adds nothing the report does
// not say: a field the report does not know is left out, never filled with a
// guess. Its subject (metadata.component) is the model, and its components
// are the files the report attested, by name, size, and SHA-256: one for a
// single-file report, every file of a model directory, whose subject digest
// is then the manifest digest over them.
//
// The model carries its upstream origin when the report recorded one bound to
// that hash: a Package URL and version only for a huggingface.co repository at
// a pinned commit, and the hub account as supplier. Its license is the one the
// artifact states, by SPDX id where SPDX lists it; a report that identifies no
// license, or whose sources disagree, gives none. The base models the artifact
// declares are its pedigree, marked as claims. The tokenizer and chat-template
// hashes are model-card properties of the model's input.
//
// Each check row travels as a property carrying its status, so a NOT_TESTED
// row reads NOT_TESTED in the BOM too and never as an absence of findings. The
// framework entries each row addresses travel as CycloneDX Attestations
// (definitions.standards and declarations), which map requirements to claims
// without asserting conformance. The report itself is referenced by its
// document hash as the artifact's static-analysis report, and as its
// attestation once signed.
//
// Output is deterministic for a fixed document: the timestamp is the report's
// issue time and the serial number is derived from the document, not from the
// clock or a random source. The G7 "SBOM for AI: Minimum Elements" mapping is
// in docs/cyclonedx.md.
package cyclonedx

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks/license"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// SpecVersion is the CycloneDX version emitted.
const SpecVersion = "1.6"

// MediaType is the CycloneDX JSON media type for this version.
const MediaType = "application/vnd.cyclonedx+json; version=1.6"

type bom struct {
	BOMFormat    string        `json:"bomFormat"`
	SpecVersion  string        `json:"specVersion"`
	SerialNumber string        `json:"serialNumber"`
	Version      int           `json:"version"`
	Metadata     metadata      `json:"metadata"`
	Components   []component   `json:"components"`
	Dependencies []dependency  `json:"dependencies"`
	Compositions []composition `json:"compositions"`
	Declarations *declarations `json:"declarations,omitempty"`
	Definitions  *definitions  `json:"definitions,omitempty"`
}

type metadata struct {
	Timestamp  string      `json:"timestamp,omitempty"`
	Lifecycles []lifecycle `json:"lifecycles"`
	Tools      tools       `json:"tools"`
	Authors    []contact   `json:"authors"`
	Component  *component  `json:"component,omitempty"`
}

type lifecycle struct {
	Phase string `json:"phase"`
}

type contact struct {
	Name string `json:"name"`
}

type entity struct {
	Name string   `json:"name"`
	URL  []string `json:"url,omitempty"`
}

type tools struct {
	Components []component `json:"components"`
}

type component struct {
	Type               string          `json:"type"`
	BOMRef             string          `json:"bom-ref,omitempty"`
	Supplier           *entity         `json:"supplier,omitempty"`
	Publisher          string          `json:"publisher,omitempty"`
	Name               string          `json:"name"`
	Version            string          `json:"version,omitempty"`
	Hashes             []hash          `json:"hashes,omitempty"`
	Licenses           []licenseChoice `json:"licenses,omitempty"`
	Purl               string          `json:"purl,omitempty"`
	Pedigree           *pedigree       `json:"pedigree,omitempty"`
	ExternalReferences []externalRef   `json:"externalReferences,omitempty"`
	ModelCard          *modelCard      `json:"modelCard,omitempty"`
	Properties         []property      `json:"properties,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type licenseChoice struct {
	License licenseEntry `json:"license"`
}

// licenseEntry is a CycloneDX license: an SPDX id or a name, never both.
type licenseEntry struct {
	ID              string     `json:"id,omitempty"`
	Name            string     `json:"name,omitempty"`
	Acknowledgement string     `json:"acknowledgement"`
	Properties      []property `json:"properties,omitempty"`
}

type pedigree struct {
	Ancestors []component `json:"ancestors"`
	Notes     string      `json:"notes"`
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

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type composition struct {
	Aggregate    string   `json:"aggregate"`
	Assemblies   []string `json:"assemblies,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// definitions and declarations are CycloneDX Attestations (CDXA): the
// frameworks the checks address, as standards with requirements, and which
// check rows address each requirement.
type definitions struct {
	Standards []standard `json:"standards"`
}

type standard struct {
	BOMRef       string        `json:"bom-ref"`
	Name         string        `json:"name"`
	Version      string        `json:"version,omitempty"`
	Requirements []requirement `json:"requirements"`
}

type requirement struct {
	BOMRef     string `json:"bom-ref"`
	Identifier string `json:"identifier"`
	Text       string `json:"text,omitempty"`
}

type declarations struct {
	Attestations []cdxAttestation `json:"attestations"`
	Claims       []claim          `json:"claims"`
}

type cdxAttestation struct {
	Summary string     `json:"summary"`
	Map     []mapEntry `json:"map"`
}

type mapEntry struct {
	Requirement string   `json:"requirement"`
	Claims      []string `json:"claims"`
}

type claim struct {
	BOMRef    string `json:"bom-ref"`
	Target    string `json:"target"`
	Predicate string `json:"predicate"`
}

var (
	slug  = regexp.MustCompile(`[^a-z0-9]+`)
	hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// pinned is a git commit id, as the provenance check requires: 40 hex
	// (SHA-1) or 64 hex (SHA-256).
	pinned = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	// hubSegment is a Hugging Face account or repository name. Every
	// character it admits is unreserved in a Package URL, so a segment that
	// matches needs no percent-encoding.
	hubSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// spdxAfter16 holds SPDX ids the license catalogue uses that are newer than
// the SPDX license list the CycloneDX 1.6 schema bundles (3.23). A 1.6
// validator rejects them as license ids, so the license is given by name.
// TestEveryCatalogueLicenseValidates holds the catalogue to this list.
var spdxAfter16 = map[string]bool{"OpenMDW-1.0": true}

func checkKey(name string) string {
	return strings.Trim(slug.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// serial derives an RFC 4122 version 5 style UUID from the document, so the
// same report always yields the same BOM serial number, and a re-issued or
// signed report, whose document hash differs, a different one.
func serial(d *report.Document) string {
	sum := sha256.Sum256([]byte("socair.report/v1\x00" + d.Header.DocumentID + "\x00" + d.Artifact.SHA256 + "\x00" + d.Header.IssuedUTC + "\x00" + d.Verification.DocumentHash))
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
	modelRef := "model:" + sha
	commit := strings.ToLower(strings.TrimSpace(a.CommitSHA))
	if !pinned.MatchString(commit) {
		commit = ""
	}
	org, repo, onHub := hubRepo(a.RepoURL)

	model := component{
		Type:      "machine-learning-model",
		BOMRef:    modelRef,
		Publisher: a.Publisher,
		Name:      firstNonEmpty(a.Name, a.FileName),
		Version:   commit,
		Hashes:    []hash{{Alg: "SHA-256", Content: sha}},
		Licenses:  licenses(a.License),
		Pedigree:  ancestors(a.BaseModels),
		ModelCard: card(a),
	}
	// The hub account that published the repository supplied these bytes.
	// It is not necessarily who trained the model, so it is the supplier and
	// never the manufacturer.
	if onHub {
		model.Supplier = &entity{Name: org, URL: []string{"https://huggingface.co/" + org}}
		if commit != "" {
			model.Purl = "pkg:huggingface/" + org + "/" + repo + "@" + commit
		}
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
	add("socair:commit_or_tag", a.CommitOrTag)
	add("socair:publisher_signing_status", a.PublisherSigningState)
	if l := a.License; l != nil {
		for _, s := range l.Sources {
			v := s.Source + ": " + s.Value
			if s.ID != "" {
				v += " (" + s.ID + ")"
			}
			if s.Note != "" {
				v += "; " + s.Note
			}
			props = append(props, property{"socair:license_source", v})
		}
		add("socair:license_disagreement", l.Disagreement)
	}
	model.Properties = props

	if a.RepoURL != "" {
		if absoluteURL(a.RepoURL) {
			model.ExternalReferences = append(model.ExternalReferences, externalRef{
				Type: "vcs", URL: a.RepoURL, Comment: commitComment(commit),
			})
		} else {
			model.Properties = append(model.Properties, property{"socair:repo_url", a.RepoURL})
		}
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

	files := fileComponents(a, sha)
	fileRefs := make([]string, 0, len(files))
	for _, f := range files {
		fileRefs = append(fileRefs, f.BOMRef)
	}
	defs, decls := frameworks(d.Checks, modelRef)

	return bom{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: serial(d),
		Version:      1,
		Metadata: metadata{
			Timestamp: d.Header.IssuedUTC,
			// Socair reads a built artifact's bytes: post-build analysis.
			Lifecycles: []lifecycle{{Phase: "post-build"}},
			Tools: tools{Components: []component{{
				Type: "application", Name: "socair", Version: toolVersion(d.Scope.ToolVersions),
			}}},
			Authors:   []contact{{Name: author(d)}},
			Component: &model,
		},
		Components:   files,
		Dependencies: []dependency{{Ref: modelRef, DependsOn: fileRefs}},
		Compositions: []composition{
			{Aggregate: assembly(d), Assemblies: []string{modelRef}},
			// What the model needs beyond its own files (a runtime, an
			// adapter's base model) is not something the report inventories.
			{Aggregate: "unknown", Dependencies: []string{modelRef}},
		},
		Declarations: decls,
		Definitions:  defs,
	}, nil
}

// author is who stands behind the BOM: the report's issuer, whoever signed
// it. An unsigned report has none, and says so; no name is supplied for it.
func author(d *report.Document) string {
	if d.Issuer.SignedBy != "" {
		return d.Issuer.SignedBy
	}
	return report.Unissued
}

// hubRepo returns the account and repository a huggingface.co model
// repository URL names. Any other host, or a path that is not exactly
// account/repository, is not one: a mirror's URL does not say it serves the
// hub's repositories, and a dataset or Space is not a model.
func hubRepo(repoURL string) (org, name string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(repoURL))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "huggingface.co") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || !hubSegment.MatchString(parts[0]) || !hubSegment.MatchString(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// absoluteURL reports whether s can stand as an external reference URL: an
// absolute http(s) URL with no whitespace.
func absoluteURL(s string) bool {
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// licenses is the license the artifact states, as the report identifies it:
// by SPDX id when SPDX lists it, by name otherwise, and always declared, never
// concluded. A report that identifies no license, or whose statements
// disagree, gives none; the statements themselves travel as properties.
func licenses(l *report.License) []licenseChoice {
	if l == nil || l.ID == "" || l.Disagreement != "" {
		return nil
	}
	e := licenseEntry{Acknowledgement: "declared", Properties: []property{{"socair:license_id", l.ID}}}
	if c, ok := license.Lookup(l.ID); ok && c.SPDX != "" && !spdxAfter16[c.SPDX] {
		e.ID = c.SPDX
	} else {
		e.Name = firstNonEmpty(l.Name, l.ID)
	}
	return []licenseChoice{{e}}
}

// ancestors are the base models the artifact declares. They are claims, not
// verified lineage, and the pedigree says so.
func ancestors(bases []report.BaseModel) *pedigree {
	if len(bases) == 0 {
		return nil
	}
	p := &pedigree{Notes: "The base models the artifact declares, as it declares them; socair:declared_in names where. " +
		"They are claims, not verified lineage."}
	for _, b := range bases {
		c := component{Type: "machine-learning-model", Name: b.Name}
		if absoluteURL(b.URL) {
			c.ExternalReferences = []externalRef{{Type: "vcs", URL: b.URL}}
		}
		c.Properties = []property{{"socair:declared_in", b.Source}}
		if b.Repo != "" {
			c.Properties = append(c.Properties, property{"socair:declared_repo", b.Repo})
		}
		if b.Organization != "" {
			c.Properties = append(c.Properties, property{"socair:declared_organization", b.Organization})
		}
		p.Ancestors = append(p.Ancestors, c)
	}
	return p
}

// card is the model card: the architecture, the quantization labels, and the
// hashes of what prepares the model's input, the tokenizer and the chat
// template.
func card(a report.ArtifactIdentity) *modelCard {
	c := &modelCard{}
	if a.Architecture != "" {
		c.ModelParameters = &modelParameters{ModelArchitecture: a.Architecture}
	}
	for _, p := range []property{
		{"socair:quant_declared", a.QuantDeclared},
		{"socair:quant_observed", a.QuantObserved},
		{"socair:input:tokenizer_sha256", a.TokenizerHash},
		{"socair:input:chat_template_sha256", a.ChatTemplateHash},
	} {
		if p.Value != "" {
			c.Properties = append(c.Properties, p)
		}
	}
	if c.ModelParameters == nil && len(c.Properties) == 0 {
		return nil
	}
	return c
}

// assembly says how complete the list of the model's files is. A model
// directory's report lists every file it holds, so it is complete, unless the
// scan excluded an entry other than tool metadata (a symlinked directory, an
// unreadable or non-regular file). One part of a split file is incomplete. A
// single file may need files the report never saw, so it is unknown.
func assembly(d *report.Document) string {
	if len(d.Artifact.Files) == 0 {
		if d.Artifact.Split != "" {
			return "incomplete"
		}
		return "unknown"
	}
	for _, u := range d.OutOfScope.UnparsedFormats {
		p, _, excluded := strings.Cut(u, ": excluded (")
		if !excluded {
			continue
		}
		dir, isDir := strings.CutSuffix(p, "/")
		if _, tool := modeldir.Skipped(path.Base(dir)); !isDir || !tool {
			return "incomplete"
		}
	}
	return "complete"
}

// frameworks carries the framework entries each check row addresses as
// CycloneDX Attestations: each framework edition a standard whose
// requirements are the entries, each row a claim about the model carrying its
// status, and one attestation mapping each requirement to the rows that
// address it. It states no conformance or confidence: a mapping says what a
// check inspects, not that the model meets anything. Everything comes from
// the rows' maps_to, so a report keeps the editions it was mapped against.
func frameworks(rows []report.CheckResult, target string) (*definitions, *declarations) {
	type std struct{ name, version string }
	entries := map[std]map[string]string{} // edition -> entry id -> entry name
	claimsFor := map[string][]string{}     // requirement bom-ref -> claim bom-refs
	var claims []claim
	used := map[string]int{}
	for _, c := range rows {
		if len(c.MapsTo) == 0 {
			continue
		}
		ref := "claim:" + checkKey(c.Name)
		if used[ref]++; used[ref] > 1 {
			ref += fmt.Sprintf("-%d", used[ref])
		}
		pred := fmt.Sprintf("Check %q returned %s.", c.Name, c.Status)
		if l := strings.TrimRight(c.LooksFor, ". "); l != "" {
			pred += " It looks for: " + l + "."
		}
		claims = append(claims, claim{BOMRef: ref, Target: target, Predicate: pred})
		for _, m := range c.MapsTo {
			if m.Framework == "" || m.ID == "" {
				continue
			}
			s := std{m.Framework, m.Version}
			if entries[s] == nil {
				entries[s] = map[string]string{}
			}
			if _, ok := entries[s][m.ID]; !ok {
				entries[s][m.ID] = m.Name
			}
			r := requirementRef(s.name, s.version, m.ID)
			if n := len(claimsFor[r]); n == 0 || claimsFor[r][n-1] != ref {
				claimsFor[r] = append(claimsFor[r], ref)
			}
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}

	stds := make([]std, 0, len(entries))
	for s := range entries {
		stds = append(stds, s)
	}
	sort.Slice(stds, func(i, j int) bool {
		if stds[i].name != stds[j].name {
			return stds[i].name < stds[j].name
		}
		return stds[i].version < stds[j].version
	})
	defs := &definitions{}
	att := cdxAttestation{Summary: "Which check rows address each framework entry, as the report maps them. " +
		"A mapping names what a check inspects; it states no conformance and no confidence. Each claim carries its row's status."}
	for _, s := range stds {
		ids := make([]string, 0, len(entries[s]))
		for id := range entries[s] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		st := standard{BOMRef: "standard:" + standardKey(s.name, s.version), Name: s.name, Version: s.version}
		for _, id := range ids {
			r := requirementRef(s.name, s.version, id)
			st.Requirements = append(st.Requirements, requirement{BOMRef: r, Identifier: id, Text: entries[s][id]})
			att.Map = append(att.Map, mapEntry{Requirement: r, Claims: claimsFor[r]})
		}
		defs.Standards = append(defs.Standards, st)
	}
	return defs, &declarations{Attestations: []cdxAttestation{att}, Claims: claims}
}

func standardKey(framework, version string) string {
	if version == "" {
		return checkKey(framework)
	}
	return checkKey(framework) + "-" + checkKey(version)
}

func requirementRef(framework, version, id string) string {
	return "requirement:" + standardKey(framework, version) + ":" + id
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

// fileComponents lists the attested files: the one file of a single-file
// report, or every file of a model directory, each with its own hash and role.
func fileComponents(a report.ArtifactIdentity, sha string) []component {
	if len(a.Files) == 0 {
		return []component{{
			Type:   "file",
			BOMRef: "file:" + sha,
			Name:   a.FileName,
			Hashes: []hash{{Alg: "SHA-256", Content: sha}},
			Properties: []property{
				{"socair:format", a.Format},
				{"socair:size_bytes", fmt.Sprint(a.SizeBytes)},
			},
		}}
	}
	out := make([]component, 0, len(a.Files))
	for _, f := range a.Files {
		out = append(out, component{
			Type:   "file",
			BOMRef: "file:" + f.Path,
			Name:   f.Path,
			Hashes: []hash{{Alg: "SHA-256", Content: f.SHA256}},
			Properties: []property{
				{"socair:role", f.Role},
				{"socair:size_bytes", fmt.Sprint(f.SizeBytes)},
			},
		})
	}
	return out
}
