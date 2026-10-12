package intake

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/provenance"
)

const (
	resultName = "Intake policy"
	looksFor   = "The artifact against your intake policy (SOCAIR_INTAKE_POLICY): allowed formats, publisher allow and deny lists, and publishers whose models need a verified signature"
)

// Facts are what the scan established about the artifact. The engine fills
// them from what it already read; nothing here comes from a file or
// directory name.
type Facts struct {
	// Files are the artifact's model files with the formats their bytes were
	// identified as: the file itself for a single-file scan (Identify), and
	// DirFiles for a model directory.
	Files []File
	// Manifest is a provenance manifest bound to the artifact's hash
	// (provenance.Bind), or nil; Unbound says why there is none.
	Manifest *provenance.Manifest
	Unbound  string
	// SignatureChecked is false for a header-only scan, which checks no
	// publisher signature.
	SignatureChecked bool
	// Signature is the verification of an OpenSSF Model Signing signature
	// over the artifact, or nil when there is none.
	Signature *provenance.Signature
}

// outcome collects what each rule found.
type outcome struct {
	findings []checks.Finding
	broken   []string
	gaps     []string
	held     []string
}

// maxFindings bounds the findings one rule lists; the rest are counted.
const maxFindings = 8

// Check checks the artifact against every rule the policy sets. A rule the
// artifact breaks is a FAIL with a finding that names the rule; a rule that
// cannot be evaluated is NOT_TESTED, with the reason; PASS needs every rule to
// hold and says what each was checked against. A rule the policy does not set
// is not checked.
func (p *Policy) Check(f Facts) checks.Result {
	var o outcome
	if p.formats != nil {
		p.checkFormats(f.Files, &o)
	}
	pub := publisherOf(f.Manifest, f.Unbound)
	if len(pub.names) == 0 {
		p.checkUnknownPublisher(pub, f, &o)
	} else {
		if p.denied != nil {
			p.checkDenied(pub, &o)
		}
		if p.allowed != nil {
			p.checkAllowed(pub, &o)
		}
		if p.signed != nil {
			p.checkSigned(pub, f, &o)
		}
	}

	r := checks.Result{Name: resultName, LooksFor: looksFor, Findings: o.findings}
	parts := []string{"Intake policy " + p.Name + " (sha256 " + p.SHA256[:12] + ")."}
	if len(pub.names) > 0 && (p.denied != nil || p.allowed != nil || p.signed != nil) {
		parts = append(parts, "Publisher: "+pub.String()+".")
	}
	switch {
	case len(o.findings) > 0:
		r.Status = checks.Fail
		parts = append(parts, "Broken: "+strings.Join(o.broken, "; ")+".")
	case len(o.gaps) > 0:
		r.Status = checks.NotTested
	default:
		r.Status = checks.Pass
		parts = append(parts, "Every rule it sets holds: "+strings.Join(o.held, "; ")+".")
	}
	if len(o.gaps) > 0 {
		parts = append(parts, "Not evaluated: "+strings.Join(o.gaps, "; ")+".")
	}
	if r.Status != checks.Pass && len(o.held) > 0 {
		parts = append(parts, "Held: "+strings.Join(o.held, "; ")+".")
	}
	r.Notes = strings.Join(parts, " ")
	return r
}

func (o *outcome) find(rule string, fs []checks.Finding, clause string) {
	if len(fs) > maxFindings {
		more := len(fs) - maxFindings
		fs = append(fs[:maxFindings:maxFindings], checks.Finding{Pattern: fs[0].Pattern, Span: fmt.Sprintf("and %d more", more)})
	}
	o.findings = append(o.findings, fs...)
	o.broken = append(o.broken, rule+": "+clause)
}

// checkFormats holds every model file to the allowed formats. A file in
// another format is positive evidence. A file whose bytes are none of the
// formats is evidence too when every allowed format has a fixed header; when
// one does not (pickle, numpy), whether the file is that format is not
// established.
func (p *Policy) checkFormats(files []File, o *outcome) {
	allowed := sorted(p.formats)
	rule := "allowed formats (" + strings.Join(allowed, ", ") + ")"
	if len(files) == 0 {
		o.gaps = append(o.gaps, rule+": the artifact holds no model file, so no format was checked")
		return
	}
	headerOnly := true
	for f := range p.formats {
		headerOnly = headerOnly && headerFormats[f]
	}
	var fs []checks.Finding
	var bad, unknown, ok []string
	for _, f := range files {
		switch {
		case f.Format != "" && p.formats[f.Format]:
			ok = append(ok, f.Path+" is "+f.Format)
		case f.Format != "":
			fs = append(fs, checks.Finding{Pattern: "format-not-allowed", Span: f.Path,
				Detail: f.Format + ", by its bytes: " + f.How + "; allowed: " + strings.Join(allowed, ", ")})
			bad = append(bad, f.Path+" is "+f.Format)
		case headerOnly:
			fs = append(fs, checks.Finding{Pattern: "format-not-allowed", Span: f.Path,
				Detail: f.How + ", so not " + orList(allowed)})
			bad = append(bad, f.Path+" is not "+orList(allowed))
		default:
			unknown = append(unknown, f.Path+" ("+f.How+")")
		}
	}
	if len(fs) > 0 {
		o.find(rule, fs, listed(bad))
	}
	if len(unknown) > 0 {
		o.gaps = append(o.gaps, rule+": the format of "+listed(unknown)+" was not identified, so whether it is allowed is not established")
	}
	if len(fs) == 0 && len(unknown) == 0 {
		o.held = append(o.held, rule+": "+listed(ok)+", identified from the bytes")
	}
}

// publisher is who the scan knows published the artifact.
type publisher struct {
	names []string // lowercase, distinct
	from  []string // where each name was read, parallel to names
	why   string   // why no name is known
}

func (p *publisher) add(name, from string) {
	for i, n := range p.names {
		if n == name {
			p.from[i] += " and " + from
			return
		}
	}
	p.names = append(p.names, name)
	p.from = append(p.from, from)
}

// list names the publisher, without where it was read.
func (p publisher) list() string { return strings.Join(p.names, " and ") }

// String names the publisher and where each name was read.
func (p publisher) String() string {
	var parts []string
	for i, n := range p.names {
		parts = append(parts, n+" ("+p.from[i]+")")
	}
	return strings.Join(parts, " and ")
}

// publisherOf reads the publisher from a manifest bound to the artifact: the
// organization of its hub repo URL, and its publisher field. Both are read,
// and each is held to the lists, so a manifest cannot name an allowed
// publisher beside a repo of another.
func publisherOf(m *provenance.Manifest, unbound string) publisher {
	if m == nil {
		if unbound == "" {
			unbound = "no provenance manifest supplied"
		}
		return publisher{why: unbound}
	}
	var p publisher
	if org := repoOrg(m.RepoURL); org != "" {
		p.add(org, "the organization in the bound provenance manifest's repo_url "+m.RepoURL)
	}
	if v := strings.ToLower(strings.TrimSpace(m.Publisher)); v != "" {
		from := "the bound provenance manifest's publisher field"
		if len(p.names) > 0 {
			from = "the manifest's publisher field"
		}
		p.add(v, from)
	}
	if len(p.names) == 0 {
		p.why = "the bound provenance manifest has no publisher field, and its repo_url"
		if m.RepoURL == "" {
			p.why += " is empty"
		} else {
			p.why += " (" + m.RepoURL + ") is not a hub repo URL, https://<hub>/<organization>/<name>"
		}
	}
	return p
}

// hubRepo matches a hub repo id, organization/name.
var hubRepo = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// repoOrg returns the organization of a hub repo URL whose path is exactly
// /<organization>/<name>, lowercased, or "".
func repoOrg(repoURL string) string {
	u, err := url.Parse(strings.TrimSpace(repoURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	path := strings.Trim(u.Path, "/")
	if !hubRepo.MatchString(path) {
		return ""
	}
	org, _, _ := strings.Cut(path, "/")
	return strings.ToLower(org)
}

func (p *Policy) deniedRule() string {
	return "denied publishers (" + strings.Join(sorted(p.denied), ", ") + ")"
}

func (p *Policy) allowedRule() string {
	return "allowed publishers (" + strings.Join(sorted(p.allowed), ", ") + ")"
}

func (p *Policy) signedRule() string {
	return "signature required for (" + strings.Join(sorted(p.signed), ", ") + ")"
}

// verified reports a publisher signature that verified against the
// operator's trust.
func verified(f Facts) bool {
	return f.SignatureChecked && f.Signature != nil && f.Signature.State == provenance.SignatureVerified
}

// checkUnknownPublisher grades the publisher rules when the scan does not
// know the publisher. None can be evaluated, except that a verified
// signature satisfies the signature rule whoever the publisher is.
func (p *Policy) checkUnknownPublisher(pub publisher, f Facts, o *outcome) {
	var rules []string
	if p.denied != nil {
		rules = append(rules, p.deniedRule())
	}
	if p.allowed != nil {
		rules = append(rules, p.allowedRule())
	}
	if p.signed != nil {
		if verified(f) {
			o.held = append(o.held, p.signedRule()+": a publisher signature verified ("+f.Signature.Format+", "+f.Signature.Signer+")")
		} else {
			rules = append(rules, p.signedRule())
		}
	}
	if len(rules) > 0 {
		o.gaps = append(o.gaps, strings.Join(rules, ", ")+": the publisher is not known ("+pub.why+")")
	}
}

func (p *Policy) checkDenied(pub publisher, o *outcome) {
	rule := p.deniedRule()
	var fs []checks.Finding
	var bad []string
	for i, n := range pub.names {
		if p.denied[n] {
			fs = append(fs, checks.Finding{Pattern: "publisher-denied", Span: pub.from[i], Detail: n + " is on the denied list"})
			bad = append(bad, n)
		}
	}
	if len(fs) > 0 {
		o.find(rule, fs, "the publisher is "+strings.Join(bad, " and "))
		return
	}
	o.held = append(o.held, rule+": "+pub.list()+" is not on it")
}

func (p *Policy) checkAllowed(pub publisher, o *outcome) {
	rule := p.allowedRule()
	var fs []checks.Finding
	var bad []string
	for i, n := range pub.names {
		if !p.allowed[n] {
			fs = append(fs, checks.Finding{Pattern: "publisher-not-allowed", Span: pub.from[i], Detail: n + " is not on the allowed list"})
			bad = append(bad, n)
		}
	}
	if len(fs) > 0 {
		o.find(rule, fs, "the publisher "+strings.Join(bad, " and ")+" is not on it")
		return
	}
	o.held = append(o.held, rule+": "+pub.list()+" is on it")
}

// checkSigned requires a verified publisher signature of a listed publisher's
// models. A verified signature satisfies the rule whoever the publisher is. No
// signature, or one from a trusted signer that does not hold, breaks it. A
// signature that could not be verified (an untrusted or unsupported signer, or
// no keyless verifier configured) leaves it not established.
func (p *Policy) checkSigned(pub publisher, f Facts, o *outcome) {
	rule := p.signedRule()
	sig := f.Signature
	if verified(f) {
		o.held = append(o.held, rule+": a publisher signature verified ("+sig.Format+", "+sig.Signer+")")
		return
	}
	var need []string
	for _, n := range pub.names {
		if p.signed[n] {
			need = append(need, n)
		}
	}
	who := strings.Join(need, " and ")
	switch {
	case len(need) == 0:
		o.held = append(o.held, rule+": "+pub.list()+" is not on it")
	case !f.SignatureChecked:
		o.gaps = append(o.gaps, rule+": "+who+" needs a verified publisher signature, and a header-only scan checks none")
	case sig == nil:
		o.find(rule, []checks.Finding{{Pattern: "publisher-signature-required", Span: "publisher " + who,
			Detail: "no OpenSSF Model Signing signature over the artifact"}}, who+" needs a verified publisher signature, and the artifact carries none")
	case sig.State == provenance.SignatureInvalid:
		o.find(rule, []checks.Finding{{Pattern: "publisher-signature-required", Span: "publisher " + who,
			Detail: "the " + sig.Format + " signature does not hold: " + sig.Detail}}, who+" needs a verified publisher signature, and the artifact's does not hold")
	default:
		o.gaps = append(o.gaps, rule+": "+who+" needs a verified publisher signature, and the "+sig.Format+" signature present was not verified: "+sig.Detail)
	}
}

// listed names up to eight items and counts the rest.
func listed(items []string) string {
	if len(items) > maxFindings {
		return strings.Join(items[:maxFindings], ", ") + fmt.Sprintf(", and %d more", len(items)-maxFindings)
	}
	return strings.Join(items, ", ")
}

func orList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}
