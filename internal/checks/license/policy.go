package license

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
)

const (
	resultName = "License policy"
	looksFor   = "The license the artifact states, against the operator's allowed list (SOCAIR_LICENSE_POLICY)"
)

// Policy is the operator's list of allowed licenses.
type Policy struct {
	Path    string
	allowed map[string]bool
}

// LoadPolicy reads a policy file: one license per line, by catalogue id, SPDX
// id, or model-card tag; "#" starts a comment. A name the catalogue does not
// know refuses the whole policy, as does a policy that allows nothing: a
// misspelled id would otherwise fail every model with evidence that misleads.
func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p := &Policy{Path: path, allowed: map[string]bool{}}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		e, ok := Lookup(name)
		if !ok {
			return nil, fmt.Errorf("%s line %d: %q is not a license the catalogue knows (docs/provenance-bundle.md lists the ids)", path, n, name)
		}
		p.allowed[e.ID] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(p.allowed) == 0 {
		return nil, fmt.Errorf("%s allows no license", path)
	}
	return p, nil
}

// Allowed returns the allowed catalogue ids, sorted.
func (p *Policy) Allowed() []string {
	out := make([]string, 0, len(p.allowed))
	for id := range p.allowed {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Describe names the policy for the report's reference data.
func (p *Policy) Describe() string {
	return fmt.Sprintf("license policy %s (%d allowed: %s)", p.Path, len(p.allowed), strings.Join(p.Allowed(), ", "))
}

// Check grades an identification against the policy. FAIL needs the
// artifact's statements to agree on one license the policy does not allow.
// Statements that name different licenses, one of them not allowed, are a
// LEAD: which one governs needs a person. No identified license, or an
// allowed one beside a statement the catalogue cannot read, is NOT_TESTED.
func (p *Policy) Check(id Identification) checks.Result {
	r := checks.Result{Name: resultName, LooksFor: looksFor}
	var notAllowed []string
	for _, x := range id.Identified() {
		if !p.allowed[x] {
			notAllowed = append(notAllowed, x)
		}
	}
	unread := id.Unrecognized()
	switch {
	case id.Disagreement != "" && len(notAllowed) > 0:
		r.Status = checks.Lead
		for _, x := range notAllowed {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "license-disagreement", Span: strings.Join(id.sources(x), "; "),
				Detail: "not on the allowed list: " + Name(x) + ", " + x})
		}
		r.Notes = sentence(id.Disagreement) + " " + plural(len(notAllowed), "One is", "Some are") + " not on the allowed list in " + p.Path +
			", so which license governs the artifact needs a person's review."
	case id.ID != "" && !p.allowed[id.ID]:
		r.Status = checks.Fail
		r.Findings = []checks.Finding{{Pattern: "license-not-allowed", Span: strings.Join(id.sources(id.ID), "; "),
			Detail: "not on the allowed list: " + id.Name + ", " + id.ID}}
		r.Notes = "The artifact states " + id.Name + " (" + id.ID + "), which the allowed list in " + p.Path + " does not include."
	case id.ID == "" && id.Disagreement == "":
		r.Status = checks.NotTested
		r.Notes = "No license could be identified, so the policy could not be checked: " + unidentified(id) + "."
	case len(unread) > 0:
		r.Status = checks.NotTested
		var parts []string
		for _, c := range unread {
			parts = append(parts, c.Source+" (\""+c.Value+"\") "+c.Note)
		}
		r.Notes = "What was identified is on the allowed list, but " + strings.Join(parts, "; ") +
			", so the license the artifact carries is not established."
	case id.Disagreement != "":
		r.Status = checks.Pass
		r.Notes = sentence(id.Disagreement) + " Each is on the allowed list in " + p.Path + "."
	default:
		r.Status = checks.Pass
		r.Notes = id.Name + " (" + id.ID + "), stated by " + strings.Join(id.sources(id.ID), "; ") + ", is on the allowed list in " + p.Path + "."
	}
	if obl := id.Obligations(); len(obl) > 0 {
		r.Notes += " Usage-policy obligations, listed and not checked: " + strings.Join(obl, ". ") + "."
	}
	return r
}

// unidentified says why nothing was identified.
func unidentified(id Identification) string {
	if len(id.Claims) == 0 {
		return "nothing in the artifact states a license"
	}
	var parts []string
	for _, c := range id.Claims {
		switch {
		case c.Kind == Inherited:
			parts = append(parts, c.Source+" is released under "+Name(c.ID)+", which is not a statement of this artifact's license")
		case c.Note != "":
			parts = append(parts, c.Source+" \""+c.Value+"\" "+c.Note)
		}
	}
	return strings.Join(parts, "; ")
}

func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
