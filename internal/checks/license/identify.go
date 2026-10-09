// Package license identifies a model's license from what the artifact says
// about it, and checks the license against an operator's allowed list.
//
// Identification is identity, not a check: the report names the license, and
// every statement it read, in the artifact identity. A license is read from
// three places: the model card's front matter (license, license_name,
// license_link), the LICENSE files beside it, and a GGUF's general.license
// keys. A LICENSE file is identified by its text against a small catalogue
// (catalogue.go): by its whole text through a fingerprint, or by phrases a
// license's text alone carries. A text the catalogue does not hold is
// reported as unrecognized, with its first line, never guessed. When the
// statements name different licenses, the report says so.
//
// The License policy row runs only when the operator names a policy
// (SOCAIR_LICENSE_POLICY). It is not legal advice, and usage-policy
// obligations such as an acceptable-use policy are listed, never marked met.
package license

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxText bounds a LICENSE file read into memory. License texts are tens of
// kilobytes.
const MaxText = 1 << 20

// Kind is what a claim can establish.
type Kind int

const (
	// Stated is the artifact's own statement of its license: a model-card
	// value, a LICENSE file, a GGUF key.
	Stated Kind = iota
	// Pointer is a link, or a placeholder such as "other": read and listed,
	// never matched as a license.
	Pointer
	// Inherited is the license a declared base model's publisher releases it
	// under. It can disagree with a stated license; it never identifies the
	// artifact's own.
	Inherited
)

// Claim is one statement about the license, and where it was read.
type Claim struct {
	Kind   Kind
	Source string
	// Value is what the source said: a value, or a file's first line.
	Value string
	// ID is the catalogue entry it names, or "" when it names none.
	ID string
	// Note says why it names none, or what it is.
	Note string
}

// unrecognized reports whether a stated claim names no catalogue license.
func (c Claim) unrecognized() bool { return c.Kind == Stated && c.ID == "" }

// FromText identifies a LICENSE file's text.
func FromText(source string, text []byte) Claim {
	c := Claim{Kind: Stated, Source: source, Value: firstLine(text)}
	ws := words(string(text))
	joined := strings.Join(ws, " ")
	var hits []string
	for i := range catalogue {
		if textMatches(&catalogue[i], ws, joined) {
			hits = append(hits, catalogue[i].ID)
		}
	}
	switch len(hits) {
	case 1:
		c.ID = hits[0]
	case 0:
		c.Note = "not a license text the catalogue recognizes"
		for i := range catalogue {
			e := &catalogue[i]
			b, ok := bodies[e.ID]
			if !ok {
				continue
			}
			if f := b.fit(ws); f.near(b) {
				switch {
				case !f.titled(e):
					c.Note = "holds the " + e.Name + " text after other text (\"" + clip(strings.Join(f.preamble, " "), 80) + "\"), so it is not that license"
				case f.changed == "added":
					c.Note = "holds the " + e.Name + " text with other text added, so it is not that license"
				default:
					c.Note = "holds most of the " + e.Name + " text, with words added, removed, or changed, so it is not that license"
				}
				break
			}
		}
	default:
		c.Note = "matches more than one catalogue license (" + strings.Join(hits, ", ") + "), so it is not identified"
	}
	return c
}

// titled reports whether the text's preamble is at most a title for the
// license: no more than maxPreamble words, each from its name or SPDX id, or
// "the", "license", "version", "all rights reserved". Anything else before
// the license text could be a term of its own.
func (f bodyFit) titled(e *Entry) bool {
	if len(f.preamble) > maxPreamble {
		return false
	}
	ok := map[string]bool{"the": true, "license": true, "licence": true, "version": true, "all": true, "rights": true, "reserved": true}
	for _, w := range words(e.Name + " " + e.SPDX) {
		ok[w] = true
	}
	for _, w := range f.preamble {
		if !ok[w] {
			return false
		}
	}
	return true
}

func textMatches(e *Entry, ws []string, joined string) bool {
	if b, ok := bodies[e.ID]; ok {
		if f := b.fit(ws); f.matches() && f.titled(e) {
			return true
		}
	}
	for _, r := range e.Texts {
		if r.MaxWords > 0 && len(ws) > r.MaxWords {
			continue
		}
		all := true
		for _, p := range r.Phrases {
			all = all && hasPhrase(joined, p)
		}
		if all {
			return true
		}
	}
	return false
}

// Value claims name a license by a model-card or GGUF value.
func valueClaim(source, value string) Claim {
	c := Claim{Kind: Stated, Source: source, Value: value}
	v := strings.ToLower(strings.TrimSpace(value))
	if why, ok := placeholders[v]; ok {
		c.Kind, c.Note = Pointer, why
		return c
	}
	if e, ok := Lookup(v); ok {
		c.ID = e.ID
		return c
	}
	c.Note = "not a license name the catalogue recognizes"
	return c
}

// linkClaim reads a license link. A link to a known license's page names it;
// any other link is a pointer the scan does not follow.
func linkClaim(source, value string) Claim {
	if e, ok := byLink(value); ok {
		return Claim{Kind: Stated, Source: source, Value: value, ID: e.ID}
	}
	return Claim{Kind: Pointer, Source: source, Value: value, Note: "a link; the scan does not follow links"}
}

// nameClaim reads a license_name. Under license "other" it is a free-form
// label for a license outside Hugging Face's list, and the LICENSE file or
// link says which license it is, so a label the catalogue does not know is
// a pointer, not an unreadable statement.
func nameClaim(source, value string, other bool) Claim {
	c := valueClaim(source, value)
	if other && c.unrecognized() {
		c.Kind = Pointer
		c.Note = "a free-form name for an \"other\" license, which the catalogue does not know; the LICENSE file or link says which license it is"
	}
	return c
}

func hasOther(values ...string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), "other") {
			return true
		}
	}
	return false
}

// CodeLicense marks a LICENSE file that covers a repository's code, beside
// a file that covers the model (DeepSeek's LICENSE-CODE and LICENSE-MODEL):
// it is listed, and the model's license is read from the other file.
func CodeLicense(c Claim) Claim {
	note := "the license of the repository's code; a model license file beside it states the model's"
	if c.Note != "" {
		note += " (this text " + c.Note + ")"
	}
	c.Kind, c.Note = Pointer, note
	return c
}

// Claims returns what a model card says about the license.
func (c Card) Claims() []Claim {
	var out []Claim
	for _, v := range c.License {
		out = append(out, valueClaim("model card license", v))
	}
	other := hasOther(c.License...)
	for _, v := range c.LicenseName {
		out = append(out, nameClaim("model card license_name", v, other))
	}
	for _, v := range c.LicenseLink {
		out = append(out, linkClaim("model card license_link", v))
	}
	return out
}

// GGUFLicense is a GGUF's license keys.
type GGUFLicense struct {
	License, Name, Link string
}

// Claims returns what a GGUF's general.license keys say. in names the file
// within a directory, or is "" for a file scanned on its own.
func (g GGUFLicense) Claims(in string) []Claim {
	src := func(key string) string {
		if in == "" {
			return "GGUF " + key
		}
		return "GGUF " + key + " in " + in
	}
	var out []Claim
	if g.License != "" {
		out = append(out, valueClaim(src("general.license"), g.License))
	}
	if g.Name != "" {
		out = append(out, nameClaim(src("general.license.name"), g.Name, hasOther(g.License)))
	}
	if g.Link != "" {
		out = append(out, linkClaim(src("general.license.link"), g.Link))
	}
	return out
}

// BaseModel is one declared base model: a model card's base_model, or a
// GGUF's general.base_model.N keys.
type BaseModel struct {
	Name         string
	Organization string
	// Repo is the Hugging Face repo id (org/name) when the declaration names
	// one: the card's value, or the path of a huggingface.co repo_url.
	Repo string
	// URL is a GGUF's repo_url as written.
	URL    string
	Source string
}

// RepoFromURL returns the org/name of a huggingface.co model URL, or "".
func RepoFromURL(u string) string {
	s := strings.TrimSpace(u)
	for _, p := range []string{"https://huggingface.co/", "http://huggingface.co/", "https://hf.co/", "http://hf.co/"} {
		if rest, ok := strings.CutPrefix(s, p); ok {
			parts := strings.Split(strings.Trim(rest, "/"), "/")
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				return parts[0] + "/" + parts[1]
			}
		}
	}
	return ""
}

// inherited is the license a base model's publisher releases it under, when
// the catalogue knows the publisher's family.
func (b BaseModel) inherited() (Claim, bool) {
	e, ok := byBaseRepo(b.Repo)
	if !ok {
		return Claim{}, false
	}
	return Claim{Kind: Inherited, Source: "declared base model " + b.Repo + " (" + b.Source + ")", Value: b.Repo, ID: e.ID,
		Note: "the license its publisher releases that model under; not a statement by this artifact"}, true
}

// Identification is what the artifact says its license is.
type Identification struct {
	// ID and Name are the identified license: set when the artifact's own
	// statements name exactly one, and no declared base model's license is
	// of another family.
	ID   string
	Name string
	// Claims is every statement read, including the declared base models'
	// licenses.
	Claims     []Claim
	BaseModels []BaseModel
	// Disagreement says which licenses the statements name when they name
	// more than one.
	Disagreement string
}

// Identify combines the claims read from an artifact.
func Identify(claims []Claim, bases []BaseModel) Identification {
	id := Identification{Claims: claims, BaseModels: bases}
	for _, b := range bases {
		if c, ok := b.inherited(); ok {
			id.Claims = append(id.Claims, c)
		}
	}
	stated := id.ids(Stated)
	if len(stated) == 0 {
		return id
	}
	e := byID[stated[0]]
	conflict := len(stated) > 1
	for _, inh := range id.ids(Inherited) {
		conflict = conflict || byID[inh].Family != e.Family
	}
	if conflict {
		id.Disagreement = id.describe()
		return id
	}
	id.ID, id.Name = e.ID, e.Name
	return id
}

// ids returns the distinct catalogue ids the claims of one kind name, in the
// order they were read.
func (i Identification) ids(k Kind) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range i.Claims {
		if c.Kind == k && c.ID != "" && !seen[c.ID] {
			seen[c.ID] = true
			out = append(out, c.ID)
		}
	}
	return out
}

// Identified returns every license a stated or inherited claim names.
func (i Identification) Identified() []string {
	return append(i.ids(Stated), i.without(i.ids(Inherited), i.ids(Stated))...)
}

func (i Identification) without(ids, drop []string) []string {
	var out []string
	for _, id := range ids {
		if !contains(drop, id) {
			out = append(out, id)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// describe names each license the claims name and where each was read.
func (i Identification) describe() string {
	var parts []string
	for _, id := range i.Identified() {
		parts = append(parts, byID[id].Name+" ("+strings.Join(i.sources(id), "; ")+")")
	}
	return "the sources name different licenses: " + strings.Join(parts, ", and ")
}

// sources lists where the claims naming id were read.
func (i Identification) sources(id string) []string {
	var out []string
	for _, c := range i.Claims {
		if c.ID == id && !contains(out, c.Source) {
			out = append(out, c.Source)
		}
	}
	return out
}

// Unrecognized returns the stated claims that name no catalogue license.
func (i Identification) Unrecognized() []Claim {
	var out []Claim
	for _, c := range i.Claims {
		if c.unrecognized() {
			out = append(out, c)
		}
	}
	return out
}

// Obligations lists the usage-policy obligations of the identified license,
// or of every license the statements name when they disagree, each with its
// license's name.
func (i Identification) Obligations() []string {
	ids := i.Identified()
	if i.ID != "" {
		ids = []string{i.ID}
	}
	var out []string
	for _, id := range ids {
		e := byID[id]
		if len(e.Obligations) > 0 {
			out = append(out, e.Name+": "+strings.Join(e.Obligations, "; "))
		}
	}
	return out
}

// Name returns a catalogue id's display name, or the id.
func Name(id string) string {
	if e, ok := byID[id]; ok {
		return e.Name
	}
	return id
}

// firstLine is a text's first non-empty line, without markdown emphasis, as
// the report shows an unrecognized text.
func firstLine(text []byte) string {
	for _, line := range strings.Split(string(text), "\n") {
		t := strings.Trim(strings.ReplaceAll(strings.TrimSpace(line), "**", ""), "#*_= \t\ufeff")
		if t != "" {
			return clip(t, 120)
		}
	}
	return "(empty)"
}

// clip bounds s to n runes, dropping control characters.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
