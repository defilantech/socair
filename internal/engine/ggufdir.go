package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/gguf"
)

// ggufHeader is one GGUF file of a model directory, read for its metadata.
type ggufHeader struct {
	path string
	m    *gguf.Manifest // nil when err is set
	err  error
}

// templateGroup is the GGUF files of a directory that carry the same chat
// templates and special tokens: one version of the model's templates.
type templateGroup struct {
	key   string
	files []string
	m     *gguf.Manifest // the first file's, for its templates and tokens
}

// label names the group's files in the row: the first, and how many more.
func (g templateGroup) label() string {
	if len(g.files) == 1 {
		return g.files[0]
	}
	return fmt.Sprintf("%s and %d more GGUF file(s) with the same chat templates", g.files[0], len(g.files)-1)
}

// maxGroupsListed bounds the template versions named in the notes.
const maxGroupsListed = 8

// ggufTemplateParts grades the chat templates of a directory's GGUF files,
// which a serving stack reads from each file's own metadata, so each quant of
// a model can carry a different one. Files that carry the same templates and
// special tokens are graded once, as one part. When they do not all carry the
// same, each version is also compared with the others as with a reference
// (chattemplate.Options.Siblings): one that renders like another on every
// standard probe but adds a content-conditional branch is a LEAD. That a
// version differs is listed in note, not judged: a quant made before its
// model's template was fixed differs as well.
func ggufTemplateParts(heads []ggufHeader, refs *references) (parts []checks.Part, note string) {
	var groups []*templateGroup
	byKey := map[string]*templateGroup{}
	for _, h := range heads {
		if h.err != nil {
			parts = append(parts, checks.Part{File: h.path, Result: checks.Result{Status: checks.NotTested,
				Notes: "GGUF metadata could not be read, so its chat template was not inspected: " + h.err.Error()}})
			continue
		}
		if len(h.m.ChatTemplates) == 0 && len(h.m.ChatTemplateNonString) == 0 {
			continue // a projector, an imatrix, a later split shard, or a base model
		}
		k := groupKey(h.m)
		g, ok := byKey[k]
		if !ok {
			g = &templateGroup{key: k, m: h.m}
			byKey[k] = g
			groups = append(groups, g)
		}
		g.files = append(g.files, h.path)
	}
	for _, g := range groups {
		opts := refs.templateOptions(chattemplate.TokensFromGGUF(g.m.Tokenizer))
		for _, other := range groups {
			if other == g {
				continue
			}
			for name, text := range other.m.ChatTemplates {
				if own, ok := g.m.ChatTemplates[name]; ok && own != text {
					if opts.Siblings == nil {
						opts.Siblings = map[string][]chattemplate.Reference{}
					}
					opts.Siblings[name] = append(opts.Siblings[name], chattemplate.Reference{Label: other.label(), Text: text})
				}
			}
		}
		parts = append(parts, checks.Part{File: g.label(),
			Result: chattemplate.InspectAllWith(g.m.ChatTemplates, g.m.ChatTemplateNonString, opts)})
	}
	if len(groups) > 1 {
		var vs []string
		for i, g := range groups {
			if i == maxGroupsListed {
				vs = append(vs, fmt.Sprintf("and %d more", len(groups)-i))
				break
			}
			vs = append(vs, fmt.Sprintf("%s in %s", templatesID(g.m), listFiles(g.files)))
		}
		note = fmt.Sprintf("the GGUF files do not all carry the same chat templates: %d versions (%s). "+
			"Each version was graded and compared with the others on every probe; a difference that adds a content-conditional "+
			"branch is a LEAD, and any other difference is listed here, not judged: a quant made before its model's template was "+
			"changed differs as well", len(groups), strings.Join(vs, "; "))
	}
	return parts, note
}

// groupKey identifies a file's chat templates and the special tokens they
// render with.
func groupKey(m *gguf.Manifest) string {
	h := sha256.New()
	names := make([]string, 0, len(m.ChatTemplates))
	for n := range m.ChatTemplates {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(h, "t%d:%s%d:%s", len(n), n, len(m.ChatTemplates[n]), m.ChatTemplates[n])
	}
	ns := append([]string(nil), m.ChatTemplateNonString...)
	sort.Strings(ns)
	for _, n := range ns {
		fmt.Fprintf(h, "n%d:%s", len(n), n)
	}
	tok := chattemplate.TokensFromGGUF(m.Tokenizer)
	vars := make([]string, 0, len(tok.Named))
	for v := range tok.Named {
		vars = append(vars, v)
	}
	sort.Strings(vars)
	for _, v := range vars {
		fmt.Fprintf(h, "v%d:%s%d:%s", len(v), v, len(tok.Named[v]), tok.Named[v])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// templatesID names a version by the SHA-256 of its default template, or of
// its first named one.
func templatesID(m *gguf.Manifest) string {
	name := "default"
	if _, ok := m.ChatTemplates[name]; !ok {
		names := make([]string, 0, len(m.ChatTemplates))
		for n := range m.ChatTemplates {
			names = append(names, n)
		}
		sort.Strings(names)
		if len(names) == 0 {
			return "no string template"
		}
		name = names[0]
	}
	sum := sha256.Sum256([]byte(m.ChatTemplates[name]))
	label := "tokenizer.chat_template"
	if name != "default" {
		label += "." + name
	}
	return label + " " + hex.EncodeToString(sum[:])[:12]
}

// joinNote appends a note, if any, to notes.
func joinNote(notes, note string) string {
	switch {
	case note == "":
		return notes
	case notes == "":
		return note
	}
	return notes + "; " + note
}

// listFiles names files, bounded.
func listFiles(files []string) string {
	const max = 6
	if len(files) > max {
		return strings.Join(files[:max], ", ") + fmt.Sprintf(", and %d more", len(files)-max)
	}
	return strings.Join(files, ", ")
}
