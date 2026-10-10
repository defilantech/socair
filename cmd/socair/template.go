package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/gguf"
)

// templateDump prints every chat template of an artifact and the Chat template
// row's findings with their evidence spans. It is the tuning tool: it shows why a
// template was flagged.
func templateDump(path string) error {
	m, err := gguf.ReadHeader(path)
	if err != nil {
		return err
	}
	if len(m.ChatTemplates) == 0 && len(m.ChatTemplateNonString) == 0 {
		fmt.Printf("%s: no chat template in metadata\n", m.FileName)
		return nil
	}

	names := make([]string, 0, len(m.ChatTemplates))
	for n := range m.ChatTemplates {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := m.ChatTemplates[n]
		fmt.Printf("=== %s: template %q (%d bytes, sha %s) ===\n", m.FileName, n, len(t), shortSHA(t))
		fmt.Println(safeForTerminal(strings.TrimSpace(t)))
	}
	for _, n := range m.ChatTemplateNonString {
		fmt.Printf("=== %s: template %q is not a string; not inspected ===\n", m.FileName, n)
	}

	fmt.Println("=== Chat template check ===")
	r := chattemplate.InspectAllWith(m.ChatTemplates, m.ChatTemplateNonString, chattemplate.Options{Tokens: chattemplate.TokensFromGGUF(m.Tokenizer)})
	fmt.Printf("status: %s\nnotes: %s\n", r.Status, safeForTerminal(r.Notes))
	for _, f := range r.Findings {
		fmt.Printf("  pattern=%s span=%q detail=%s\n", f.Pattern, f.Span, safeForTerminal(f.Detail))
	}
	return nil
}

// safeForTerminal escapes control and invisible characters, so a hostile
// template cannot drive the operator's terminal with escape sequences or hide
// text in it. Newlines and tabs are kept for readability.
func safeForTerminal(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, "\\u{%04X}", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func shortSHA(s string) string {
	return gguf.SHA256Hex([]byte(s))[:16]
}
