package main

import (
	"fmt"
	"strings"

	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/gguf"
)

// templateDump prints the chat template of an artifact and the hero-check
// findings with their evidence spans. It is the tuning tool: it shows why a
// template was flagged.
func templateDump(path string) error {
	m, err := gguf.ReadHeader(path)
	if err != nil {
		return err
	}
	if !m.ChatTemplatePresent {
		fmt.Printf("%s: no chat template in metadata\n", m.FileName)
		return nil
	}

	fmt.Printf("=== %s (template %d bytes, sha %s) ===\n", m.FileName, m.ChatTemplateBytes, m.ChatTemplateSHA256[:16])
	fmt.Println(strings.TrimSpace(m.ChatTemplate))
	fmt.Println("=== hero check ===")

	r := chattemplate.Inspect(m.ChatTemplate)
	fmt.Printf("status: %s\nnotes: %s\n", r.Status, r.Notes)
	for _, f := range r.Findings {
		fmt.Printf("  pattern=%s span=%q\n", f.Pattern, f.Span)
	}
	return nil
}
