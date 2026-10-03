package modeldir

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

// maxTemplateFile bounds a template or tokenizer config read into memory.
const maxTemplateFile = 32 << 20

// ChatTemplates reads every chat template a transformers loader could use
// from a snapshot: tokenizer_config.json's chat_template (a string, or a list
// of named templates), chat_template.json's chat_template (processors), and
// any .jinja file, which covers chat_template.jinja and
// additional_chat_templates/. Keys name the source. A chat_template value
// that is present but not a string is named in nonString, as the GGUF reader
// does, so the template check can report it rather than skip it. unread names
// a file that could not be read or parsed.
func ChatTemplates(root string, files []File) (templates map[string]string, nonString, unread []string) {
	templates = map[string]string{}
	read := func(f File) ([]byte, bool) {
		if f.Size > maxTemplateFile {
			unread = append(unread, fmt.Sprintf("%s: %d bytes, over the %d-byte limit", f.Path, f.Size, maxTemplateFile))
			return nil, false
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if err != nil {
			unread = append(unread, f.Path+": "+err.Error())
			return nil, false
		}
		return b, true
	}
	for _, f := range files {
		base := path.Base(f.Path)
		switch {
		case path.Ext(base) == ".jinja":
			if b, ok := read(f); ok {
				templates[f.Path] = string(b)
			}
		case base == "tokenizer_config.json" || base == "chat_template.json":
			b, ok := read(f)
			if !ok {
				continue
			}
			var cfg map[string]json.RawMessage
			if err := json.Unmarshal(b, &cfg); err != nil {
				unread = append(unread, f.Path+": not a JSON object")
				continue
			}
			raw, ok := cfg["chat_template"]
			if !ok {
				continue
			}
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				templates[f.Path] = s
				continue
			}
			var named []struct {
				Name     string `json:"name"`
				Template string `json:"template"`
			}
			if err := json.Unmarshal(raw, &named); err == nil && len(named) > 0 {
				for _, n := range named {
					templates[f.Path+"#"+n.Name] = n.Template
				}
				continue
			}
			nonString = append(nonString, f.Path+"#chat_template")
		}
	}
	return templates, nonString, unread
}
