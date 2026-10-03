// Package remotecode finds the code a model loader would execute.
//
// A transformers model can name its own Python classes in an auto_map entry
// of config.json, tokenizer_config.json, or a processor config, and ship the
// .py files that define them; loading it with trust_remote_code runs that code
// with the loader's privileges. That is not proof of malice (many legitimate
// architectures ship this way) but it is code no weight-level check examines,
// so it is a LEAD that names every file and entry, cleared only by review. A
// directory with no .py file and no auto_map in a config it could read PASSes.
// A config that does not parse as JSON is NOT_TESTED: it might carry an
// auto_map this check could not see.
package remotecode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/modeldir"
)

const (
	resultName = "Remote code"
	looksFor   = "Code a loader would run: auto_map entries and Python files (trust_remote_code)"
)

// maxConfig bounds a config read into memory.
const maxConfig = 16 << 20

// Inspect reads the files of a model directory snapshot rooted at root.
func Inspect(root string, files []modeldir.File) checks.Result {
	r := checks.Result{Name: resultName, LooksFor: looksFor}
	var unread []string
	configs := 0
	for _, f := range files {
		if f.Role == modeldir.RoleCode {
			r.Findings = append(r.Findings, checks.Finding{Pattern: "python-file", Span: f.Path,
				Detail: "Python source a loader can import"})
			continue
		}
		if path.Ext(f.Path) != ".json" || f.Size > maxConfig {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if err != nil {
			unread = append(unread, f.Path+": "+err.Error())
			continue
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '{' {
			continue // not a config object (a list, a vocabulary, a merges table)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(raw, &top); err != nil {
			unread = append(unread, f.Path+": not valid JSON")
			continue
		}
		configs++
		am, ok := top["auto_map"]
		if !ok {
			continue
		}
		r.Findings = append(r.Findings, checks.Finding{Pattern: "auto_map", Span: f.Path + ": " + autoMapTargets(am),
			Detail: "the config names classes for trust_remote_code to load"})
	}

	switch {
	case len(r.Findings) > 0:
		r.Status = checks.Lead
		var spans []string
		for _, f := range r.Findings {
			spans = append(spans, f.Span)
		}
		r.Notes = fmt.Sprintf("this model ships code a loader runs with trust_remote_code: %s. Review it before serving, or serve without trust_remote_code.", strings.Join(spans, "; "))
	case len(unread) > 0:
		r.Status = checks.NotTested
		r.Notes = "could not read every config, so an auto_map may be unseen: " + strings.Join(unread, "; ")
	default:
		r.Status = checks.Pass
		r.Notes = fmt.Sprintf("no .py file and no auto_map in the %d JSON config(s) read", configs)
	}
	return r
}

// autoMapTargets names the classes an auto_map points at, bounded.
func autoMapTargets(raw json.RawMessage) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "auto_map (unreadable value)"
	}
	var out []string
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out = append(out, k+" -> "+t)
		case []any:
			var parts []string
			for _, x := range t {
				if s, ok := x.(string); ok {
					parts = append(parts, s)
				}
			}
			out = append(out, k+" -> "+strings.Join(parts, ", "))
		default:
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) > 6 {
		out = append(out[:6], fmt.Sprintf("and %d more", len(out)-6))
	}
	return "auto_map {" + strings.Join(out, "; ") + "}"
}
