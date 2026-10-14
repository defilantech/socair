package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const header = `"format": "socair.intake-policy/v1"`

func TestParseValidPolicy(t *testing.T) {
	raw := []byte(`{` + header + `, "allowed_formats": ["Safetensors", "gguf"], "allowed_publishers": ["Meta-Llama", "google"],
		"denied_publishers": ["bad_org"], "signature_required": ["acme.ml"]}`)
	p, err := Parse("acme.json", raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if p.Name != "acme.json" || p.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("name %q sha256 %q: a policy is named by its file name and the hash of its bytes", p.Name, p.SHA256)
	}
	if !p.formats[Safetensors] || !p.formats[GGUF] || len(p.formats) != 2 {
		t.Errorf("formats %v", p.formats)
	}
	if !p.allowed["meta-llama"] || !p.denied["bad_org"] || !p.signed["acme.ml"] {
		t.Errorf("publisher names are matched lowercased: allowed %v denied %v signed %v", p.allowed, p.denied, p.signed)
	}
}

// TestLoadNamesTheFileNotItsPath: the report carries the base name, never the
// local path (issue #170).
func TestLoadNamesTheFileNotItsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "org", "intake.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{`+header+`, "allowed_formats": ["gguf"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "intake.json" {
		t.Errorf("name %q, want the base name", p.Name)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing policy file must be an error")
	}
}

// TestParseIsStrict: every way a policy could load with a rule quietly
// missing or wrong stops the scan instead. Falsification: drop any of these
// refusals and its case loads.
func TestParseIsStrict(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"unknown key":          {`{` + header + `, "allowed_format": ["gguf"]}`, `"allowed_format" is not a policy key`},
		"key given twice":      {`{` + header + `, "denied_publishers": ["a"], "denied_publishers": ["b"]}`, "given twice"},
		"empty list":           {`{` + header + `, "allowed_formats": []}`, "empty list"},
		"null list":            {`{` + header + `, "allowed_publishers": null}`, "is null"},
		"not a list":           {`{` + header + `, "allowed_formats": "gguf"}`, "list of strings"},
		"empty entry":          {`{` + header + `, "allowed_formats": [""]}`, "empty entry"},
		"unknown format":       {`{` + header + `, "allowed_formats": ["onnx"]}`, `"onnx" in allowed_formats is not a format Socair identifies`},
		"repo id as publisher": {`{` + header + `, "allowed_publishers": ["meta-llama/Llama-3.1-8B"]}`, `list the organization (for a repo id, "meta-llama")`},
		"URL as publisher":     {`{` + header + `, "denied_publishers": ["https://huggingface.co/x"]}`, "not an organization"},
		"space in publisher":   {`{` + header + `, "signature_required": ["meta llama"]}`, "not a hub organization name"},
		"double dash":          {`{` + header + `, "allowed_publishers": ["a--b"]}`, "not a hub organization name"},
		"leading dash":         {`{` + header + `, "allowed_publishers": ["-ab"]}`, "not a hub organization name"},
		"allowed and denied":   {`{` + header + `, "allowed_publishers": ["Acme"], "denied_publishers": ["acme"]}`, "both allowed and denied"},
		"no rule":              {`{` + header + `}`, "sets no rule"},
		"no format":            {`{"allowed_formats": ["gguf"]}`, `"format" must be "socair.intake-policy/v1"`},
		"wrong format":         {`{"format": "socair.intake-policy/v2", "allowed_formats": ["gguf"]}`, "must be"},
		"format not a string":  {`{"format": 1, "allowed_formats": ["gguf"]}`, "must be the string"},
		"not an object":        {`["gguf"]`, "must be a JSON object"},
		"trailing data":        {`{` + header + `, "allowed_formats": ["gguf"]} {}`, "data after the policy object"},
		"not JSON":             {`format: socair.intake-policy/v1`, "not JSON"},
		"truncated":            {`{` + header + `, "allowed_formats": ["gguf"]`, "not JSON"},
	}
	for name, c := range cases {
		_, err := Parse("p.json", []byte(c.body))
		if err == nil {
			t.Errorf("%s: loaded; it must stop the scan", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "p.json: ") {
			t.Errorf("%s: error %q, want it to name the file and say %q", name, err, c.want)
		}
	}
}
