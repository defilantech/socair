package cyclonedx

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/defilantech/socair/internal/report"
)

// schema compiles the CycloneDX 1.6 BOM schema from testdata, offline: its
// references to the SPDX and JSF schemas resolve to the copies beside it.
func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	for _, name := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
		f, err := os.Open(filepath.Join("testdata", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource("http://cyclonedx.org/schema/"+name, doc); err != nil {
			t.Fatal(err)
		}
	}
	c.AssertFormat()
	s, err := c.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func golden(t *testing.T) *report.Document {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d report.Document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

func render(t *testing.T, d *report.Document) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func validate(t *testing.T, s *jsonschema.Schema, b []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(inst)
}

// TestBOMValidatesAgainstCycloneDX16 covers the golden report, a signed
// conditional one with an upstream origin, and one with no optional fields.
func TestBOMValidatesAgainstCycloneDX16(t *testing.T) {
	s := schema(t)

	plain := golden(t)

	rich := golden(t)
	rich.Artifact.RepoURL = "https://huggingface.co/org/model"
	rich.Artifact.CommitSHA = "71034c5d8bde858ff824298bdedc65515b97d2b9"
	rich.Artifact.Publisher = "org"
	rich.Artifact.Architecture = "llama"
	rich.Verification.DocumentHash = strings.Repeat("ab", 32)
	rich.Verification.SignerKeyID = strings.Repeat("cd", 32)
	rich.PromotionAuthorization = report.PromotionAuthorization{
		State: report.StateAuthorizedWithConditions, Authorized: true,
		AcceptedBy: "ciso@example.com", AcceptedSurfaces: []string{"File inventory and payloads"},
		AcceptanceExpires: "2027-01-31T00:00:00Z",
	}

	bare := golden(t)
	bare.Artifact = report.ArtifactIdentity{Name: "", FileName: "m.bin", SHA256: plain.Artifact.SHA256, Format: "unknown"}
	bare.Scope.ToolVersions = ""

	for name, d := range map[string]*report.Document{"golden": plain, "signed conditional": rich, "bare": bare} {
		if err := validate(t, s, render(t, d)); err != nil {
			t.Errorf("%s: BOM does not validate against CycloneDX 1.6: %v", name, err)
		}
	}
}

// asMap renders d and decodes the BOM generically.
func asMap(t *testing.T, d *report.Document) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(render(t, d), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func subject(m map[string]any) map[string]any {
	return m["metadata"].(map[string]any)["component"].(map[string]any)
}

func props(c map[string]any) map[string]string {
	out := map[string]string{}
	for _, p := range c["properties"].([]any) {
		p := p.(map[string]any)
		out[p["name"].(string)] = p["value"].(string)
	}
	return out
}

// TestSchemaRejectsABrokenBOM: the validator must actually bite. A BOM with
// an invalid component type, a malformed hash, or a numeric spec version must
// not validate.
func TestSchemaRejectsABrokenBOM(t *testing.T) {
	s := schema(t)
	for name, mutate := range map[string]func(map[string]any){
		"component type": func(m map[string]any) { subject(m)["type"] = "neural-thing" },
		"hash content": func(m map[string]any) {
			subject(m)["hashes"].([]any)[0].(map[string]any)["content"] = "not-a-hash"
		},
		"spec version": func(m map[string]any) { m["specVersion"] = 1.6 },
	} {
		m := asMap(t, golden(t))
		mutate(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(t, s, b); err == nil {
			t.Errorf("%s: a broken BOM validated", name)
		}
	}
}

// TestBOMSaysWhatTheReportSays: every check row appears with its status, a
// gap stays a gap, and an unsigned report claims no attestation.
func TestBOMSaysWhatTheReportSays(t *testing.T) {
	d := golden(t)
	m := asMap(t, d)
	got := props(subject(m))
	for _, c := range d.Checks {
		if v := got["socair:check:"+checkKey(c.Name)]; v != string(c.Status) {
			t.Errorf("check %q: BOM says %q, report says %s", c.Name, v, c.Status)
		}
	}
	if got["socair:promotion_state"] != d.PromotionAuthorization.State {
		t.Error("the promotion state must travel in the BOM")
	}
	for _, r := range subject(m)["externalReferences"].([]any) {
		if r.(map[string]any)["type"] == "attestation" {
			t.Error("an unsigned report must not reference an attestation")
		}
	}
	if !bytes.Equal(render(t, d), render(t, d)) {
		t.Error("the BOM must be byte-stable for a fixed document")
	}
	files := m["components"].([]any)
	if len(files) != 1 || files[0].(map[string]any)["name"] != d.Artifact.FileName {
		t.Errorf("the BOM's component must be the attested file, got %v", files)
	}
}

func TestHeaderOnlyScanHasNoBOM(t *testing.T) {
	d := golden(t)
	d.Artifact.SHA256 = ""
	if err := Render(&bytes.Buffer{}, d); err == nil {
		t.Fatal("a report with no artifact hash describes no exact bytes and must not produce a BOM")
	}
}
