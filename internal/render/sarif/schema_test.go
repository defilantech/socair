package sarif

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/defilantech/socair/internal/report"
)

var update = flag.Bool("update", false, "rewrite testdata/report.sarif.json from testdata/report.json")

// schemaURL is the schema's own id, so the compiler resolves it to the copy in
// testdata and never fetches it.
const schemaURL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

// schema compiles the OASIS SARIF 2.1.0 schema (Errata 01) from testdata,
// offline, asserting formats such as uri-reference.
func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "schema", "sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, doc); err != nil {
		t.Fatal(err)
	}
	c.AssertFormat()
	s, err := c.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, b []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(inst)
}

// TestGoldenSARIF pins the SARIF of the golden report byte for byte, so a
// change to what it says, a fingerprint included, is a reviewed diff. Run with
// -update to rewrite it.
func TestGoldenSARIF(t *testing.T) {
	var got bytes.Buffer
	if err := Render(&got, loadGolden(t)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join("testdata", "report.sarif.json")
	if *update {
		if err := os.WriteFile(p, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("the SARIF of testdata/report.json differs from %s; if the change is intended, run go test ./internal/render/sarif -run TestGoldenSARIF -update", p)
	}
	if err := validate(t, schema(t), want); err != nil {
		t.Fatalf("the golden SARIF does not validate: %v", err)
	}
}

// TestSARIFValidatesAgainstTheSchema covers the golden report, a report with a
// row of every status, a model directory, a header-only report with no
// artifact hash, and a file name a URI must escape.
func TestSARIFValidatesAgainstTheSchema(t *testing.T) {
	s := schema(t)

	every := loadGolden(t)
	every.Checks[1].Status, every.Checks[1].Evidence = report.StatusFail, "embedded-script: offset 12 (a shebang)"
	every.Checks[2].Status, every.Checks[2].Evidence = report.StatusLead, "token-instruction: token 7: \"ignore\""

	dir := loadGolden(t)
	dir.Artifact.FileName, dir.Artifact.Format = "Org-AI_Model-7B", "model directory"
	dir.Artifact.Files = []report.ArtifactFile{{Path: "model.safetensors", SHA256: dir.Artifact.SHA256, SizeBytes: 1, Role: "weights"}}

	headers := loadGolden(t)
	headers.Artifact.SHA256 = ""

	spaced := loadGolden(t)
	spaced.Artifact.FileName = "my model: v2 #1 100%.gguf"

	for name, d := range map[string]*report.Document{"golden": loadGolden(t), "every status": every,
		"model directory": dir, "header-only": headers, "escaped name": spaced} {
		var b bytes.Buffer
		if err := Render(&b, d); err != nil {
			t.Fatalf("%s: Render: %v", name, err)
		}
		if err := validate(t, s, b.Bytes()); err != nil {
			t.Errorf("%s: SARIF does not validate against SARIF 2.1.0: %v", name, err)
		}
	}
}
