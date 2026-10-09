package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestSchemaMatchesModel holds docs/report-schema/v1.json to the Go model. Every
// object in the schema must close with additionalProperties: false, and at
// every level the schema's properties and the Go struct's JSON fields must be
// the same set. Falsification: add a field to any report struct without the
// schema, or a property to the schema without the struct, and this fails.
func TestSchemaMatchesModel(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	compare(t, "", reflect.TypeOf(Document{}), schema)
}

func compare(t *testing.T, path string, typ reflect.Type, node map[string]any) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Slice, reflect.Array:
		items, _ := node["items"].(map[string]any)
		if items == nil {
			t.Errorf("%s: Go has a list but the schema has no items", orRoot(path))
			return
		}
		compare(t, path+"[]", typ.Elem(), items)
		return
	case reflect.Struct:
	default:
		return
	}

	if node["additionalProperties"] != false {
		t.Errorf("%s: schema object must set additionalProperties: false", orRoot(path))
	}
	props, _ := node["properties"].(map[string]any)
	goFields := map[string]reflect.Type{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" || !f.IsExported() {
			continue
		}
		goFields[name] = f.Type
	}
	for _, name := range sortedNames(goFields) {
		sub, ok := props[name].(map[string]any)
		if !ok {
			t.Errorf("%s.%s: in the Go model but not in the schema", orRoot(path), name)
			continue
		}
		compare(t, path+"."+name, goFields[name], sub)
	}
	for name := range props {
		if _, ok := goFields[name]; !ok {
			t.Errorf("%s.%s: in the schema but not in the Go model", orRoot(path), name)
		}
	}
}

func sortedNames(m map[string]reflect.Type) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orRoot(p string) string {
	if p == "" {
		return "(root)"
	}
	return p
}

// TestHandWrittenReportsMatchSchema: the engine's output is the Go model, so
// TestSchemaMatchesModel covers it. The golden and the sample report are written
// by hand, so their keys are checked against the closed schema directly.
func TestHandWrittenReportsMatchSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join("..", "..", "testdata", "report.json"),
		filepath.Join("..", "demo", "report.json"),
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		for _, k := range unknownKeys("", doc, schema) {
			t.Errorf("%s: %s is not in the schema", p, k)
		}
	}
}

// TestSchemaBoundedStatementIsTheFixedSet: the schema admits exactly the
// fixed sentences, the Tier 1 pair then the Tier 2 pair, so the published
// contract and the engine cannot drift. Falsification: edit any sentence in
// one place only and this fails.
func TestSchemaBoundedStatementIsTheFixedSet(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			BoundedStatement struct {
				Enum []string `json:"enum"`
			} `json:"bounded_statement"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	want := []string{BoundedStatementNoIndicators, BoundedStatementIndicators, BoundedStatementTier2NoIndicators, BoundedStatementTier2Indicators}
	if got := schema.Properties.BoundedStatement.Enum; !reflect.DeepEqual(got, want) {
		t.Fatalf("schema bounded_statement enum = %q, want %q", got, want)
	}
}

func unknownKeys(path string, v any, node map[string]any) []string {
	var out []string
	switch v := v.(type) {
	case map[string]any:
		props, _ := node["properties"].(map[string]any)
		for k, sub := range v {
			sn, ok := props[k].(map[string]any)
			if !ok {
				out = append(out, path+"."+k)
				continue
			}
			out = append(out, unknownKeys(path+"."+k, sub, sn)...)
		}
	case []any:
		items, _ := node["items"].(map[string]any)
		for _, x := range v {
			out = append(out, unknownKeys(path+"[]", x, items)...)
		}
	}
	return out
}
