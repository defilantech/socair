package inventory

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/openvino/openvinotest"
)

// TestOpenVINOText: an OpenVINO IR's rt_info, its layers' attributes, and
// everything else in its XML go through the same payload patterns as GGUF
// and safetensors metadata. Falsification: drop the OpenVINO case from
// Inspect, or stop the reader keeping a kind of text, and the FAILs go.
func TestOpenVINOText(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("echo socair; ", 60)))
	cases := map[string]struct {
		edit    func(*openvinotest.Model)
		pattern string
	}{
		"rt_info value": {func(m *openvinotest.Model) { m.RTInfo += `<note value="#!/bin/sh&#10;echo socair"/>` }, "embedded-script"},
		"rt_info name":  {func(m *openvinotest.Model) { m.RTInfo += `<info name="&lt;script&gt;x" value="v"/>` }, "embedded-script"},
		"rt_info text":  {func(m *openvinotest.Model) { m.RTInfo += "<config>" + b64 + "</config>" }, "embedded-base64-blob"},
		"layer rt_info": {func(m *openvinotest.Model) {
			m.Layers[2].Raw = `<rt_info><attribute name="x" version="0" value="powershell -enc AAAA"/></rt_info>`
		}, "embedded-script"},
		"data attribute": {func(m *openvinotest.Model) {
			m.Layers[2].Data = append(m.Layers[2].Data, openvinotest.Attr{Name: "note", Value: b64})
		}, "embedded-base64-blob"},
		"layer name":       {func(m *openvinotest.Model) { m.Layers[2].Name = "Invoke-Expression x" }, "embedded-script"},
		"comment":          {func(m *openvinotest.Model) { m.Prolog = "<!-- #!/bin/bash\nid -->\n" }, "embedded-script"},
		"unknown element":  {func(m *openvinotest.Model) { m.Raw = "<extra>" + b64 + "</extra>" }, "embedded-base64-blob"},
		"legacy meta_data": {func(m *openvinotest.Model) { m.Raw = `<meta_data><x value="#!/bin/sh"/></meta_data>` }, "embedded-script"},
		"body layer rt_info": {func(m *openvinotest.Model) {
			m.Layers[2].Raw = "<body><layers><layer id=\"0\" name=\"" + b64 + "\" type=\"Parameter\" version=\"opset1\"/></layers></body>"
		}, "embedded-base64-blob"},
	}
	for name, c := range cases {
		m := openvinotest.Clean()
		c.edit(&m)
		r := Inspect(writeFixture(t, "openvino_model.xml", m.XML()), Options{})
		if r.Status != checks.Fail || len(r.Findings) == 0 || r.Findings[0].Pattern != c.pattern {
			t.Errorf("%s: %s %v: %s", name, r.Status, r.Findings, r.Notes)
		}
	}
	// A clean IR has no indicator; with no repo mirror the row is a gap.
	r := Inspect(writeFixture(t, "openvino_model.xml", openvinotest.Clean().XML()), Options{})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "artifact: OpenVINO IR XML") || !strings.Contains(r.Notes, "no payload indicator") {
		t.Errorf("clean: %s: %s", r.Status, r.Notes)
	}
	r = Inspect(writeFixture(t, "openvino_model.xml", openvinotest.Clean().XML()), Options{RepoMirror: cleanMirror(t)})
	if r.Status != checks.Pass {
		t.Errorf("clean with a mirror: %s: %s", r.Status, r.Notes)
	}
	// XML that does not parse is a gap, named.
	r = Inspect(writeFixture(t, "openvino_model.xml", []byte("<net><layers>")), Options{})
	if r.Status != checks.NotTested || !strings.Contains(r.Notes, "could not read the OpenVINO IR's text") {
		t.Errorf("unparseable: %s: %s", r.Status, r.Notes)
	}
}
