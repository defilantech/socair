package license

import (
	"strings"
	"testing"
)

// Short distinctive phrases stand in for the license files: a CC legal
// code's title and a Llama agreement's title and release line identify them,
// and the repository carries no license text.
const (
	ccByNCText  = "Attribution-NonCommercial 4.0 International\n\nCreative Commons Attribution-NonCommercial 4.0 International Public License\n\nBy exercising the Licensed Rights...\n"
	llama31Text = "LLAMA 3.1 COMMUNITY LICENSE AGREEMENT\nLlama 3.1 Version Release Date: July 23, 2024\n\n\"Agreement\" means the terms...\n"
)

func TestFromTextIdentifiesByPhrase(t *testing.T) {
	for text, want := range map[string]string{
		ccByNCText:  "cc-by-nc-4.0",
		llama31Text: "llama-3.1-license-2024",
		"Licensed under the Apache License, Version 2.0 (the \"License\");\nyou may not use this file except in compliance with the License.\n": "apache-2.0",
	} {
		c := FromText("LICENSE", []byte(text))
		if c.ID != want || c.Kind != Stated {
			t.Errorf("%q: id %q (%s), want %q", firstLine([]byte(text)), c.ID, c.Note, want)
		}
	}
}

// An unrecognized text is reported with its first line and never guessed,
// and a text two entries claim is not identified.
func TestFromTextNeverGuesses(t *testing.T) {
	c := FromText("LICENSE", []byte("\n# **ACME MODEL LICENSE**\nYou may use this model for good.\n"))
	if c.ID != "" || c.Value != "ACME MODEL LICENSE" || !strings.Contains(c.Note, "not a license text the catalogue recognizes") {
		t.Errorf("unrecognized text: %+v", c)
	}
	both := FromText("LICENSE", []byte(ccByNCText+"\n"+llama31Text))
	if both.ID != "" || !strings.Contains(both.Note, "more than one") {
		t.Errorf("a text two licenses claim: %+v", both)
	}
	// The Apache notice identifies only a short file: inside a longer text it
	// could be quoting the license, not granting it.
	long := FromText("LICENSE", []byte(strings.Repeat("Other terms apply to this model. ", 40)+
		"Licensed under the Apache License, Version 2.0; you may not use this file except in compliance with the License."))
	if long.ID != "" {
		t.Errorf("an Apache notice inside a long text was identified as %s", long.ID)
	}
}

func TestReadCard(t *testing.T) {
	readme := "\ufeff---\r\nlicense: \"Apache-2.0\"  \r\nlicense_name: other-name # a comment\r\nlicense_link: >-\r\n  https://example.com/\r\n  terms\r\nbase_model:\r\n- org/base-a\r\n-   'org/base-b'\r\ntags: [x]\r\nextra_gated_fields:\r\n  license: not-this\r\n---\r\n# Model\r\nlicense: not-this-either\r\n"
	c := ReadCard([]byte(readme))
	if strings.Join(c.License, ",") != "Apache-2.0" || strings.Join(c.LicenseName, ",") != "other-name" ||
		strings.Join(c.LicenseLink, ",") != "https://example.com/ terms" || strings.Join(c.BaseModels, ",") != "org/base-a,org/base-b" {
		t.Errorf("card %+v", c)
	}
	if c := ReadCard([]byte("---\nlicense: [mit, apache-2.0]\n---\n")); strings.Join(c.License, ",") != "mit,apache-2.0" {
		t.Errorf("inline list: %+v", c)
	}
	if c := ReadCard([]byte("# No front matter\nlicense: mit\n")); len(c.License) != 0 {
		t.Errorf("a card without front matter says nothing: %+v", c)
	}
}

func TestCardClaims(t *testing.T) {
	c := Card{License: []string{"other"}, LicenseName: []string{"modified-mit", "qwen"}, LicenseLink: []string{"https://mistral.ai/licenses/MRL-0.1.md", "LICENSE"}}
	claims := c.Claims()
	want := []struct {
		kind Kind
		id   string
	}{{Pointer, ""}, {Pointer, ""}, {Stated, "qwen-2024"}, {Stated, "socair-mistral-research-0.1"}, {Pointer, ""}}
	if len(claims) != len(want) {
		t.Fatalf("claims %+v", claims)
	}
	for i, w := range want {
		if claims[i].Kind != w.kind || claims[i].ID != w.id {
			t.Errorf("claim %d %+v, want kind %d id %q", i, claims[i], w.kind, w.id)
		}
	}
	// Without "other", an unknown license_name is a statement the catalogue
	// cannot read.
	if got := (Card{License: []string{"mit"}, LicenseName: []string{"acme"}}).Claims()[1]; !got.unrecognized() {
		t.Errorf("license_name beside a listed license: %+v", got)
	}
}

// The issue's falsification: a model card that says Apache-2.0 over a
// non-commercial LICENSE file is a disagreement, and identifies neither.
// Neuter the comparison in Identify and this fails.
func TestCardOverNonCommercialLicenseDisagrees(t *testing.T) {
	claims := append(Card{License: []string{"apache-2.0"}}.Claims(), FromText("LICENSE", []byte(ccByNCText)))
	id := Identify(claims, nil)
	if id.ID != "" || id.Disagreement == "" {
		t.Fatalf("identified %q with no disagreement; want the card and LICENSE to disagree", id.ID)
	}
	for _, s := range []string{"Apache License 2.0 (model card license)", "Creative Commons Attribution-NonCommercial 4.0 International (LICENSE)"} {
		if !strings.Contains(id.Disagreement, s) {
			t.Errorf("disagreement %q does not name %s", id.Disagreement, s)
		}
	}
	agree := Identify(append(Card{License: []string{"cc-by-nc-4.0"}}.Claims(), FromText("LICENSE", []byte(ccByNCText))), nil)
	if agree.ID != "cc-by-nc-4.0" || agree.Disagreement != "" {
		t.Errorf("agreeing sources: %+v", agree)
	}
}

// A declared base model's license can disagree with what the artifact states,
// but a later revision of the same publisher's license does not, and the
// base alone identifies nothing.
func TestBaseModelLicense(t *testing.T) {
	base := []BaseModel{{Repo: "meta-llama/Llama-3.1-8B", Source: "model card base_model"}}
	if id := Identify(Card{License: []string{"apache-2.0"}}.Claims(), base); id.Disagreement == "" || id.ID != "" {
		t.Errorf("an Apache card over a Llama 3.1 base: %+v", id)
	}
	if id := Identify(Card{License: []string{"llama3.3"}}.Claims(), base); id.ID != "llama-3.3-license-2024" || id.Disagreement != "" {
		t.Errorf("Llama 3.3 over a Llama 3.1 base is one family: %+v", id)
	}
	if id := Identify(nil, base); id.ID != "" || id.Disagreement != "" || len(id.Claims) != 1 || id.Claims[0].Kind != Inherited {
		t.Errorf("a base alone: %+v", id)
	}
	if RepoFromURL("https://huggingface.co/google/gemma-3-12b-pt") != "google/gemma-3-12b-pt" || RepoFromURL("https://example.com/a/b") != "" {
		t.Error("RepoFromURL")
	}
}

func TestGGUFClaims(t *testing.T) {
	claims := GGUFLicense{License: "other", Name: "qwen", Link: "https://huggingface.co/Qwen/Qwen2.5-72B-Instruct/blob/main/LICENSE"}.Claims("m.gguf")
	id := Identify(claims, nil)
	if id.ID != "qwen-2024" || claims[0].Source != "GGUF general.license in m.gguf" {
		t.Errorf("GGUF qwen: %+v", id)
	}
	if c := (GGUFLicense{License: "llama3.1"}).Claims(""); len(c) != 1 || c[0].ID != "llama-3.1-license-2024" || c[0].Source != "GGUF general.license" {
		t.Errorf("GGUF llama3.1: %+v", c)
	}
}

func TestCodeLicenseIsAPointer(t *testing.T) {
	code := CodeLicense(FromText("LICENSE-CODE", []byte(ccByNCText)))
	model := FromText("LICENSE-MODEL", []byte(llama31Text))
	id := Identify([]Claim{code, model}, nil)
	if id.ID != "llama-3.1-license-2024" || id.Disagreement != "" || code.Kind != Pointer {
		t.Errorf("a code license beside a model license: %+v", id)
	}
}
