package intake

import (
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/provenance"
)

func policy(t *testing.T, rules string) *Policy {
	t.Helper()
	p, err := Parse("acme-intake.json", []byte(`{`+header+`, `+rules+`}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func manifest(repoURL, publisher string) *provenance.Manifest {
	return &provenance.Manifest{ArtifactSHA256: strings.Repeat("a", 64), RepoURL: repoURL, Publisher: publisher,
		CommitSHA: strings.Repeat("b", 40)}
}

func patterns(r checks.Result) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Pattern)
	}
	return out
}

func has(r checks.Result, pattern string) bool {
	for _, p := range patterns(r) {
		if p == pattern {
			return true
		}
	}
	return false
}

var (
	pickleFile = File{Path: "model.pkl", Format: Pickle, How: "a protocol 2 pickle stream"}
	stFile     = File{Path: "model.safetensors", Format: Safetensors, How: "a safetensors header"}
	ggufFile   = File{Path: "model.gguf", Format: GGUF, How: "the GGUF magic"}
	onnxFile   = File{Path: "model.onnx", How: ".onnx weights; its bytes are not GGUF, safetensors, NumPy, or a pickle Socair recognises"}
)

// TestPickleUnderSafetensorsOnly is the issue's acceptance case: a pickle
// checkpoint under "safetensors only" is a FAIL whose finding names the rule.
// Falsification: allow every identified format and this fails.
func TestPickleUnderSafetensorsOnly(t *testing.T) {
	r := policy(t, `"allowed_formats": ["safetensors"]`).Check(Facts{Files: []File{pickleFile}})
	if r.Status != checks.Fail || !has(r, "format-not-allowed") {
		t.Fatalf("%s %v (%s), want FAIL format-not-allowed", r.Status, patterns(r), r.Notes)
	}
	if r.Findings[0].Span != "model.pkl" || !strings.Contains(r.Findings[0].Detail, "pickle") {
		t.Errorf("finding %+v must name the file and its format", r.Findings[0])
	}
	if !strings.Contains(r.Notes, "allowed formats (safetensors)") || !strings.Contains(r.Notes, "acme-intake.json") {
		t.Errorf("notes must name the policy and the rule: %s", r.Notes)
	}
}

func TestFormatRule(t *testing.T) {
	cases := []struct {
		name    string
		allowed string
		files   []File
		want    checks.Status
	}{
		{"allowed", `["safetensors", "gguf"]`, []File{stFile, ggufFile}, checks.Pass},
		{"one file not allowed", `["safetensors"]`, []File{stFile, ggufFile}, checks.Fail},
		// Safetensors and GGUF have fixed headers: a file that is neither is
		// positively not either.
		{"unidentified, header formats only", `["safetensors", "gguf"]`, []File{stFile, onnxFile}, checks.Fail},
		// A pickle is recognised by sniffing, which misses some: an
		// unidentified file might be one.
		{"unidentified, pickle allowed", `["safetensors", "pickle"]`, []File{stFile, onnxFile}, checks.NotTested},
		{"unidentified beside a broken rule", `["pickle"]`, []File{ggufFile, onnxFile}, checks.Fail},
		{"no model file", `["safetensors"]`, nil, checks.NotTested},
	}
	for _, c := range cases {
		r := policy(t, `"allowed_formats": `+c.allowed).Check(Facts{Files: c.files})
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, r.Status, r.Notes, c.want)
		}
		if r.Status == checks.Fail && !has(r, "format-not-allowed") {
			t.Errorf("%s: a FAIL needs its finding: %v", c.name, patterns(r))
		}
		if r.Status != checks.Fail && len(r.Findings) > 0 {
			t.Errorf("%s: findings %v on a %s", c.name, patterns(r), r.Status)
		}
	}
}

// TestPublisherRules: the publisher is the organization of the bound
// manifest's repo URL, and its publisher field when set; each is held to
// the lists. Falsification: read only the repo URL and the publisher-field
// cases pass; skip the deny list and its case passes.
func TestPublisherRules(t *testing.T) {
	const hub = "https://huggingface.co/"
	cases := []struct {
		name     string
		rules    string
		m        *provenance.Manifest
		want     checks.Status
		pattern  string
		inFinder string
	}{
		{"allowed", `"allowed_publishers": ["google"]`, manifest(hub+"google/gemma-3-12b-it", ""), checks.Pass, "", ""},
		{"allowed, case folded", `"allowed_publishers": ["Qwen"]`, manifest(hub+"QWEN/Qwen3-8B", "qwen"), checks.Pass, "", ""},
		{"not allowed", `"allowed_publishers": ["google"]`, manifest(hub+"someone/gemma-3-12b-it", ""), checks.Fail, "publisher-not-allowed", "repo_url"},
		{"publisher field not allowed", `"allowed_publishers": ["google"]`, manifest(hub+"google/gemma", "someone"), checks.Fail, "publisher-not-allowed", "publisher field"},
		{"denied", `"denied_publishers": ["someone"]`, manifest(hub+"someone/model", ""), checks.Fail, "publisher-denied", "repo_url"},
		{"denied in publisher field", `"denied_publishers": ["someone"]`, manifest(hub+"google/model", "someone"), checks.Fail, "publisher-denied", "publisher field"},
		{"not denied", `"denied_publishers": ["someone"]`, manifest(hub+"google/model", "google"), checks.Pass, "", ""},
		{"publisher field only", `"allowed_publishers": ["google"]`, manifest("", "google"), checks.Pass, "", ""},
		{"no manifest", `"allowed_publishers": ["google"]`, nil, checks.NotTested, "", ""},
		{"no manifest, deny list", `"denied_publishers": ["someone"]`, nil, checks.NotTested, "", ""},
		{"not a hub repo URL", `"allowed_publishers": ["google"]`, manifest(hub+"google/gemma/tree/main", ""), checks.NotTested, "", ""},
	}
	for _, c := range cases {
		r := policy(t, c.rules).Check(Facts{Manifest: c.m, Unbound: map[bool]string{true: "no provenance manifest supplied"}[c.m == nil]})
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, r.Status, r.Notes, c.want)
			continue
		}
		if c.pattern != "" && (!has(r, c.pattern) || !strings.Contains(r.Findings[0].Span, c.inFinder)) {
			t.Errorf("%s: findings %+v, want %s from the %s", c.name, r.Findings, c.pattern, c.inFinder)
		}
		if r.Status == checks.NotTested && !strings.Contains(r.Notes, "the publisher is not known") {
			t.Errorf("%s: a rule that cannot be evaluated says why: %s", c.name, r.Notes)
		}
	}
}

// TestSignatureRule: a listed publisher's model needs a verified publisher
// signature. None, or one that does not hold, is a FAIL; one that was not
// verified is not established; a header-only scan checks none.
// Falsification: treat a missing signature as not established and the
// unsigned case fails.
func TestSignatureRule(t *testing.T) {
	m := manifest("https://huggingface.co/acme-ml/model", "")
	sig := func(state string) *provenance.Signature {
		return &provenance.Signature{State: state, Format: "OMS", Signer: "key sha256:abc", Detail: "detail"}
	}
	p := policy(t, `"signature_required": ["acme-ml"]`)
	cases := []struct {
		name    string
		facts   Facts
		want    checks.Status
		pattern string
	}{
		{"verified", Facts{Manifest: m, SignatureChecked: true, Signature: sig(provenance.SignatureVerified)}, checks.Pass, ""},
		{"unsigned", Facts{Manifest: m, SignatureChecked: true}, checks.Fail, "publisher-signature-required"},
		{"does not hold", Facts{Manifest: m, SignatureChecked: true, Signature: sig(provenance.SignatureInvalid)}, checks.Fail, "publisher-signature-required"},
		{"not verified", Facts{Manifest: m, SignatureChecked: true, Signature: sig(provenance.SignatureUnverified)}, checks.NotTested, ""},
		{"header-only scan", Facts{Manifest: m}, checks.NotTested, ""},
		{"publisher not listed", Facts{Manifest: manifest("https://huggingface.co/google/gemma", ""), SignatureChecked: true}, checks.Pass, ""},
		{"publisher unknown", Facts{Unbound: "no provenance manifest supplied", SignatureChecked: true}, checks.NotTested, ""},
		{"publisher unknown, verified", Facts{Unbound: "no provenance manifest supplied", SignatureChecked: true, Signature: sig(provenance.SignatureVerified)}, checks.Pass, ""},
	}
	for _, c := range cases {
		r := p.Check(c.facts)
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, r.Status, r.Notes, c.want)
		}
		if c.pattern != "" && !has(r, c.pattern) {
			t.Errorf("%s: findings %v, want %s", c.name, patterns(r), c.pattern)
		}
	}
}

// TestEveryRuleIsNamed: a PASS says what each rule was checked against, and
// a FAIL names each rule it breaks beside what held.
func TestEveryRuleIsNamed(t *testing.T) {
	p := policy(t, `"allowed_formats": ["safetensors"], "allowed_publishers": ["google"], "denied_publishers": ["someone"], "signature_required": ["acme-ml"]`)
	f := Facts{Files: []File{stFile}, Manifest: manifest("https://huggingface.co/google/gemma", ""), SignatureChecked: true}
	r := p.Check(f)
	if r.Status != checks.Pass {
		t.Fatalf("%s (%s)", r.Status, r.Notes)
	}
	for _, want := range []string{"allowed formats (safetensors): model.safetensors is safetensors", "allowed publishers (google)",
		"denied publishers (someone)", "signature required for (acme-ml)", "repo_url https://huggingface.co/google/gemma"} {
		if !strings.Contains(r.Notes, want) {
			t.Errorf("PASS notes must say %q: %s", want, r.Notes)
		}
	}

	f.Files = []File{pickleFile}
	f.Manifest = manifest("https://huggingface.co/someone/model", "")
	r = p.Check(f)
	if r.Status != checks.Fail {
		t.Fatalf("%s (%s)", r.Status, r.Notes)
	}
	for _, want := range []string{"format-not-allowed", "publisher-not-allowed", "publisher-denied"} {
		if !has(r, want) {
			t.Errorf("findings %v, want %s", patterns(r), want)
		}
	}
	if !strings.Contains(r.Notes, "Held: signature required for (acme-ml)") {
		t.Errorf("a FAIL still says which rules held: %s", r.Notes)
	}
}

// TestNeverLead: the policy grades only PASS, FAIL, and NOT_TESTED; a LEAD
// would be a judgment the rules do not make.
func TestNeverLead(t *testing.T) {
	p := policy(t, `"allowed_formats": ["pickle"], "allowed_publishers": ["a"], "signature_required": ["a"]`)
	for _, f := range []Facts{{}, {Files: []File{onnxFile}}, {Files: []File{stFile}, Manifest: manifest("https://h/a/b", "c")}} {
		if r := p.Check(f); r.Status == checks.Lead {
			t.Errorf("LEAD on %+v", f)
		}
	}
}

func TestManyFilesAreCounted(t *testing.T) {
	var files []File
	for i := 0; i < 20; i++ {
		files = append(files, File{Path: "shard.bin", Format: Pickle, How: "x"})
	}
	r := policy(t, `"allowed_formats": ["safetensors"]`).Check(Facts{Files: files})
	if len(r.Findings) != maxFindings+1 || r.Findings[maxFindings].Span != "and 12 more" {
		t.Errorf("%d findings, last %+v", len(r.Findings), r.Findings[len(r.Findings)-1])
	}
}
