package engine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/render"
	"github.com/defilantech/socair/internal/render/cyclonedx"
	"github.com/defilantech/socair/internal/render/sarif"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
	"github.com/defilantech/socair/internal/tier2/tier2test"
)

// sentinel names the directory every host path in these tests lies under:
// the inputs, the helpers, the scan snapshots, HOME, and TMPDIR. A report
// that carries any of those paths, whole or in part, carries the sentinel.
const sentinel = "SOCAIRHOSTPATH"

// sentinelHost makes the sentinel directory and points HOME, TMPDIR, and the
// scan snapshots into it. bin holds the helpers: a link to this test binary
// under each name (run through the link, a helper's own path is a sentinel
// path), a file that is not executable, and a script whose interpreter does
// not exist.
func sentinelHost(t *testing.T) (root, bin string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), sentinel)
	for _, d := range []string{"home", "tmp", "scan", "bin", "inputs"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("TMPDIR", filepath.Join(root, "tmp"))
	t.Setenv("SOCAIR_SCAN_TMP", filepath.Join(root, "scan"))
	for _, k := range []string{"SOCAIR_FEED", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_REPO_MIRROR", "SOCAIR_TOKENIZER_REFERENCE",
		"SOCAIR_TEMPLATE_REFERENCE", "SOCAIR_LICENSE_POLICY", "SOCAIR_ACCEPTED_BY", "SOCAIR_OMS_SIGNATURE", "SOCAIR_SIGSTORE_VERIFIER"} {
		t.Setenv(k, "")
	}
	noTier2(t)

	bin = filepath.Join(root, "bin")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"socair-probe", "socair-sigstore"} {
		if err := os.Symlink(exe, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "not-executable"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "no-interpreter"), []byte("#!"+filepath.Join(bin, "no-such-interpreter")+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root, bin
}

// carriesNoHostPath fails if the sentinel appears in the report or in any
// rendering a reader files: the JSON, the HTML, SARIF, and the CycloneDX BOM.
// (The PDF reads the same fields as the HTML, through compressed streams.)
func carriesNoHostPath(t *testing.T, name string, d *report.Document) {
	t.Helper()
	outputs := map[string][]byte{}
	js, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	outputs["report JSON"] = js
	for kind, r := range map[string]func(*bytes.Buffer, *report.Document) error{
		"HTML":      func(b *bytes.Buffer, d *report.Document) error { return render.Render(b, d) },
		"SARIF":     func(b *bytes.Buffer, d *report.Document) error { return sarif.Render(b, d) },
		"CycloneDX": func(b *bytes.Buffer, d *report.Document) error { return cyclonedx.Render(b, d) },
	} {
		var b bytes.Buffer
		if err := r(&b, d); err != nil {
			t.Fatalf("%s: %s: %v", name, kind, err)
		}
		outputs[kind] = b.Bytes()
	}
	for kind, out := range outputs {
		if i := bytes.Index(out, []byte(sentinel)); i >= 0 {
			t.Errorf("%s: the %s carries a host path: ...%s...", name, kind, out[max(0, i-120):min(len(out), i+80)])
		}
	}
}

// notRunReason is why the report says Tier 2 did not run.
func notRunReason(d *report.Document) string {
	for _, c := range d.OutOfScope.NotRun {
		if report.IsTier2Check(c.Name) {
			return c.Reason
		}
	}
	return ""
}

// TestHelperOutputCarriesNoHostPath: a filed report must not carry a path
// from the scanning host (#170). The two external helpers are handed host
// paths, and what they write can reach a report: the Tier 2 probe helper's
// standard error, start failure, timeout, and answer reach the Tier 2 section,
// a Tier 2 row, and the not-run reason; the keyless Sigstore verifier's reach
// the provenance row and the publisher signing state. Every input, helper,
// snapshot, HOME, and TMPDIR here lies under the sentinel directory, each
// helper repeats every path it was handed or fails to start, and no
// rendering of the report may contain the sentinel. Each report must still
// say that the helper failed, and why, naming files by their base names and
// the environment's paths by their variables. Falsification: quote a
// helper's standard error or an exec error as it is, or record a measurement
// as the helper wrote it, and this fails.
func TestHelperOutputCarriesNoHostPath(t *testing.T) {
	root, bin := sentinelHost(t)
	inputs := filepath.Join(root, "inputs")
	fixture := filepath.Join(inputs, "fixture.safetensors")
	if err := os.WriteFile(fixture, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	modelDir := filepath.Join(inputs, "model-dir")
	if err := os.Rename(modelRepo(t, nil), modelDir); err != nil {
		t.Fatal(err)
	}
	pack := filepath.Join(inputs, "probe-pack.json")
	if err := os.WriteFile(pack, []byte(`["The capital of France is"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := tier2test.Engine(t, "engine", tier2test.Echo)

	tier2Cases := []struct {
		name, helper, mode, path string
		timeout                  string
		want                     []string
		row                      bool
	}{
		{"helper fails, echoing its paths", "socair-probe", tier2test.EchoFail, fixture, "",
			[]string{"the Tier 2 probe helper failed: exit status 1: probe failed:", "helper socair-probe", "artifact fixture.safetensors",
				"probe pack probe-pack.json", "HOME $HOME", "TMPDIR $TMPDIR"}, false},
		{"answer refused on a path", "socair-probe", tier2test.EchoRefused, fixture, "",
			[]string{`answer was refused: json: unknown field "fixture.safetensors"`}, false},
		{"measurement repeats its paths", "socair-probe", tier2test.EchoMeasured, fixture, "",
			[]string{"helper socair-probe, artifact fixture.safetensors, probe pack probe-pack.json, HOME $HOME, TMPDIR $TMPDIR", "fixture.safetensors 1"}, true},
		{"measurement on a model directory", "socair-probe", tier2test.EchoMeasured, modelDir, "",
			[]string{"artifact model-dir,", "model-dir 1"}, true},
		{"helper times out", "socair-probe", tier2test.Hang, fixture, "1s",
			[]string{"the Tier 2 probe helper did not answer within 1s"}, false},
		{"helper is not executable", "not-executable", tier2test.EchoFail, fixture, "",
			[]string{"the Tier 2 probe helper not-executable could not be started: permission denied"}, false},
		{"helper's interpreter is missing", "no-interpreter", tier2test.EchoFail, fixture, "",
			[]string{"the Tier 2 probe helper no-interpreter could not be started:"}, false},
	}
	for _, c := range tier2Cases {
		noTier2(t)
		t.Setenv("SOCAIR_TIER2_HELPER", filepath.Join(bin, c.helper))
		t.Setenv("SOCAIR_TIER2_ENDPOINT", engine.URL)
		t.Setenv("SOCAIR_TIER2_PROBES", pack)
		t.Setenv("SOCAIR_TIER2_TIMEOUT", c.timeout)
		t.Setenv(tier2test.ModeVar, c.mode)
		d, err := Scan(c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Fatalf("%s: %v", c.name, problems)
		}
		carriesNoHostPath(t, c.name, d)
		got := notRunReason(d)
		if c.row {
			r := row(d, tier2test.CanaryCheck)
			got = r.Notes + " | " + r.Evidence
		}
		t.Logf("%s: %s", c.name, got)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q does not say %q", c.name, got, w)
			}
		}
	}

	// A check that cannot read a file of the snapshot names it in its row. A
	// shard index can name a path under a regular file, which no read
	// reaches; the operating system's error names the snapshot directory.
	noTier2(t)
	indexed := filepath.Join(inputs, "indexed-dir")
	if err := os.Rename(modelRepo(t, map[string]string{
		"model.safetensors.index.json": `{"weight_map":{"w":"config.json/model.safetensors"}}`,
	}), indexed); err != nil {
		t.Fatal(err)
	}
	d, err := Scan(indexed)
	if err != nil {
		t.Fatal(err)
	}
	carriesNoHostPath(t, "unreadable shard", d)
	if r := row(d, "Format and structure"); !strings.Contains(r.Notes, "config.json/model.safetensors (unreadable: not a directory)") {
		t.Errorf("unreadable shard: %q does not name the shard and the cause", r.Notes)
	}

	// The keyless verifier reads a copy of the reference implementation's
	// keyless vector, the trust root, and the identity policy, all under
	// the sentinel.
	publisherEnv(t, "", "")
	keyless := filepath.Join(inputs, "keyless")
	if err := os.Rename(vectorCopy(t, "keyless"), keyless); err != nil {
		t.Fatal(err)
	}
	trustRoot, err := os.ReadFile(filepath.Join(omsVectors, "keys", "trusted-root-public-good.json"))
	if err != nil {
		t.Fatal(err)
	}
	trustRootPath := filepath.Join(inputs, "trusted_root.json")
	ids := filepath.Join(inputs, "identities")
	if err := os.WriteFile(trustRootPath, trustRoot, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ids, []byte("https://issuer.example releases@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noTier2(t)
	t.Setenv("SOCAIR_SIGSTORE_TRUSTED_ROOT", trustRootPath)
	t.Setenv("SOCAIR_SIGSTORE_IDENTITIES", ids)
	defer func(d time.Duration) { keylessTimeout = d }(keylessTimeout)

	for _, c := range []struct {
		name, verifier, mode string
		want                 []string
	}{
		{"verifier fails, echoing its paths", "socair-sigstore", "echo-fail",
			[]string{"the keyless verifier failed: exit status 2: socair-sigstore: bad request: verifier socair-sigstore, trusted root trusted_root.json, HOME $HOME, TMPDIR $TMPDIR"}},
		{"verdict detail repeats its paths", "socair-sigstore", "echo-unverified",
			[]string{"verifier socair-sigstore, trusted root trusted_root.json, HOME $HOME, TMPDIR $TMPDIR"}},
		{"verdict state is a path", "socair-sigstore", "echo-state",
			[]string{`the keyless verifier answered "trusted_root.json"`}},
		{"verifier times out", "socair-sigstore", "hang",
			[]string{"the keyless verifier did not answer within 1s"}},
		{"verifier is not executable", "not-executable", "echo-fail",
			[]string{"the keyless verifier not-executable could not be started: permission denied"}},
		{"verifier's interpreter is missing", "no-interpreter", "echo-fail",
			[]string{"the keyless verifier no-interpreter could not be started:"}},
	} {
		// Only the hanging verifier gets the short bound. The others answer,
		// but under the race detector on a CI runner the fake verifier, this
		// test binary started again, can take longer than a second to.
		keylessTimeout = time.Minute
		if c.mode == "hang" {
			keylessTimeout = time.Second
		}
		t.Setenv("SOCAIR_SIGSTORE_VERIFIER", filepath.Join(bin, c.verifier))
		t.Setenv("SOCAIR_FAKE_SIGSTORE", c.mode)
		d, err := Scan(keyless)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if problems := report.Validate(d); len(problems) != 0 {
			t.Fatalf("%s: %v", c.name, problems)
		}
		carriesNoHostPath(t, c.name, d)
		r := row(d, provRow)
		t.Logf("%s: %s", c.name, d.Artifact.PublisherSigningState)
		for _, w := range c.want {
			if r.Status != report.StatusNotTested || !strings.Contains(r.Notes, w) || !strings.Contains(d.Artifact.PublisherSigningState, w) {
				t.Errorf("%s: provenance %s, %q, signing state %q, want %q", c.name, r.Status, r.Notes, d.Artifact.PublisherSigningState, w)
			}
		}
	}
}

// TestNameSnapshotNamesTheArtifact: a check that cannot read a file of the
// snapshot quotes an error naming the snapshot's path on the host; the
// finished document names the artifact there instead, in every field. A
// header-only sweep reads the operator's own path, whose directory can be any
// directory the artifact's own text also names, so that is left alone.
// Falsification: skip nameSnapshot, or name a header sweep's directory, and
// this fails.
func TestNameSnapshotNamesTheArtifact(t *testing.T) {
	private := filepath.Join(t.TempDir(), "socair-scan-1")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(private, "model.gguf")
	if err := os.WriteFile(snap, []byte("GGUF"), 0o400); err != nil {
		t.Fatal(err)
	}
	doc := func() *report.Document {
		d := &report.Document{}
		d.Artifact.FileName = "model.gguf"
		d.Artifact.PublisherSigningState = "invalid (OMS): open " + snap + ": input/output error"
		d.Checks = []report.CheckResult{{Name: "Format and structure", Notes: "gguf: reading key 3: read " + snap + ": input/output error",
			Evidence: "in " + private + " and " + filepath.Join(private, "other")}}
		d.OutOfScope.UnparsedFormats = []string{snap + ": unreadable"}
		return d
	}
	d := doc()
	nameSnapshot(d, snap, true)
	js, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), filepath.Dir(private)) {
		t.Fatalf("the snapshot's path survives: %s", js)
	}
	if d.Checks[0].Notes != "gguf: reading key 3: read model.gguf: input/output error" ||
		d.Checks[0].Evidence != "in socair-scan-1 and socair-scan-1/other" ||
		d.OutOfScope.UnparsedFormats[0] != "model.gguf: unreadable" ||
		d.Artifact.PublisherSigningState != "invalid (OMS): open model.gguf: input/output error" {
		t.Errorf("named %s", js)
	}

	h := doc()
	nameSnapshot(h, snap, false)
	if h.Checks[0].Notes != "gguf: reading key 3: read model.gguf: input/output error" || !strings.Contains(h.Checks[0].Evidence, private) {
		t.Errorf("a header sweep: %q / %q", h.Checks[0].Notes, h.Checks[0].Evidence)
	}
}
