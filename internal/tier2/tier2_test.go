package tier2_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2"
	"github.com/defilantech/socair/internal/tier2/tier2test"
)

// TestMain lets the test binary stand in for the probe helper: with
// tier2test.ModeVar set it answers one request and exits.
func TestMain(m *testing.M) {
	tier2test.Serve()
	os.Exit(m.Run())
}

var artifact = tier2.Artifact{Path: "/snapshot/model.gguf", SHA256: strings.Repeat("a", 64), FileName: "model.gguf", Format: "GGUF"}

// config runs this test binary as the helper, in mode, against endpoint.
func config(t *testing.T, mode, endpoint string) *tier2.Config {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(tier2test.ModeVar, mode)
	return &tier2.Config{Helper: exe, Endpoint: endpoint, Decoding: tier2.DefaultDecoding(), Timeout: time.Minute}
}

// The helper drives the engine, and what it reports becomes a section whose
// node classes are keyed by hashes Socair computed and labelled as the
// helper's report.
func TestRunDrivesTheEngine(t *testing.T) {
	e := tier2test.Engine(t, "fake-vllm", tier2test.Echo)
	cfg := config(t, tier2test.Differential, e.URL)
	cfg.NodeClass = &report.NodeClass{Schema: report.NodeClassSchema, GPUModel: "NVIDIA H100 80GB HBM3", Driver: "570.86.15"}

	sec, err := tier2.Run(context.Background(), cfg, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if e.Calls.Load() != int64(2*len(tier2test.Prompts)) {
		t.Fatalf("the engine served %d completions, want %d", e.Calls.Load(), 2*len(tier2test.Prompts))
	}
	if len(sec.Measurements) != 1 || len(sec.NodeClasses) != 1 {
		t.Fatalf("section %+v", sec)
	}
	m, nc := sec.Measurements[0], sec.NodeClasses[0]
	if m.Outcome != report.OutcomeMeasured || *m.Score != 1 || m.DatasetDigest != tier2test.DatasetDigest() {
		t.Errorf("measurement %+v", m)
	}
	if nc.Facts.GPUModel != "NVIDIA H100 80GB HBM3" || nc.Facts.EngineName != "fake-vllm" {
		t.Errorf("node class facts %+v", nc.Facts)
	}
	if nc.Hash != nc.Facts.Hash() || m.NodeClass != nc.Hash || nc.ReportedBy != report.NodeClassReportedByHelper {
		t.Errorf("node class %s (%s), measurement points at %s", nc.Hash, nc.ReportedBy, m.NodeClass)
	}
	if sec.Statement != report.Tier2Statement || sec.Helper != "tier2test 1" {
		t.Errorf("section header %q %q", sec.Statement, sec.Helper)
	}
}

// A divergence between two engines is a LEAD, recorded against both classes.
func TestRunDivergenceIsALead(t *testing.T) {
	a := tier2test.Engine(t, "engine-a", tier2test.Echo)
	b := tier2test.Engine(t, "engine-b", func(p string) string {
		if strings.HasPrefix(p, "Water") {
			return " 90 degrees"
		}
		return tier2test.Echo(p)
	})
	cfg := config(t, tier2test.Differential, a.URL)
	cfg.ReferenceEndpoint = b.URL
	sec, err := tier2.Run(context.Background(), cfg, artifact)
	if err != nil {
		t.Fatal(err)
	}
	m := sec.Measurements[0]
	if m.Outcome != report.OutcomeLead || *m.Score != 0.75 || m.ReferenceNodeClass == "" || len(sec.NodeClasses) != 2 {
		t.Fatalf("measurement %+v over %d classes", m, len(sec.NodeClasses))
	}
	if b.Calls.Load() == 0 {
		t.Error("the reference engine was not probed")
	}
}

// Every way a helper can answer out of protocol is refused, with a reason
// that names it. Falsification: decode leniently, skip a bound, or accept a
// pass outcome, and the matching case fails.
func TestRunRefusesOutOfProtocol(t *testing.T) {
	e := tier2test.Engine(t, "fake", tier2test.Echo)
	for mode, want := range map[string]string{
		tier2test.UnknownField:     `unknown field "verdict"`,
		tier2test.Oversize:         "answer is over 1048576 bytes",
		tier2test.Crash:            "failed: exit status 3: probe pack  [31mexploded [0m",
		tier2test.PassOutcome:      `outcome "pass" is not one of measured, lead, fail, error`,
		tier2test.Trailing:         "trailing data after the answer",
		tier2test.NotJSON:          "answer was refused: invalid character",
		tier2test.UnknownNodeClass: `node_class "gpu-0" is not an id in node_classes`,
		tier2test.JudgedFail:       "a FAIL needs a deterministic, matcher-confirmed scorer",
		tier2test.WrongProtocol:    `protocol "socair.tier2/v0"`,
	} {
		_, err := tier2.Run(context.Background(), config(t, mode, e.URL), artifact)
		if !errors.Is(err, tier2.ErrHelper) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want ErrHelper naming %q", mode, err, want)
		}
	}
}

// A helper that does not answer in time is stopped and refused. The
// falsification is the time: without the limit this test waits a minute.
func TestRunTimesOut(t *testing.T) {
	cfg := config(t, tier2test.Hang, "http://127.0.0.1:1")
	cfg.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := tier2.Run(context.Background(), cfg, artifact)
	if !errors.Is(err, tier2.ErrHelper) || !strings.Contains(err.Error(), "did not answer within 300ms") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatalf("the hung helper ran %s", time.Since(start))
	}
}

// The helper is third-party code beside the model: it gets no token or proxy
// setting of Socair's, only what starts a program and its own SOCAIR_PROBE_*.
// Falsification: pass os.Environ() through and HF_TOKEN appears.
func TestHelperGetsNoSecrets(t *testing.T) {
	e := tier2test.Engine(t, "fake", tier2test.Echo)
	t.Setenv("HF_TOKEN", "hf_secret")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
	t.Setenv("SOCAIR_PROBE_API_KEY", "for-the-endpoint")
	sec, err := tier2.Run(context.Background(), config(t, tier2test.Env, e.URL), artifact)
	if err != nil {
		t.Fatal(err)
	}
	seen := " " + sec.Measurements[0].Notes + " "
	for _, k := range []string{"HF_TOKEN", "HTTPS_PROXY", "SOCAIR_ACCEPTED_BY"} {
		if strings.Contains(seen, " "+k+" ") {
			t.Errorf("the helper was given %s", k)
		}
	}
	if !strings.Contains(seen, " SOCAIR_PROBE_API_KEY ") || !strings.Contains(seen, " PATH ") {
		t.Errorf("the helper must get PATH and its own SOCAIR_PROBE_* settings, got %s", seen)
	}
}

// The Python helper's example answer (tools/socair-probe), which its own
// tests hold to the shape it writes, decodes strictly and forms a valid
// section. Falsification: rename a field on either side and one of the two
// tests fails.
func TestPythonHelperExampleIsAccepted(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "tools", "socair-probe", "testdata", "example-response.json"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tier2.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := tier2.Section(resp)
	if err != nil {
		t.Fatal(err)
	}
	if sec.Helper != "socair-probe 0.1.0" || len(sec.NodeClasses) != 2 || sec.Measurements[0].Outcome != report.OutcomeMeasured {
		t.Fatalf("section %+v", sec)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	for name, body := range map[string]string{
		"nested unknown field": `{"protocol":"socair.tier2/v1","helper":{"name":"x","version":"1","build":"y"},"node_classes":[],"measurements":[]}`,
		"unknown fact":         `{"protocol":"socair.tier2/v1","helper":{"name":"x"},"node_classes":[{"id":"a","facts":{"gpu":"H100"}}],"measurements":[]}`,
		"two answers":          `{"protocol":"socair.tier2/v1"} {}`,
		"wrong type":           `{"protocol":"socair.tier2/v1","measurements":[{"n":"eight"}]}`,
	} {
		if _, err := tier2.Decode([]byte(body)); !errors.Is(err, tier2.ErrHelper) {
			t.Errorf("%s: decoded, want a refusal", name)
		}
	}
}

// Node classes are keyed by Socair's own hash, so a helper's ids are only
// labels: two ids with the same facts are one class, and a class no
// measurement ran on is not recorded.
func TestSectionKeysClassesByTheirFacts(t *testing.T) {
	m := report.Measurement{
		Check: "Serving-stack differential (Tier 2)", Suite: "s", SuiteVersion: "1", DatasetDigest: tier2test.DatasetDigest(),
		Scorer: report.ScorerDeterministic, N: 1, Score: new(float64), Decoding: tier2.DefaultDecoding(), Engine: "vllm",
		NodeClass: "a", ReferenceNodeClass: "b", StartedUTC: "2026-10-09T10:00:00Z", EndedUTC: "2026-10-09T10:00:01Z", Outcome: report.OutcomeMeasured,
	}
	sec, err := tier2.Section(&tier2.Response{
		Protocol: tier2.Protocol, Helper: tier2.HelperInfo{Name: "h"},
		NodeClasses: []tier2.ReportedNodeClass{
			{ID: "a", Facts: report.NodeClass{EngineName: "vllm"}},
			{ID: "b", Facts: report.NodeClass{EngineName: "vllm"}},
			{ID: "unused", Facts: report.NodeClass{EngineName: "sglang"}},
		},
		Measurements: []report.Measurement{m},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sec.NodeClasses) != 1 || sec.Measurements[0].NodeClass != sec.Measurements[0].ReferenceNodeClass {
		t.Fatalf("classes %+v, measurement %+v", sec.NodeClasses, sec.Measurements[0])
	}
}

func TestFromEnv(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	clear := func() {
		for _, k := range []string{"SOCAIR_TIER2_HELPER", "SOCAIR_TIER2_ENDPOINT", "SOCAIR_TIER2_REFERENCE_ENDPOINT", "SOCAIR_TIER2_PROBES", "SOCAIR_TIER2_NODE_CLASS", "SOCAIR_TIER2_TIMEOUT"} {
			t.Setenv(k, "")
		}
	}

	clear()
	if cfg, err := tier2.FromEnv(); cfg != nil || err != nil {
		t.Fatalf("unconfigured: %+v, %v; Tier 2 must not run by default", cfg, err)
	}

	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"endpoint without helper": {map[string]string{"SOCAIR_TIER2_ENDPOINT": "http://127.0.0.1:8000"}, "SOCAIR_TIER2_HELPER is not"},
		"helper is a directory":   {map[string]string{"SOCAIR_TIER2_HELPER": dir, "SOCAIR_TIER2_ENDPOINT": "http://x"}, "is not a file"},
		"helper without endpoint": {map[string]string{"SOCAIR_TIER2_HELPER": exe}, "needs SOCAIR_TIER2_ENDPOINT"},
		"not a URL":               {map[string]string{"SOCAIR_TIER2_HELPER": exe, "SOCAIR_TIER2_ENDPOINT": "localhost:8000"}, "is not an http(s) URL"},
		"credentials in the URL":  {map[string]string{"SOCAIR_TIER2_HELPER": exe, "SOCAIR_TIER2_ENDPOINT": "http://u:p@x"}, "carries credentials"},
		"bad reference":           {map[string]string{"SOCAIR_TIER2_HELPER": exe, "SOCAIR_TIER2_ENDPOINT": "http://x", "SOCAIR_TIER2_REFERENCE_ENDPOINT": "ftp://y"}, "SOCAIR_TIER2_REFERENCE_ENDPOINT"},
		"bad timeout":             {map[string]string{"SOCAIR_TIER2_HELPER": exe, "SOCAIR_TIER2_ENDPOINT": "http://x", "SOCAIR_TIER2_TIMEOUT": "forever"}, "SOCAIR_TIER2_TIMEOUT"},
		"unknown node-class fact": {map[string]string{"SOCAIR_TIER2_HELPER": exe, "SOCAIR_TIER2_ENDPOINT": "http://x", "SOCAIR_TIER2_NODE_CLASS": write("nc.json", `{"gpu":"H100"}`)}, "unknown field"},
		"other node-class schema": {map[string]string{"SOCAIR_TIER2_HELPER": exe, "SOCAIR_TIER2_ENDPOINT": "http://x", "SOCAIR_TIER2_NODE_CLASS": write("nc2.json", `{"schema":"x/v2"}`)}, "schema"},
	} {
		clear()
		for k, v := range c.env {
			t.Setenv(k, v)
		}
		if _, err := tier2.FromEnv(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error naming %q", name, err, c.want)
		}
	}

	clear()
	t.Setenv("SOCAIR_TIER2_HELPER", exe)
	t.Setenv("SOCAIR_TIER2_ENDPOINT", "http://127.0.0.1:8000/")
	t.Setenv("SOCAIR_TIER2_TIMEOUT", "45m")
	t.Setenv("SOCAIR_TIER2_PROBES", "builtin:greedy")
	t.Setenv("SOCAIR_TIER2_NODE_CLASS", write("ok.json", `{"gpu_model":"NVIDIA B200","gpu_count":8,"cuda_graphs":true}`))
	cfg, err := tier2.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "http://127.0.0.1:8000" || cfg.Timeout != 45*time.Minute || cfg.ProbePack != "builtin:greedy" ||
		cfg.NodeClass.GPUModel != "NVIDIA B200" || cfg.NodeClass.Schema != report.NodeClassSchema || !*cfg.NodeClass.CUDAGraphs {
		t.Fatalf("config %+v, node class %+v", cfg, cfg.NodeClass)
	}
	if req := cfg.NewRequest(artifact); req.Limits.MaxResponseBytes != tier2.MaxResponse || req.Limits.TimeoutSeconds != 2700 || req.Decoding.Temperature != 0 {
		t.Errorf("request %+v", req)
	}
}
