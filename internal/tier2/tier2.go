// Package tier2 runs the opt-in Tier 2 probe helper: an external program,
// named by SOCAIR_TIER2_HELPER, that drives the site's own inference engine
// and returns measurements (docs/tier2.md).
//
// Socair trusts the helper no further than the protocol. Its answer must
// arrive within a time limit and a size limit, decode with no unknown field,
// and form a well-formed Tier 2 section (report.Tier2.Problems), or it is
// refused with the reason. What the helper says about the hardware is
// recorded as its report, keyed by a hash Socair computes, never by one the
// helper supplies.
package tier2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/defilantech/socair/internal/report"
)

// Protocol names this version of the request and the response.
const Protocol = "socair.tier2/v1"

// Bounds on a helper's answer. The request tells the helper the first three.
const (
	MaxResponse     = 1 << 20
	MaxMeasurements = 256
	MaxNodeClasses  = 16
	maxNodeClass    = 16 << 10 // canonical bytes of one node class
	maxName         = 200
	maxText         = 4096
	maxMetrics      = 64
	stderrTail      = 400
)

// DefaultTimeout bounds one helper run when SOCAIR_TIER2_TIMEOUT is unset.
const DefaultTimeout = 30 * time.Minute

// ErrHelper marks a helper run that produced nothing Socair can record: it
// failed, ran out of time, or answered out of protocol. Tier 2 did not run.
var ErrHelper = errors.New("the Tier 2 probe helper")

// Config is the operator's Tier 2 configuration.
type Config struct {
	// Helper is the helper executable (SOCAIR_TIER2_HELPER).
	Helper string
	// Endpoint is the OpenAI-compatible base URL of the engine serving the
	// artifact (SOCAIR_TIER2_ENDPOINT); ReferenceEndpoint, optional, is the
	// engine it is compared with (SOCAIR_TIER2_REFERENCE_ENDPOINT).
	Endpoint          string
	ReferenceEndpoint string
	// ProbePack names the probe set, a path or a name the helper knows
	// (SOCAIR_TIER2_PROBES); empty means the helper's own default.
	ProbePack string
	// NodeClass is what the operator declares about the node
	// (SOCAIR_TIER2_NODE_CLASS); the helper may complete it, and the report
	// records the helper's account.
	NodeClass *report.NodeClass
	Decoding  report.Decoding
	Timeout   time.Duration
}

// Artifact identifies the attested artifact to the helper. Path is the scan's
// read-only snapshot, so a helper that loads the model itself loads the
// attested bytes.
type Artifact struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	FileName string `json:"file_name"`
	Format   string `json:"format"`
}

// Request is what Socair writes to the helper's standard input.
type Request struct {
	Protocol          string            `json:"protocol"`
	Artifact          Artifact          `json:"artifact"`
	Endpoint          string            `json:"endpoint"`
	ReferenceEndpoint string            `json:"reference_endpoint,omitempty"`
	ProbePack         string            `json:"probe_pack,omitempty"`
	NodeClass         *report.NodeClass `json:"node_class"`
	Decoding          report.Decoding   `json:"decoding"`
	Limits            Limits            `json:"limits"`
}

// Limits tells the helper the bounds its answer is held to.
type Limits struct {
	MaxResponseBytes int `json:"max_response_bytes"`
	MaxMeasurements  int `json:"max_measurements"`
	TimeoutSeconds   int `json:"timeout_seconds"`
}

// Response is what the helper writes to its standard output. Each
// measurement names its node classes by an id from NodeClasses; Socair
// replaces the ids with the hashes it computes.
type Response struct {
	Protocol     string               `json:"protocol"`
	Helper       HelperInfo           `json:"helper"`
	NodeClasses  []ReportedNodeClass  `json:"node_classes"`
	Measurements []report.Measurement `json:"measurements"`
}

// HelperInfo is how the helper names itself.
type HelperInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ReportedNodeClass is a node class as the helper reports it.
type ReportedNodeClass struct {
	ID    string           `json:"id"`
	Facts report.NodeClass `json:"facts"`
}

// DefaultDecoding is greedy: temperature 0, top_p 1, 32 tokens, seed 0. A
// suite that samples records the decoding it used in its measurement.
func DefaultDecoding() report.Decoding {
	seed := int64(0)
	return report.Decoding{Temperature: 0, TopP: 1, MaxTokens: 32, Seed: &seed}
}

// FromEnv reads the Tier 2 configuration. It returns nil when no helper is
// configured: Tier 2 does not run, which is the default. A partial or
// malformed configuration is an error, because an operator who set an
// endpoint and no helper would otherwise get a report that quietly ran no
// Tier 2.
func FromEnv() (*Config, error) {
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	helper := get("SOCAIR_TIER2_HELPER")
	if helper == "" {
		for _, k := range []string{"SOCAIR_TIER2_ENDPOINT", "SOCAIR_TIER2_REFERENCE_ENDPOINT", "SOCAIR_TIER2_PROBES", "SOCAIR_TIER2_NODE_CLASS", "SOCAIR_TIER2_TIMEOUT"} {
			if get(k) != "" {
				return nil, fmt.Errorf("%s is set but SOCAIR_TIER2_HELPER is not; Tier 2 runs only through a probe helper", k)
			}
		}
		return nil, nil
	}
	if fi, err := os.Stat(helper); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("SOCAIR_TIER2_HELPER %q is not a file", helper)
	}
	cfg := &Config{Helper: helper, ProbePack: get("SOCAIR_TIER2_PROBES"), Decoding: DefaultDecoding(), Timeout: DefaultTimeout}
	if get("SOCAIR_TIER2_ENDPOINT") == "" {
		return nil, errors.New("SOCAIR_TIER2_HELPER needs SOCAIR_TIER2_ENDPOINT, the OpenAI-compatible base URL of the engine serving this artifact")
	}
	var err error
	if cfg.Endpoint, err = endpoint("SOCAIR_TIER2_ENDPOINT", get("SOCAIR_TIER2_ENDPOINT")); err != nil {
		return nil, err
	}
	if v := get("SOCAIR_TIER2_REFERENCE_ENDPOINT"); v != "" {
		if cfg.ReferenceEndpoint, err = endpoint("SOCAIR_TIER2_REFERENCE_ENDPOINT", v); err != nil {
			return nil, err
		}
	}
	if v := get("SOCAIR_TIER2_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second || d > 24*time.Hour {
			return nil, fmt.Errorf("SOCAIR_TIER2_TIMEOUT %q: want a duration from 1s to 24h, e.g. 45m", v)
		}
		cfg.Timeout = d
	}
	if v := get("SOCAIR_TIER2_NODE_CLASS"); v != "" {
		if cfg.NodeClass, err = readNodeClass(v); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func endpoint(name, v string) (string, error) {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%s %q is not an http(s) URL", name, v)
	}
	if u.User != nil {
		return "", fmt.Errorf("%s carries credentials; give the helper a key through SOCAIR_PROBE_API_KEY instead", name)
	}
	return strings.TrimRight(v, "/"), nil
}

// readNodeClass reads the operator's node-class declaration: the node-class
// record's JSON fields (docs/tier2.md), any subset, no unknown field.
func readNodeClass(p string) (*report.NodeClass, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("SOCAIR_TIER2_NODE_CLASS: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxNodeClass))
	dec.DisallowUnknownFields()
	var n report.NodeClass
	if err := dec.Decode(&n); err != nil {
		return nil, fmt.Errorf("SOCAIR_TIER2_NODE_CLASS %s is not a node-class record: %v", p, err)
	}
	if n.Schema != "" && n.Schema != report.NodeClassSchema {
		return nil, fmt.Errorf("SOCAIR_TIER2_NODE_CLASS %s: schema %q, want %q", p, n.Schema, report.NodeClassSchema)
	}
	n.Schema = report.NodeClassSchema
	return &n, nil
}

// NewRequest is the request for one artifact.
func (c *Config) NewRequest(a Artifact) Request {
	return Request{
		Protocol:          Protocol,
		Artifact:          a,
		Endpoint:          c.Endpoint,
		ReferenceEndpoint: c.ReferenceEndpoint,
		ProbePack:         c.ProbePack,
		NodeClass:         c.NodeClass,
		Decoding:          c.Decoding,
		Limits:            Limits{MaxResponseBytes: MaxResponse, MaxMeasurements: MaxMeasurements, TimeoutSeconds: int(c.Timeout / time.Second)},
	}
}

// Run sends the helper its request and returns the Tier 2 section it
// measured. Every failure wraps ErrHelper and names its reason.
func Run(ctx context.Context, c *Config, a Artifact) (*report.Tier2, error) {
	req, err := json.Marshal(c.NewRequest(a))
	if err != nil {
		return nil, err
	}
	out, err := invoke(ctx, c, req)
	if err != nil {
		return nil, err
	}
	resp, err := Decode(out)
	if err != nil {
		return nil, err
	}
	return Section(resp)
}

// helperEnv is the environment a helper runs with: enough to start a program
// and reach the endpoint, and SOCAIR_PROBE_* for the helper's own settings
// (SOCAIR_PROBE_API_KEY, for one). Nothing else of Socair's environment, such
// as HF_TOKEN or proxy settings, reaches third-party code that sits next to
// the model.
var helperEnvKeys = map[string]bool{
	"PATH": true, "HOME": true, "LANG": true, "LC_ALL": true, "LC_CTYPE": true,
	"TMPDIR": true, "TMP": true, "TEMP": true, "SYSTEMROOT": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
}

func helperEnv(environ []string) []string {
	var out []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if helperEnvKeys[k] || strings.HasPrefix(k, "SOCAIR_PROBE_") {
			out = append(out, kv)
		}
	}
	return out
}

func invoke(ctx context.Context, c *Config, req []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Helper)
	cmd.Env = helperEnv(os.Environ())
	cmd.Stdin = bytes.NewReader(req)
	stdout := &capped{max: MaxResponse}
	stderr := &tail{max: stderrTail}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// A helper's children can hold its output open after it is killed; stop
	// waiting for them shortly after.
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	switch {
	case stdout.over:
		return nil, fmt.Errorf("%w's answer is over %d bytes", ErrHelper, MaxResponse)
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("%w did not answer within %s", ErrHelper, c.Timeout)
	case err != nil:
		return nil, fmt.Errorf("%w failed: %v%s", ErrHelper, err, stderr.detail())
	}
	return stdout.buf.Bytes(), nil
}

// capped keeps at most max bytes and fails the write past them, which closes
// the pipe on a helper that keeps writing.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.over = true
		return 0, errors.New("answer over its bound")
	}
	return c.buf.Write(p)
}

// tail keeps the last max bytes of the helper's standard error, for the
// reason a failed run gives.
type tail struct {
	b   []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tail) detail() string {
	s := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return ' '
		}
		return r
	}, string(t.b)))
	if s == "" {
		return ""
	}
	return ": " + s
}

func refused(format string, args ...any) error {
	return fmt.Errorf("%w's answer was refused: %s", ErrHelper, fmt.Sprintf(format, args...))
}

// Decode reads a helper's answer strictly: one JSON object, no unknown field
// at any level, nothing after it. Run reads at most MaxResponse bytes of it.
func Decode(b []byte) (*Response, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Response
	if err := dec.Decode(&r); err != nil {
		return nil, refused("%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, refused("trailing data after the answer")
	}
	return &r, nil
}

// Section turns a decoded answer into the report's Tier 2 section: node
// classes keyed by the hash of their facts and labelled as the helper's
// report, measurements pointing at those hashes, and only the classes a
// measurement ran on. It refuses an answer out of its bounds or one the
// section's own rules reject.
func Section(r *Response) (*report.Tier2, error) {
	if r.Protocol != Protocol {
		return nil, refused("protocol %q, want %q", r.Protocol, Protocol)
	}
	name := strings.TrimSpace(r.Helper.Name)
	if name == "" || len(name) > maxName || len(r.Helper.Version) > maxName {
		return nil, refused("the helper must name itself in at most %d bytes", maxName)
	}
	if n := len(r.NodeClasses); n == 0 || n > MaxNodeClasses {
		return nil, refused("%d node classes; want 1 to %d", n, MaxNodeClasses)
	}
	if n := len(r.Measurements); n == 0 || n > MaxMeasurements {
		return nil, refused("%d measurements; want 1 to %d", n, MaxMeasurements)
	}

	hashOf := map[string]string{}
	facts := map[string]report.NodeClass{}
	for i, nc := range r.NodeClasses {
		switch _, dup := hashOf[nc.ID]; {
		case nc.ID == "" || len(nc.ID) > maxName:
			return nil, refused("node_classes[%d] needs an id of at most %d bytes", i, maxName)
		case dup:
			return nil, refused("node_classes[%d] repeats the id %q", i, nc.ID)
		case nc.Facts.Schema != "" && nc.Facts.Schema != report.NodeClassSchema:
			return nil, refused("node_classes[%d].facts.schema %q, want %q", i, nc.Facts.Schema, report.NodeClassSchema)
		}
		nc.Facts.Schema = report.NodeClassSchema
		if len(nc.Facts.Canonical()) > maxNodeClass {
			return nil, refused("node_classes[%d] is over %d bytes", i, maxNodeClass)
		}
		h := nc.Facts.Hash()
		hashOf[nc.ID] = h
		facts[h] = nc.Facts
	}

	sec := &report.Tier2{Statement: report.Tier2Statement, Helper: strings.TrimSpace(name + " " + strings.TrimSpace(r.Helper.Version))}
	recorded := map[string]bool{}
	resolve := func(i int, field, id string) (string, error) {
		h, ok := hashOf[id]
		if !ok {
			return "", refused("measurements[%d].%s %q is not an id in node_classes", i, field, id)
		}
		if !recorded[h] {
			recorded[h] = true
			sec.NodeClasses = append(sec.NodeClasses, report.NodeClassRecord{Hash: h, ReportedBy: report.NodeClassReportedByHelper, Facts: facts[h]})
		}
		return h, nil
	}
	for i, m := range r.Measurements {
		for _, f := range []string{m.Check, m.Suite, m.SuiteVersion, m.Scorer, m.Engine} {
			if len(f) > maxName {
				return nil, refused("measurements[%d] has a name over %d bytes", i, maxName)
			}
		}
		if len(m.Notes) > maxText || len(m.Evidence) > maxText || len(m.Metrics) > maxMetrics {
			return nil, refused("measurements[%d] has notes or evidence over %d bytes, or over %d metrics", i, maxText, maxMetrics)
		}
		var err error
		if m.NodeClass, err = resolve(i, "node_class", m.NodeClass); err != nil {
			return nil, err
		}
		if m.ReferenceNodeClass != "" {
			if m.ReferenceNodeClass, err = resolve(i, "reference_node_class", m.ReferenceNodeClass); err != nil {
				return nil, err
			}
		}
		sec.Measurements = append(sec.Measurements, m)
	}
	if problems := sec.Problems(); len(problems) > 0 {
		return nil, refused("%s", strings.Join(problems, "; "))
	}
	return sec, nil
}
