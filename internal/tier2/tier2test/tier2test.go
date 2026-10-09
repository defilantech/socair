// Package tier2test stands in for a Tier 2 probe helper and the inference
// engine it drives, so the protocol, and the engine's handling of it, are
// tested end to end with no GPU and no Python. A test binary calls Serve
// first thing in TestMain; named by SOCAIR_TIER2_HELPER, the binary then
// re-executes itself as the helper, which drives an httptest server that
// speaks the OpenAI completions API.
package tier2test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2"
)

// ModeVar selects what the stand-in helper does. Its SOCAIR_PROBE_ prefix is
// what lets it through to the helper's environment.
const ModeVar = "SOCAIR_PROBE_FAKE_MODE"

// Modes of the stand-in helper.
const (
	// Differential compares greedy continuations of Prompts between the
	// endpoint and the reference endpoint (or a second pass on the endpoint):
	// any difference is a LEAD, as a statistical signal is.
	Differential = "differential"
	// Canary FAILs when a continuation contains CanaryText: deterministic,
	// matcher-confirmed evidence.
	Canary = "canary"
	// Env reports, in its notes, which environment variables it was given.
	Env = "env"
	// The rest answer out of protocol, each in its own way.
	UnknownField     = "unknown-field"
	Oversize         = "oversize"
	Hang             = "hang"
	Crash            = "crash"
	PassOutcome      = "pass"
	Trailing         = "trailing"
	NotJSON          = "not-json"
	UnknownNodeClass = "unknown-node-class"
	JudgedFail       = "judged-fail"
	WrongProtocol    = "wrong-protocol"
)

// Check names the stand-in measures.
const (
	DifferentialCheck = "Serving-stack differential (Tier 2)"
	CanaryCheck       = "Forward-pass trigger probes (Tier 2)"
)

// CanaryText is the string the Canary mode matches.
const CanaryText = "CANARY-7f3a"

// Prompts is the stand-in's fixed probe set.
var Prompts = []string{"The capital of France is", "def add(a, b):", "Water boils at", "Translate to French: good morning"}

// DatasetDigest identifies Prompts.
func DatasetDigest() string {
	sum := sha256.Sum256([]byte(strings.Join(Prompts, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Serve answers one request as the helper and exits, when ModeVar is set.
// Otherwise it returns at once.
func Serve() {
	mode := os.Getenv(ModeVar)
	if mode == "" {
		return
	}
	os.Exit(answer(mode, os.Stdin, os.Stdout, os.Stderr))
}

// Helper points the engine at the running test binary as its helper.
func Helper(t testing.TB, mode, endpoint string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_TIER2_HELPER", exe)
	t.Setenv("SOCAIR_TIER2_ENDPOINT", endpoint)
	t.Setenv(ModeVar, mode)
}

// FakeEngine is an httptest server that speaks enough of the OpenAI API for
// a probe: GET /v1/models and greedy POST /v1/completions.
type FakeEngine struct {
	*httptest.Server
	// Calls counts completions served, so a test can see the helper drove it.
	Calls atomic.Int64
}

// Engine starts a fake engine named name whose greedy continuation of a
// prompt is complete(prompt). It refuses a request that is not greedy.
func Engine(t testing.TB, name string, complete func(prompt string) string) *FakeEngine {
	t.Helper()
	e := &FakeEngine{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"object":"list","data":[{"id":"fake-model","object":"model","owned_by":%q}]}`, name)
	})
	mux.HandleFunc("POST /v1/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model       string  `json:"model"`
			Prompt      string  `json:"prompt"`
			MaxTokens   int     `json:"max_tokens"`
			Temperature float64 `json:"temperature"`
			TopP        float64 `json:"top_p"`
			Seed        *int64  `json:"seed"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Model != "fake-model" || req.Temperature != 0 || req.MaxTokens < 1 {
			http.Error(w, `{"error":"want a greedy completion of fake-model"}`, http.StatusBadRequest)
			return
		}
		e.Calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":  "text_completion",
			"model":   req.Model,
			"choices": []map[string]any{{"index": 0, "text": complete(req.Prompt), "finish_reason": "length"}},
		})
	})
	e.Server = httptest.NewServer(mux)
	t.Cleanup(e.Close)
	return e
}

// Echo is a continuation that depends only on the prompt.
func Echo(prompt string) string { return " continuation of " + prompt }

func answer(mode string, in io.Reader, out, errOut io.Writer) int {
	// The request is read as strictly as Socair reads the answer.
	dec := json.NewDecoder(in)
	dec.DisallowUnknownFields()
	var req tier2.Request
	if err := dec.Decode(&req); err != nil || req.Protocol != tier2.Protocol || req.Endpoint == "" || req.Decoding.MaxTokens < 1 {
		fmt.Fprintf(errOut, "bad request: %v\n", err)
		return 2
	}
	switch mode {
	case Hang:
		time.Sleep(time.Minute)
		return 0
	case Crash:
		fmt.Fprintln(errOut, "probe pack \x1b[31mexploded\x1b[0m")
		return 3
	case Oversize:
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for i := 0; i < 64; i++ {
			if _, err := out.Write(chunk); err != nil {
				return 1
			}
		}
		return 0
	case NotJSON:
		fmt.Fprintln(out, "all good, no findings")
		return 0
	}

	start := time.Now().UTC().Format(time.RFC3339)
	resp, err := measure(mode, req, start)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	b, _ := json.Marshal(resp)
	switch mode {
	case UnknownField:
		b = append([]byte(`{"verdict":"safe",`), b[1:]...)
	case Trailing:
		b = append(b, []byte(`{"protocol":"again"}`)...)
	}
	_, _ = out.Write(b)
	return 0
}

func measure(mode string, req tier2.Request, start string) (map[string]any, error) {
	facts := report.NodeClass{}
	if req.NodeClass != nil {
		facts = *req.NodeClass
	}
	name, err := engineName(req.Endpoint)
	if err != nil {
		return nil, err
	}
	if facts.EngineName == "" {
		facts.EngineName = name
	}
	classes := []map[string]any{{"id": "endpoint", "facts": facts}}

	a, err := continuations(req.Endpoint, req.Decoding)
	if err != nil {
		return nil, err
	}
	m := map[string]any{
		"suite": "tier2test/" + mode, "suite_version": "1", "dataset_digest": DatasetDigest(),
		"scorer": report.ScorerDeterministic, "n": len(Prompts), "decoding": req.Decoding,
		"engine": facts.EngineName, "node_class": "endpoint", "outcome": report.OutcomeMeasured,
	}
	switch mode {
	case Canary, JudgedFail:
		m["check"] = CanaryCheck
		hits := 0
		for i, c := range a {
			if strings.Contains(c, CanaryText) {
				hits++
				m["outcome"], m["evidence"] = report.OutcomeFail, fmt.Sprintf("probe %d continued %q", i, c)
			}
		}
		m["score"] = float64(hits) / float64(len(a))
		if mode == JudgedFail {
			m["outcome"], m["evidence"] = report.OutcomeFail, "the judge thought so"
			m["scorer"] = report.ScorerLLMJudgePrefix + DatasetDigest()
		}
	case Env:
		m["check"] = DifferentialCheck
		m["score"] = 1.0
		var keys []string
		for _, kv := range os.Environ() {
			k, _, _ := strings.Cut(kv, "=")
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m["notes"] = strings.Join(keys, " ")
	default:
		m["check"] = DifferentialCheck
		ref, refName := req.Endpoint, name
		if req.ReferenceEndpoint != "" {
			ref = req.ReferenceEndpoint
			if refName, err = engineName(ref); err != nil {
				return nil, err
			}
			classes = append(classes, map[string]any{"id": "reference", "facts": report.NodeClass{EngineName: refName}})
			m["reference_node_class"] = "reference"
		}
		b, err := continuations(ref, req.Decoding)
		if err != nil {
			return nil, err
		}
		agree := 0
		for i := range a {
			if a[i] == b[i] {
				agree++
			}
		}
		m["score"] = float64(agree) / float64(len(a))
		m["metrics"] = map[string]float64{"agreement": float64(agree) / float64(len(a))}
		if agree < len(a) {
			m["outcome"] = report.OutcomeLead
			m["notes"] = fmt.Sprintf("%d of %d greedy continuations differ between %s and %s", len(a)-agree, len(a), name, refName)
		}
	}
	switch mode {
	case PassOutcome:
		m["outcome"] = "pass"
	case UnknownNodeClass:
		m["node_class"] = "gpu-0"
	}
	m["started_utc"], m["ended_utc"] = start, time.Now().UTC().Format(time.RFC3339)
	protocol := tier2.Protocol
	if mode == WrongProtocol {
		protocol = "socair.tier2/v0"
	}
	return map[string]any{
		"protocol":     protocol,
		"helper":       map[string]string{"name": "tier2test", "version": "1"},
		"node_classes": classes,
		"measurements": []map[string]any{m},
	}, nil
}

var client = &http.Client{Timeout: 10 * time.Second}

func engineName(endpoint string) (string, error) {
	resp, err := client.Get(endpoint + "/v1/models")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var models struct {
		Data []struct {
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil || len(models.Data) == 0 {
		return "", fmt.Errorf("%s/v1/models: no model listed (%v)", endpoint, err)
	}
	return models.Data[0].OwnedBy, nil
}

func continuations(endpoint string, dc report.Decoding) ([]string, error) {
	var out []string
	for _, p := range Prompts {
		body, _ := json.Marshal(map[string]any{
			"model": "fake-model", "prompt": p, "max_tokens": dc.MaxTokens,
			"temperature": dc.Temperature, "top_p": dc.TopP, "seed": dc.Seed,
		})
		resp, err := client.Post(endpoint+"/v1/completions", "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		var c struct {
			Choices []struct {
				Text string `json:"text"`
			} `json:"choices"`
		}
		err = json.NewDecoder(resp.Body).Decode(&c)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || len(c.Choices) != 1 {
			return nil, fmt.Errorf("%s/v1/completions: HTTP %d (%v)", endpoint, resp.StatusCode, err)
		}
		out = append(out, c.Choices[0].Text)
	}
	return out, nil
}
