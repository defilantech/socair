package derivation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/dsse"
)

var (
	inSHA  = strings.Repeat("ab", 32)
	outSHA = strings.Repeat("cd", 32)
	docSHA = strings.Repeat("ef", 32)
	tSHA   = strings.Repeat("01", 32)
)

func key(t *testing.T) (ed25519.PrivateKey, string, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := dsse.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, id, map[string]ed25519.PublicKey{id: pub}
}

func predicate() Predicate {
	return Predicate{
		Converter: Converter{Name: "socair airlock convert", Version: "dev", Rules: "socair-convert/1", Grammar: "socair-wo/1"},
		Input: Input{Name: "pytorch_model.bin", Digest: map[string]string{"sha256": inSHA}, Format: "torch.save zip",
			ByteOrder: "little", Attestation: Attestation{DocumentID: "SOCAIR-x", DocumentHash: docSHA, PickleRow: "PASS"}},
		Output:      Output{Name: "pytorch_model.safetensors", Digest: map[string]string{"sha256": outSHA}, Format: "safetensors", SizeBytes: 100},
		ConvertedAt: "2026-10-14T12:00:00Z",
		Tensors: []Tensor{
			{Name: "embed.weight", Dtype: "F32", SourceDtype: "float32", Shape: []int64{2}, SHA256: tSHA, SizeBytes: 8, DataOffsets: [2]int64{0, 8}},
			{Name: "lm_head.weight", Dtype: "F32", SourceDtype: "float32", Shape: []int64{2}, SHA256: tSHA, SizeBytes: 8, DataOffsets: [2]int64{0, 8}, AliasOf: "embed.weight"},
		},
		Metadata: map[string]string{"format": "pt", "lm_head.weight": "embed.weight"},
	}
}

func signed(t *testing.T, p Predicate) ([]byte, map[string]ed25519.PublicKey) {
	t.Helper()
	priv, id, ring := key(t)
	raw, err := Sign(p, id, func(m []byte) []byte { return ed25519.Sign(priv, m) })
	if err != nil {
		t.Fatal(err)
	}
	return raw, ring
}

func TestSignVerifyRoundTrip(t *testing.T) {
	raw, ring := signed(t, predicate())
	r, err := Verify(raw, ring)
	if err != nil {
		t.Fatal(err)
	}
	if r.Input.Digest["sha256"] != inSHA || r.Output.Digest["sha256"] != outSHA || len(r.Tensors) != 2 || r.DoesNotAuthorize != DoesNotAuthorize {
		t.Fatalf("%+v", r.Predicate)
	}
	var e dsse.Envelope
	_ = json.Unmarshal(raw, &e)
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	for _, s := range []string{`"predicateType":"` + PredicateType + `"`, `"subject":[{"name":"pytorch_model.safetensors","digest":{"sha256":"` + outSHA + `"}}]`} {
		if !strings.Contains(string(payload), s) {
			t.Errorf("payload does not hold %s", s)
		}
	}
}

// TestTamperedRecordFails: a record changed after signing, or signed by a key
// the verifier does not trust, does not verify. Falsification: skip the
// signature check and these pass.
func TestTamperedRecordFails(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"input hash":  func(p string) string { return strings.Replace(p, inSHA, strings.Repeat("aa", 32), 1) },
		"tensor hash": func(p string) string { return strings.Replace(p, tSHA, strings.Repeat("02", 32), 1) },
		"rules":       func(p string) string { return strings.Replace(p, "socair-convert/1", "socair-convert/2", 1) },
	} {
		raw, ring := signed(t, predicate())
		var e dsse.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		p, _ := base64.StdEncoding.DecodeString(e.Payload)
		e.Payload = base64.StdEncoding.EncodeToString([]byte(edit(string(p))))
		out, _ := json.Marshal(e)
		if _, err := Verify(out, ring); err == nil {
			t.Errorf("%s: a tampered record verified", name)
		}
	}
	raw, _ := signed(t, predicate())
	_, _, other := key(t)
	if _, err := Verify(raw, other); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("an untrusted key: %v", err)
	}
}

func TestMalformedRecordsAreRefused(t *testing.T) {
	priv, id, _ := key(t)
	sign := func(m []byte) []byte { return ed25519.Sign(priv, m) }
	for name, edit := range map[string]func(*Predicate){
		"no input hash":          func(p *Predicate) { p.Input.Digest = nil },
		"input is output":        func(p *Predicate) { p.Input.Digest["sha256"] = outSHA },
		"no attestation":         func(p *Predicate) { p.Input.Attestation.DocumentHash = "" },
		"no tensors":             func(p *Predicate) { p.Tensors = nil },
		"no rules":               func(p *Predicate) { p.Converter.Rules = "" },
		"a free-text time":       func(p *Predicate) { p.ConvertedAt = "today" },
		"a tensor named twice":   func(p *Predicate) { p.Tensors[1].Name = "embed.weight"; p.Tensors[1].AliasOf = "" },
		"an alias of nothing":    func(p *Predicate) { p.Tensors[1].AliasOf = "missing" },
		"an alias with no entry": func(p *Predicate) { delete(p.Metadata, "lm_head.weight") },
		"an alias of other bytes": func(p *Predicate) {
			p.Tensors[1].SHA256 = strings.Repeat("03", 32)
		},
	} {
		p := predicate()
		edit(&p)
		if _, err := Sign(p, id, sign); err == nil {
			t.Errorf("%s: Sign must refuse", name)
		}
	}
}
