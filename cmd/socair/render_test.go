package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/attest"
)

const unsignedChip = `class="unsigned-chip"`

// TestRenderAnAttestation: render --attestation verifies the envelope against
// the operator's key, as verify does, and renders the signed document: no
// UNSIGNED mark, the signer named. The same envelope against another key, or
// tampered, renders nothing. Falsification: render the predicate without
// verifying it and the untrusted and tampered cases render.
func TestRenderAnAttestation(t *testing.T) {
	dir := t.TempDir()
	env, op := withheldAttestation(t, dir)
	art := filepath.Join(dir, "clean-Q5_K_M.gguf")

	html, err := stdout(t, func() error {
		return renderCmd([]string{"--attestation", env, "--trusted", op + ".pub", "--artifact", art})
	})
	if err != nil {
		t.Fatalf("render --attestation: %v", err)
	}
	if strings.Contains(html, unsignedChip) {
		t.Error("a verified attestation rendered with the UNSIGNED mark")
	}
	keyID, _, err := attest.LoadPublicKey(op + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, keyID) {
		t.Errorf("the rendered attestation does not name its signer key %s", keyID)
	}
	pdfOut := filepath.Join(dir, "r.pdf")
	if _, err := stdout(t, func() error {
		return renderCmd([]string{"--attestation", env, "--trusted", op + ".pub", "--pdf", pdfOut})
	}); err != nil {
		t.Fatalf("render --attestation --pdf: %v", err)
	}
	if b, _ := os.ReadFile(pdfOut); !strings.HasPrefix(string(b), "%PDF") {
		t.Error("render --attestation --pdf wrote no PDF")
	}

	other := filepath.Join(dir, "other")
	if _, err := attest.GenerateKey(other); err != nil {
		t.Fatal(err)
	}
	if out, err := stdout(t, func() error {
		return renderCmd([]string{"--attestation", env, "--trusted", other + ".pub"})
	}); err == nil || out != "" {
		t.Errorf("an attestation rendered against a key that did not sign it: err %v, %d bytes", err, len(out))
	}

	// Tamper with the signed payload itself: one byte of the statement.
	var e map[string]any
	b, _ := os.ReadFile(env)
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	e["payload"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(payload), "withheld", "authorized", 1)))
	tampered := filepath.Join(dir, "tampered.dsse.json")
	writeJSONFile(t, tampered, e)
	if out, err := stdout(t, func() error {
		return renderCmd([]string{"--attestation", tampered, "--trusted", op + ".pub"})
	}); err == nil || out != "" {
		t.Errorf("a tampered attestation rendered: err %v, %d bytes", err, len(out))
	}

	if err := os.WriteFile(art, []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stdout(t, func() error {
		return renderCmd([]string{"--attestation", env, "--trusted", op + ".pub", "--artifact", art})
	}); err == nil {
		t.Error("an attestation rendered bound to other bytes")
	}
}

// TestRenderAReport: render --report renders a saved report document without
// scanning again, marked UNSIGNED, and refuses one that names a signature:
// a signature is proven by its envelope, so a report file's own claim to one
// is not rendered as signed. Falsification: drop the refusal and the edited
// report renders without the UNSIGNED mark.
func TestRenderAReport(t *testing.T) {
	dir := t.TempDir()
	env, _ := withheldAttestation(t, dir)

	var e struct {
		Payload string `json:"payload"`
	}
	b, _ := os.ReadFile(env)
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Predicate map[string]any `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}

	// The predicate as signed names its signer: refused.
	signedDoc := filepath.Join(dir, "signed-report.json")
	writeJSONFile(t, signedDoc, st.Predicate)
	if out, err := stdout(t, func() error { return renderCmd([]string{"--report", signedDoc}) }); err == nil || out != "" ||
		!strings.Contains(err.Error(), "--attestation") {
		t.Errorf("a report naming a signature rendered: err %v, %d bytes", err, len(out))
	}

	// The same report with its signature fields cleared is a draft: rendered,
	// marked UNSIGNED.
	v := st.Predicate["verification"].(map[string]any)
	v["signer_key_id"], v["document_hash"] = "", ""
	if h, ok := st.Predicate["header"].(map[string]any); ok {
		h["document_hash"] = ""
	}
	draft := filepath.Join(dir, "report.json")
	writeJSONFile(t, draft, st.Predicate)
	html, err := stdout(t, func() error { return renderCmd([]string{"--report", draft}) })
	if err != nil {
		t.Fatalf("render --report: %v", err)
	}
	if !strings.Contains(html, unsignedChip) {
		t.Error("an unsigned report rendered without the UNSIGNED mark")
	}

	// One source at a time.
	for _, args := range [][]string{
		{"model.gguf", "--report", draft},
		{"--report", draft, "--attestation", env},
		{"--attestation", env},
	} {
		if _, err := stdout(t, func() error { return renderCmd(args) }); err == nil {
			t.Errorf("render %v: want a usage error", args)
		}
	}
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
