package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/dsse"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// snapshotDir writes a minimal snapshot by hand: one approved entry whose
// attestation file is env, a one-line chained log, and the signed statement.
func snapshotDir(t *testing.T, k *attest.PrivateKey, env []byte, id string) string {
	return snapshotDirWith(t, k, env, id, nil)
}

// snapshotDirWith is snapshotDir with a mutation of the statement before it is
// signed, so a case can corrupt exactly one thing under a valid signature.
func snapshotDirWith(t *testing.T, k *attest.PrivateKey, env []byte, id string, mutate func(*Statement)) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "models", id), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "models", id, "attestation.dsse.json"), env, 0o644)
	line := []byte(`{"ts":"2026-10-04T00:00:00Z","action":"promote","outcome":"ok","sha256":"` + id + `","prev":"` + airlock.Genesis + "\"}\n")
	_ = os.WriteFile(filepath.Join(dir, "log.jsonl"), line, 0o644)
	head := sha256.Sum256(line[:len(line)-1])
	envSum := sha256.Sum256(env)
	// The entry mirrors the attestation's own claims (read, not verified:
	// Verify under test does the verifying).
	body, _, _, err := dsse.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	var stmt struct {
		Predicate report.Document `json:"predicate"`
	}
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	pa := stmt.Predicate.PromotionAuthorization
	st := Build([]airlock.Model{{ID: id, Name: "m", Location: "clean", Stage: airlock.StageApproved, PromotionState: "authorized", SignerKeyID: k.ID, AcceptanceExpires: pa.AcceptanceExpires}},
		map[string][]byte{id: env}, hex.EncodeToString(head[:]), "socair test", time.Unix(0, 0))
	if st.Predicate.Models[0].AttestationSHA256 != hex.EncodeToString(envSum[:]) {
		t.Fatal("Build did not hash the attestation")
	}
	if mutate != nil {
		mutate(&st)
	}
	payload, signed, err := Sign(st, k)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "inventory.json"), payload, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "inventory.dsse.json"), signed, 0o644)
	return dir
}

func TestInventoryRoundTrip(t *testing.T) {
	env, id, k, ring := authorizedEnvelope(t)
	dir := snapshotDir(t, k, env, id)
	st, err := Verify(dir, ring, VerifyOptions{})
	if err != nil || len(st.Predicate.Models) != 1 {
		t.Fatalf("%v %+v", err, st)
	}
	if st.SignerKeyID != k.ID {
		t.Errorf("signer %q, want %q", st.SignerKeyID, k.ID)
	}
}

// Falsification: drop each check in Verify and its case passes.
func TestInventoryVerifyCatches(t *testing.T) {
	env, id, k, ring := authorizedEnvelope(t)
	cases := map[string]func(dir string){
		"changed attestation": func(dir string) {
			p := filepath.Join(dir, "models", id, "attestation.dsse.json")
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, append(b, ' '), 0o644)
		},
		"dropped attestation": func(dir string) { _ = os.RemoveAll(filepath.Join(dir, "models", id)) },
		"edited log": func(dir string) {
			p := filepath.Join(dir, "log.jsonl")
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, []byte(strings.Replace(string(b), "promote", "promoTe", 1)), 0o644)
		},
		"truncated log": func(dir string) { _ = os.WriteFile(filepath.Join(dir, "log.jsonl"), nil, 0o644) },
		"edited statement": func(dir string) {
			p := filepath.Join(dir, "inventory.dsse.json")
			b, _ := os.ReadFile(p)
			b[len(b)/2] ^= 1
			_ = os.WriteFile(p, b, 0o644)
		},
		"unsigned": func(dir string) { _ = os.Remove(filepath.Join(dir, "inventory.dsse.json")) },
	}
	for name, tamper := range cases {
		dir := snapshotDir(t, k, env, id)
		tamper(dir)
		if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// An untrusted verifier key refuses too.
	if _, err := Verify(snapshotDir(t, k, env, id), attest.Keyring{}, VerifyOptions{}); err == nil {
		t.Error("verified with no trusted key")
	}
}

// authorizedEnvelope scans a clean safetensors fixture with the three trust
// inputs supplied, signs the authorized document with a fresh key, and returns
// the envelope, the artifact id, the key, and a keyring trusting it.
func authorizedEnvelope(t *testing.T) (env []byte, id string, k *attest.PrivateKey, ring attest.Keyring) {
	t.Helper()
	dir := t.TempDir()
	mirror := filepath.Join(dir, "mirror")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_REPO_MIRROR", mirror)
	deny := filepath.Join(dir, "denylist.txt")
	if err := os.WriteFile(deny, []byte("0000000000000000000000000000000000000000000000000000000000000000  known-bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_DENYLIST", deny)
	sum := sha256.Sum256(safetensorstest.Clean())
	prov := filepath.Join(dir, "provenance.json")
	bound := fmt.Sprintf(`{"artifact_sha256":%q,"publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/example/model","commit_or_tag":"main","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(prov, []byte(bound), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_PROVENANCE", prov)
	t.Setenv("SOCAIR_ACCEPTED_BY", "")
	artifact := filepath.Join(dir, "fixture.safetensors")
	if err := os.WriteFile(artifact, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(artifact)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("fixture did not reach authorized: state=%s", d.PromotionAuthorization.State)
	}
	prefix := filepath.Join(dir, "op")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	if k, err = attest.LoadPrivateKey(prefix + ".key"); err != nil {
		t.Fatal(err)
	}
	if env, err = attest.Sign(*d, k); err != nil {
		t.Fatal(err)
	}
	if ring, err = attest.LoadKeyring(prefix + ".pub"); err != nil {
		t.Fatal(err)
	}
	return env, d.Artifact.SHA256, k, ring
}

// Falsification: each case corrupts one thing under a valid signature (the
// statement is re-signed with the trusted key), so only the targeted check can
// refuse it.
func TestInventoryResignedTamperRefused(t *testing.T) {
	env, id, k, ring := authorizedEnvelope(t)
	cases := map[string]func(*Statement){
		"wrong statement type": func(s *Statement) { s.Type = "https://example.com/Statement" },
		"wrong predicate type": func(s *Statement) { s.PredicateType = "https://socair.ai/inventory/v2" },
		"subject name":         func(s *Statement) { s.Subject[0].Name = "other" },
		"subject digest":       func(s *Statement) { s.Subject[0].Digest["sha256"] = strings.Repeat("a", 64) },
		"extra subject": func(s *Statement) {
			s.Subject = append(s.Subject, Subject{Name: "x", Digest: map[string]string{"sha256": strings.Repeat("b", 64)}})
		},
		"dropped subject":    func(s *Statement) { s.Subject = []Subject{} },
		"promotion_state":    func(s *Statement) { s.Predicate.Models[0].PromotionState = "authorized_with_conditions" },
		"signer_key_id":      func(s *Statement) { s.Predicate.Models[0].SignerKeyID = "someone-else" },
		"accepted_surfaces":  func(s *Statement) { s.Predicate.Models[0].AcceptedSurfaces = []string{"structure"} },
		"acceptance_expires": func(s *Statement) { s.Predicate.Models[0].AcceptanceExpires = "2030-01-01T00:00:00Z" },
		"empty log head":     func(s *Statement) { s.Predicate.LogHead = "" },
		"non-hex id": func(s *Statement) {
			s.Predicate.Models[0].ID = "../x"
			s.Subject[0].Digest["sha256"] = "../x"
		},
		"uppercase id": func(s *Statement) {
			s.Predicate.Models[0].ID = strings.ToUpper(id)
			s.Subject[0].Digest["sha256"] = strings.ToUpper(id)
		},
	}
	for name, mutate := range cases {
		dir := snapshotDirWith(t, k, env, id, mutate)
		if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// signedRaw replaces the snapshot's statement with raw JSON, signed validly.
func signedRaw(t *testing.T, dir string, k *attest.PrivateKey, raw []byte) {
	t.Helper()
	signed, err := dsseSign(raw, k)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "inventory.json"), raw, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "inventory.dsse.json"), signed, 0o644)
}

func TestInventoryRawStatementTamperRefused(t *testing.T) {
	env, id, k, ring := authorizedEnvelope(t)
	good, err := os.ReadFile(filepath.Join(snapshotDir(t, k, env, id), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"trailing data": append(append([]byte{}, good...), []byte(`{"x":1}`)...),
		"unknown field": []byte(strings.Replace(string(good), `"tool_version"`, `"extra": 1, "tool_version"`, 1)),
	}
	for name, raw := range cases {
		dir := snapshotDir(t, k, env, id)
		signedRaw(t, dir, k, raw)
		if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// inventory.json differing from the signed payload is refused.
	dir := snapshotDir(t, k, env, id)
	_ = os.WriteFile(filepath.Join(dir, "inventory.json"), append(append([]byte{}, good...), '\n'), 0o644)
	if _, err := Verify(dir, ring, VerifyOptions{}); err == nil {
		t.Error("inventory.json differing from the signed payload verified")
	}
}

func TestInventoryAllowUnsigned(t *testing.T) {
	env, id, k, ring := authorizedEnvelope(t)
	dir := snapshotDir(t, k, env, id)
	_ = os.Remove(filepath.Join(dir, "inventory.dsse.json"))
	v, err := Verify(dir, ring, VerifyOptions{AllowUnsigned: true})
	if err != nil || v.SignerKeyID != "" {
		t.Fatalf("consistent unsigned snapshot: %v %+v", err, v)
	}
	// Contents are still checked.
	p := filepath.Join(dir, "models", id, "attestation.dsse.json")
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, append(b, ' '), 0o644)
	if _, err := Verify(dir, ring, VerifyOptions{AllowUnsigned: true}); err == nil {
		t.Error("unsigned snapshot with a changed attestation verified")
	}
	// A present but invalid envelope is never waved through.
	dir = snapshotDir(t, k, env, id)
	e, _ := os.ReadFile(filepath.Join(dir, "inventory.dsse.json"))
	e[len(e)/2] ^= 1
	_ = os.WriteFile(filepath.Join(dir, "inventory.dsse.json"), e, 0o644)
	if _, err := Verify(dir, ring, VerifyOptions{AllowUnsigned: true}); err == nil {
		t.Error("invalid envelope verified with AllowUnsigned")
	}
}

func dsseSign(payload []byte, k *attest.PrivateKey) ([]byte, error) {
	return dsse.Sign(payload, k.ID, k.Sign)
}
