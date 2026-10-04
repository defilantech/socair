package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// snapshotDir writes a minimal snapshot by hand: one approved entry whose
// attestation file is env, a one-line chained log, and the signed statement.
func snapshotDir(t *testing.T, k *attest.PrivateKey, env []byte, id string) string {
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
	st := Build([]airlock.Model{{ID: id, Name: "m", Location: "clean", Stage: airlock.StageApproved, PromotionState: "authorized"}},
		map[string][]byte{id: env}, hex.EncodeToString(head[:]), "socair test", time.Unix(0, 0))
	if st.Predicate.Models[0].AttestationSHA256 != hex.EncodeToString(envSum[:]) {
		t.Fatal("Build did not hash the attestation")
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
