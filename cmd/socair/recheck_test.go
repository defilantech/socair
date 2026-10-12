package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// promotedFixture promotes an authorized safetensors fixture into a new store
// and returns the store root and the model's id.
func promotedFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	art := filepath.Join(dir, "fixture.safetensors")
	if err := os.WriteFile(art, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}
	mirror := filepath.Join(dir, "mirror")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	deny := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(deny, []byte(strings.Repeat("0", 64)+"  known-bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"SOCAIR_REPO_MIRROR": mirror, "SOCAIR_DENYLIST": deny, "SOCAIR_FEED": "", "SOCAIR_ACCEPTED_BY": ""} {
		t.Setenv(k, v)
	}
	d, err := engine.Scan(art)
	if err != nil {
		t.Fatal(err)
	}
	prov := filepath.Join(dir, "provenance.json")
	bound := `{"artifact_sha256":"` + d.Artifact.SHA256 + `","publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/example/model","commit_or_tag":"main","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`
	if err := os.WriteFile(prov, []byte(bound), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_PROVENANCE", prov)
	if d, err = engine.Scan(art); err != nil || d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("fixture: %v %s", err, d.PromotionAuthorization.State)
	}
	op := filepath.Join(dir, "operator")
	if _, err := attest.GenerateKey(op); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(op + ".key")
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, "r.dsse.json")
	if err := os.WriteFile(envPath, env, 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "store")
	s, err := airlock.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(op + ".pub"); err != nil {
		t.Fatal(err)
	}
	if _, err := airlock.Promote(s, art, envPath); err != nil {
		t.Fatal(err)
	}
	return root, d.Artifact.SHA256
}

// The command exits non-zero when a model is flagged, so a scheduled run
// surfaces it, and zero when every model is unchanged.
func TestRecheckCommandExitsNonZeroOnAFlag(t *testing.T) {
	root, id := promotedFixture(t)
	list := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(list, []byte(id+"  reported after promotion\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_DENYLIST", list)
	out, err := stdout(t, func() error { return airlockRecheck([]string{"--store", root}) })
	if err == nil || !strings.Contains(err.Error(), "flagged") {
		t.Fatalf("a flagged model must fail the command: %v\n%s", err, out)
	}
	if !strings.Contains(out, "flagged") || !strings.Contains(out, "reported after promotion") || !strings.Contains(out, "1 flagged") {
		t.Fatalf("output:\n%s", out)
	}

	if err := os.WriteFile(list, []byte(strings.Repeat("1", 64)+"  another model\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = stdout(t, func() error { return airlockRecheck([]string{"--store", root}) })
	if err != nil || !strings.Contains(out, "1 unchanged") {
		t.Fatalf("a cleared model passes the command: %v\n%s", err, out)
	}
	if _, err := stdout(t, func() error { return airlockRecheck([]string{"--store", root, "extra"}) }); err == nil ||
		!strings.Contains(err.Error(), "usage") {
		t.Fatalf("a stray argument must be refused: %v", err)
	}
}
