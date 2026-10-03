package airlock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// conditionalDirectory writes a small model directory and scans it. The
// directory's NOT_TESTED rows are accepted, so it crosses with conditions.
func conditionalDirectory(t *testing.T) (string, *report.Document) {
	t.Helper()
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_ACCEPTED_BY", "ciso@example.com")
	dir := filepath.Join(t.TempDir(), "tiny-model")
	for rel, body := range map[string]string{
		"config.json":           `{"model_type":"llama"}`,
		"model.safetensors":     string(safetensorstest.Clean()),
		"tokenizer_config.json": `{"chat_template":"{% for m in messages %}{{ m['content'] }}{% endfor %}"}`,
		"sub/attestation.json":  `{"a file named like store metadata": true}`,
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d, err := engine.Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.PromotionAuthorization.State != report.StateAuthorizedWithConditions {
		t.Fatalf("fixture state %s, want authorized_with_conditions", d.PromotionAuthorization.State)
	}
	return dir, d
}

func TestPromoteADirectory(t *testing.T) {
	dir, d := conditionalDirectory(t)
	s := trustedStore(t)
	e, err := Promote(s, dir, writeReport(t, d))
	if err != nil {
		t.Fatalf("an attested directory crosses: %v", err)
	}
	if e.Outcome != OutcomeConditional {
		t.Errorf("outcome %s", e.Outcome)
	}
	stored := filepath.Join(s.CleanPath(d.Artifact.SHA256), "tiny-model")
	got, _, err := modeldir.Hash(stored)
	if err != nil || got != d.Artifact.SHA256 {
		t.Fatalf("the stored tree must hash to the subject: %s (%v), want %s", got, err, d.Artifact.SHA256)
	}
	for _, f := range []string{attestationDoc, attestationEnvelope} {
		if _, err := os.Stat(filepath.Join(s.CleanPath(d.Artifact.SHA256), f)); err != nil {
			t.Errorf("%s missing beside the tree: %v", f, err)
		}
	}

	// A repeat promotion restores a stored tree that was altered.
	if err := os.Chmod(filepath.Join(stored, "config.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stored, "config.json"), []byte(`{"auto_map":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(s, dir, writeReport(t, d)); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := modeldir.Hash(stored); got != d.Artifact.SHA256 {
		t.Fatal("a repeat promotion must restore the attested tree")
	}
	if entries, _ := os.ReadDir(filepath.Join(s.Root, tmpDir)); len(entries) != 0 {
		t.Errorf("in-progress copies must not be left behind: %v", entries)
	}
}

// Every change after signing is refused, naming the file. Falsification:
// skip the digest comparison in placeVerifiedDir and these cross.
func TestPromoteRefusesAChangedDirectory(t *testing.T) {
	cases := map[string]struct {
		change func(dir string) error
		names  string
	}{
		"changed": {func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"model_type":"other"}`), 0o644)
		}, "changed: config.json"},
		"added": {func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "modeling_x.py"), []byte("import os"), 0o644)
		}, "added: modeling_x.py"},
		"removed": {func(dir string) error {
			return os.Remove(filepath.Join(dir, "tokenizer_config.json"))
		}, "removed: tokenizer_config.json"},
	}
	for name, c := range cases {
		dir, d := conditionalDirectory(t)
		ticket := writeReport(t, d)
		if err := c.change(dir); err != nil {
			t.Fatal(err)
		}
		s := trustedStore(t)
		_, err := Promote(s, dir, ticket)
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), c.names) {
			t.Errorf("%s: want a refusal naming %q, got %v", name, c.names, err)
		}
		if _, err := os.Stat(s.CleanPath(d.Artifact.SHA256)); err == nil {
			t.Errorf("%s: nothing may land in clean on a refusal", name)
		}
	}
}

// The copy is what is verified: bytes swapped while it runs are refused, not
// stored.
func TestPromoteDirectoryStoresOnlyVerifiedBytes(t *testing.T) {
	dir, d := conditionalDirectory(t)
	ticket := writeReport(t, d)
	promoteOpened = func() {
		_ = os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("swapped"), 0o644)
	}
	t.Cleanup(func() { promoteOpened = nil })
	s := trustedStore(t)
	if _, err := Promote(s, dir, ticket); !errors.Is(err, ErrRefused) {
		t.Fatalf("bytes swapped mid-copy must be refused, got %v", err)
	}
}

func TestPromoteRefusesAShapeMismatch(t *testing.T) {
	dir, d := conditionalDirectory(t)
	s := trustedStore(t)
	if _, err := Promote(s, filepath.Join(dir, "model.safetensors"), writeReport(t, d)); !errors.Is(err, ErrRefused) {
		t.Errorf("a directory attestation must not carry a single file: %v", err)
	}
	file, fd := authorizedArtifact(t)
	if _, err := Promote(s, filepath.Dir(file), writeReport(t, fd)); !errors.Is(err, ErrRefused) {
		t.Errorf("a single-file attestation must not carry a directory: %v", err)
	}
}
