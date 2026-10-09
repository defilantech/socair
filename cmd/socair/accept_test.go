package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/gguf/gguftest"
	"github.com/defilantech/socair/internal/report"
)

// stdout runs f and returns what it printed.
func stdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	runErr := f()
	os.Stdout = orig
	_ = w.Close()
	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String(), runErr
}

// withheldAttestation scans a clean GGUF with no operational inputs, so its
// trust rows are NOT_TESTED and it is withheld, and signs it with a new
// operator key. It returns the attestation and the operator key prefix.
func withheldAttestation(t *testing.T, dir string) (string, string) {
	t.Helper()
	for _, k := range []string{"SOCAIR_REPO_MIRROR", "SOCAIR_DENYLIST", "SOCAIR_PROVENANCE", "SOCAIR_ACCEPTED_BY", "SOCAIR_FEED", "SOCAIR_TOKENIZER_REFERENCE"} {
		t.Setenv(k, "")
	}
	art := filepath.Join(dir, "clean-Q5_K_M.gguf")
	if err := os.WriteFile(art, gguftest.BuildGGUF(gguftest.Clean()), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := engine.Scan(art)
	if err != nil {
		t.Fatal(err)
	}
	if d.PromotionAuthorization.State != report.StateWithheld {
		t.Fatalf("fixture is %s, want withheld", d.PromotionAuthorization.State)
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
	p := filepath.Join(dir, "r.dsse.json")
	if err := os.WriteFile(p, env, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, op
}

// reissueArgs takes the re-issue command accept printed, puts in the
// operator's key, and returns its arguments after "socair sign".
func reissueArgs(t *testing.T, out, opKey string) []string {
	t.Helper()
	i := strings.Index(out, "socair sign ")
	if i < 0 {
		t.Fatalf("accept printed no re-issue command:\n%s", out)
	}
	line := strings.SplitN(out[i+len("socair sign "):], "\n", 2)[0]
	if strings.ContainsAny(line, "<>'\"") {
		t.Fatalf("the printed command has shell metacharacters or quoting this test does not expect: %q", line)
	}
	return strings.Fields(strings.ReplaceAll(line, "OPERATOR_KEY", opKey))
}

// TestAcceptPrintsARunnableReissue: the hint accept printed omitted the
// trust flags sign --acceptance requires, so run as printed it failed with
// "pass --trusted <key.pub|dir> or --store <path>". It now carries the trust
// source accept used, and this runs it. Falsification: drop the trust flags
// from the hint and signCmd refuses.
func TestAcceptPrintsARunnableReissue(t *testing.T) {
	expires := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	t.Run("trusted keys", func(t *testing.T) {
		dir := t.TempDir()
		env, op := withheldAttestation(t, dir)
		acc := filepath.Join(dir, "acceptor")
		if _, err := attest.GenerateKey(acc); err != nil {
			t.Fatal(err)
		}
		out, err := stdout(t, func() error {
			return acceptCmd([]string{"--attestation", env, "--key", acc + ".key", "--by", "Jane Doe, CISO",
				"--expires", expires, "--trusted", op + ".pub"})
		})
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if _, err := stdout(t, func() error { return signCmd(reissueArgs(t, out, op+".key")) }); err != nil {
			t.Fatalf("the printed re-issue command failed: %v\n%s", err, out)
		}
		if _, err := os.Stat(filepath.Join(dir, "r.conditional.dsse.json")); err != nil {
			t.Fatalf("no re-issued attestation: %v", err)
		}
	})

	t.Run("store", func(t *testing.T) {
		dir := t.TempDir()
		env, op := withheldAttestation(t, dir)
		acc := filepath.Join(dir, "acceptor")
		if _, err := attest.GenerateKey(acc); err != nil {
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
		if _, err := s.TrustAcceptor(acc + ".pub"); err != nil {
			t.Fatal(err)
		}
		out, err := stdout(t, func() error {
			return acceptCmd([]string{"--attestation", env, "--key", acc + ".key", "--by", "Jane Doe, CISO",
				"--expires", expires, "--store", root})
		})
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if _, err := stdout(t, func() error { return signCmd(reissueArgs(t, out, op+".key")) }); err != nil {
			t.Fatalf("the printed re-issue command failed: %v\n%s", err, out)
		}
	})
}
