package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2/tier2test"
)

// TestMain lets the test binary stand in for the socair-sigstore helper:
// with SOCAIR_FAKE_SIGSTORE set it answers one request with that verdict, so
// the engine's side of the protocol is tested without building the helper.
// The helper's own cryptography is tested in tools/socair-sigstore.
func TestMain(m *testing.M) {
	// It also stands in for the Tier 2 probe helper (internal/tier2/tier2test).
	tier2test.Serve()
	if verdict := os.Getenv("SOCAIR_FAKE_SIGSTORE"); verdict != "" {
		in, _ := io.ReadAll(os.Stdin)
		var req struct {
			Bundle      string            `json:"bundle"`
			TrustedRoot string            `json:"trusted_root"`
			Identities  []json.RawMessage `json:"identities"`
		}
		if json.Unmarshal(in, &req) != nil || req.Bundle == "" || req.TrustedRoot == "" || len(req.Identities) == 0 {
			fmt.Fprintln(os.Stderr, "bad request")
			os.Exit(2)
		}
		if verdict == "crash" {
			os.Exit(3)
		}
		fmt.Printf(`{"state":%q,"signer":"releases@example.com (https://issuer.example)","detail":"fake %s"}`+"\n", verdict, verdict)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// keylessEnv points the engine at the test binary as its keyless verifier.
func keylessEnv(t *testing.T, verdict string) {
	t.Helper()
	publisherEnv(t, "", "")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, _ := filepath.Abs(filepath.Join(omsVectors, "keys", "trusted-root-public-good.json"))
	ids := filepath.Join(t.TempDir(), "identities")
	if err := os.WriteFile(ids, []byte("# accepted signers\nhttps://issuer.example releases@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_SIGSTORE_VERIFIER", exe)
	t.Setenv("SOCAIR_SIGSTORE_TRUSTED_ROOT", root)
	t.Setenv("SOCAIR_SIGSTORE_IDENTITIES", ids)
	t.Setenv("SOCAIR_FAKE_SIGSTORE", verdict)
}

func TestKeylessVerdictsReachTheReport(t *testing.T) {
	cases := map[string]struct {
		status  report.Status
		signing string
	}{
		"verified":   {report.StatusPass, "verified (OMS, releases@example.com"},
		"invalid":    {report.StatusFail, "invalid (OMS): fake invalid"},
		"unverified": {report.StatusNotTested, "present, not verified (OMS): fake unverified"},
		"crash":      {report.StatusNotTested, "present, not verified (OMS): the keyless verifier did not run"},
	}
	for verdict, want := range cases {
		keylessEnv(t, verdict)
		d, err := Scan(vectorCopy(t, "keyless"))
		if err != nil {
			t.Fatal(err)
		}
		if r := row(d, provRow); r.Status != want.status || !strings.HasPrefix(d.Artifact.PublisherSigningState, want.signing) {
			t.Errorf("%s: provenance %s, signing %q (%s)", verdict, r.Status, d.Artifact.PublisherSigningState, r.Notes)
		}
	}
}

// The helper vouches for the signature; the scanner still binds the files.
// Falsification: skip CheckFiles for keyless and this passes.
func TestKeylessVerifiedStillBindsTheFiles(t *testing.T) {
	keylessEnv(t, "verified")
	dir := vectorCopy(t, "keyless")
	if err := os.WriteFile(filepath.Join(dir, "signme-1"), []byte("changed!"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusFail || !strings.Contains(r.Notes, "changed: signme-1") {
		t.Fatalf("provenance %s (%s)", r.Status, r.Notes)
	}
}

func TestKeylessWithoutVerifierIsNamed(t *testing.T) {
	publisherEnv(t, "", "")
	t.Setenv("SOCAIR_SIGSTORE_VERIFIER", "")
	d, err := Scan(vectorCopy(t, "keyless"))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "SOCAIR_SIGSTORE_VERIFIER") {
		t.Fatalf("provenance %s (%s)", r.Status, r.Notes)
	}
}

// A verifier with no identity policy would accept any signer: that is a
// configuration error, not a scan result.
func TestKeylessConfigurationErrors(t *testing.T) {
	for name, c := range map[string]struct {
		key, value, want string
	}{
		"no identities":          {"SOCAIR_SIGSTORE_IDENTITIES", "", "SOCAIR_SIGSTORE_IDENTITIES"},
		"no trusted root":        {"SOCAIR_SIGSTORE_TRUSTED_ROOT", "", "SOCAIR_SIGSTORE_TRUSTED_ROOT"},
		"missing verifier":       {"SOCAIR_SIGSTORE_VERIFIER", "/nonexistent/socair-sigstore", "SOCAIR_SIGSTORE_VERIFIER"},
		"empty identities":       {"SOCAIR_SIGSTORE_IDENTITIES", writeTemp(t, "# nobody\n"), "names no signer"},
		"malformed line":         {"SOCAIR_SIGSTORE_IDENTITIES", writeTemp(t, "only-one-field\n"), "line 1"},
		"trust root is not JSON": {"SOCAIR_SIGSTORE_TRUSTED_ROOT", writeTemp(t, "not json"), "not a readable JSON trust root"},
	} {
		keylessEnv(t, "verified")
		t.Setenv(c.key, c.value)
		if _, err := Scan(vectorCopy(t, "keyless")); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a configuration error naming %q", name, err, c.want)
		}
	}
}

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRealKeylessVerifier runs the real helper end to end on the reference
// implementation's keyless vector. Build it first:
//
//	(cd tools/socair-sigstore && go build -o /tmp/socair-sigstore .)
//	SOCAIR_TEST_SIGSTORE_VERIFIER=/tmp/socair-sigstore go test ./internal/engine -run RealKeyless -v
func TestRealKeylessVerifier(t *testing.T) {
	bin := os.Getenv("SOCAIR_TEST_SIGSTORE_VERIFIER")
	if bin == "" {
		t.Skip("set SOCAIR_TEST_SIGSTORE_VERIFIER to a built socair-sigstore")
	}
	publisherEnv(t, "", "")
	t.Setenv("SOCAIR_FAKE_SIGSTORE", "")
	root, _ := filepath.Abs(filepath.Join(omsVectors, "keys", "trusted-root-public-good.json"))
	t.Setenv("SOCAIR_SIGSTORE_VERIFIER", bin)
	t.Setenv("SOCAIR_SIGSTORE_TRUSTED_ROOT", root)
	for policy, want := range map[string]report.Status{
		"https://sigstore.verify.ibm.com/oauth2 stefanb@us.ibm.com\n":      report.StatusPass,
		"https://sigstore.verify.ibm.com/oauth2 someone-else@us.ibm.com\n": report.StatusNotTested,
	} {
		t.Setenv("SOCAIR_SIGSTORE_IDENTITIES", writeTemp(t, policy))
		d, err := Scan(vectorCopy(t, "keyless"))
		if err != nil {
			t.Fatal(err)
		}
		r := row(d, provRow)
		t.Logf("%s -> %s | %s", strings.TrimSpace(policy), r.Status, d.Artifact.PublisherSigningState)
		if r.Status != want {
			t.Errorf("policy %q: provenance %s (%s), want %s", policy, r.Status, r.Notes, want)
		}
	}
}
