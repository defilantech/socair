package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2/tier2test"
)

// TestMain lets the test binary stand in for the socair-sigstore helper: run
// through a link with a mode file beside it (fakeVerifier), it answers one
// request with the verdict or behavior the file names, so the engine's side
// of the protocol is tested without building the helper. The helper's own
// cryptography is tested in tools/socair-sigstore.
func TestMain(m *testing.M) {
	// It also stands in for the Tier 2 probe helper (internal/tier2/tier2test).
	tier2test.Serve()
	if verdict := fakeVerifierMode(); verdict != "" {
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
		// The echo modes repeat every host path the verifier was handed, as
		// a verifier's diagnostics can: on standard error before it fails,
		// in its verdict's detail, and as its state. Its environment is
		// among what it was handed.
		echo := fmt.Sprintf("verifier %s, trusted root %s, environment [%s]", os.Args[0], req.TrustedRoot, strings.Join(os.Environ(), " "))
		switch verdict {
		case "crash":
			os.Exit(3)
		case "hang":
			time.Sleep(time.Minute)
			os.Exit(0)
		case "environ":
			// It records its whole environment beside itself, for the test
			// to read as it was, and answers unverified.
			out, _ := json.Marshal(os.Environ())
			if err := os.WriteFile(os.Args[0]+fakeEnvironSuffix, out, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(4)
			}
			fmt.Println(`{"state":"unverified","detail":"fake environ"}`)
			os.Exit(0)
		case "at-bound":
			fmt.Print(verifiedAnswer(keylessMaxAnswer))
			os.Exit(0)
		case "over-bound":
			fmt.Print(verifiedAnswer(keylessMaxAnswer + 1))
			os.Exit(0)
		case "echo-fail":
			fmt.Fprintln(os.Stderr, "socair-sigstore: bad request:", echo)
			os.Exit(2)
		case "echo-unverified":
			out, _ := json.Marshal(map[string]string{"state": "unverified", "detail": echo})
			fmt.Println(string(out))
			os.Exit(0)
		case "echo-state":
			out, _ := json.Marshal(map[string]string{"state": req.TrustedRoot})
			fmt.Println(string(out))
			os.Exit(0)
		}
		fmt.Printf(`{"state":%q,"signer":"releases@example.com (https://issuer.example)","detail":"fake %s"}`+"\n", verdict, verdict)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// The fake verifier's mode is a file beside the link it is run through, not
// a variable: the verifier is given none of Socair's environment.
const (
	fakeModeSuffix    = ".fake-sigstore"
	fakeEnvironSuffix = ".environ"
)

// fakeVerifierMode is the mode this process answers in as the keyless
// verifier, or "" when it is not one.
func fakeVerifierMode() string {
	b, err := os.ReadFile(os.Args[0] + fakeModeSuffix)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// fakeVerifier makes dir/name a link to this test binary that answers as the
// keyless verifier in mode, and returns the link. Called again with the same
// link, it changes the mode.
func fakeVerifier(t *testing.T, dir, name, mode string) string {
	t.Helper()
	link := filepath.Join(dir, name)
	if _, err := os.Lstat(link); err != nil {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(exe, link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(link+fakeModeSuffix, []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	return link
}

// verifiedAnswer is a verified verdict, newline included, of exactly size
// bytes.
func verifiedAnswer(size int) string {
	head, tail := `{"state":"verified","signer":"releases@example.com (https://issuer.example)","detail":"`, "\"}\n"
	return head + strings.Repeat("x", size-len(head)-len(tail)) + tail
}

// keylessEnv points the engine at the test binary as its keyless verifier,
// answering verdict, and returns the verifier's path.
func keylessEnv(t *testing.T, verdict string) string {
	t.Helper()
	publisherEnv(t, "", "")
	root, _ := filepath.Abs(filepath.Join(omsVectors, "keys", "trusted-root-public-good.json"))
	ids := filepath.Join(t.TempDir(), "identities")
	if err := os.WriteFile(ids, []byte("# accepted signers\nhttps://issuer.example releases@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := fakeVerifier(t, t.TempDir(), "socair-sigstore", verdict)
	t.Setenv("SOCAIR_SIGSTORE_VERIFIER", bin)
	t.Setenv("SOCAIR_SIGSTORE_TRUSTED_ROOT", root)
	t.Setenv("SOCAIR_SIGSTORE_IDENTITIES", ids)
	return bin
}

func TestKeylessVerdictsReachTheReport(t *testing.T) {
	cases := map[string]struct {
		status  report.Status
		signing string
	}{
		"verified":   {report.StatusPass, "verified (OMS, releases@example.com"},
		"invalid":    {report.StatusFail, "invalid (OMS): fake invalid"},
		"unverified": {report.StatusNotTested, "present, not verified (OMS): fake unverified"},
		"crash":      {report.StatusNotTested, "present, not verified (OMS): the keyless verifier failed: exit status 3"},
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

// The keyless verifier is given only the variables keylessEnvKeys allows, of
// which there are none (#228): no hub token, no proxy, no GODEBUG, no other
// Socair input, and not the Tier 2 helper's SOCAIR_PROBE_* either.
// Falsification: run the verifier with os.Environ(), or let verifierEnv
// return nil (which inherits it), and HF_TOKEN reaches it.
func TestKeylessVerifierGetsOnlyAllowedEnvironment(t *testing.T) {
	bin := keylessEnv(t, "environ")
	const secret = "SENTINEL"
	for _, k := range []string{"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "SIGSTORE_ID_TOKEN", "HTTPS_PROXY",
		"SOCAIR_PROBE_API_KEY", "SOCAIR_ACCEPTED_BY", "SOCAIR_TEST_UNLISTED"} {
		t.Setenv(k, secret)
	}
	// An unknown GODEBUG key changes nothing in this process.
	t.Setenv("GODEBUG", "socairsentinel="+secret)
	// Real paths, so this process still works: they must not reach the
	// verifier either.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TMPDIR", os.TempDir())
	for k := range keylessEnvKeys {
		t.Setenv(k, "allowed-"+k)
	}

	d, err := Scan(vectorCopy(t, "keyless"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Artifact.PublisherSigningState, "fake environ") {
		t.Fatalf("the fake verifier did not answer: %q", d.Artifact.PublisherSigningState)
	}
	raw, err := os.ReadFile(bin + fakeEnvironSuffix)
	if err != nil {
		t.Fatal(err)
	}
	var environ []string
	if err := json.Unmarshal(raw, &environ); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
		if !keylessEnvKeys[k] {
			t.Errorf("the verifier was given %s", k)
		}
	}
	if strings.Contains(string(raw), secret) {
		t.Errorf("a sentinel value reached the verifier: %s", raw)
	}
	for k := range keylessEnvKeys {
		if got[k] != "allowed-"+k {
			t.Errorf("the verifier must be given %s, got %q", k, got[k])
		}
	}
}

// The verifier's answer is bounded: one of keylessMaxAnswer bytes is read,
// and one a byte over is refused whole, though it would read as verified.
// Falsification: read its standard output unbounded and the over-bound
// answer passes; bound it lower and the at-bound answer is refused.
func TestKeylessAnswerIsBounded(t *testing.T) {
	keylessEnv(t, "at-bound")
	d, err := Scan(vectorCopy(t, "keyless"))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusPass || !strings.HasPrefix(d.Artifact.PublisherSigningState, "verified (OMS, releases@example.com") {
		t.Errorf("an answer of %d bytes: provenance %s, signing %q", keylessMaxAnswer, r.Status, d.Artifact.PublisherSigningState)
	}

	keylessEnv(t, "over-bound")
	d, err = Scan(vectorCopy(t, "keyless"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("present, not verified (OMS): the keyless verifier's answer is over %d bytes", keylessMaxAnswer)
	if r := row(d, provRow); r.Status != report.StatusNotTested || d.Artifact.PublisherSigningState != want || !strings.Contains(r.Notes, want[len("present, not verified (OMS): "):]) {
		t.Errorf("an answer over the bound: provenance %s (%s), signing %q, want %q", r.Status, r.Notes, d.Artifact.PublisherSigningState, want)
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
