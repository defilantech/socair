package ociattest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/ociattest"
	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/registry/registrytest"
)

// runCosign runs cosign verify-attestation for the binding's predicate type
// with a key and no transparency log, in a scratch home so it reads no
// local Sigstore state, and returns its standard output.
func runCosign(t *testing.T, cosign, pub, image string, env []string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, cosign, "verify-attestation", "--key", pub,
		"--type", ociattest.BindingPredicateType, "--insecure-ignore-tlog=true", image)
	home := t.TempDir()
	cmd.Env = append(env, "HOME="+home, "TUF_ROOT="+home+"/tuf", "SIGSTORE_NO_CACHE=true")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	t.Logf("cosign %s: %v\n%s", image, err, errb.String())
	return out.String(), err
}

// TestCosignVerifiesTheBinding runs a real cosign against an attached
// artifact: cosign verify-attestation with the operator's Ed25519 public key
// must find the Sigstore bundle referrer and verify the binding, offline
// (--insecure-ignore-tlog: no transparency log entry exists), and must
// refuse the same artifact under another key and an artifact with no
// binding. Opt-in, like the other tests that need a tool or a resource:
//
//	SOCAIR_TEST_COSIGN=/path/to/cosign go test ./internal/ociattest -run Cosign -v
//
// It talks only to the in-process registry on 127.0.0.1.
func TestCosignVerifiesTheBinding(t *testing.T) {
	cosign := os.Getenv("SOCAIR_TEST_COSIGN")
	if cosign == "" {
		t.Skip("set SOCAIR_TEST_COSIGN to a cosign binary to run")
	}
	modes(t, func(t *testing.T, o registrytest.Options) {
		f := attached(t, o)
		run := func(pub, image string) (string, error) { return runCosign(t, cosign, pub, image, os.Environ()) }
		image := f.srv.Host + "/" + f.ref.Repository + "@" + f.md
		out, err := run(f.k.pub, image)
		if err != nil {
			t.Fatalf("cosign verify-attestation refused the binding: %v", err)
		}
		// cosign prints the verified envelope; its statement is the binding.
		var env struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal([]byte(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]), &env); err != nil {
			t.Fatalf("cosign output %q: %v", out, err)
		}
		payload, _ := base64.StdEncoding.DecodeString(env.Payload)
		var st ociattest.Statement
		if err := json.Unmarshal(payload, &st); err != nil {
			t.Fatal(err)
		}
		if "sha256:"+st.Subject[0].Digest["sha256"] != f.md || st.Predicate.Attestation.PromotionState != f.doc.PromotionAuthorization.State {
			t.Errorf("cosign verified %+v", st)
		}

		if _, err := run(newKey(t, "").pub, image); err == nil {
			t.Error("cosign verified the binding under another key")
		}
		ref2, md2 := f.secondArtifact(t)
		image2 := f.srv.Host + "/" + f.ref.Repository + "@" + md2
		if _, err := run(f.k.pub, image2); err == nil {
			t.Error("cosign verified an artifact that has no binding")
		}
		// The first artifact's bundle, listed as a referrer of the second
		// (which carries the same bytes): the signed subject is the first's
		// digest, so cosign must refuse it.
		b, _ := f.srv.ManifestBytes(f.ref.Repository, f.att.Bundle.Digest)
		var m registry.Manifest
		json.Unmarshal(b, &m)
		art, err := client().Repo(ref2).Manifest(ctx, md2)
		if err != nil {
			t.Fatal(err)
		}
		m.Subject = &registry.Descriptor{MediaType: art.Descriptor.MediaType, Digest: md2, Size: art.Descriptor.Size}
		pushReferrer(t, ref2, m)
		if _, err := run(f.k.pub, image2); err == nil {
			t.Error("cosign verified a binding whose subject is another artifact")
		}
	})
}
