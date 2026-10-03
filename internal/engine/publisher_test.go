package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/report"
)

const omsVectors = "../oms/testdata/interop"

func vectorCopy(t *testing.T, name string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), name)
	err := filepath.Walk(filepath.Join(omsVectors, name), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join(omsVectors, name), p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func publisherEnv(t *testing.T, keys, roots string) {
	t.Helper()
	for _, k := range []string{"SOCAIR_PROVENANCE", "SOCAIR_OMS_SIGNATURE"} {
		t.Setenv(k, "")
	}
	abs := func(p string) string {
		if p == "" {
			return ""
		}
		a, err := filepath.Abs(filepath.Join(omsVectors, "keys", p))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	t.Setenv("SOCAIR_PUBLISHER_KEYS", abs(keys))
	t.Setenv("SOCAIR_PUBLISHER_ROOTS", abs(roots))
}

const provRow = "Hash, provenance, lineage"

// A directory signed by the reference implementation, with the publisher's
// key trusted, PASSes provenance on the signature and names the signer.
func TestOMSSignedDirectoryVerifies(t *testing.T) {
	for _, c := range []struct{ dir, keys, roots, signer string }{
		{"key256", "p256.pub", "", "key sha256:"},
		{"cert", "", "ca.crt", "model-release-signer"},
		{"shards", "p256.pub", "", "key sha256:"},
	} {
		publisherEnv(t, c.keys, c.roots)
		d, err := Scan(vectorCopy(t, c.dir))
		if err != nil {
			t.Fatal(err)
		}
		r := row(d, provRow)
		if r.Status != report.StatusPass || !strings.Contains(r.Notes, "not of safety") {
			t.Errorf("%s: provenance %s (%s)", c.dir, r.Status, r.Notes)
		}
		if s := d.Artifact.PublisherSigningState; !strings.HasPrefix(s, "verified (OMS, ") || !strings.Contains(s, c.signer) {
			t.Errorf("%s: publisher_signing_status %q", c.dir, s)
		}
	}
}

// The issue's falsification: a tampered OMS-signed model reports invalid,
// not verified, and is withheld.
func TestTamperedOMSDirectoryFails(t *testing.T) {
	publisherEnv(t, "p256.pub", "")
	dir := vectorCopy(t, "key256")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"model_type":"evil!"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, provRow)
	if r.Status != report.StatusFail || !strings.Contains(r.Notes, "changed: config.json") {
		t.Fatalf("provenance %s (%s), want FAIL naming config.json", r.Status, r.Notes)
	}
	if !strings.HasPrefix(d.Artifact.PublisherSigningState, "invalid (OMS)") || d.PromotionAuthorization.Authorized {
		t.Fatalf("signing %q, state %s", d.Artifact.PublisherSigningState, d.PromotionAuthorization.State)
	}
}

// With no trust configured, a signature is named but proves nothing.
func TestUntrustedOMSSignatureIsNamedNotTrusted(t *testing.T) {
	publisherEnv(t, "", "")
	d, err := Scan(vectorCopy(t, "key256"))
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, provRow)
	if r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "OMS signature present, not verified") {
		t.Fatalf("provenance %s (%s)", r.Status, r.Notes)
	}
	if !strings.HasPrefix(d.Artifact.PublisherSigningState, "present, not verified (OMS)") {
		t.Errorf("signing %q", d.Artifact.PublisherSigningState)
	}
}

func TestOMSSignedSingleFile(t *testing.T) {
	publisherEnv(t, "p256.pub", "")
	dir := vectorCopy(t, "single")
	d, err := Scan(filepath.Join(dir, "model.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusPass {
		t.Fatalf("provenance %s (%s)", r.Status, r.Notes)
	}
	// The sidecar no longer matches once the file changes.
	if err := os.WriteFile(filepath.Join(dir, "model.bin"), []byte("other bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err = Scan(filepath.Join(dir, "model.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusFail {
		t.Fatalf("changed file: provenance %s (%s)", r.Status, r.Notes)
	}
}

// A .sig that is not a Sigstore bundle (minisign, GPG) is not an OMS
// signature: the row keeps naming it as an unverified sidecar.
func TestNonOMSSidecarIsLeftAlone(t *testing.T) {
	publisherEnv(t, "p256.pub", "")
	p := writeFixture(t, "model.gguf", []byte("GGUF-ish"))
	if err := os.WriteFile(p+".sig", []byte("untrusted comment: minisign\nRWQ...\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "model.gguf.sig present, not verified") {
		t.Fatalf("provenance %s (%s)", r.Status, r.Notes)
	}
}

func TestMisconfiguredPublisherTrustIsAnError(t *testing.T) {
	publisherEnv(t, "", "")
	bad := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(bad, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_PUBLISHER_KEYS", bad)
	if _, err := Scan(vectorCopy(t, "key256")); err == nil {
		t.Fatal("a trust policy that does not load must stop the scan, not silently trust nothing")
	}
}
