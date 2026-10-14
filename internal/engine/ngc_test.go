package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/oms/omstest"
	"github.com/defilantech/socair/internal/report"
)

// ngcModel writes a model directory laid out as the NGC CLI downloads one
// (`ngc registry model download-version` and `download-version-signature`
// to the same --dest): the model's files, and result.sigstore at the root.
// The signature is made the way NVIDIA makes NGC's: a certificate chain to a
// root, files serialization, no ignore_paths. It returns the directory and
// the root certificate's file, for SOCAIR_PUBLISHER_ROOTS.
func ngcModel(t *testing.T, from, to time.Time) (string, string, *omstest.PKI) {
	t.Helper()
	p, err := omstest.NewPKI("Test Publisher", from, to)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "detector_v1.0")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"labels.txt":         "car\nbicycle\nperson\nroad_sign\n",
		"nvinfer_config.txt": "net-scale-factor=0.0039\nnum-detected-classes=4\n",
		"detector.onnx":      "not a real network, only bytes to sign",
		"int8_cache.txt":     "calibration table\n",
	} {
		writeFixtureAt(t, filepath.Join(dir, name), []byte(body))
	}
	sig, err := omstest.Sign(dir, omstest.Options{Key: p.LeafKey, Chain: p.Chain(), NGC: true})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureAt(t, filepath.Join(dir, "result.sigstore"), sig)
	root := filepath.Join(t.TempDir(), "root.crt")
	writeFixtureAt(t, root, p.RootPEM())
	return dir, root, p
}

func ngcEnv(t *testing.T, roots string) {
	t.Helper()
	for _, k := range []string{"SOCAIR_PROVENANCE", "SOCAIR_OMS_SIGNATURE", "SOCAIR_PUBLISHER_KEYS", "SOCAIR_SIGSTORE_VERIFIER"} {
		t.Setenv(k, "")
	}
	t.Setenv("SOCAIR_PUBLISHER_ROOTS", roots)
}

// ngcModelNow is ngcModel with a leaf valid around the scan's time.
func ngcModelNow(t *testing.T) (string, string, *omstest.PKI) {
	t.Helper()
	return ngcModel(t, time.Now().AddDate(0, -1, 0), time.Now().AddDate(1, 0, 0))
}

// A directory scan finds result.sigstore at the root, as NGC downloads it,
// and with the publisher's root trusted it PASSes provenance on the
// signature. Falsification: look only for model.sig and the row is
// NOT_TESTED with no provenance input.
func TestNGCSignatureAtRootVerifies(t *testing.T) {
	dir, root, _ := ngcModelNow(t)
	ngcEnv(t, root)
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, provRow)
	if r.Status != report.StatusPass || !strings.Contains(r.Notes, "not of safety") {
		t.Fatalf("provenance %s (%s)", r.Status, r.Notes)
	}
	if s := d.Artifact.PublisherSigningState; !strings.HasPrefix(s, "verified (OMS, certificate ") || !strings.Contains(s, "Test Publisher Model Signing Issuer 001") {
		t.Fatalf("publisher_signing_status %q", s)
	}
}

// The issue's falsification: an NGC-layout model with one file changed FAILs
// provenance, naming the file.
func TestNGCChangedFileFails(t *testing.T) {
	dir, root, _ := ngcModelNow(t)
	ngcEnv(t, root)
	if err := os.WriteFile(filepath.Join(dir, "labels.txt"), []byte("car\nbicycle\nperson\nstop_sign_is_a_speed_limit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, provRow)
	if r.Status != report.StatusFail || !strings.Contains(r.Notes, "changed: labels.txt") {
		t.Fatalf("provenance %s (%s), want FAIL naming labels.txt", r.Status, r.Notes)
	}
	if d.PromotionAuthorization.Authorized {
		t.Fatal("a changed signed file must withhold promotion")
	}
}

// The issue's falsification: with no trusted root for its signer, the
// signature is named and not judged, never PASS, and an untrusted signer
// cannot FAIL a model either, changed or not.
func TestNGCUntrustedSignerIsNamedNotJudged(t *testing.T) {
	dir, _, _ := ngcModelNow(t)
	_, otherRoot, _ := ngcModelNow(t)
	for name, roots := range map[string]string{"no root": "", "another root": otherRoot} {
		ngcEnv(t, roots)
		for _, changed := range []bool{false, true} {
			if changed {
				if err := os.WriteFile(filepath.Join(dir, "detector.onnx"), []byte("other bytes"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			d, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			r := row(d, provRow)
			if r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "OMS signature present, not verified") {
				t.Errorf("%s, changed %v: provenance %s (%s)", name, changed, r.Status, r.Notes)
			}
			if !strings.HasPrefix(d.Artifact.PublisherSigningState, "present, not verified (OMS)") {
				t.Errorf("%s, changed %v: signing %q", name, changed, d.Artifact.PublisherSigningState)
			}
		}
	}
}

// NVIDIA's NIM guide downloads the signature to a separate directory. The
// scan does not search outside the model's directory; SOCAIR_OMS_SIGNATURE
// names the file.
func TestNGCSignatureOutsideTheDirectory(t *testing.T) {
	dir, root, _ := ngcModelNow(t)
	sig := filepath.Join(t.TempDir(), "signatures", "detector_v1.0", "result.sigstore")
	if err := os.MkdirAll(filepath.Dir(sig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "result.sigstore"), sig); err != nil {
		t.Fatal(err)
	}
	ngcEnv(t, root)
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "no provenance input") {
		t.Fatalf("not named: provenance %s (%s)", r.Status, r.Notes)
	}
	t.Setenv("SOCAIR_OMS_SIGNATURE", sig)
	if d, err = Scan(dir); err != nil {
		t.Fatal(err)
	}
	if r := row(d, provRow); r.Status != report.StatusPass {
		t.Fatalf("named: provenance %s (%s)", r.Status, r.Notes)
	}
}

// model.sig and result.sigstore both at the root: the scan does not choose.
// Named with SOCAIR_OMS_SIGNATURE, the other is left out of the comparison
// and named as not covered, so it is not a difference.
func TestTwoRootSignaturesAreNotChosen(t *testing.T) {
	dir, root, _ := ngcModelNow(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := omstest.Sign(dir, omstest.Options{Key: k, Ignore: []string{"result.sigstore"}})
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureAt(t, filepath.Join(dir, "model.sig"), other)
	ngcEnv(t, root)
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, provRow)
	if r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "does not choose between them") {
		t.Fatalf("both: provenance %s (%s)", r.Status, r.Notes)
	}
	t.Setenv("SOCAIR_OMS_SIGNATURE", filepath.Join(dir, "result.sigstore"))
	if d, err = Scan(dir); err != nil {
		t.Fatal(err)
	}
	r = row(d, provRow)
	if r.Status != report.StatusPass || !strings.Contains(r.Notes, "model.sig (a signature file, not the one verified)") {
		t.Fatalf("named: provenance %s (%s)", r.Status, r.Notes)
	}
}

// A certificate outside its validity at the scan's time proves nothing: the
// signature is named, not verified, and does not FAIL the row.
func TestExpiredSigningCertificateIsNotVerified(t *testing.T) {
	dir, root, _ := ngcModel(t, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	ngcEnv(t, root)
	d, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := row(d, provRow)
	if r.Status != report.StatusNotTested || !strings.Contains(r.Notes, "not valid at the scan time") {
		t.Fatalf("provenance %s (%s)", r.Status, r.Notes)
	}
}
