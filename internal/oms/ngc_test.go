package oms_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/oms"
	"github.com/defilantech/socair/internal/oms/omstest"
)

// signedAt is inside every generated leaf's validity, so a test's verdict
// never depends on the clock.
var signedAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func newPKI(t *testing.T, from, to time.Time) *omstest.PKI {
	t.Helper()
	p, err := omstest.NewPKI("Test Publisher", from, to)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ngcDir writes a small model directory and signs it as NVIDIA signs NGC
// models: a certificate chain, files serialization, no ignore_paths. The
// signature is written to result.sigstore at the root after signing, as the
// NGC CLI downloads it there.
func ngcDir(t *testing.T, p *omstest.PKI) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"labels.txt":         "car\nbicycle\nperson\nroad_sign\n",
		"nvinfer_config.txt": "net-scale-factor=0.0039\n",
		"model.onnx":         "not a real network, only bytes to sign",
		"sub/int8.txt":       "calibration\n",
	} {
		write(t, filepath.Join(dir, name), body)
	}
	b, err := omstest.Sign(dir, omstest.Options{Key: p.LeafKey, Chain: p.Chain(), NGC: true})
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "result.sigstore"), string(b))
	return dir
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rootTrust(t *testing.T, p *omstest.PKI, now time.Time) oms.Trust {
	t.Helper()
	f := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(f, p.RootPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err := oms.LoadTrust("", f)
	if err != nil {
		t.Fatal(err)
	}
	tr.Now = now
	return tr
}

func verifyDir(t *testing.T, dir string, tr oms.Trust, c oms.Compare) (oms.Outcome, []string, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "result.sigstore"))
	if err != nil {
		t.Fatal(err)
	}
	o := oms.Verify(raw, tr)
	if o.State != oms.Verified {
		return o, nil, nil
	}
	_, files, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	diffs, ignored, err := oms.CheckFiles(o.Manifest, dir, files, c)
	if err != nil {
		t.Fatal(err)
	}
	return o, diffs, ignored
}

// A signature shaped as NGC's verifies against its root, names the leaf, and
// binds every file; with the root untrusted it proves nothing.
func TestNGCShapedSignature(t *testing.T) {
	p := newPKI(t, signedAt.AddDate(0, -1, 0), signedAt.AddDate(2, 0, 0))
	dir := ngcDir(t, p)
	o, diffs, ignored := verifyDir(t, dir, rootTrust(t, p, signedAt), oms.Compare{Signature: "result.sigstore"})
	if o.State != oms.Verified || o.Method != "certificate" || !strings.Contains(o.Signer, "Test Publisher Model Signing Issuer 001") {
		t.Fatalf("%s %s %q (%s)", o.State, o.Method, o.Signer, o.Detail)
	}
	if len(diffs) != 0 || len(ignored) != 0 {
		t.Fatalf("diffs %v, ignored %v", diffs, ignored)
	}
	if o, _, _ := verifyDir(t, dir, oms.Trust{Now: signedAt}, oms.Compare{}); o.State != oms.Unverified {
		t.Fatalf("no root trusted: %s, want unverified", o.State)
	}
	other := newPKI(t, signedAt.AddDate(0, -1, 0), signedAt.AddDate(2, 0, 0))
	if o, _, _ := verifyDir(t, dir, rootTrust(t, other, signedAt), oms.Compare{}); o.State != oms.Unverified {
		t.Fatalf("another root trusted: %s, want unverified", o.State)
	}
}

// OMS v1.0 section 8.2: the leaf must be within its validity period. The
// chain is checked at the scan's time, and outside the leaf's period it is
// unverified (it proves nothing), not invalid. Falsification: check at the
// leaf's own notBefore, as model_signing 1.1.1 did, and the expired and
// not-yet-valid cases verify.
func TestChainCheckedAtScanTime(t *testing.T) {
	from, to := signedAt.AddDate(0, -1, 0), signedAt.AddDate(0, 1, 0)
	p := newPKI(t, from, to)
	dir := ngcDir(t, p)
	for name, at := range map[string]time.Time{
		"expired":       to.Add(time.Hour),
		"not yet valid": from.Add(-time.Hour),
	} {
		o, _, _ := verifyDir(t, dir, rootTrust(t, p, at), oms.Compare{})
		if o.State != oms.Unverified || !strings.Contains(o.Detail, "not valid at the scan time") {
			t.Errorf("%s: %s (%s), want unverified at the scan time", name, o.State, o.Detail)
		}
	}
	if o, _, _ := verifyDir(t, dir, rootTrust(t, p, signedAt), oms.Compare{}); o.State != oms.Verified {
		t.Errorf("inside the period: %s (%s)", o.State, o.Detail)
	}
}

// NGC manifests list no ignore_paths, so OMS's default exclusions decide a
// top-level .gitattributes or .github: named as not covered, never "not
// signed". The defaults are top-level only. Falsification: drop the default
// exclusions and .gitattributes becomes a difference.
func TestDefaultExclusionsApplyAtTheTop(t *testing.T) {
	p := newPKI(t, signedAt.AddDate(0, -1, 0), signedAt.AddDate(2, 0, 0))
	dir := ngcDir(t, p)
	write(t, filepath.Join(dir, ".gitattributes"), "*.onnx filter=lfs\n")
	write(t, filepath.Join(dir, ".github", "workflows", "x.yml"), "on: push\n")
	write(t, filepath.Join(dir, "sub", ".gitignore"), "*.tmp\n")
	_, diffs, ignored := verifyDir(t, dir, rootTrust(t, p, signedAt), oms.Compare{Signature: "result.sigstore"})
	if strings.Join(diffs, "|") != "not signed: sub/.gitignore" {
		t.Errorf("diffs %v, want only the nested .gitignore", diffs)
	}
	want := []string{".gitattributes (an OMS default exclusion)", ".github/workflows/x.yml (an OMS default exclusion)"}
	if strings.Join(ignored, "|") != strings.Join(want, "|") {
		t.Errorf("ignored %v, want %v", ignored, want)
	}
}

// A path the verifier leaves out is left out only when the manifest does not
// list it: a listed file is always compared. Unsigned files are tolerated
// only when asked, and a change or a missing file is still a difference.
func TestCompareOptions(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.bin"), "a")
	write(t, filepath.Join(dir, "b.bin"), "b")
	m := &oms.Manifest{Method: "files", HashType: "sha256", Resources: []oms.Resource{
		{Name: "a.bin", Algorithm: "sha256", Digest: sum("a")},
		{Name: "b.bin", Algorithm: "sha256", Digest: sum("b")},
		{Name: "c.bin", Algorithm: "sha256", Digest: sum("c")},
	}}
	write(t, filepath.Join(dir, "a.bin"), "changed")
	write(t, filepath.Join(dir, "extra", "x"), "x")
	write(t, filepath.Join(dir, "model.sig"), "{}")
	_, files, err := modeldir.Hash(dir)
	if err != nil {
		t.Fatal(err)
	}
	check := func(c oms.Compare) ([]string, []string) {
		d, i, err := oms.CheckFiles(m, dir, files, c)
		if err != nil {
			t.Fatal(err)
		}
		return d, i
	}

	d, i := check(oms.Compare{Exclude: []oms.Exclusion{{Path: "extra", Why: "excluded by the verifier"}, {Path: "a.bin", Why: "excluded by the verifier"}, {Path: "model.sig", Why: "a signature file"}}})
	if strings.Join(d, "|") != "changed: a.bin|missing: c.bin" {
		t.Errorf("exclusions: diffs %v", d)
	}
	if strings.Join(i, "|") != "extra/x (excluded by the verifier)|model.sig (a signature file)" {
		t.Errorf("exclusions: ignored %v", i)
	}

	d, i = check(oms.Compare{AllowUnsigned: true})
	if strings.Join(d, "|") != "changed: a.bin|missing: c.bin" || len(i) != 2 {
		t.Errorf("unsigned tolerated: diffs %v, ignored %v", d, i)
	}
	d, _ = check(oms.Compare{})
	if strings.Join(d, "|") != "changed: a.bin|missing: c.bin|not signed: extra/x|not signed: model.sig" {
		t.Errorf("no options: diffs %v", d)
	}
}

// A single file checked against a signature over several files is not
// judged when it is one of them (the others are not in hand), and differs
// when it is none of them.
func TestSingleFileAgainstADirectorySignature(t *testing.T) {
	m := &oms.Manifest{Method: "files", HashType: "sha256", Resources: []oms.Resource{
		{Name: "a.bin", Algorithm: "sha256", Digest: sum("a")},
		{Name: "b.bin", Algorithm: "sha256", Digest: sum("b")},
	}}
	if d, err := oms.CheckFile(m, sum("b")); err == nil || len(d) != 0 || !strings.Contains(err.Error(), "one of them (b.bin)") {
		t.Errorf("one of them: %v %v", d, err)
	}
	if d, err := oms.CheckFile(m, sum("z")); err != nil || len(d) != 1 {
		t.Errorf("none of them: %v %v", d, err)
	}
}

// Several root files load as one pool.
func TestLoadTrustFromSeveralRoots(t *testing.T) {
	p1 := newPKI(t, signedAt.AddDate(0, -1, 0), signedAt.AddDate(2, 0, 0))
	p2 := newPKI(t, signedAt.AddDate(0, -1, 0), signedAt.AddDate(2, 0, 0))
	var paths []string
	for i, p := range []*omstest.PKI{p1, p2} {
		f := filepath.Join(t.TempDir(), "root"+string(rune('a'+i))+".crt")
		if err := os.WriteFile(f, p.RootPEM(), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, f)
	}
	tr, err := oms.LoadTrustFrom(nil, paths)
	if err != nil {
		t.Fatal(err)
	}
	tr.Now = signedAt
	if o, _, _ := verifyDir(t, ngcDir(t, p2), tr, oms.Compare{Signature: "result.sigstore"}); o.State != oms.Verified {
		t.Fatalf("%s (%s)", o.State, o.Detail)
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
