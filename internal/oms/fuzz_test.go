package oms

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzVerify feeds hostile signature files to Verify, with a key and a root
// trusted so every path past the trust check is reachable. It must never
// panic, and never report an unrecognized file as verified.
func FuzzVerify(f *testing.F) {
	for _, p := range []string{"key256/model.sig", "cert/model.sig", "shards/model.sig", "single/model.gguf.sig"} {
		if b, err := os.ReadFile(filepath.Join(interop, p)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"dsseEnvelope":{}}`))
	tr, err := LoadTrust(filepath.Join(interop, "keys", "p256.pub"), filepath.Join(interop, "keys", "ca.pem"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		o := Verify(raw, tr)
		if o.State == Verified && (!o.Recognized || o.Manifest == nil) {
			t.Fatalf("verified without a recognized bundle and manifest: %+v", o)
		}
		if o.Manifest != nil {
			_, _ = CheckFile(o.Manifest, "")
		}
	})
}
