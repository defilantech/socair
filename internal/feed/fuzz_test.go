package feed

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzLoad feeds hostile statements to Load. It must never panic, and never
// accept a statement no trusted key signed.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"x","sig":"AA=="}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, StatementFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, keys := signer(t)
		if _, err := Load(dir, keys, time.Now()); err == nil {
			t.Fatal("loaded a feed no trusted key signed")
		}
	})
}
