package acceptance

import (
	"crypto/ed25519"
	"testing"
)

// FuzzParse feeds hostile envelopes to Parse and Verify. They must never
// panic, and Verify must never accept what no trusted key signed.
func FuzzParse(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id, _ := KeyID(pub)
	if raw, err := Sign(predicate(), "m", sha, priv, id); err == nil {
		f.Add(raw)
	}
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"x","sig":""}]}`))
	ring := map[string]ed25519.PublicKey{}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Parse(raw)
		if _, err := Verify(raw, ring); err == nil {
			t.Fatal("verified with an empty keyring")
		}
	})
}
