package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestNewerReportFieldIsNamedAsSuch (#250): a signed report with a field this
// socair does not know is still refused, since a verifier shows every field
// it accepts, and the error says the likely cause, a report signed by a newer
// socair, instead of only that the predicate is not a report. Falsification:
// accept unknown fields and the report verifies; drop the hint and the
// message does not say what to do.
func TestNewerReportFieldIsNamedAsSuch(t *testing.T) {
	k, ring, _ := newKey(t)
	env, err := Sign(golden(t), k)
	if err != nil {
		t.Fatal(err)
	}
	var e Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	var st map[string]any
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	st["predicate"].(map[string]any)["added_in_a_newer_socair"] = "x"
	payload, _ = json.Marshal(st)
	e.Payload = base64.StdEncoding.EncodeToString(payload)
	e.Signatures = []Signature{{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(k.key, pae(e.PayloadType, payload)))}}
	out, _ := json.Marshal(e)

	_, err = Verify(out, ring)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("Verify = %v, want ErrVerify", err)
	}
	for _, want := range []string{`unknown field "added_in_a_newer_socair"`, "newer socair"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Verify error %q does not say %q", err, want)
		}
	}
}
