package airlock

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/safetensors/safetensorstest"
)

// authorizedArtifact returns an on-disk fixture plus the engine's attestation
// of it, with the three trust inputs supplied so every row PASSes. It is a
// safetensors file: a GGUF cannot reach a clean authorization in Tier 1,
// because its tokenizer row is a label-only NOT_TESTED.
func authorizedArtifact(t *testing.T) (string, *report.Document) {
	t.Helper()
	dir := t.TempDir()

	mirror := filepath.Join(dir, "mirror")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_REPO_MIRROR", mirror)

	deny := filepath.Join(dir, "denylist.txt")
	if err := os.WriteFile(deny, []byte("0000000000000000000000000000000000000000000000000000000000000000  known-bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_DENYLIST", deny)

	prov := filepath.Join(dir, "provenance.json")
	sum := sha256.Sum256(safetensorstest.Clean())
	bound := fmt.Sprintf(`{"artifact_sha256":%q,"publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/example/model","commit_or_tag":"main","commit_sha":"71034c5d8bde858ff824298bdedc65515b97d2b9"}`, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(prov, []byte(bound), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCAIR_PROVENANCE", prov)
	t.Setenv("SOCAIR_ACCEPTED_BY", "")

	artifact := filepath.Join(dir, "fixture.safetensors")
	if err := os.WriteFile(artifact, safetensorstest.Clean(), 0o600); err != nil {
		t.Fatal(err)
	}

	d, err := engine.Scan(artifact)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if d.PromotionAuthorization.State != report.StateAuthorized {
		t.Fatalf("fixture did not reach authorized: state=%s", d.PromotionAuthorization.State)
	}
	return artifact, d
}

// testKey signs test attestations. The tests build the DSSE envelope by hand
// rather than through attest.Sign, so they can sign documents Sign would
// refuse (a forged state, a wrong hash) and show the gate catches them anyway;
// TestPromoteStoresArtifactAndAttestation covers the real Sign path.
var testKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func testKeyID(t *testing.T) string {
	t.Helper()
	id, err := attest.KeyID(testKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// trustedStore is a store whose trust policy holds testKey. The key file is
// written directly so the activity log starts empty.
func trustedStore(t *testing.T) *Store {
	t.Helper()
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(testKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(s.TrustPath(), "test.pub"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

// envelopeFor signs d with testKey as attest.Sign would, without validating d.
func envelopeFor(t *testing.T, d *report.Document) []byte {
	t.Helper()
	doc := *d
	id := testKeyID(t)
	doc.Verification.SigningMethod = attest.SigningMethod
	doc.Verification.SignerKeyID = id
	doc.Header.SignerKeyID = id
	h, err := attest.DocumentHash(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Verification.DocumentHash, doc.Header.DocumentHash = h, h
	st := attest.Statement{
		Type:          attest.StatementType,
		Subject:       []attest.Subject{{Name: doc.Artifact.FileName, Digest: map[string]string{"sha256": doc.Artifact.SHA256}}},
		PredicateType: attest.PredicateType,
		Predicate:     doc,
	}
	payload, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	msg := fmt.Sprintf("DSSEv1 %d %s %d %s", len(attest.PayloadType), attest.PayloadType, len(payload), payload)
	env := attest.Envelope{
		PayloadType: attest.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []attest.Signature{{KeyID: id, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(testKey, []byte(msg)))}},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeReport writes d as an attestation signed by testKey and returns its path.
func writeReport(t *testing.T, d *report.Document) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "attestation.dsse.json")
	if err := os.WriteFile(p, envelopeFor(t, d), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPromoteStoresArtifactAndAttestation runs the real path: a generated
// operator key, trusted by the store, signing through attest.Sign.
func TestPromoteStoresArtifactAndAttestation(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "operator")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(prefix + ".pub"); err != nil {
		t.Fatal(err)
	}
	k, err := attest.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	env, err := attest.Sign(*d, k)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(t.TempDir(), "a.dsse.json")
	if err := os.WriteFile(envPath, env, 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := Promote(s, artifact, envPath)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if e.Action != ActionPromote || e.Outcome != OutcomeOK || !strings.Contains(e.Detail, attest.ShortID(k.ID)) {
		t.Fatalf("event = %+v, want a clean promote naming the signer", e)
	}

	clean := s.CleanPath(d.Artifact.SHA256)
	stored, err := os.ReadFile(filepath.Join(clean, filepath.Base(artifact)))
	if err != nil {
		t.Fatalf("stored artifact: %v", err)
	}
	want, _ := os.ReadFile(artifact)
	if string(stored) != string(want) {
		t.Fatal("the stored bytes are not the artifact that crossed")
	}
	storedEnv, err := os.ReadFile(filepath.Join(clean, "attestation.dsse.json"))
	if err != nil || string(storedEnv) != string(env) {
		t.Fatalf("the signed envelope must travel with the artifact, byte for byte (err %v)", err)
	}
	doc, err := os.ReadFile(filepath.Join(clean, "attestation.json"))
	if err != nil {
		t.Fatalf("stored attestation: %v", err)
	}
	var back report.Document
	if err := json.Unmarshal(doc, &back); err != nil {
		t.Fatal(err)
	}
	if back.Artifact.SHA256 != d.Artifact.SHA256 || back.Verification.SignerKeyID != k.ID {
		t.Errorf("stored attestation = %s signed by %s", back.Artifact.SHA256, back.Verification.SignerKeyID)
	}
}

// TestPromoteRefusesUnsignedAndUntrusted: before signing, any document that
// validated was a ticket. An unsigned document, a signature by a key the store
// does not trust, and a store that trusts no key are all refused.
// Falsification: skip attest.Verify in Promote and the bare document crosses.
func TestPromoteRefusesUnsignedAndUntrusted(t *testing.T) {
	artifact, d := authorizedArtifact(t)

	bare := filepath.Join(t.TempDir(), "report.json")
	b, _ := json.Marshal(d)
	if err := os.WriteFile(bare, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s := trustedStore(t)
	if _, err := Promote(s, artifact, bare); !errors.Is(err, ErrRefused) {
		t.Fatalf("an unsigned document must be refused, got %v", err)
	}

	other, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Promote(other, artifact, writeReport(t, d))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no trusted signing key") {
		t.Fatalf("a store with no trusted key must refuse and say how to add one, got %v", err)
	}

	prefix := filepath.Join(t.TempDir(), "stranger")
	if _, err := attest.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Trust(prefix + ".pub"); err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(other, artifact, writeReport(t, d)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a signature by an untrusted key must be refused, got %v", err)
	}
	for _, st := range []*Store{s, other} {
		if entries, _ := os.ReadDir(st.CleanPath(d.Artifact.SHA256)); len(entries) != 0 {
			t.Fatalf("nothing may cross on a refused ticket, found %d entries", len(entries))
		}
	}
}

// TestRepromotionRestoresTheArtifact: a repeat promotion skipped placing the
// artifact when the attestation matched, so a deleted or altered clean copy
// was never restored. Falsification: skip placeVerified on "already promoted"
// and the deleted copy stays missing.
func TestRepromotionRestoresTheArtifact(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	s := trustedStore(t)
	env := writeReport(t, d)
	if _, err := Promote(s, artifact, env); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(s.CleanPath(d.Artifact.SHA256), filepath.Base(artifact))
	for _, damage := range []func(){
		func() { _ = os.Remove(stored) },
		func() { _ = os.WriteFile(stored, []byte("altered in the clean store"), 0o600) },
	} {
		damage()
		if _, err := Promote(s, artifact, env); err != nil {
			t.Fatal(err)
		}
		if got, err := hashFile(stored); err != nil || got != d.Artifact.SHA256 {
			t.Fatalf("re-promotion did not restore the clean copy: %s %v", got, err)
		}
	}
}

// TestReservedArtifactNameIsRefused: an artifact named attestation.json was
// overwritten by the report in its clean entry.
func TestReservedArtifactNameIsRefused(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	for _, name := range []string{"attestation.json", "attestation.dsse.json"} {
		renamed := filepath.Join(t.TempDir(), name)
		b, _ := os.ReadFile(artifact)
		if err := os.WriteFile(renamed, b, 0o600); err != nil {
			t.Fatal(err)
		}
		d.Artifact.FileName = name
		s := trustedStore(t)
		if _, err := Promote(s, renamed, writeReport(t, d)); !errors.Is(err, ErrRefused) {
			t.Fatalf("artifact named %s must be refused, got %v", name, err)
		}
	}
}

func TestPromoteRefusesWithheld(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	// Turn the report into a FAIL: withheld, not clearable here.
	d.Checks[0].Status = report.StatusFail
	d.Findings.Fails = []string{d.Checks[0].Name}
	d.PromotionAuthorization = report.PromotionAuthorization{State: report.StateWithheld, Level: "Tier 1 only"}

	s := trustedStore(t)
	_, err := Promote(s, artifact, writeReport(t, d))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("a withheld attestation must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "withholds promotion") {
		t.Errorf("the refusal should name the state, got %q", err)
	}
	if entries, _ := os.ReadDir(s.CleanPath(d.Artifact.SHA256)); len(entries) != 0 {
		t.Errorf("nothing may cross into the clean store on a refusal, found %d entries", len(entries))
	}
	ev, _ := s.Events()
	if len(ev) != 1 || ev[0].Action != ActionRefuse || ev[0].Outcome != OutcomeRefused {
		t.Errorf("a refusal must be logged, got %+v", ev)
	}
}

// TestPromoteRefusesForgedState: a report with a FAIL row whose promotion
// state was hand-edited to authorized used to cross into the clean store,
// because validation checked the state against its own fields but not against
// the checks. Falsification: drop validateStateAgainstChecks and this artifact
// lands in clean/.
func TestPromoteRefusesForgedState(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	d.Checks[0].Status = report.StatusFail
	d.Findings.Fails = []string{d.Checks[0].Name}
	// The forgery: the state still claims authorized.

	s := trustedStore(t)
	_, err := Promote(s, artifact, writeReport(t, d))
	if err == nil {
		t.Fatal("a forged authorized state over a FAIL must not promote")
	}
	if entries, _ := os.ReadDir(s.CleanPath(d.Artifact.SHA256)); len(entries) != 0 {
		t.Errorf("nothing may cross into the clean store on a forged report, found %d entries", len(entries))
	}
}

// TestPromoteCrossesOnlyVerifiedBytes: the gate hashed the artifact, then
// re-opened it by path to copy, so bytes swapped in between crossed into the
// clean store unverified. The hook rewrites the file after the gate opens it.
// The bytes that land in clean/ must be the bytes that were hashed: either the
// promotion is refused, or the stored file hashes to the attested digest.
// Falsification: hash first and copy by path, and the swapped bytes cross.
func TestPromoteCrossesOnlyVerifiedBytes(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	s := trustedStore(t)

	promoteOpened = func() {
		if err := os.WriteFile(artifact, []byte("swapped payload"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { promoteOpened = nil })

	_, err := Promote(s, artifact, writeReport(t, d))
	stored := filepath.Join(s.CleanPath(d.Artifact.SHA256), filepath.Base(artifact))
	if err == nil {
		got, herr := hashFile(stored)
		if herr != nil {
			t.Fatal(herr)
		}
		if got != d.Artifact.SHA256 {
			t.Fatalf("the clean store holds bytes hashing to %s, not the attested %s", got, d.Artifact.SHA256)
		}
		return
	}
	if _, statErr := os.Stat(stored); statErr == nil {
		t.Fatal("a refused promotion left bytes in the clean store")
	}
}

func TestPromoteRefusesHashMismatch(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	// The attestation authorizes a different artifact than the one on disk.
	fake := strings.Repeat("a", 64)
	d.Artifact.SHA256 = fake
	d.Verification.ArtifactSHA256 = fake

	s := trustedStore(t)
	_, err := Promote(s, artifact, writeReport(t, d))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("an artifact that does not hash to its ticket must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "on disk hashes to") {
		t.Errorf("the refusal should name the mismatch, got %q", err)
	}
}

func TestPromoteConditionsTravelWithArtifact(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	// A gap accepted by a named person: authorized with conditions.
	d.Checks[0].Status = report.StatusNotTested
	d.Findings.NotTested = []string{d.Checks[0].Name}
	d.PromotionAuthorization = report.PromotionAuthorization{
		State:            report.StateAuthorizedWithConditions,
		Authorized:       true,
		Level:            "Tier 1 only",
		AcceptedBy:       "chris",
		AcceptedSurfaces: []string{d.Checks[0].Name},
	}

	s := trustedStore(t)
	e, err := Promote(s, artifact, writeReport(t, d))
	if err != nil {
		t.Fatalf("a conditional attestation crosses: %v", err)
	}
	if e.Outcome != OutcomeConditional {
		t.Fatalf("a conditional crossing must be logged as conditional, got %q", e.Outcome)
	}

	stored, _ := os.ReadFile(filepath.Join(s.CleanPath(d.Artifact.SHA256), "attestation.json"))
	var back report.Document
	if err := json.Unmarshal(stored, &back); err != nil {
		t.Fatal(err)
	}
	if back.PromotionAuthorization.State != report.StateAuthorizedWithConditions {
		t.Errorf("state was flattened to %q", back.PromotionAuthorization.State)
	}
	if len(back.PromotionAuthorization.AcceptedSurfaces) != 1 {
		t.Errorf("the accepted surfaces must travel with the stored attestation, got %v",
			back.PromotionAuthorization.AcceptedSurfaces)
	}
}

func TestPromoteIsIdempotent(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	s := trustedStore(t)
	reportPath := writeReport(t, d)

	if _, err := Promote(s, artifact, reportPath); err != nil {
		t.Fatalf("first promote: %v", err)
	}
	if _, err := Promote(s, artifact, reportPath); err != nil {
		t.Fatalf("second promote: %v", err)
	}

	ev, _ := s.Events()
	if len(ev) != 2 {
		t.Fatalf("expected two promote events, got %d", len(ev))
	}
	if !strings.Contains(ev[1].Detail, "already promoted") {
		t.Errorf("re-promotion of an identical identity must be a store no-op, detail = %q", ev[1].Detail)
	}
	entries, _ := os.ReadDir(s.CleanPath(d.Artifact.SHA256))
	if len(entries) != 3 {
		t.Errorf("expected the artifact, the attestation, and its envelope, got %d entries", len(entries))
	}
}

func TestPromoteRejectsAnUnreadableArtifact(t *testing.T) {
	_, d := authorizedArtifact(t)
	s := trustedStore(t)
	if _, err := Promote(s, filepath.Join(t.TempDir(), "absent.gguf"), writeReport(t, d)); err == nil {
		t.Fatal("an unreadable artifact must be an error, not a promotion")
	}
}
