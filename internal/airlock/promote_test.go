package airlock

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if err := os.WriteFile(prov, []byte(`{"publisher":"example","signing_status":"signed","repo_url":"https://huggingface.co/example/model","commit_or_tag":"main"}`), 0o600); err != nil {
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

// writeReport marshals a document to a temp file.
func writeReport(t *testing.T, d *report.Document) string {
	t.Helper()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPromoteStoresArtifactAndAttestation(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reportPath := writeReport(t, d)
	reportBytes, _ := os.ReadFile(reportPath)

	e, err := Promote(s, artifact, reportPath)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if e.Action != ActionPromote || e.Outcome != OutcomeOK {
		t.Fatalf("event = %+v, want a clean promote", e)
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
	attest, err := os.ReadFile(filepath.Join(clean, "attestation.json"))
	if err != nil {
		t.Fatalf("stored attestation: %v", err)
	}
	if string(attest) != string(reportBytes) {
		t.Fatal("the promoted artifact must carry its attestation, byte for byte")
	}
	var back report.Document
	if err := json.Unmarshal(attest, &back); err != nil {
		t.Fatal(err)
	}
	if back.Artifact.SHA256 != d.Artifact.SHA256 {
		t.Errorf("stored attestation hashes %s, store key is %s", back.Artifact.SHA256, d.Artifact.SHA256)
	}
}

func TestPromoteRefusesWithheld(t *testing.T) {
	artifact, d := authorizedArtifact(t)
	// Turn the report into a FAIL: withheld, not clearable here.
	d.Checks[0].Status = report.StatusFail
	d.Findings.Fails = []string{d.Checks[0].Name}
	d.PromotionAuthorization = report.PromotionAuthorization{State: report.StateWithheld, Level: "Tier 1 only"}

	s, _ := Init(t.TempDir())
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

	s, _ := Init(t.TempDir())
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
	s, _ := Init(t.TempDir())

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

	s, _ := Init(t.TempDir())
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

	s, _ := Init(t.TempDir())
	e, err := Promote(s, artifact, writeReport(t, d))
	if err != nil {
		t.Fatalf("a conditional attestation crosses: %v", err)
	}
	if e.Outcome != OutcomeConditional {
		t.Fatalf("a conditional crossing must be logged as conditional, got %q", e.Outcome)
	}

	attest, _ := os.ReadFile(filepath.Join(s.CleanPath(d.Artifact.SHA256), "attestation.json"))
	var back report.Document
	if err := json.Unmarshal(attest, &back); err != nil {
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
	s, _ := Init(t.TempDir())
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
	if len(entries) != 2 {
		t.Errorf("expected the artifact and one attestation, got %d entries", len(entries))
	}
}

func TestPromoteRejectsAnUnreadableArtifact(t *testing.T) {
	_, d := authorizedArtifact(t)
	s, _ := Init(t.TempDir())
	if _, err := Promote(s, filepath.Join(t.TempDir(), "absent.gguf"), writeReport(t, d)); err == nil {
		t.Fatal("an unreadable artifact must be an error, not a promotion")
	}
}
