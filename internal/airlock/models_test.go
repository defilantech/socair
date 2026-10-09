package airlock

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defilantech/socair/internal/report"
)

func modelByID(t *testing.T, s *Store, id string, at time.Time) Model {
	t.Helper()
	ms, err := s.Models(at)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("model %s not listed in %+v", id, ms)
	return Model{}
}

func TestStageStagedAndScanned(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageStaged || m.Next.Action != "scan" || m.Location != "staging" {
		t.Fatalf("%+v", m)
	}
	_, d := authorizedArtifact(t)
	if err := s.SaveReport(id, d); err != nil {
		t.Fatal(err)
	}
	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageScanned || m.Next.Action != "sign" || !strings.Contains(m.Next.Command, "socair sign") {
		t.Fatalf("%+v", m)
	}
}

func TestStageReadyNeedsAcceptanceBlocked(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	if _, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageReady || m.Next.Action != "promote" {
		t.Fatalf("authorized: %+v", m)
	}

	gap := *d
	withholdForGap(&gap)
	if _, err := s.SaveAttestation(id, envelopeFor(t, &gap), time.Now()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageNeedsAcceptance || m.Next.Action != "accept" ||
		!strings.Contains(m.Next.Command, "socair accept") {
		t.Fatalf("withheld on a gap: %+v", m)
	}

	// Falsification: treat any withheld state as needs-acceptance and this fails.
	lead := *d
	lead.Checks = append([]report.CheckResult(nil), d.Checks...)
	lead.Checks[0].Status = report.StatusLead
	lead.BoundedStatement = report.BoundedStatementFor(lead.Checks)
	lead.Findings.Leads = []string{lead.Checks[0].Name}
	lead.PromotionAuthorization = report.PromotionAuthorization{State: report.StateWithheld, Level: "Tier 1 only",
		Conditions: "Withheld: " + lead.Checks[0].Name + " is a LEAD."}
	if _, err := s.SaveAttestation(id, envelopeFor(t, &lead), time.Now()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageBlocked || m.Next.Action != "none" {
		t.Fatalf("a LEAD is blocked, never acceptable: %+v", m)
	}
	// Placeholders in copyable commands carry no shell metacharacters.
	if _, err := s.SaveAttestation(id, envelopeFor(t, &gap), time.Now()); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); !strings.Contains(m.Next.Command, "ACCEPTOR_KEY") || strings.ContainsAny(m.Next.Command, "<>") {
		t.Fatalf("command has shell metacharacters: %q", m.Next.Command)
	}
}

func promoted(t *testing.T, s *Store) string {
	t.Helper()
	artifact, d := authorizedArtifact(t)
	if _, err := Promote(s, artifact, writeReport(t, d)); err != nil {
		t.Fatal(err)
	}
	return d.Artifact.SHA256
}

func TestStageApprovedThenDoesNotVerify(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageApproved || m.Location != "clean" || m.PromotionState != report.StateAuthorized || m.PromotedAt == "" {
		t.Fatalf("%+v", m)
	}
	// Falsification: list clean entries without verifying them and this stays approved.
	if err := os.Remove(filepath.Join(s.TrustPath(), "test.pub")); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageDoesNotVerify || m.StageReason == "" {
		t.Fatalf("an attestation no trusted key verifies must not show as approved: %+v", m)
	}
}

// Review Focus 4: the expiry boundaries.
func TestConditionalExpiryBoundaries(t *testing.T) {
	s := trustedStore(t)
	artifact, d := authorizedArtifact(t)
	withholdForGap(d)
	ticket := acceptedTicket(t, s, d, 40*24*time.Hour)
	if _, err := Promote(s, artifact, ticket); err != nil {
		t.Fatal(err)
	}
	id := d.Artifact.SHA256
	m := modelByID(t, s, id, time.Now())
	exp, err := time.Parse(time.RFC3339, m.AcceptanceExpires)
	if err != nil || m.Stage != StageApproved || m.PromotionState != report.StateAuthorizedWithConditions || len(m.AcceptedSurfaces) == 0 {
		t.Fatalf("%+v %v", m, err)
	}
	if m.ExpiresSoon {
		t.Error("40 days out is not expires-soon")
	}
	if m := modelByID(t, s, id, exp.Add(-30*24*time.Hour)); !m.ExpiresSoon {
		t.Error("exactly 30 days out is expires-soon")
	}
	if m := modelByID(t, s, id, exp.Add(-31*24*time.Hour)); m.ExpiresSoon {
		t.Error("31 days out is not expires-soon")
	}
	if m := modelByID(t, s, id, exp); m.Stage != StageAcceptanceExpired {
		t.Errorf("at the expiry instant: %s", m.Stage)
	}
}

// Review Focus 1 and 2: stray entries are skipped; a staging entry without
// exactly one artifact is listed, staged, with the reason.
func TestStrayAndBrokenEntries(t *testing.T) {
	s := trustedStore(t)
	_ = os.MkdirAll(filepath.Join(s.Root, "incoming", ".tmp"), 0o755)
	_ = os.MkdirAll(filepath.Join(s.Root, "clean", "not-a-hash"), 0o755)
	_ = os.WriteFile(filepath.Join(s.Root, "incoming", "loose.txt"), []byte("x"), 0o644)
	empty := strings.Repeat("a", 64)
	_ = os.MkdirAll(s.StagingPath(empty), 0o755)
	_ = os.WriteFile(filepath.Join(s.StagingPath(empty), ProvenanceFile), []byte("{}"), 0o644)

	ms, err := s.Models(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].ID != empty || ms[0].Stage != StageStaged || !strings.Contains(ms[0].StageReason, "no artifact") {
		t.Fatalf("%+v", ms)
	}
}

// Review Focus 3: listing reads evidence only, never artifact bytes.
func TestModelsNeverReadsArtifactBytes(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user")
	}
	s := trustedStore(t)
	id := promoted(t, s)
	art := filepath.Join(s.CleanPath(id), "fixture.safetensors")
	if err := os.Chmod(art, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(art, 0o644) })
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageApproved {
		t.Fatalf("%+v", m)
	}
}

func TestModelDetailReturnsTheDocument(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	m, d, err := s.Model(id, time.Now())
	if err != nil || d == nil || d.Artifact.SHA256 != id || m.ID != id {
		t.Fatalf("%+v %v %v", m, d, err)
	}
	if _, _, err := s.Model(strings.Repeat("b", 64), time.Now()); err == nil {
		t.Fatal("an unknown id must be an error")
	}
}

func TestCleanEntryWithWithheldEnvelopeDoesNotVerify(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	_, d := authorizedArtifact(t)
	withholdForGap(d)
	// Falsification: drop the Admits check in derive and this shows approved.
	if err := os.WriteFile(filepath.Join(s.CleanPath(id), attestationEnvelope), envelopeFor(t, d), 0o644); err != nil {
		t.Fatal(err)
	}
	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageDoesNotVerify || m.StageReason == "" {
		t.Fatalf("a withheld envelope in clean must not be approved: %+v", m)
	}
}

func TestStagingUsesMostRecentEvidence(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	dir := s.StagingPath(id)
	artifact, d := authorizedArtifact(t)
	_ = artifact
	gap := *d
	gap.Checks = append([]report.CheckResult(nil), d.Checks...)
	withholdForGap(&gap)
	ticket, err := os.ReadFile(acceptedTicket(t, s, &gap, 10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveAttestation(id, ticket, time.Now()); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	chtimes := func(name string, at time.Time) {
		t.Helper()
		if err := os.Chtimes(filepath.Join(dir, name), at, at); err != nil {
			t.Fatal(err)
		}
	}
	chtimes(StagedConditional, base)
	later := time.Now().Add(20 * 24 * time.Hour) // past the 10-day acceptance
	if m := modelByID(t, s, id, later); m.Stage != StageAcceptanceExpired {
		t.Fatalf("expected expired: %+v", m)
	}
	// (a) a newer scan report supersedes the older signed evidence.
	if err := s.SaveReport(id, d); err != nil {
		t.Fatal(err)
	}
	chtimes(StagedReport, base.Add(time.Minute))
	if m := modelByID(t, s, id, later); m.Stage != StageScanned {
		t.Fatalf("a rescan supersedes: %+v", m)
	}
	// (b) a newer authorized envelope supersedes the report and the conditional.
	if _, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now()); err != nil {
		t.Fatal(err)
	}
	chtimes(StagedAttestation, base.Add(2*time.Minute))
	if m := modelByID(t, s, id, later); m.Stage != StageReady {
		t.Fatalf("newest envelope wins: %+v", m)
	}
}

func TestExpiredAcceptanceForAnotherSubjectDoesNotVerify(t *testing.T) {
	s := trustedStore(t)
	_, d := authorizedArtifact(t)
	withholdForGap(d)
	ticket, err := os.ReadFile(acceptedTicket(t, s, d, 10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Plant that subject's conditional under a different entry.
	other := strings.Repeat("c", 64)
	dir := s.StagingPath(other)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.safetensors"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, StagedConditional), ticket, 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(20 * 24 * time.Hour)
	m := modelByID(t, s, other, later)
	if m.Stage != StageDoesNotVerify || !strings.Contains(m.StageReason, "not this entry") {
		t.Fatalf("expired must not mask a wrong subject: %+v", m)
	}
}

func TestShellQuoteRoundTrips(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	if got := shellQuote("/a/b-c_d.e/F1"); got != "/a/b-c_d.e/F1" {
		t.Fatalf("plain path changed: %q", got)
	}
	for _, in := range []string{"", "a b", "it's", "$HOME", "a`id`b", `say "hi"`, "a<b>c;d"} {
		q := shellQuote(in)
		if !strings.HasPrefix(q, "'") {
			t.Errorf("%q not single-quoted: %s", in, q)
		}
		out, err := exec.Command(sh, "-c", "printf %s "+q).Output()
		if err != nil || string(out) != in {
			t.Errorf("%q -> %s -> %q (%v)", in, q, out, err)
		}
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("escape form: %s", got)
	}
}

func TestCleanArtifactNeedsExactlyOne(t *testing.T) {
	s := trustedStore(t)
	id := promoted(t, s)
	if err := os.WriteFile(filepath.Join(s.CleanPath(id), "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.ArtifactPath != "" {
		t.Fatalf("ambiguous artifact must be empty: %q", m.ArtifactPath)
	}
}

// Promote leaves the staged copy in place, so after promotion the id is in
// both incoming and clean. The list shows the clean, approved entry only.
// Falsification: drop the approved-id skip in Models and the staged copy is
// listed too (as ready).
func TestPromotedModelLeavesStaging(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	name, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	art, err := s.stagedArtifact(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Promote(s, art, filepath.Join(s.StagingPath(id), name)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(art); err != nil {
		t.Fatalf("promote must not delete the staged copy: %v", err)
	}
	ms, err := s.Models(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].ID != id || ms[0].Location != "clean" || ms[0].Stage != StageApproved {
		t.Fatalf("want only the clean approved entry: %+v", ms)
	}
	// The staged copy is still reachable for the console's actions.
	if m, _, err := s.StagedModel(id, time.Now()); err != nil || m.Location != "staging" || m.Stage != StageReady {
		t.Fatalf("staged model: %+v %v", m, err)
	}
}

// A clean entry whose acceptance has expired keeps its staged copy listed: it
// is the way to re-scan and re-accept.
func TestExpiredCleanKeepsItsStagedCopy(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	artifact, d := authorizedArtifact(t)
	withholdForGap(d)
	if _, err := Promote(s, artifact, acceptedTicket(t, s, d, 24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(48 * time.Hour)
	ms, err := s.Models(later)
	if err != nil {
		t.Fatal(err)
	}
	var clean, staged bool
	for _, m := range ms {
		if m.ID != id {
			continue
		}
		clean = clean || (m.Location == "clean" && m.Stage == StageAcceptanceExpired)
		staged = staged || m.Location == "staging"
	}
	if !clean || !staged || len(ms) != 2 {
		t.Fatalf("want the expired clean entry and its staged copy: %+v", ms)
	}
	// Approved now, so the staged copy is hidden again.
	if ms, _ := s.Models(time.Now()); len(ms) != 1 || ms[0].Location != "clean" {
		t.Fatalf("%+v", ms)
	}
}

// A staged envelope that does not verify offers a rescan: a newer report.json
// supersedes it. Falsification: leave Next as none and this fails.
func TestStagedDoesNotVerifyOffersAScan(t *testing.T) {
	s := trustedStore(t)
	id := stage(t, s)
	_, d := authorizedArtifact(t)
	if _, err := s.SaveAttestation(id, envelopeFor(t, d), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.TrustPath(), "test.pub")); err != nil {
		t.Fatal(err)
	}
	m := modelByID(t, s, id, time.Now())
	if m.Stage != StageDoesNotVerify || m.Next.Action != "scan" || !strings.Contains(m.Next.Command, "socair scan") ||
		!strings.Contains(m.Next.Command, StagedReport) {
		t.Fatalf("%+v", m)
	}
	// The way out works: a newer scan report supersedes the envelope.
	later := time.Now().Add(time.Minute)
	if err := s.SaveReport(id, d); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(s.StagingPath(id), StagedReport), later, later); err != nil {
		t.Fatal(err)
	}
	if m := modelByID(t, s, id, time.Now()); m.Stage != StageScanned {
		t.Fatalf("after a rescan: %+v", m)
	}
}
