package airlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/report"
)

// Stage is where an entry stands, derived only from the evidence files in the
// store, through the gate's own checks (Assess).
type Stage string

const (
	StageStaged            Stage = "staged"
	StageScanned           Stage = "scanned"
	StageReady             Stage = "ready"
	StageNeedsAcceptance   Stage = "needs-acceptance"
	StageBlocked           Stage = "blocked"
	StageApproved          Stage = "approved"
	StageAcceptanceExpired Stage = "acceptance-expired"
	StageDoesNotVerify     Stage = "does-not-verify"
)

// ExpiresSoonWindow is how far ahead an acceptance's expiry is flagged.
const ExpiresSoonWindow = 30 * 24 * time.Hour

// Next is the step an entry waits for: an action the console can take, or the
// exact CLI command when the step needs a key.
type Next struct {
	Action  string `json:"action"` // scan | sign | accept | promote | none
	Command string `json:"command,omitempty"`
}

// Model is one entry of the store as the console shows it.
type Model struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Format            string   `json:"format,omitempty"`
	SizeBytes         int64    `json:"size_bytes,omitempty"`
	Location          string   `json:"location"` // staging | clean
	Stage             Stage    `json:"stage"`
	StageReason       string   `json:"stage_reason,omitempty"`
	PromotionState    string   `json:"promotion_state,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	SignerKeyID       string   `json:"signer_key_id,omitempty"`
	AcceptedSurfaces  []string `json:"accepted_surfaces,omitempty"`
	AcceptedBy        string   `json:"accepted_by,omitempty"`
	AcceptanceExpires string   `json:"acceptance_expires,omitempty"`
	ExpiresSoon       bool     `json:"expires_soon,omitempty"`
	PromotedAt        string   `json:"promoted_at,omitempty"`
	Next              Next     `json:"next"`
	// ArtifactPath and EnvelopePath are for the API's actions, never sent.
	ArtifactPath string `json:"-"`
	EnvelopePath string `json:"-"`
}

// Models lists every clean and staging entry, clean first, each by id. It
// reads only evidence files (envelopes and small JSON), never artifact bytes.
// Stray names that are not 64-hex directories are skipped. Promote leaves the
// staged copy in place, so a staging entry whose id is approved in clean is
// omitted: it has crossed. One whose clean entry is acceptance-expired or does
// not verify stays listed, as the way to re-scan or re-accept.
func (s *Store) Models(at time.Time) ([]Model, error) {
	promoted, err := s.promotedAt()
	if err != nil {
		return nil, err
	}
	var out []Model
	approved := map[string]bool{}
	for _, loc := range []string{cleanDir, stagingDir} {
		entries, err := os.ReadDir(filepath.Join(s.Root, loc))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", loc, err)
		}
		var ids []string
		for _, e := range entries {
			if e.IsDir() && hexSHA256.MatchString(e.Name()) {
				ids = append(ids, e.Name())
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			if loc == stagingDir && approved[id] {
				continue
			}
			m, _ := s.derive(loc, id, at)
			if loc == cleanDir {
				m.PromotedAt = promoted[id]
				approved[id] = m.Stage == StageApproved
			}
			out = append(out, m)
		}
	}
	return out, nil
}

// Model returns one entry and the report it carries: the verified attestation's
// document when there is one, else the unsigned scan report, else nil.
func (s *Store) Model(id string, at time.Time) (Model, *report.Document, error) {
	if !hexSHA256.MatchString(id) {
		return Model{}, nil, ErrNoModel
	}
	for _, loc := range []string{cleanDir, stagingDir} {
		if fi, err := os.Stat(filepath.Join(s.Root, loc, id)); err == nil && fi.IsDir() {
			m, d := s.derive(loc, id, at)
			if loc == cleanDir {
				promoted, err := s.promotedAt()
				if err != nil {
					return Model{}, nil, err
				}
				m.PromotedAt = promoted[id]
			}
			return m, d, nil
		}
	}
	return Model{}, nil, ErrNoModel
}

// StagedModel returns the staging entry for id, never the clean one, with the
// report it carries. The console's scan and upload act on the staged copy,
// which can exist beside a clean entry of the same id.
func (s *Store) StagedModel(id string, at time.Time) (Model, *report.Document, error) {
	if !hexSHA256.MatchString(id) {
		return Model{}, nil, ErrNoModel
	}
	if fi, err := os.Stat(s.StagingPath(id)); err != nil || !fi.IsDir() {
		return Model{}, nil, ErrNoModel
	}
	m, d := s.derive(stagingDir, id, at)
	return m, d, nil
}

// derive works out one entry's stage from its files.
func (s *Store) derive(loc, id string, at time.Time) (Model, *report.Document) {
	dir := filepath.Join(s.Root, loc, id)
	m := Model{ID: id, Name: id[:12], Location: "staging", Next: Next{Action: "none"}}
	if loc == cleanDir {
		m.Location = "clean"
		m.EnvelopePath = filepath.Join(dir, attestationEnvelope)
		m.ArtifactPath = s.cleanArtifact(dir)
		env, err := os.ReadFile(m.EnvelopePath)
		if err != nil {
			m.Stage, m.StageReason = StageDoesNotVerify, "no attestation in the clean entry: "+err.Error()
			return m, nil
		}
		a, err := s.Assess(env, at)
		switch {
		case a != nil && a.SHA256 != id:
			m.Stage, m.StageReason = StageDoesNotVerify, fmt.Sprintf("the attestation is for %s, not this entry", a.SHA256)
			return m, nil
		case errors.Is(err, ErrAcceptanceExpired):
			fill(&m, a, at)
			m.Stage, m.StageReason = StageAcceptanceExpired, err.Error()
			return m, &a.Verified.Document
		case err != nil:
			m.Stage, m.StageReason = StageDoesNotVerify, err.Error()
			return m, nil
		}
		if err := a.Admits(); err != nil {
			m.Stage, m.StageReason = StageDoesNotVerify, err.Error()
			return m, nil
		}
		fill(&m, a, at)
		m.Stage = StageApproved
		return m, &a.Verified.Document
	}

	art, err := s.stagedArtifact(id)
	if err != nil {
		m.Stage, m.StageReason = StageStaged, err.Error()
		return m, nil
	}
	m.ArtifactPath = art
	m.Name = filepath.Base(art)
	reportPath := filepath.Join(dir, StagedReport)
	// The most recent evidence wins: the newest envelope (a tie prefers the
	// conditional one), unless a scan report is newer than every envelope.
	var newest string
	var newestTime time.Time
	for _, name := range []string{StagedConditional, StagedAttestation} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if newest == "" || fi.ModTime().After(newestTime) {
			newest, newestTime = name, fi.ModTime()
		}
	}
	rescanned := false
	if newest != "" {
		if fi, err := os.Stat(reportPath); err == nil && fi.ModTime().After(newestTime) {
			rescanned = true
		}
	}
	if newest != "" && !rescanned {
		name := newest
		p := filepath.Join(dir, name)
		if env, err := os.ReadFile(p); err == nil {
			m.EnvelopePath = p
			a, err := s.Assess(env, at)
			switch {
			case a != nil && a.SHA256 != id:
				m.Stage, m.StageReason = StageDoesNotVerify, fmt.Sprintf("%s is for %s, not this entry", name, a.SHA256)
				m.Next = Next{Action: "scan", Command: s.scanCommand(dir, art)}
				return m, nil
			case errors.Is(err, ErrAcceptanceExpired):
				fill(&m, a, at)
				m.Stage, m.StageReason = StageAcceptanceExpired, err.Error()
				m.Next = Next{Action: "scan", Command: s.scanCommand(dir, art)}
				return m, &a.Verified.Document
			case err != nil:
				// A rescan writes a report newer than this envelope, which
				// then supersedes it: that is the way out.
				m.Stage, m.StageReason = StageDoesNotVerify, name+": "+err.Error()
				m.Next = Next{Action: "scan", Command: s.scanCommand(dir, art)}
				return m, nil
			}
			fill(&m, a, at)
			d := &a.Verified.Document
			switch {
			case a.Admits() == nil:
				m.Stage = StageReady
				m.Next = Next{Action: "promote", Command: "socair airlock promote " + shellQuote(art) + " --attestation " + shellQuote(p) + " --store " + shellQuote(s.Root)}
			case hasFailOrLead(d):
				m.Stage, m.StageReason = StageBlocked, "a FAIL or LEAD withholds it, and no acceptance clears it; it needs a person's review outside Socair"
			default:
				m.Stage = StageNeedsAcceptance
				m.StageReason = "withheld on NOT_TESTED rows: " + strings.Join(d.Findings.NotTested, ", ")
				acc := filepath.Join(dir, StagedAcceptance)
				m.Next = Next{Action: "accept", Command: "socair accept --attestation " + shellQuote(p) +
					` --key ACCEPTOR_KEY --by "NAME, ROLE" --expires EXPIRES_RFC3339 --store ` + shellQuote(s.Root) +
					"\nsocair sign --key OPERATOR_KEY --attestation " + shellQuote(p) + " --acceptance " + shellQuote(acc) +
					" --store " + shellQuote(s.Root)}
			}
			return m, d
		}
	}
	if b, err := os.ReadFile(reportPath); err == nil {
		var d report.Document
		if json.Unmarshal(b, &d) == nil {
			m.Stage = StageScanned
			m.PromotionState = d.PromotionAuthorization.State
			named(&m, &d)
			m.Next = Next{Action: "sign", Command: "socair sign --key OPERATOR_KEY --report " + shellQuote(reportPath)}
			return m, &d
		}
		m.StageReason = StagedReport + " does not parse; scan again"
	}
	m.Stage = StageStaged
	m.Next = Next{Action: "scan", Command: s.scanCommand(dir, art)}
	return m, nil
}

func (s *Store) scanCommand(dir, art string) string {
	return "SOCAIR_PROVENANCE=" + shellQuote(filepath.Join(dir, ProvenanceFile)) + " socair scan " + shellQuote(art) +
		" > " + shellQuote(filepath.Join(dir, StagedReport))
}

// fill copies what an assessed attestation says into the model.
func fill(m *Model, a *Assessment, at time.Time) {
	d := &a.Verified.Document
	named(m, d)
	m.PromotionState, m.Issuer, m.SignerKeyID = a.State, a.Issuer, a.Verified.KeyID
	if a.State == report.StateAuthorizedWithConditions {
		pa := d.PromotionAuthorization
		m.AcceptedSurfaces, m.AcceptedBy, m.AcceptanceExpires = pa.AcceptedSurfaces, pa.AcceptedBy, pa.AcceptanceExpires
		left := a.Expires.Sub(at)
		m.ExpiresSoon = left > 0 && left <= ExpiresSoonWindow
	}
}

func named(m *Model, d *report.Document) {
	if d.Artifact.Name != "" {
		m.Name = d.Artifact.Name
	}
	m.Format, m.SizeBytes = d.Artifact.Format, d.Artifact.SizeBytes
}

func hasFailOrLead(d *report.Document) bool {
	for _, c := range d.Checks {
		if c.Status == report.StatusFail || c.Status == report.StatusLead {
			return true
		}
	}
	return false
}

// cleanArtifact is the artifact in a clean entry: the one name that is not
// store metadata.
func (s *Store) cleanArtifact(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	found := ""
	for _, e := range entries {
		if e.Name() == attestationDoc || e.Name() == attestationEnvelope {
			continue
		}
		if found != "" {
			return ""
		}
		found = filepath.Join(dir, e.Name())
	}
	return found
}

// promotedAt maps each promoted hash to the time of its last promotion.
func (s *Store) promotedAt() (map[string]string, error) {
	ev, err := s.Events()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range ev {
		if e.Action == ActionPromote && (e.Outcome == OutcomeOK || e.Outcome == OutcomeConditional) && e.SHA256 != "" {
			out[normalizeSHA(e.SHA256)] = e.TS
		}
	}
	return out, nil
}

// shellQuote quotes a path for a copyable POSIX shell command.
func shellQuote(p string) string {
	if p != "" && strings.IndexFunc(p, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}) < 0 {
		return p
	}
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}
