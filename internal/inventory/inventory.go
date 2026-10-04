// Package inventory is a signed snapshot of an airlock store: which models
// are approved, on what attestation, and the activity log's head at the time.
// It is an in-toto Statement v1 (predicate type
// https://socair.ai/inventory/v1) in a DSSE envelope signed with Ed25519, the
// same machinery as attestations. Signing it makes the list itself
// tamper-evident: a model cannot be added or dropped without breaking it.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/dsse"
	"github.com/defilantech/socair/internal/report"
)

const (
	PredicateType = "https://socair.ai/inventory/v1"
	statementType = "https://in-toto.io/Statement/v1"
)

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Entry struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	PromotionState    string   `json:"promotion_state"`
	Issuer            string   `json:"issuer,omitempty"`
	SignerKeyID       string   `json:"signer_key_id,omitempty"`
	AttestationSHA256 string   `json:"attestation_sha256"`
	AcceptedSurfaces  []string `json:"accepted_surfaces,omitempty"`
	AcceptanceExpires string   `json:"acceptance_expires,omitempty"`
	PromotedAt        string   `json:"promoted_at,omitempty"`
}

type Other struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Stage  airlock.Stage `json:"stage"`
	Reason string        `json:"reason,omitempty"`
}

type Predicate struct {
	GeneratedUTC string  `json:"generated_utc"`
	LogHead      string  `json:"log_head"`
	ToolVersion  string  `json:"tool_version"`
	Models       []Entry `json:"models"`
	Other        []Other `json:"other"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Build makes the statement from the store's models. attestations maps an
// approved model's id to its attestation.dsse.json bytes.
func Build(models []airlock.Model, attestations map[string][]byte, logHead, toolVersion string, at time.Time) Statement {
	st := Statement{Type: statementType, PredicateType: PredicateType, Subject: []Subject{},
		Predicate: Predicate{GeneratedUTC: at.UTC().Format(time.RFC3339), LogHead: logHead, ToolVersion: toolVersion,
			Models: []Entry{}, Other: []Other{}}}
	for _, m := range models {
		if m.Stage != airlock.StageApproved {
			st.Predicate.Other = append(st.Predicate.Other, Other{ID: m.ID, Name: m.Name, Stage: m.Stage, Reason: m.StageReason})
			continue
		}
		sum := sha256.Sum256(attestations[m.ID])
		st.Subject = append(st.Subject, Subject{Name: m.Name, Digest: map[string]string{"sha256": m.ID}})
		st.Predicate.Models = append(st.Predicate.Models, Entry{ID: m.ID, Name: m.Name, PromotionState: m.PromotionState,
			Issuer: m.Issuer, SignerKeyID: m.SignerKeyID, AttestationSHA256: hex.EncodeToString(sum[:]),
			AcceptedSurfaces: m.AcceptedSurfaces, AcceptanceExpires: m.AcceptanceExpires, PromotedAt: m.PromotedAt})
	}
	return st
}

// Sign returns the statement's JSON and its DSSE envelope.
func Sign(st Statement, k *attest.PrivateKey) (payload, envelope []byte, err error) {
	payload, err = jsonIndent(st)
	if err != nil {
		return nil, nil, err
	}
	envelope, err = dsse.Sign(payload, k.ID, k.Sign)
	return payload, envelope, err
}

type VerifyOptions struct {
	// AllowUnsigned checks an unsigned snapshot's contents (steps 2 to 4)
	// against its inventory.json. Without it an unsigned snapshot fails.
	AllowUnsigned bool
}

// Verified is a snapshot that passed Verify. SignerKeyID is the key that
// signed the statement, empty for an AllowUnsigned check.
type Verified struct {
	Statement
	SignerKeyID string
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// sameSet compares two string lists as sets, nil equal to empty.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// Verify checks a snapshot directory:
//  1. the envelope verifies against trusted, and its predicate type is inventory/v1;
//  2. every listed attestation file is present and hashes to its recorded value;
//  3. every attestation verifies against trusted, for the listed id;
//  4. log.jsonl verifies as a hash chain whose head is the recorded log_head.
func Verify(dir string, trusted attest.Keyring, opts VerifyOptions) (*Verified, error) {
	var payload []byte
	var signer string
	env, err := os.ReadFile(filepath.Join(dir, "inventory.dsse.json"))
	switch {
	case err == nil:
		p, kid, err := dsse.Verify(env, trusted)
		if err != nil {
			return nil, fmt.Errorf("the inventory signature does not verify: %w", err)
		}
		payload, signer = p, kid
		if plain, err := os.ReadFile(filepath.Join(dir, "inventory.json")); err == nil && !bytes.Equal(plain, payload) {
			return nil, errors.New("inventory.json differs from the signed statement")
		}
	case errors.Is(err, os.ErrNotExist) && opts.AllowUnsigned:
		payload, err = os.ReadFile(filepath.Join(dir, "inventory.json"))
		if err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		return nil, errors.New("the snapshot is unsigned (no inventory.dsse.json); export it with --key, or pass --allow-unsigned to check its contents only")
	default:
		return nil, err
	}
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil || st.Type != statementType || st.PredicateType != PredicateType {
		return nil, errors.New("not a Socair inventory statement")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("trailing data after the inventory statement")
	}
	if len(st.Predicate.Models) > 0 && st.Predicate.LogHead == "" {
		return nil, errors.New("the inventory lists approved models but records no log head")
	}
	if len(st.Subject) != len(st.Predicate.Models) {
		return nil, errors.New("the statement's subjects do not match its models")
	}
	for _, e := range st.Predicate.Models {
		if !idPattern.MatchString(e.ID) {
			return nil, fmt.Errorf("%q is not a model id (64 lowercase hex characters)", e.ID)
		}
		if !slices.ContainsFunc(st.Subject, func(s Subject) bool { return s.Name == e.Name && s.Digest["sha256"] == e.ID }) {
			return nil, fmt.Errorf("%s: no matching subject in the statement", e.ID)
		}
		b, err := os.ReadFile(filepath.Join(dir, "models", e.ID, "attestation.dsse.json"))
		if err != nil {
			return nil, fmt.Errorf("%s: the listed attestation is missing", e.ID)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != e.AttestationSHA256 {
			return nil, fmt.Errorf("%s: the attestation file is not the one the inventory recorded", e.ID)
		}
		v, err := attest.Verify(b, trusted)
		if err != nil {
			return nil, fmt.Errorf("%s: the attestation does not verify: %w", e.ID, err)
		}
		if v.SHA256 != e.ID {
			return nil, fmt.Errorf("%s: the attestation is for %s", e.ID, v.SHA256)
		}
		pa := v.Document.PromotionAuthorization
		switch {
		case e.PromotionState != string(pa.State):
			return nil, fmt.Errorf("%s: promotion_state %q disagrees with the attestation (%q)", e.ID, e.PromotionState, pa.State)
		case e.SignerKeyID != v.KeyID:
			return nil, fmt.Errorf("%s: signer_key_id %q disagrees with the attestation (%q)", e.ID, e.SignerKeyID, v.KeyID)
		case pa.State == report.StateAuthorizedWithConditions && !sameSet(e.AcceptedSurfaces, pa.AcceptedSurfaces):
			return nil, fmt.Errorf("%s: accepted_surfaces disagree with the attestation", e.ID)
		case pa.State == report.StateAuthorizedWithConditions && e.AcceptanceExpires != pa.AcceptanceExpires:
			return nil, fmt.Errorf("%s: acceptance_expires %q disagrees with the attestation (%q)", e.ID, e.AcceptanceExpires, pa.AcceptanceExpires)
		case pa.State != report.StateAuthorizedWithConditions && (len(e.AcceptedSurfaces) > 0 || e.AcceptanceExpires != ""):
			return nil, fmt.Errorf("%s: accepted_surfaces or acceptance_expires on a model that is not authorized with conditions", e.ID)
		}
	}
	r, err := airlock.VerifyFile(filepath.Join(dir, "log.jsonl"), airlock.VerifyOptions{ExpectHead: st.Predicate.LogHead})
	if err != nil {
		return nil, err
	}
	if r.Broken != 0 || r.Head != st.Predicate.LogHead {
		return nil, fmt.Errorf("the activity log does not verify to the recorded head: %s", r.Reason)
	}
	return &Verified{Statement: st, SignerKeyID: signer}, nil
}

func jsonIndent(st Statement) ([]byte, error) { return json.MarshalIndent(st, "", "  ") }
