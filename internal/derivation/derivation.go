// Package derivation is the signed derivation record: a statement that one
// artifact's bytes were rebuilt from another's, by which converter, tensor by
// tensor.
//
// A record is an in-toto Statement v1 (predicate type
// https://socair.ai/derivation/v1) in a DSSE envelope signed with Ed25519,
// the machinery Socair signs attestations and acceptances with. Its subject
// is the output, the artifact the record describes; the predicate names the
// input by its hash and the verified attestation that let it be converted.
//
// A record binds the output to the input. It does not attest the output: the
// output is a new artifact, scanned and promoted on its own attestation, and
// nothing about the conversion authorizes it.
package derivation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/dsse"
)

const (
	// PredicateType names a Socair derivation record.
	PredicateType = "https://socair.ai/derivation/v1"
	statementType = "https://in-toto.io/Statement/v1"
)

// DoesNotAuthorize is the record's fixed statement of what it is not. It is
// the same in every record.
const DoesNotAuthorize = "This record binds the output's bytes to the input's attested bytes. " +
	"It does not attest the output: the output is a new artifact, scanned and promoted on its own attestation."

// ErrVerify marks a record that does not verify.
var ErrVerify = errors.New("derivation record does not verify")

// Predicate is what the converter signs.
type Predicate struct {
	Converter   Converter `json:"converter"`
	Input       Input     `json:"input"`
	Output      Output    `json:"output"`
	ConvertedAt string    `json:"converted_at"`
	// Tensors are every input tensor, by name: the output tensor that holds
	// its bytes and where they came from.
	Tensors []Tensor `json:"tensors"`
	// Metadata is the output's __metadata__.
	Metadata map[string]string `json:"metadata"`
	// NotCarried names what the output does not carry from the input.
	NotCarried       []string `json:"not_carried,omitempty"`
	DoesNotAuthorize string   `json:"does_not_authorize"`
}

// Converter names the program and the rules that made the output.
type Converter struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Rules is the converter's rule version; Grammar the pickle grammar whose
	// model the tensors were read from.
	Rules   string `json:"rules"`
	Grammar string `json:"grammar"`
}

// Input is the artifact converted, and the attestation that admitted it.
type Input struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
	Format string            `json:"format"`
	// ByteOrder says how the storages' byte order was established.
	ByteOrder   string      `json:"byte_order"`
	Attestation Attestation `json:"attestation"`
}

// Attestation identifies the verified attestation of the input.
type Attestation struct {
	DocumentID      string `json:"document_id"`
	DocumentHash    string `json:"document_hash"`
	SignerKeyID     string `json:"signer_key_id"`
	State           string `json:"state"`
	CheckSetVersion string `json:"check_set_version"`
	// PickleRow is the Pickle opcode scan row's status: PASS. NotTested names
	// the input's NOT_TESTED rows, which the conversion does not resolve.
	PickleRow string   `json:"pickle_row"`
	NotTested []string `json:"not_tested,omitempty"`
}

// Output is the artifact the record describes.
type Output struct {
	Name      string            `json:"name"`
	Digest    map[string]string `json:"digest"`
	Format    string            `json:"format"`
	SizeBytes int64             `json:"size_bytes"`
}

// Tensor is one input tensor and its place in the output.
type Tensor struct {
	Name string `json:"name"`
	// Dtype is the output's dtype, SourceDtype the input's.
	Dtype       string  `json:"dtype"`
	SourceDtype string  `json:"source_dtype"`
	Shape       []int64 `json:"shape"`
	// Source is the input record and byte offset its bytes came from.
	Source    Source `json:"source"`
	SizeBytes int64  `json:"size_bytes"`
	// SHA256 hashes its bytes, the same in the input record and the output.
	SHA256 string `json:"sha256"`
	// DataOffsets locate its bytes in the output's data section.
	DataOffsets [2]int64 `json:"data_offsets"`
	// AliasOf names the output tensor that holds its bytes, for an exact
	// alias written once.
	AliasOf string `json:"alias_of,omitempty"`
}

// Source is where a tensor's bytes sit in the input.
type Source struct {
	Record      string `json:"record"`
	OffsetBytes int64  `json:"offset_bytes"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Record is a verified derivation record.
type Record struct {
	Predicate
	// KeyID is the key that verified it.
	KeyID string
}

// Sign signs a record of p as keyID with sign, an Ed25519 signer. The
// predicate must be well-formed (see check).
func Sign(p Predicate, keyID string, sign func([]byte) []byte) ([]byte, error) {
	p.DoesNotAuthorize = DoesNotAuthorize
	if err := p.check(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(statement{
		Type:          statementType,
		Subject:       []subject{{Name: p.Output.Name, Digest: map[string]string{"sha256": p.Output.Digest["sha256"]}}},
		PredicateType: PredicateType,
		Predicate:     p,
	})
	if err != nil {
		return nil, err
	}
	return dsse.Sign(payload, keyID, sign)
}

// Verify checks a record's signature against keys, by key id, and its
// shape: one subject, the output the predicate names.
func Verify(raw []byte, keys map[string]ed25519.PublicKey) (*Record, error) {
	payload, keyID, err := dsse.Verify(raw, keys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	var st statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%w: payload is not a derivation statement: %v", ErrVerify, err)
	}
	switch {
	case st.Type != statementType || st.PredicateType != PredicateType:
		return nil, fmt.Errorf("%w: predicate type %q is not %s", ErrVerify, st.PredicateType, PredicateType)
	case len(st.Subject) != 1:
		return nil, fmt.Errorf("%w: want one subject, got %d", ErrVerify, len(st.Subject))
	case st.Subject[0].Name != st.Predicate.Output.Name || strings.ToLower(st.Subject[0].Digest["sha256"]) != st.Predicate.Output.Digest["sha256"]:
		return nil, fmt.Errorf("%w: the subject is not the output the predicate names", ErrVerify)
	}
	if err := st.Predicate.check(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	return &Record{Predicate: st.Predicate, KeyID: keyID}, nil
}

// check holds a predicate to what every record needs.
func (p *Predicate) check() error {
	in, out := p.Input.Digest["sha256"], p.Output.Digest["sha256"]
	switch {
	case !isSHA256(in):
		return errors.New("the record names no input sha256")
	case !isSHA256(out):
		return errors.New("the record names no output sha256")
	case in == out:
		return errors.New("the input and the output are the same bytes")
	case strings.TrimSpace(p.Input.Name) == "" || strings.TrimSpace(p.Output.Name) == "":
		return errors.New("the record does not name the input and the output")
	case !isSHA256(p.Input.Attestation.DocumentHash):
		return errors.New("the record names no attestation document hash")
	case p.Converter.Name == "" || p.Converter.Rules == "":
		return errors.New("the record names no converter and rules")
	case len(p.Tensors) == 0:
		return errors.New("the record maps no tensors")
	case p.DoesNotAuthorize != DoesNotAuthorize:
		return errors.New("the record's does_not_authorize statement is not the fixed wording")
	}
	if _, err := time.Parse(time.RFC3339, p.ConvertedAt); err != nil {
		return fmt.Errorf("converted_at %q is not RFC 3339", p.ConvertedAt)
	}
	names := map[string]*Tensor{}
	for i := range p.Tensors {
		t := &p.Tensors[i]
		if t.Name == "" || names[t.Name] != nil {
			return fmt.Errorf("tensor %q is unnamed or named twice", t.Name)
		}
		if !isSHA256(t.SHA256) {
			return fmt.Errorf("tensor %q has no sha256", t.Name)
		}
		names[t.Name] = t
	}
	for _, t := range p.Tensors {
		if t.AliasOf == "" {
			continue
		}
		k := names[t.AliasOf]
		if k == nil || k.AliasOf != "" || k.SHA256 != t.SHA256 || p.Metadata[t.Name] != t.AliasOf {
			return fmt.Errorf("tensor %q is an alias of %q, which the record does not hold as a written tensor with its bytes", t.Name, t.AliasOf)
		}
	}
	return nil
}

func isSHA256(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
