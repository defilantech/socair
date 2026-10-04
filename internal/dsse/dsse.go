// Package dsse is the DSSE envelope Socair signs its own statements with
// (acceptances, feeds): an in-toto payload signed with Ed25519, keys named by
// the SHA-256 of their PKIX DER encoding. Attestations are verified through
// socair-verify, which implements the same envelope.
package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// PayloadType is the in-toto statement payload type.
const PayloadType = "application/vnd.in-toto+json"

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// PAE is DSSE's pre-authentication encoding of an in-toto payload.
func PAE(payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(PayloadType)))
	b.WriteByte(' ')
	b.WriteString(PayloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// KeyID names a public key: the hex SHA-256 of its PKIX DER encoding.
func KeyID(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// Sign wraps payload in an envelope signed by sign (an Ed25519 signer) as
// keyID.
func Sign(payload []byte, keyID string, sign func([]byte) []byte) ([]byte, error) {
	return json.MarshalIndent(Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sign(PAE(payload)))}},
	}, "", "  ")
}

// Open decodes an envelope with exactly one signature, without verifying it,
// returning the payload, the signature, and the key id it claims.
func Open(raw []byte) (payload, sig []byte, keyID string, err error) {
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, nil, "", fmt.Errorf("not a DSSE envelope: %w", err)
	}
	if e.PayloadType != PayloadType || len(e.Signatures) != 1 {
		return nil, nil, "", errors.New("want one signature over an in-toto payload")
	}
	if payload, err = base64.StdEncoding.DecodeString(e.Payload); err != nil {
		return nil, nil, "", errors.New("payload is not base64")
	}
	if sig, err = base64.StdEncoding.DecodeString(e.Signatures[0].Sig); err != nil {
		return nil, nil, "", errors.New("signature is not base64")
	}
	return payload, sig, e.Signatures[0].KeyID, nil
}

// Verify opens an envelope and checks its signature against keys, by key id.
func Verify(raw []byte, keys map[string]ed25519.PublicKey) (payload []byte, keyID string, err error) {
	payload, sig, keyID, err := Open(raw)
	if err != nil {
		return nil, "", err
	}
	pub, ok := keys[keyID]
	if !ok {
		return nil, keyID, fmt.Errorf("signed by key %s, which is not trusted", short(keyID))
	}
	if !ed25519.Verify(pub, PAE(payload), sig) {
		return nil, keyID, fmt.Errorf("the signature does not verify against key %s", short(keyID))
	}
	return payload, keyID, nil
}

func short(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}
