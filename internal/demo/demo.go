// Package demo carries a fabricated attestation for a first sales
// conversation. It is sample data and is rendered with the SAMPLE mark; it
// must never be presented as a real issuance.
package demo

import (
	_ "embed"
	"encoding/json"

	"github.com/defilantech/socair/internal/report"
)

//go:embed report.json
var raw []byte

// Document returns the sample report document.
func Document() (*report.Document, error) {
	var d report.Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
