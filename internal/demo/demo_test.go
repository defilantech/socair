package demo

import (
	"testing"

	"github.com/defilantech/socair/internal/report"
)

func TestSampleDocumentValidates(t *testing.T) {
	d, err := Document()
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if problems := report.Validate(d); len(problems) != 0 {
		t.Fatalf("sample report does not validate: %v", problems)
	}
	if len(d.Checks) < 5 {
		t.Errorf("sample should exercise several checks, got %d", len(d.Checks))
	}
}
