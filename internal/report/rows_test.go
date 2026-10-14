package report

import "testing"

// A withheld report said "File inventory and payloads, Hash, provenance,
// lineage, Known-bad hash match are NOT_TESTED", three rows that read as
// five, and "Known-bad hash match are NOT_TESTED" for one.
func TestRowNames(t *testing.T) {
	three := []string{"File inventory and payloads", "Hash, provenance, lineage", "Known-bad hash match"}
	if got, want := RowNames(three), "File inventory and payloads; Hash, provenance, lineage; Known-bad hash match"; got != want {
		t.Errorf("RowNames = %q, want %q", got, want)
	}
	if got, want := RowsAre(three), "File inventory and payloads; Hash, provenance, lineage; Known-bad hash match are"; got != want {
		t.Errorf("RowsAre = %q, want %q", got, want)
	}
	if got, want := RowsAre([]string{"Known-bad hash match"}), "Known-bad hash match is"; got != want {
		t.Errorf("RowsAre of one row = %q, want %q", got, want)
	}
}
