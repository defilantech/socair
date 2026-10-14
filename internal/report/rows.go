package report

import "strings"

// RowNames joins check row names for a sentence. They are joined with "; ",
// because a row name can hold commas ("Hash, provenance, lineage"), and a
// comma-joined list of three rows reads as five.
func RowNames(names []string) string {
	return strings.Join(names, "; ")
}

// RowsAre is RowNames with the verb that agrees with the count: "Known-bad
// hash match is", "Chat template; Tokenizer config are".
func RowsAre(names []string) string {
	if len(names) == 1 {
		return names[0] + " is"
	}
	return RowNames(names) + " are"
}
