package main

import (
	"reflect"
	"testing"
)

// A list flag may repeat and may carry comma-separated values, so
// `--exclude metal/ --exclude original/` and `--exclude metal/,original/`
// say the same thing.
func TestListFlagsRepeatAndSplit(t *testing.T) {
	fs := parseFlags([]string{"--repo", "org/m", "--exclude", "inference/", "--exclude", "metal/, original/", "--include=*.json", "--revision", "abc"})
	if got, _ := fs.patterns("exclude"); !reflect.DeepEqual(got, []string{"inference/", "metal/", "original/"}) {
		t.Errorf("exclude = %q", got)
	}
	if got, _ := fs.patterns("include"); !reflect.DeepEqual(got, []string{"*.json"}) {
		t.Errorf("include = %q", got)
	}
	if fs.val("repo") != "org/m" || fs.val("revision") != "abc" {
		t.Errorf("single-valued flags changed: %+v", fs.vals)
	}
}

// A pattern meant to narrow a pull must never be dropped silently, or the
// pull widens: a bare flag, an empty value, or an empty list item is refused.
// A comma inside [...] belongs to the class, not the list.
// Falsification: return list() from patterns() and the refusals pass.
func TestPatternFlagsRefuseEmptyValues(t *testing.T) {
	for _, args := range [][]string{
		{"--exclude"},
		{"--exclude", "--revision", "abc"},
		{"--exclude="},
		{"--exclude", "a,,b"},
		{"--exclude", " "},
	} {
		if _, err := parseFlags(args).patterns("exclude"); err == nil {
			t.Errorf("%q must be refused", args)
		}
	}
	got, err := parseFlags([]string{"--exclude", "model-0000[1,2]-*.safetensors,metal/"}).patterns("exclude")
	if err != nil || !reflect.DeepEqual(got, []string{"model-0000[1,2]-*.safetensors", "metal/"}) {
		t.Fatalf("patterns = %q, %v", got, err)
	}
	if got, err := parseFlags(nil).patterns("exclude"); err != nil || got != nil {
		t.Fatalf("an absent flag = %q, %v", got, err)
	}
}
