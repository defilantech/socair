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
	if got := fs.list("exclude"); !reflect.DeepEqual(got, []string{"inference/", "metal/", "original/"}) {
		t.Errorf("exclude = %q", got)
	}
	if got := fs.list("include"); !reflect.DeepEqual(got, []string{"*.json"}) {
		t.Errorf("include = %q", got)
	}
	if got := fs.list("missing"); got != nil {
		t.Errorf("an absent list flag = %q, want nil", got)
	}
	if fs.val("repo") != "org/m" || fs.val("revision") != "abc" {
		t.Errorf("single-valued flags changed: %+v", fs.vals)
	}
}
