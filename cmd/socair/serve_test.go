package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// --scan-root repeats, wins over SOCAIR_SCAN_ROOTS, and is never dropped
// silently when given without a directory: a dropped root would only narrow
// what the API reads, but the operator should hear about the typo.
func TestScanRootArgs(t *testing.T) {
	t.Setenv("SOCAIR_SCAN_ROOTS", strings.Join([]string{"/env/a", "/env/b"}, string(filepath.ListSeparator)))

	got, err := scanRootArgs(parseFlags([]string{"--scan-root", "/models", "--scan-root=/store/incoming"}))
	if err != nil || !reflect.DeepEqual(got, []string{"/models", "/store/incoming"}) {
		t.Errorf("flags = %q, %v", got, err)
	}
	got, err = scanRootArgs(parseFlags(nil))
	if err != nil || !reflect.DeepEqual(got, []string{"/env/a", "/env/b"}) {
		t.Errorf("env = %q, %v", got, err)
	}
	for _, args := range [][]string{{"--scan-root"}, {"--scan-root", "--web", "x"}} {
		if _, err := scanRootArgs(parseFlags(args)); err == nil {
			t.Errorf("%q must be refused", args)
		}
	}
	t.Setenv("SOCAIR_SCAN_ROOTS", "")
	if got, err := scanRootArgs(parseFlags(nil)); err != nil || len(got) != 0 {
		t.Errorf("no flag and no env = %q, %v", got, err)
	}
}
