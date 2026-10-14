package main

import "testing"

// Falsification: return false from asksForHelp and `socair serve --help`
// starts the API again.
func TestAsksForHelp(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"init", "--help"},
		{"--store", "s", "-h"},
	} {
		if !asksForHelp(args) {
			t.Errorf("%q asks for help", args)
		}
	}
	for _, args := range [][]string{
		nil,
		{"model.gguf"},
		{"--store", "s", "--scan-root", "/srv/models"},
		{"--helpful"},
		{"help.gguf"},
	} {
		if asksForHelp(args) {
			t.Errorf("%q does not ask for help", args)
		}
	}
}
