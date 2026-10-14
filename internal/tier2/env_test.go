package tier2

import "testing"

// An environment with none of the allowed variables still gives the helper an
// empty environment, not a nil one: exec.Cmd runs a command whose Env is nil
// with the parent's whole environment, so a nil here would hand the helper
// HF_TOKEN and every other setting of Socair's. TestHelperGetsNoSecrets cannot
// reach this case, because its stand-in helper's own SOCAIR_PROBE_ mode
// variable always passes. Falsification: start from a nil slice and this
// fails.
func TestHelperEnvIsNeverNil(t *testing.T) {
	for name, environ := range map[string][]string{
		"no environment":        nil,
		"only secrets":          {"HF_TOKEN=hf_secret", "HTTPS_PROXY=http://proxy.example:3128"},
		"only Socair's own":     {"SOCAIR_ACCEPTED_BY=ciso@example.com", "SOCAIR_STORE=/srv/store"},
		"a near miss of a key":  {"PATHX=/usr/bin", "SOCAIR_PROBEX=1"},
		"empty name and values": {"=", "HF_TOKEN="},
	} {
		got := helperEnv(environ)
		if got == nil {
			t.Errorf("%s: helperEnv returned nil, which exec reads as Socair's whole environment", name)
		}
		if len(got) != 0 {
			t.Errorf("%s: helperEnv passed %q", name, got)
		}
	}
}
