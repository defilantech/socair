// Package intake checks an artifact against an organization's intake policy
// (SOCAIR_INTAKE_POLICY): the formats its model files may be in, the
// publishers it may or may not come from, and the publishers whose models need
// a verified publisher signature.
//
// The policy can only withhold. Its row, "Intake policy", is added only when a
// policy is configured. A rule the artifact breaks is a FAIL whose finding
// names the rule, a rule that cannot be evaluated is NOT_TESTED with the
// reason, and a PASS says which rules held and on what. It never changes
// another row, and it never authorizes or clears anything.
//
// Everything it compares is something the scan already established: a model
// file's format from its bytes, never its name; the publisher from a
// provenance manifest bound to the artifact's hash, never a file, directory,
// or config name; and the publisher signature from the engine's verification.
package intake

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Schema is the policy file's format value.
const Schema = "socair.intake-policy/v1"

// The format names a policy may list. Each is identified from a file's bytes
// (Identify).
const (
	GGUF        = "gguf"
	NumPy       = "numpy"
	Pickle      = "pickle"
	Safetensors = "safetensors"
)

// Formats lists every format name a policy may allow, sorted.
var Formats = []string{GGUF, NumPy, Pickle, Safetensors}

// headerFormats are identified by a fixed header that every file of the
// format begins with, so a file identified as no format is positively not one
// of them. A pickle is recognised by sniffing, which misses protocol 0 and 1
// streams and archives it does not open, and a NumPy archive with an entry
// that is not an array is not recognised, so an unidentified file might still
// be either.
var headerFormats = map[string]bool{GGUF: true, Safetensors: true}

// maxPolicy bounds the policy file. A real policy is a few lines.
const maxPolicy = 1 << 20

// Policy is a loaded intake policy. Name and SHA256 identify it in a report
// (its file's base name and the SHA-256 of its bytes), never by its path.
type Policy struct {
	Name   string
	SHA256 string

	formats map[string]bool
	allowed map[string]bool
	denied  map[string]bool
	signed  map[string]bool
}

// The policy file's keys.
const (
	keyFormat            = "format"
	keyAllowedFormats    = "allowed_formats"
	keyAllowedPublishers = "allowed_publishers"
	keyDeniedPublishers  = "denied_publishers"
	keySignatureRequired = "signature_required"
)

var knownKeys = []string{keyFormat, keyAllowedFormats, keyAllowedPublishers, keyDeniedPublishers, keySignatureRequired}

// Load reads and parses the policy file at path.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPolicy+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPolicy {
		return nil, fmt.Errorf("%s is over %d bytes", path, maxPolicy)
	}
	return Parse(filepath.Base(path), raw)
}

// Parse parses a policy. It is strict, because a policy that loads with a
// rule quietly missing would pass models the organization meant to refuse: a
// key it does not know, a key given twice, a null or empty list, a format it
// does not identify, a publisher name that is not a hub organization, a
// publisher both allowed and denied, or a policy that sets no rule is an
// error, and the scan stops.
func Parse(name string, raw []byte) (*Policy, error) {
	fail := func(format string, a ...any) (*Policy, error) {
		return nil, fmt.Errorf("%s: %s", name, fmt.Sprintf(format, a...))
	}
	fields, err := objectFields(raw)
	if err != nil {
		return fail("%v", err)
	}
	sum := sha256.Sum256(raw)
	p := &Policy{Name: name, SHA256: hex.EncodeToString(sum[:])}

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	format := ""
	for _, k := range keys {
		v := fields[k]
		switch k {
		case keyFormat:
			if err := json.Unmarshal(v, &format); err != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return fail("%q must be the string %q", keyFormat, Schema)
			}
		case keyAllowedFormats:
			list, err := stringList(k, v)
			if err != nil {
				return fail("%v", err)
			}
			p.formats = map[string]bool{}
			for _, f := range list {
				f = strings.ToLower(f)
				if !known(f) {
					return fail("%q in %s is not a format Socair identifies; the formats are %s", f, k, strings.Join(Formats, ", "))
				}
				p.formats[f] = true
			}
		case keyAllowedPublishers, keyDeniedPublishers, keySignatureRequired:
			list, err := stringList(k, v)
			if err != nil {
				return fail("%v", err)
			}
			set := map[string]bool{}
			for _, n := range list {
				if err := checkPublisher(n); err != nil {
					return fail("%q in %s %v", n, k, err)
				}
				set[strings.ToLower(n)] = true
			}
			switch k {
			case keyAllowedPublishers:
				p.allowed = set
			case keyDeniedPublishers:
				p.denied = set
			default:
				p.signed = set
			}
		default:
			return fail("%q is not a policy key; the keys are %s", k, strings.Join(knownKeys, ", "))
		}
	}
	if format != Schema {
		return fail("%q must be %q (got %q)", keyFormat, Schema, format)
	}
	if p.formats == nil && p.allowed == nil && p.denied == nil && p.signed == nil {
		return fail("sets no rule: give at least one of %s", strings.Join(knownKeys[1:], ", "))
	}
	for n := range p.allowed {
		if p.denied[n] {
			return fail("%q is both allowed and denied", n)
		}
	}
	return p, nil
}

// objectFields reads one JSON object, refusing a key given twice and anything
// after the object: encoding/json keeps the last of two equal keys, which
// would drop a list without a word.
func objectFields(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("the policy must be a JSON object")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("not JSON: %w", err)
		}
		key, _ := tok.(string)
		if _, dup := fields[key]; dup {
			return nil, fmt.Errorf("%q is given twice", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("not JSON: %w", err)
		}
		fields[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("there is data after the policy object")
	}
	return fields, nil
}

// stringList decodes a non-empty list of non-empty strings.
func stringList(key string, v json.RawMessage) ([]string, error) {
	if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		return nil, fmt.Errorf("%q is null; leave the key out to set no rule", key)
	}
	var list []string
	if err := json.Unmarshal(v, &list); err != nil {
		return nil, fmt.Errorf("%q must be a list of strings", key)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%q is an empty list; leave the key out to set no rule", key)
	}
	for _, s := range list {
		if s == "" {
			return nil, fmt.Errorf("%q has an empty entry", key)
		}
	}
	return list, nil
}

func known(format string) bool {
	for _, f := range Formats {
		if f == format {
			return true
		}
	}
	return false
}

// orgName is a hub namespace as huggingface_hub's validate_repo_id accepts
// one: 1 to 96 of letters, digits, '-', '_', and '.', beginning and ending
// with a letter, digit, or '_', with no "--" or "..".
var orgName = regexp.MustCompile(`^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,94}[A-Za-z0-9_])?$`)

// checkPublisher refuses a name that is not a hub organization, so a repo id
// or a URL in a list fails at load instead of matching nothing.
func checkPublisher(n string) error {
	switch {
	case strings.Contains(n, "/"):
		org, _, _ := strings.Cut(n, "/")
		return fmt.Errorf("names a repo or a URL, not an organization; list the organization (for a repo id, %q)", org)
	case !orgName.MatchString(n) || strings.Contains(n, "--") || strings.Contains(n, ".."):
		return errors.New("is not a hub organization name (1 to 96 letters, digits, '-', '_', or '.')")
	}
	return nil
}

// sorted returns a set's members, sorted.
func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
