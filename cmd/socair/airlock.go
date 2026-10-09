package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/attest"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/inventory"
	"github.com/defilantech/socair/internal/report"
)

// airlockCmd is the controlled junction between untrusted egress and the clean
// store. A pull lands in staging; only a promotion moves bytes across.
func airlockCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: socair airlock <init|pull|ingest|trust|promote|log|export>")
	}
	switch args[0] {
	case "init":
		return airlockInit(args[1:])
	case "pull":
		return airlockPull(args[1:])
	case "ingest":
		return airlockIngest(args[1:])
	case "trust":
		return airlockTrust(args[1:])
	case "promote":
		return airlockPromote(args[1:])
	case "log":
		return airlockLog(args[1:])
	case "export":
		return airlockExport(args[1:])
	default:
		return fmt.Errorf("unknown airlock command %q", args[0])
	}
}

func airlockInit(args []string) error {
	fs := parseFlags(args)
	root := storeRoot(fs)
	if len(fs.pos) > 0 {
		root = fs.pos[0]
	}
	s, err := airlock.Init(root)
	if err != nil {
		return err
	}
	fmt.Printf("airlock store ready at %s\n  incoming/  pulls and ingests that have not crossed\n  clean/     promoted artifacts, keyed by hash\n  log.jsonl  append-only activity log\n", s.Root)
	return nil
}

func airlockPull(args []string) error {
	fs := parseFlags(args)
	repo, sha, file := fs.val("repo"), fs.val("sha256"), fs.val("file")
	include, err := fs.patterns("include")
	if err != nil {
		return err
	}
	exclude, err := fs.patterns("exclude")
	if err != nil {
		return err
	}
	sel := airlock.Selection{Include: include, Exclude: exclude}
	if repo == "" || (file != "" && sha == "") {
		return errors.New("usage: socair airlock pull --repo <org/name> --file <name> --sha256 <hash> [--revision main] [--store <path>]\n" +
			"       socair airlock pull --repo <org/name> (--revision <commit> | --sha256 <manifest digest>) [--include <glob>]... [--exclude <glob>]... [--store <path>]   whole repo, as a model directory")
	}
	if file != "" && (len(sel.Include) > 0 || len(sel.Exclude) > 0) {
		return errors.New("--include and --exclude select files from a whole-repo pull; a single-file pull names its file with --file")
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	if file == "" {
		ev, staged, err := airlock.PullRepoSelected(context.Background(), s, repo, fs.val("revision"), sha, sel, airlock.DefaultEgressPolicy())
		if err != nil {
			return err
		}
		fmt.Printf("pulled %s as a model directory\n  manifest digest %s\n  %s\nstaged at %s\nscan it with its provenance:\n  SOCAIR_PROVENANCE=%s socair scan %s\n",
			repo, ev.SHA256, ev.Detail, staged, filepath.Join(filepath.Dir(staged), "provenance.json"), staged)
		return nil
	}
	dst, err := s.StagingFile(sha, file)
	if err != nil {
		return err
	}
	ev, err := airlock.Pull(context.Background(), s, dst, repo, fs.val("revision"), sha, airlock.DefaultEgressPolicy())
	if err != nil {
		return err
	}
	fmt.Printf("pulled %s from %s at %s\nstaged at %s\n", ev.SHA256, repo, revOrMain(fs), dst)
	return nil
}

func airlockIngest(args []string) error {
	fs := parseFlags(args)
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}

	var resolved, source string
	switch {
	case fs.has("local"):
		source = "local"
		resolved, err = airlock.IngestLocal(fs.val("local"))
	case fs.has("cache"):
		source = "cache"
		resolved, err = airlock.ResolveCache(airlock.DefaultCacheDir(), fs.val("repo"), fs.val("revision"), fs.val("file"))
	default:
		return errors.New("usage: socair airlock ingest --local <file or directory> | --cache --repo <org/name> [--file <name>] [--revision main] [--scan]")
	}
	if err != nil {
		return err
	}

	ev := airlock.Event{Action: airlock.ActionIngest, Outcome: airlock.OutcomeOK, Source: source, Detail: resolved}

	// --scan proves the ingest fills Sections 2 and 3 of the report.
	if fs.has("scan") {
		d, err := engine.Scan(resolved)
		if err != nil {
			return err
		}
		if problems := report.Validate(d); len(problems) != 0 {
			return fmt.Errorf("report did not validate: %v", problems)
		}
		ev.SHA256 = d.Artifact.SHA256
		b, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	} else {
		fmt.Println(resolved)
	}
	return s.Record(ev)
}

func airlockPromote(args []string) error {
	fs := parseFlags(args)
	if fs.val("report") != "" {
		return errors.New("promote takes a signed attestation, not a bare report: sign it with `socair sign`, then pass --attestation")
	}
	if len(fs.pos) != 1 || fs.val("attestation") == "" {
		return errors.New("usage: socair airlock promote <artifact> --attestation <attestation.dsse.json> [--store <path>]")
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	artifact := fs.pos[0]
	ev, err := airlock.Promote(s, artifact, fs.val("attestation"))
	if err != nil {
		return err
	}
	fmt.Printf("promoted %s into the clean store\n  %s\n  outcome: %s (%s)\n",
		ev.SHA256, s.CleanPath(ev.SHA256), ev.Outcome, ev.Detail)
	return nil
}

func airlockTrust(args []string) error {
	const usage = "usage: socair airlock trust add [--acceptor] <key.pub> [--name <issuer>] [--store <path>]"
	if len(args) == 0 || args[0] != "add" {
		return errors.New(usage)
	}
	fs := parseFlags(args[1:])
	// "--acceptor key.pub" parses as a flag with a value, "key.pub
	// --acceptor" as a bare flag; both mean the same.
	acceptor := fs.has("acceptor")
	if v := fs.val("acceptor"); v != "" && v != "true" {
		fs.pos = append(fs.pos, v)
	}
	if len(fs.pos) != 1 {
		return errors.New(usage)
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	if acceptor {
		id, err := s.TrustAcceptor(fs.pos[0])
		if err != nil {
			return err
		}
		fmt.Printf("store %s now honours acceptances signed by key %s\n", s.Root, id)
		return nil
	}
	name := fs.val("name")
	if name == "true" {
		return errors.New(usage)
	}
	id, err := s.TrustAs(fs.pos[0], name)
	if err != nil {
		return err
	}
	if _, names, err := s.TrustedIssuers(); err == nil && names[id] != "" {
		fmt.Printf("store %s now trusts signing key %s as issuer %q\n", s.Root, id, names[id])
	} else {
		fmt.Printf("store %s now trusts signing key %s (unnamed: attestations it signs show their issuer as claimed; pass --name to name it)\n", s.Root, id)
	}
	return nil
}

func airlockLog(args []string) error {
	fs := parseFlags(args)
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	if fs.has("verify") || fs.val("expect-head") != "" {
		r, err := s.Verify(airlock.VerifyOptions{ExpectHead: fs.val("expect-head")})
		if err != nil {
			return err
		}
		if r.Broken != 0 {
			return fmt.Errorf("activity log chain broken at line %d: %s", r.Broken, r.Reason)
		}
		fmt.Printf("activity log chain intact: %d entries", r.Entries)
		if r.Legacy > 0 {
			fmt.Printf(" (the first %d predate chaining and are not covered)", r.Legacy)
		}
		fmt.Printf("\nhead %s\nRecord the head; `socair airlock log --verify --expect-head <head>` later also detects entries cut off the end.\n", r.Head)
		return nil
	}
	ev, err := s.Events()
	if err != nil {
		return err
	}
	if len(ev) == 0 {
		fmt.Println("no airlock activity")
		return nil
	}
	for _, e := range ev {
		fmt.Printf("%s  %-8s %-11s %s  %s  %s\n",
			e.TS, e.Action, e.Outcome, shortHash(e.SHA256), e.Repo, e.Detail)
	}
	return nil
}

// storeRoot resolves the store: --store, then SOCAIR_STORE, then ~/.socair/store.
func storeRoot(fs *flagSet) string {
	if v := fs.val("store"); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("SOCAIR_STORE")); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".socair", "store")
	}
	return filepath.Join(home, ".socair", "store")
}

func revOrMain(fs *flagSet) string {
	if v := fs.val("revision"); v != "" {
		return v
	}
	return "main"
}

func shortHash(sha string) string {
	if len(sha) >= 12 {
		return sha[:12]
	}
	if sha == "" {
		return "-"
	}
	return sha
}

// flagSet is the CLI's hand-rolled flag parser, matching the render command's
// convention of flags before or after positionals.
type flagSet struct {
	vals map[string]string
	// all keeps every value a repeated flag was given, in order.
	all map[string][]string
	// bare marks flags given with no value.
	bare map[string]bool
	pos  []string
}

func parseFlags(args []string) *flagSet {
	fs := &flagSet{vals: map[string]string{}, all: map[string][]string{}, bare: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			fs.pos = append(fs.pos, a)
			continue
		}
		key := strings.TrimPrefix(a, "--")
		if eq := strings.IndexByte(key, '='); eq >= 0 {
			fs.set(key[:eq], key[eq+1:])
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			fs.vals[key] = "true"
			fs.bare[key] = true
			continue
		}
		i++
		fs.set(key, args[i])
	}
	return fs
}

func (f *flagSet) set(key, v string) {
	f.vals[key] = v
	f.all[key] = append(f.all[key], v)
}

// patterns returns every value of a repeatable pattern flag, each split on
// the commas outside [...]. A pattern narrows what a command does, so a bare
// flag or an empty pattern is refused rather than dropped, which would widen
// it.
func (f *flagSet) patterns(key string) ([]string, error) {
	if f.bare[key] {
		return nil, fmt.Errorf("--%s needs a pattern", key)
	}
	var out []string
	for _, v := range f.all[key] {
		for _, part := range splitOutsideBrackets(v) {
			if part = strings.TrimSpace(part); part == "" {
				return nil, fmt.Errorf("--%s has an empty pattern in %q", key, v)
			}
			out = append(out, part)
		}
	}
	return out, nil
}

func splitOutsideBrackets(s string) []string {
	var parts []string
	depth, start := 0, 0
	for i, r := range s {
		switch {
		case r == '[':
			depth++
		case r == ']' && depth > 0:
			depth--
		case r == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func (f *flagSet) val(key string) string { return f.vals[key] }
func (f *flagSet) has(key string) bool   { return f.vals[key] != "" }

// airlockExport writes a snapshot of the store: socair airlock export --out <dir> [--key <k>] [--store <p>].
func airlockExport(args []string) error {
	fs := parseFlags(args)
	if fs.val("out") == "" {
		return errors.New("usage: socair airlock export --out <dir> [--key <operator.key>] [--store <path>]")
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	var k *attest.PrivateKey
	if fs.val("key") != "" {
		if k, err = attest.LoadPrivateKey(fs.val("key")); err != nil {
			return err
		}
	}
	st, err := inventory.Export(s, fs.val("out"), k, time.Now(), "socair "+engine.Version)
	if err != nil {
		return err
	}
	signed := "UNSIGNED (pass --key to sign)"
	if k != nil {
		signed = "signed by key " + attest.ShortID(k.ID)
	}
	fmt.Printf("exported %d approved model(s), %d other, %s, to %s\n", len(st.Predicate.Models), len(st.Predicate.Other), signed, fs.val("out"))
	return nil
}
