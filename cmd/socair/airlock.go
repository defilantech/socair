package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defilantech/socair/internal/airlock"
	"github.com/defilantech/socair/internal/engine"
	"github.com/defilantech/socair/internal/report"
)

// airlockCmd is the controlled junction between untrusted egress and the clean
// store. A pull lands in staging; only a promotion moves bytes across.
func airlockCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: socair airlock <init|pull|ingest|promote|log>")
	}
	switch args[0] {
	case "init":
		return airlockInit(args[1:])
	case "pull":
		return airlockPull(args[1:])
	case "ingest":
		return airlockIngest(args[1:])
	case "promote":
		return airlockPromote(args[1:])
	case "log":
		return airlockLog(args[1:])
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
	if repo == "" || sha == "" || file == "" {
		return errors.New("usage: socair airlock pull --repo <org/name> --file <name> --sha256 <hash> [--revision main] [--store <path>]")
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
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
		return errors.New("usage: socair airlock ingest --local <path> | --cache --repo <org/name> --file <name> [--revision main] [--scan]")
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
	if len(fs.pos) != 1 || fs.val("report") == "" {
		return errors.New("usage: socair airlock promote <artifact> --report <report.json> [--store <path>]")
	}
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
	}
	artifact := fs.pos[0]
	ev, err := airlock.Promote(s, artifact, fs.val("report"))
	if err != nil {
		return err
	}
	fmt.Printf("promoted %s into the clean store\n  %s\n  outcome: %s (%s)\n",
		ev.SHA256, s.CleanPath(ev.SHA256), ev.Outcome, ev.Detail)
	return nil
}

func airlockLog(args []string) error {
	fs := parseFlags(args)
	s, err := airlock.Open(storeRoot(fs))
	if err != nil {
		return err
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
	pos  []string
}

func parseFlags(args []string) *flagSet {
	fs := &flagSet{vals: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			fs.pos = append(fs.pos, a)
			continue
		}
		key := strings.TrimPrefix(a, "--")
		if eq := strings.IndexByte(key, '='); eq >= 0 {
			fs.vals[key[:eq]] = key[eq+1:]
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			fs.vals[key] = "true"
			continue
		}
		i++
		fs.vals[key] = args[i]
	}
	return fs
}

func (f *flagSet) val(key string) string { return f.vals[key] }
func (f *flagSet) has(key string) bool   { return f.vals[key] != "" }
