package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/chattemplate"
	"github.com/defilantech/socair/internal/checks/inventory"
	"github.com/defilantech/socair/internal/checks/pickle"
	"github.com/defilantech/socair/internal/checks/provenance"
	"github.com/defilantech/socair/internal/checks/remotecode"
	"github.com/defilantech/socair/internal/checks/structure"
	"github.com/defilantech/socair/internal/checks/tokenizer"
	"github.com/defilantech/socair/internal/diskfree"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
	"github.com/defilantech/socair/internal/tier2"
)

// pickleExt are weight files that are pickle streams, zip/tar containers of
// them, or NumPy arrays, whose object data is a pickle; the pickle check reads
// them all.
var pickleExt = map[string]bool{".bin": true, ".pt": true, ".pth": true, ".ckpt": true, ".pkl": true, ".pickle": true, ".joblib": true,
	".npy": true, ".npz": true}

// scanDir scans a model directory as one artifact (see internal/modeldir).
// Every file is snapshotted and hashed; the subject is the manifest digest.
// Each per-file check runs on every file it applies to and reports one merged
// row, so one bad shard withholds the whole directory.
func scanDir(dir string, start time.Time, refs *references, in Inputs, t2 *tier2.Config) (*report.Document, error) {
	root, files, excluded, cleanup, err := modeldir.Snapshot(dir, strings.TrimSpace(os.Getenv("SOCAIR_SCAN_TMP")))
	var short *diskfree.ShortError
	if errors.As(err, &short) {
		return nil, fmt.Errorf("%w (set SOCAIR_SCAN_TMP to a volume with room)", err)
	}
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if afterSnapshot != nil {
		afterSnapshot(dir)
	}
	at := func(f modeldir.File) string { return filepath.Join(root, filepath.FromSlash(f.Path)) }

	id := report.Identity{
		FileName: filepath.Base(filepath.Clean(dir)),
		SHA256:   modeldir.Digest(files),
		Format:   "model directory",
	}
	for _, f := range files {
		id.SizeBytes += f.Size
		id.Files = append(id.Files, report.ArtifactFile{Path: f.Path, SHA256: f.SHA256, SizeBytes: f.Size, Role: f.Role})
	}
	cfg := readConfig(root, files)
	id.Name, id.Architecture = displayName(dir, cfg.name), cfg.architecture
	var unparsed []string
	for _, e := range excluded {
		unparsed = append(unparsed, e.Path+": excluded ("+e.Reason+")")
	}
	adapterBase := ""
	if f, ok := find(files, "adapter_config.json"); ok {
		adapterBase = readAdapterBase(at(f))
		id.Name = "adapter " + id.Name
		base := adapterBase
		if base == "" {
			base = "the base model (adapter_config.json does not name one)"
		}
		unparsed = append(unparsed, "base model "+base+": an adapter runs only on its base, which is a separate artifact and needs its own attestation")
	}

	tok := tokenizer.InspectHF(root, files)
	id.TokenizerSHA256 = tok.Hash

	sig, err := dirSignature(dir, root, files)
	if err != nil {
		return nil, err
	}
	d, provOpts, expires, err := begin(start, id, dir, sig, in)
	if err != nil {
		return nil, err
	}
	d.Scope.ReferenceData = refs.scope()
	ident := dirLicense(root, files)
	d.Artifact.License, d.Artifact.BaseModels = licenseIdentity(ident)
	tokRow := tok.Result
	tokRow.Notes += refs.tokenizerNote(tok.Hash)
	tokRow = refs.compareTokenizer(tokRow, tok.Tokens, tok.HFSpecial())
	d.Verification.RerunInstructions = "socair scan <directory>"

	// Per-file rows.
	var structParts, invParts, pickleParts []checks.Part
	for _, f := range files {
		if f.Role != modeldir.RoleWeights && f.Role != modeldir.RoleAdapter {
			continue
		}
		ext := strings.ToLower(path.Ext(f.Path))
		switch {
		case ext == ".safetensors" || ext == ".gguf":
			structParts = append(structParts, checks.Part{File: f.Path, Result: structure.Validate(at(f))})
			invParts = append(invParts, checks.Part{File: f.Path, Result: inventory.Inspect(at(f), inventory.Options{RepoMirror: root})})
			if ext == ".gguf" {
				unparsed = append(unparsed, f.Path+": GGUF metadata checks (chat template, tokenizer, quant) run when the file is scanned on its own")
			}
		case pickleExt[ext]:
			pickleParts = append(pickleParts, checks.Part{File: f.Path, Result: pickle.Inspect(at(f))})
		case f.Role == modeldir.RoleAdapter:
			// adapter_config.json and friends: config, not weights.
		default:
			unparsed = append(unparsed, f.Path+": "+ext+" weights are not a format this scanner parses")
			structParts = append(structParts, checks.Part{File: f.Path, Result: checks.Result{Status: checks.NotTested,
				Notes: ext + " is not a container this scanner parses"}})
		}
	}
	for _, f := range files {
		if strings.HasSuffix(f.Path, ".safetensors.index.json") {
			structParts = append(structParts, checks.Part{File: f.Path, Result: structure.ValidateIndex(root, f.Path)})
		}
	}
	structRow := checks.Merge("Format and structure", "Malformed container structure, unexpected tensors", structParts)
	if len(structParts) == 0 {
		structRow.Notes = "the directory holds no weight file (an incomplete download, or config only)"
		if len(pickleParts) > 0 {
			structRow.Notes = "weights are pickle checkpoints; their structure is read by the pickle row"
		}
	}
	invRow := checks.Merge("File inventory and payloads", "Hidden files, embedded payloads, unexpected executables", invParts)
	if len(invParts) == 0 {
		invRow = inventory.InspectRepo(root)
	}

	templates, nonString, unread := modeldir.ChatTemplates(root, files)
	tmplRow := chattemplate.InspectAllWith(templates, nonString, refs.templateOptions(chattemplate.TokensFromHF(tok.Special, tok.AddedTexts())))
	if len(templates) == 0 && len(nonString) == 0 {
		tmplRow.Notes = "no chat template in tokenizer_config.json, chat_template.json, or a .jinja file"
	}
	if len(unread) > 0 && tmplRow.Status == checks.Pass {
		tmplRow.Status = checks.NotTested
		tmplRow.Notes += "; could not read: " + strings.Join(unread, "; ")
	}

	results := []checks.Result{
		structRow,
		invRow,
		provenance.Inspect(provOpts),
		denylistRow(files, id.SHA256, refs),
		tmplRow,
		tokRow,
		remotecode.Inspect(root, files),
	}
	if len(pickleParts) > 0 {
		results = append(results, checks.Merge(pickleParts[0].Result.Name, pickleParts[0].Result.LooksFor, pickleParts))
	}
	if row, ok := refs.licenseRow(ident, "A model directory states its license in the model card's front matter (README.md), a LICENSE file, or a GGUF's general.license; this one has none that names a license."); ok {
		results = append(results, row)
	}
	measureTier2(d, t2, root)
	return finish(d, results, unparsed, expires), nil
}

// denylistRow checks the manifest digest and every file's hash. With no list
// loaded it is one NOT_TESTED, not one per file, and a configured list that
// could not be read is named once on the merged row.
func denylistRow(files []modeldir.File, digest string, refs *references) checks.Result {
	whole := refs.match(digest)
	if !refs.loaded() {
		return whole
	}
	parts := []checks.Part{{File: "(directory manifest)", Result: whole}}
	for _, f := range files {
		parts = append(parts, checks.Part{File: f.Path, Result: refs.match(f.SHA256)})
	}
	return refs.withUnread(checks.Merge(whole.Name, whole.LooksFor, parts))
}

// repoName matches a Hugging Face repo id, org/name.
var repoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// displayName names the model for the identity section. A Hugging Face cache
// snapshot (models--org--name/snapshots/<commit>) is named by its repo; else
// config.json's _name_or_path when it is a repo id (it is often a training
// machine's local path); else the directory. It is a label, never provenance:
// origin comes only from a provenance manifest bound to the digest.
func displayName(dir, nameOrPath string) string {
	clean := filepath.Clean(dir)
	parent := filepath.Dir(clean)
	if filepath.Base(parent) == "snapshots" {
		if repo, ok := strings.CutPrefix(filepath.Base(filepath.Dir(parent)), "models--"); ok && strings.Contains(repo, "--") {
			return strings.Replace(repo, "--", "/", 1)
		}
	}
	if repoName.MatchString(nameOrPath) {
		return nameOrPath
	}
	return filepath.Base(clean)
}

// hubRepo returns the org/name a provenance repo URL names, or "" when its
// path is not one.
func hubRepo(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil || u.Host == "" {
		return ""
	}
	if p := strings.Trim(u.Path, "/"); repoName.MatchString(p) {
		return p
	}
	return ""
}

type modelConfig struct{ name, architecture string }

// readConfig takes the model's name and architecture from config.json, for
// the identity section only; nothing is judged from it.
func readConfig(root string, files []modeldir.File) modelConfig {
	f, ok := find(files, "config.json")
	if !ok || f.Size > 16<<20 {
		return modelConfig{}
	}
	b, err := os.ReadFile(filepath.Join(root, "config.json"))
	if err != nil {
		return modelConfig{}
	}
	var c struct {
		NameOrPath    string   `json:"_name_or_path"`
		Architectures []string `json:"architectures"`
		ModelType     string   `json:"model_type"`
	}
	if json.Unmarshal(b, &c) != nil {
		return modelConfig{}
	}
	m := modelConfig{name: c.NameOrPath, architecture: c.ModelType}
	if len(c.Architectures) > 0 {
		m.architecture = strings.Join(c.Architectures, ", ")
	}
	return m
}

func readAdapterBase(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var c struct {
		Base string `json:"base_model_name_or_path"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return c.Base
}

// find returns the top-level file with this exact path.
func find(files []modeldir.File, rel string) (modeldir.File, bool) {
	for _, f := range files {
		if f.Path == rel {
			return f, true
		}
	}
	return modeldir.File{}, false
}
