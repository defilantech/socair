package structure

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/pickle"
	"github.com/defilantech/socair/internal/hdf5"
	"github.com/defilantech/socair/internal/keras"
)

// The Keras rules. docs/keras.md gives the sources for each.

// ValidateKeras checks the Keras model at rel, a slash-separated path inside
// root, the directory a directory scan holds: an HDF5 file (.h5, .hdf5) or a
// .keras archive. For an archive it also returns what it read of it, entry
// by entry, for File inventory, which otherwise names every archive as
// unscanned; nil when it read none.
func ValidateKeras(root, rel string) (checks.Result, *checks.ArchiveRead) {
	r := checks.Result{Name: "Format and structure", LooksFor: "Malformed container structure, unexpected tensors"}
	return validateKeras(r, filepath.Join(root, filepath.FromSlash(rel)))
}

// KerasConfig checks a Keras serialized object stored as a JSON file in a
// model directory, as a KerasHub preset stores its backbone (config.json)
// and tokenizer (tokenizer.json): the config rules alone.
func KerasConfig(name string, v any) checks.Result {
	r := checks.Result{Name: "Format and structure", LooksFor: "Malformed container structure, unexpected tensors"}
	g := newGrade()
	addons := g.configRefs(keras.Analyze(v, name))
	summary := fmt.Sprintf("a Keras serialized object (%s)", name)
	if addons != "" {
		summary += "; " + addons
	}
	return g.result(r, summary, "No Python bytecode, pickled module, or class or function from outside Keras and TensorFlow is named. "+kerasLimits)
}

// IsKerasObject reports a decoded JSON document that is a Keras serialized
// object: a top-level object with a string class_name and module, as
// keras.saving.serialize_keras_object writes one.
func IsKerasObject(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, cn := m["class_name"].(string)
	_, mod := m["module"].(string)
	return cn && mod
}

func newGrade() *grade {
	return &grade{perPat: map[string]int{}, gapCount: map[string]*gapGroup{}}
}

func validateKeras(r checks.Result, p string) (checks.Result, *checks.ArchiveRead) {
	m, err := keras.Read(p)
	if err != nil {
		var pe *hdf5.ParseError
		what := "the Keras model"
		if k, _ := keras.Sniff(p); k == keras.HDF5 {
			what = "the HDF5 file"
		}
		r.Status = checks.NotTested
		if errors.As(err, &pe) {
			r.Notes = "could not parse " + what + ", so its structure was not checked: " + err.Error()
		} else {
			r.Notes = "could not read " + what + ", so its structure was not checked: " + reasonOf(err)
		}
		return r, nil
	}
	g := newGrade()
	var parts []string
	if m.Kind == keras.Archive {
		parts = append(parts, g.archive(m))
	}
	if m.H5Unread != "" {
		g.gap(m.H5Unread, "")
	}
	if m.H5 != nil {
		parts = append(parts, g.hdf5(m))
	}
	if addons := g.configs(m); addons != "" {
		parts = append(parts, addons)
	}
	held := ""
	switch {
	case len(m.Configs) == 0 && m.Kind == keras.HDF5 && strings.HasPrefix(m.Layout, "HDF5 with no Keras"):
		held = "No model config is present, so no code was found. "
	case len(m.Configs) == 0 && m.Kind == keras.HDF5:
		held = "No model config is present, so the file holds no code a Keras loader runs, and no code was found; a loader reads its weights by name. "
	case len(m.Configs) > 0:
		held = "No Python bytecode, pickled module, or class or function from outside Keras and TensorFlow is named in the config. "
	}
	if m.H5 != nil {
		held = "Every dataset's storage is inside the HDF5 data, sized by its type and shape, with no two overlapping, and no data or link reaches another file. " + held
	}
	if m.Kind == keras.Archive {
		held = "The archive holds only the members Keras reads. " + held
	}
	res := g.result(r, strings.Join(parts, "; "), held+kerasLimits)
	if m.Kind != keras.Archive {
		return res, nil
	}
	return res, archiveRead(m)
}

// kerasLimits says what a Keras PASS does not cover.
const kerasLimits = "Weight values are not read. A class Keras resolves itself, one from KerasHub, KerasCV, or KerasNLP, " +
	"and a function given by name alone (an activation or loss) run from the installed packages, outside this scan"

// result sets r from the grade: FAIL on a violation, LEAD on a lead, else
// NOT_TESTED on a gap, else PASS with what held.
func (g *grade) result(r checks.Result, summary, held string) checks.Result {
	r.Findings = g.findings
	gaps := g.gapNotes()
	switch {
	case g.fails > 0 || g.leads > 0:
		r.Status = checks.Lead
		if g.fails > 0 {
			r.Status = checks.Fail
		}
		parts := []string{fmt.Sprintf("%d violation(s) and %d lead(s)", g.fails, g.leads)}
		if g.dropped > 0 {
			parts = append(parts, fmt.Sprintf("%d more finding(s) not listed", g.dropped))
		}
		parts = append(parts, summary)
		if len(gaps) > 0 {
			parts = append(parts, "also not checked: "+strings.Join(gaps, "; "))
		}
		r.Notes = strings.Join(parts, ". ")
	case len(gaps) > 0:
		r.Status = checks.NotTested
		r.Notes = "parsed but could not be fully checked: " + strings.Join(gaps, "; ") + ". " + summary
	default:
		r.Status = checks.Pass
		r.Notes = summary + ". " + held
	}
	return r
}

// archive grades a .keras archive's members.
func (g *grade) archive(m *keras.Model) string {
	for _, n := range m.Escapes {
		g.lead("archive-path-escape", fmt.Sprintf("%q", clip(n, 120)),
			"a member name with an absolute path, a drive, or a \"..\" component, which no Keras writer produces: Keras extracts every member of an archive of more than three, "+
				"Python's zipfile drops those parts as it extracts, and Keras before 3.14.0 checked names against the working directory (CVE-2026-11816); another extractor can write outside its directory")
	}
	for _, n := range m.Duplicates {
		g.lead("keras-archive-entry", fmt.Sprintf("%q", clip(n, 120)), "a member name repeated in the archive: zip readers disagree on which copy they read")
	}
	for _, n := range m.Unexpected {
		g.lead("keras-archive-entry", clip(n, 160), "a member Keras neither writes nor reads, though it extracts every member of an archive of more than three: a place to carry a payload (File inventory scans its text)")
	}
	assets := 0
	for _, e := range m.Entries {
		if strings.HasPrefix(e.Name, keras.AssetsDir) && !strings.HasSuffix(e.Name, "/") {
			assets++
		}
	}
	n := fmt.Sprintf(".keras archive of %d member(s)", len(m.Entries))
	if m.KerasVersion != "" {
		n += ", saved by Keras " + clip(m.KerasVersion, 40)
	}
	if assets > 0 {
		n += fmt.Sprintf(", %d asset(s) (scanned by File inventory)", assets)
	}
	return n
}

// hdf5 grades the HDF5 file: what the reader did not model, and every
// dataset's storage.
func (g *grade) hdf5(m *keras.Model) string {
	h := m.H5
	if len(h.Unread) > 0 {
		g.gap("parts of the HDF5 file this reader does not model: "+strings.Join(h.Unread, "; "), "")
	}
	if m.UserBlock > 0 && m.Kind == keras.HDF5 {
		g.gap(fmt.Sprintf("a user block of %d bytes before the HDF5 data, which HDF5 skips and a reader of another format reads first; it was not read as a container (File inventory scans its text)", m.UserBlock), "")
	}
	lc := h.Check()
	for _, v := range lc.Violations {
		g.fail(v.Pattern, clip(v.Where, 160), v.Detail)
	}
	for _, o := range lc.Outside {
		if o.Virtual {
			g.lead("hdf5-virtual-dataset", clip(o.Where, 160), "a virtual dataset, whose data is mapped from other datasets, which can be in other files (the mapping was not read); "+
				"Keras refuses one since 3.12.3 and 3.15.0, and read it before (CVE-2026-12480)")
			continue
		}
		files := make([]string, 0, len(o.Files))
		for _, f := range o.Files {
			files = append(files, fmt.Sprintf("%q", clip(f, 120)))
		}
		g.fail("external-data-escape", clip(o.Where, 160), "data in external file(s) "+capList(files, 3)+", which the HDF5 library opens by name, outside this file, "+
			"and reads as the weights: h5py and Hugging Face transformers' loader read it, as Keras did before 3.12.1 and 3.13.2 (CVE-2026-1669), which refuse it")
	}
	for _, l := range h.Links {
		switch l.Type {
		case "external":
			g.fail("external-data-escape", clip(l.Path, 160), fmt.Sprintf("an external link to %q: h5py follows it to an object in another file when a loader reads this path, "+
				"as Keras did before 3.12.3 and 3.15.0 (CVE-2026-9335), which refuse it", clip(l.Target, 160)))
		case "soft":
			g.lead("hdf5-soft-link", clip(l.Path, 160), fmt.Sprintf("a soft link to %q: one name reads the object another name holds, which no Keras writer produces; "+
				"Keras refuses soft links since 3.12.3 and 3.15.0", clip(l.Target, 160)))
		}
	}
	for _, u := range lc.Unchecked {
		g.gap("storage that could not be checked", clip(u, 200))
	}
	groups := 0
	for _, o := range h.Objects {
		if o.Kind == hdf5.KindGroup {
			groups++
		}
	}
	file := "HDF5"
	if m.Kind == keras.Archive {
		file = keras.WeightsH5
	}
	n := fmt.Sprintf("%s superblock v%d: %d group(s), %d dataset(s) (%d contiguous, %d chunked in %d chunk(s), %d compact, %d unallocated) holding %d bytes",
		file, h.SuperblockVersion, groups, lc.Datasets, lc.Contiguous, lc.Chunked, lc.Chunks, lc.Compact, lc.Unallocated, lc.Bytes)
	if m.Kind == keras.HDF5 {
		n = m.Layout + "; " + n
		if m.KerasVersion != "" {
			n += "; keras_version " + clip(m.KerasVersion, 40)
		}
		if m.Backend != "" {
			n += ", backend " + clip(m.Backend, 40)
		}
	}
	if len(h.Aliases) > 0 {
		n += fmt.Sprintf("; %d name(s) reach an object another name reaches (a hard link)", len(h.Aliases))
	}
	return n
}

// configs grades every config the model holds and returns a note naming
// the KerasHub, KerasCV, and KerasNLP classes, which are named, not judged.
func (g *grade) configs(m *keras.Model) string {
	var refs []keras.Ref
	for _, c := range m.Configs {
		if c.Err != "" {
			g.gap("the config in "+c.Source+" could not be read: "+c.Err, "")
			continue
		}
		refs = append(refs, keras.Analyze(c.Value, c.Source)...)
	}
	return g.configRefs(refs)
}

// configRefs grades what a config names.
func (g *grade) configRefs(refs []keras.Ref) string {
	var addons []string
	seen := map[string]bool{}
	for _, ref := range refs {
		// A class many layers use is one reference.
		if ref.Kind == keras.Named || ref.Kind == keras.Addon {
			key := fmt.Sprint(ref.Kind, ref.Module, ".", ref.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		where := clip(ref.Source+" "+ref.Where, 200)
		switch ref.Kind {
		case keras.Bytecode:
			g.fail("keras-lambda", where, ref.What()+": "+ref.Detail)
		case keras.Pickle:
			g.fail("keras-pickle", where, ref.Detail)
		case keras.Refused:
			g.fail("keras-dangerous-reference", where, ref.What()+": "+ref.Detail)
		case keras.Named:
			if ref.Module != "" && pickle.Dangerous(ref.Module, ref.Name) {
				g.fail("keras-dangerous-reference", where, ref.What()+
					": a global the pickle check FAILs, named as a Keras class or function; Keras 3.0 to 3.8 and tf-keras import the module by name and take it into the model they rebuild (CVE-2025-1550)")
				continue
			}
			what := clip(ref.What(), 120)
			if ref.Module == "" {
				g.gap("classes and functions Keras does not register, which only the caller's code supplies (custom_objects or a registration): code outside this file", what)
			} else {
				g.gap("classes and functions named from modules outside Keras and TensorFlow: code outside this file, which Keras 3.9 and later resolve only from objects the caller registers, and Keras 3.0 to 3.8 and tf-keras import by name", what)
			}
		case keras.External:
			g.gap("paths outside this file that a layer opens", clip(ref.Where+": "+ref.Detail, 200))
		case keras.PathName:
			g.lead("keras-name-path", where, fmt.Sprintf("%q: %s", clip(ref.Name, 80), ref.Detail))
		case keras.Unwalked:
			g.gap("parts of the config this reader did not walk", clip(ref.Source+": "+ref.Detail, 200))
		case keras.Addon:
			addons = append(addons, clip(ref.What(), 100))
		}
	}
	if len(addons) == 0 {
		return ""
	}
	sort.Strings(addons)
	addons = dedupe(addons)
	return "classes from KerasHub, KerasCV, or KerasNLP, which Keras imports from the installed package (named, not judged): " + capList(addons, 5)
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// archiveRead is what the structure check read of a .keras archive, for
// File inventory: config.json, metadata.json, and model.weights.h5 parsed,
// and assets scanned by the inventory itself. A member it did not read is
// named, which keeps the archive unscanned.
func archiveRead(m *keras.Model) *checks.ArchiveRead {
	a := &checks.ArchiveRead{By: "Format and structure"}
	read := []string{keras.ConfigEntry + " parsed"}
	if m.H5 != nil {
		read = append(read, keras.WeightsH5+" parsed as HDF5")
	} else {
		a.Unread = append(a.Unread, "the weights ("+m.H5Unread+")")
	}
	read = append(read, "metadata.json and assets read as text by File inventory")
	a.Read = strings.Join(read, "; ")
	a.Unread = append(a.Unread, m.Unexpected...)
	for _, d := range m.Duplicates {
		a.Unread = append(a.Unread, d+" (a second member of the same name)")
	}
	for _, e := range m.Escapes {
		a.Unread = append(a.Unread, e+" (a name that leaves the extraction directory)")
	}
	return a
}
