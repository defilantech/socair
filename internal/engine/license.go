package engine

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/checks/license"
	"github.com/defilantech/socair/internal/gguf"
	"github.com/defilantech/socair/internal/modeldir"
	"github.com/defilantech/socair/internal/report"
)

// ggufLicense reads a parsed GGUF's license and base-model keys. in names the
// file within a directory, or is "" for a file scanned on its own.
func ggufLicense(m *gguf.Manifest, in string) ([]license.Claim, []license.BaseModel) {
	claims := license.GGUFLicense{License: m.License, Name: m.LicenseName, Link: m.LicenseLink}.Claims(in)
	var bases []license.BaseModel
	for i, b := range m.BaseModels {
		if b == (gguf.BaseModel{}) {
			continue
		}
		src := fmt.Sprintf("GGUF general.base_model.%d", i)
		if in != "" {
			src += " in " + in
		}
		bases = append(bases, license.BaseModel{Name: b.Name, Organization: b.Organization,
			Repo: license.RepoFromURL(b.RepoURL), URL: b.RepoURL, Source: src})
	}
	return claims, bases
}

// dirLicense reads what a model directory says about its license: the model
// card's front matter, the LICENSE files at its top level, and the license
// keys of every GGUF in it. GGUF files that say the same are read as one
// statement, naming how many files carry it.
func dirLicense(root string, files []modeldir.File) license.Identification {
	at := func(f modeldir.File) string { return filepath.Join(root, filepath.FromSlash(f.Path)) }
	var claims []license.Claim
	var bases []license.BaseModel
	licenseFile := func(f modeldir.File) bool {
		n := strings.ToLower(f.Path)
		return !strings.Contains(n, "/") && (strings.HasPrefix(n, "license") || strings.HasPrefix(n, "licence"))
	}
	modelLicense := false
	for _, f := range files {
		modelLicense = modelLicense || (licenseFile(f) && strings.Contains(strings.ToLower(f.Path), "model"))
	}
	for _, f := range files {
		if strings.Contains(f.Path, "/") {
			continue
		}
		name := strings.ToLower(f.Path)
		switch {
		case name == "readme.md":
			b, err := readText(at(f), f.Size)
			if err != nil {
				claims = append(claims, unreadClaim("model card "+f.Path, err))
				continue
			}
			card := license.ReadCard(b)
			claims = append(claims, card.Claims()...)
			for _, bm := range card.BaseModels {
				bases = append(bases, license.BaseModel{Name: bm, Repo: hubRepoID(bm), Source: "model card base_model"})
			}
		case licenseFile(f):
			b, err := readText(at(f), f.Size)
			if err != nil {
				claims = append(claims, unreadClaim(f.Path, err))
				continue
			}
			c := license.FromText(f.Path, b)
			if modelLicense && strings.Contains(name, "code") {
				c = license.CodeLicense(c)
			}
			claims = append(claims, c)
		}
	}

	type group struct {
		files []string
		m     *gguf.Manifest
	}
	var groups []*group
	byKey := map[string]*group{}
	for _, f := range files {
		if f.Role != modeldir.RoleWeights || strings.ToLower(path.Ext(f.Path)) != ".gguf" {
			continue
		}
		m, err := gguf.ReadHeader(at(f))
		if err != nil {
			claims = append(claims, unreadClaim("GGUF general.license in "+f.Path, fmt.Errorf("the GGUF metadata could not be read: %w", err)))
			continue
		}
		key := fmt.Sprintf("%q %q %q %v", m.License, m.LicenseName, m.LicenseLink, m.BaseModels)
		g, ok := byKey[key]
		if !ok {
			g = &group{m: m}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.files = append(g.files, f.Path)
	}
	for _, g := range groups {
		c, b := ggufLicense(g.m, fileCount(g.files))
		claims = append(claims, c...)
		bases = append(bases, b...)
	}
	return license.Identify(claims, bases)
}

// fileCount names a group of files: the first, and how many others.
func fileCount(files []string) string {
	sort.Strings(files)
	if len(files) == 1 {
		return files[0]
	}
	return fmt.Sprintf("%s and %d other GGUF files", files[0], len(files)-1)
}

// readText reads a small text file, refusing one larger than a license text.
func readText(p string, size int64) ([]byte, error) {
	if size > license.MaxText {
		return nil, fmt.Errorf("it is %d bytes, larger than a license text, so it was not read", size)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, license.MaxText))
}

func unreadClaim(source string, err error) license.Claim {
	return license.Claim{Kind: license.Stated, Source: source, Value: "(not read)", Note: err.Error()}
}

// hubRepoID returns a model card's base_model value when it is a repo id.
func hubRepoID(v string) string {
	if repoName.MatchString(v) {
		return v
	}
	return license.RepoFromURL(v)
}

// licenseIdentity maps an identification onto the report's identity.
func licenseIdentity(id license.Identification) (*report.License, []report.BaseModel) {
	l := &report.License{ID: id.ID, Name: id.Name, Disagreement: id.Disagreement}
	for _, c := range id.Claims {
		l.Sources = append(l.Sources, report.LicenseSource{Source: c.Source, Value: c.Value, ID: c.ID, Note: c.Note})
	}
	var bases []report.BaseModel
	for _, b := range id.BaseModels {
		name := b.Name
		if name == "" {
			name = b.Repo
		}
		bases = append(bases, report.BaseModel{Name: name, Organization: b.Organization, Repo: b.Repo, URL: b.URL, Source: b.Source})
	}
	return l, bases
}
