package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defilantech/socair/internal/modeldir"
)

// A directory report's subject must be the manifest digest of exactly its
// listed files. Falsification: drop validateFiles and every case validates.
func TestFilesMustHashToTheSubject(t *testing.T) {
	d, _ := loadGolden(t)
	files := []modeldir.File{
		{Path: "config.json", SHA256: strings.Repeat("a", 64), Size: 2, Role: modeldir.RoleConfig},
		{Path: "model.safetensors", SHA256: strings.Repeat("b", 64), Size: 9, Role: modeldir.RoleWeights},
	}
	for _, f := range files {
		d.Artifact.Files = append(d.Artifact.Files, ArtifactFile{Path: f.Path, SHA256: f.SHA256, SizeBytes: f.Size, Role: f.Role})
	}
	d.Artifact.SHA256 = modeldir.Digest(files)
	d.Verification.ArtifactSHA256 = d.Artifact.SHA256
	if problems := Validate(d); len(problems) != 0 {
		t.Fatalf("a consistent directory report must validate: %v", problems)
	}

	swapped := *d
	swapped.Artifact.Files = append([]ArtifactFile{}, d.Artifact.Files...)
	swapped.Artifact.Files[1].SHA256 = strings.Repeat("c", 64)
	if len(Validate(&swapped)) == 0 {
		t.Error("a file list that does not hash to the subject must not validate")
	}

	unsorted := *d
	unsorted.Artifact.Files = []ArtifactFile{d.Artifact.Files[1], d.Artifact.Files[0]}
	if len(Validate(&unsorted)) == 0 {
		t.Error("an unsorted file list must not validate")
	}
}

func TestSchemaRolesAreTheModeldirRoles(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			Artifact struct {
				Properties struct {
					Files struct {
						Items struct {
							Properties struct {
								Role struct {
									Enum []string `json:"enum"`
								} `json:"role"`
							} `json:"properties"`
						} `json:"items"`
					} `json:"files"`
				} `json:"properties"`
			} `json:"artifact"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	got := s.Properties.Artifact.Properties.Files.Items.Properties.Role.Enum
	want := append([]string{}, modeldir.Roles...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("schema roles %v, modeldir roles %v", got, want)
	}
}
