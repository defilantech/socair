package ociattest

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/report"
)

// ErrNotBound marks an OCI artifact whose layers could not be shown to be
// the attested bytes. The reason is in the error.
var ErrNotBound = errors.New("the artifact's layers are not shown to be the attested bytes")

func notBound(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNotBound, fmt.Sprintf(format, args...))
}

// rawLayerTypes are the layer media types whose producers write one file's
// bytes, unarchived and uncompressed, so the layer digest is the file's
// SHA-256 (docs/oci.md cites each). A tar layer, a compressed one (+gzip,
// +zstd), or a type not listed here is not matched: a consumer unpacks or
// decodes it, so the bytes it loads are not the blob's.
var rawLayerTypes = map[string]string{}

func init() {
	for _, kind := range []string{"weight", "weight.config", "doc", "code", "dataset"} {
		rawLayerTypes["application/vnd.cncf.model."+kind+".v1.raw"] = "ModelPack"
		rawLayerTypes["application/vnd.cnai.model."+kind+".v1.raw"] = "ModelPack (legacy cnai names)"
	}
	for _, kind := range []string{"model", "modelpart", "dataset", "code", "docs", "mcpb"} {
		rawLayerTypes["application/vnd.kitops.modelkit."+kind+".v1.raw"] = "KitOps ModelKit"
	}
	for _, t := range []string{"gguf.v3", "safetensors", "dduf", "mmproj", "license", "chat.template.jinja", "model.file"} {
		rawLayerTypes["application/vnd.docker.ai."+t] = "Docker Model Runner"
	}
	// Older Docker Model Runner artifacts, which it still reads.
	rawLayerTypes["application/vnd.cncf.model.weight.v1.gguf"] = "Docker Model Runner (older)"
	rawLayerTypes["application/vnd.cncf.model.weight.v1.safetensors"] = "Docker Model Runner (older)"
}

// RawLayerTypes lists the matched layer media types, sorted.
func RawLayerTypes() []string {
	out := make([]string, 0, len(rawLayerTypes))
	for t := range rawLayerTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Annotations that name the file a layer holds: ModelPack's (also written
// by KitOps and Docker Model Runner), its pre-CNCF name, and the OCI title
// ORAS writes.
const (
	AnnotationFilepath       = "org.cncf.model.filepath"
	AnnotationFilepathLegacy = "org.cnai.model.filepath"
	AnnotationTitle          = "org.opencontainers.image.title"
)

// Layer is one layer of a bound artifact and the attested files it carries.
type Layer struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
	// Path is the file path a raw layer's annotations give, when they give
	// one.
	Path string `json:"path,omitempty"`
	// Role, Entries, and Files describe a tar layer of a model-root match:
	// RoleModel or RoleBase, the entries the layer holds, and the attested
	// files it holds, as paths under the model root.
	Role    string   `json:"role,omitempty"`
	Entries int      `json:"entries,omitempty"`
	Files   []string `json:"files,omitempty"`
}

// Match kinds.
const (
	MatchFile      = "file"
	MatchDirectory = "model-directory"
)

// Match is the result of matching an artifact's layers to an attestation.
type Match struct {
	// Kind is MatchFile (one attested file, one layer), MatchDirectory
	// (every attested file of a model directory, each its own layer at its
	// path), or MatchModelRoot (an image whose tar layers hold the attested
	// files, and nothing else, under ModelRoot, mapped under Rules).
	Kind      string
	ModelRoot string
	Rules     string
	Layers    []Layer
}

// manifestTypes are the manifest media types whose layers are matched.
var manifestTypes = map[string]bool{
	registry.MediaTypeImageManifest:  true,
	registry.MediaTypeDockerManifest: true,
}

// MatchLayers checks that a manifest's layers carry exactly the attested
// bytes, and nothing else:
//
//   - for a single-file attestation, one layer, whose digest is the file's
//     SHA-256 and whose size is its size;
//   - for a model directory, one layer per attested file, each naming the
//     file's path in an annotation, with that file's SHA-256 and size, and no
//     other layer.
//
// Every layer must have a media type Socair knows holds one file's raw
// bytes. Anything else returns ErrNotBound naming each problem. The
// manifest's config blob is not matched: it is metadata the attestation does
// not cover (docs/oci.md, "What is not checked").
func MatchLayers(mediaType string, m registry.Manifest, a report.ArtifactIdentity) (*Match, error) {
	switch {
	case mediaType == registry.MediaTypeImageIndex || mediaType == registry.MediaTypeDockerList:
		return nil, notBound("it is an image index, a list of manifests; name one manifest by its digest")
	case !manifestTypes[mediaType]:
		return nil, notBound("manifest media type %q is not an OCI image manifest", mediaType)
	case len(m.Layers) == 0:
		return nil, notBound("the manifest has no layers")
	}
	var problems []string
	layers := make([]Layer, len(m.Layers))
	for i, l := range m.Layers {
		layers[i] = Layer{Digest: l.Digest, Size: l.Size, MediaType: l.MediaType}
		p, err := layerPath(l)
		if err != nil {
			problems = append(problems, fmt.Sprintf("layer %d: %v", i, err))
		}
		layers[i].Path = p
		if err := registry.ValidDigest(l.Digest); err != nil {
			problems = append(problems, fmt.Sprintf("layer %d: %v; Socair attests SHA-256", i, err))
		}
		if _, ok := rawLayerTypes[l.MediaType]; !ok {
			problems = append(problems, fmt.Sprintf("layer %d%s: media type %q %s", i, named(p), l.MediaType, whyNotRaw(l.MediaType)))
		}
	}
	if len(problems) == 0 {
		if len(a.Files) == 0 {
			problems = matchFile(layers, a)
		} else {
			problems = matchDirectory(layers, a.Files)
		}
	}
	if len(problems) != 0 {
		return nil, notBound("%s", strings.Join(problems, "; "))
	}
	kind := MatchFile
	if len(a.Files) != 0 {
		kind = MatchDirectory
	}
	return &Match{Kind: kind, Layers: layers}, nil
}

func named(p string) string {
	if p == "" {
		return ""
	}
	return " (" + p + ")"
}

func whyNotRaw(mt string) string {
	base, suffix, compressed := strings.Cut(mt, "+")
	switch {
	case compressed && (suffix == "gzip" || suffix == "zstd"):
		return "is compressed: the bytes a consumer loads are not the blob's, so its digest is not the file's hash"
	case strings.HasSuffix(base, ".tar") || strings.Contains(base, ".tar.") || strings.HasSuffix(base, "rootfs.diff.tar"):
		return "is a tar archive: a consumer unpacks it, and Socair does not unpack layers to map the files inside to the attested ones"
	}
	return "is not one Socair knows to hold one file's raw bytes (docs/oci.md lists those it matches)"
}

// layerPath reads the path a layer's annotations name, cleaned. Two
// annotations that name different paths are an error, as is a path that is
// absolute or leaves the model directory.
func layerPath(l registry.Descriptor) (string, error) {
	var found string
	for _, k := range []string{AnnotationFilepath, AnnotationFilepathLegacy, AnnotationTitle} {
		v, ok := l.Annotations[k]
		if !ok {
			continue
		}
		p, err := cleanPath(v)
		if err != nil {
			return "", fmt.Errorf("annotation %s: %v", k, err)
		}
		if found != "" && p != found {
			return "", fmt.Errorf("its annotations name two paths, %q and %q", found, p)
		}
		found = p
	}
	return found, nil
}

func cleanPath(v string) (string, error) {
	if v == "" || strings.ContainsAny(v, "\\\x00\n\r") || strings.HasPrefix(v, "/") {
		return "", fmt.Errorf("path %q is not a relative file path", v)
	}
	p := path.Clean(v)
	if p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("path %q leaves the model directory", v)
	}
	return p, nil
}

func matchFile(layers []Layer, a report.ArtifactIdentity) []string {
	want := "sha256:" + a.SHA256
	if len(layers) != 1 {
		var extra []string
		for i, l := range layers {
			if l.Digest != want {
				extra = append(extra, fmt.Sprintf("layer %d%s (%s)", i, named(l.Path), l.MediaType))
			}
		}
		return []string{fmt.Sprintf("the attestation covers one file, %s, and the artifact has %d layers; %s %s not part of it. Scan a model directory holding every file the artifact carries, at the paths its layers name, and attach that attestation",
			a.FileName, len(layers), strings.Join(extra, ", "), isAre(len(extra)))}
	}
	l := layers[0]
	var p []string
	if l.Digest != want {
		p = append(p, fmt.Sprintf("the layer is %s, but the attested file %s is %s", l.Digest, a.FileName, want))
	}
	if a.SizeBytes > 0 && l.Size != a.SizeBytes {
		p = append(p, fmt.Sprintf("the layer is %d bytes, but the attested file is %d", l.Size, a.SizeBytes))
	}
	return p
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func matchDirectory(layers []Layer, files []report.ArtifactFile) []string {
	want := map[string]report.ArtifactFile{}
	for _, f := range files {
		want[f.Path] = f
	}
	var p []string
	seen := map[string]bool{}
	for i, l := range layers {
		if l.Path == "" {
			p = append(p, fmt.Sprintf("layer %d (%s) names no file path (%s), so it cannot be placed in the attested directory", i, l.Digest, AnnotationFilepath))
			continue
		}
		if seen[l.Path] {
			p = append(p, fmt.Sprintf("two layers name %s", l.Path))
			continue
		}
		seen[l.Path] = true
		f, ok := want[l.Path]
		switch {
		case !ok:
			p = append(p, fmt.Sprintf("layer %d holds %s, which the attestation does not list", i, l.Path))
		case l.Digest != "sha256:"+f.SHA256:
			p = append(p, fmt.Sprintf("layer %d holds %s as %s, but the attested file is sha256:%s", i, l.Path, l.Digest, f.SHA256))
		case l.Size != f.SizeBytes:
			p = append(p, fmt.Sprintf("layer %d holds %s as %d bytes, but the attested file is %d", i, l.Path, l.Size, f.SizeBytes))
		}
	}
	var missing []string
	for _, f := range files {
		if !seen[f.Path] {
			missing = append(missing, f.Path)
		}
	}
	if len(missing) != 0 {
		p = append(p, "the artifact has no layer for attested file(s) "+strings.Join(missing, ", "))
	}
	return p
}
