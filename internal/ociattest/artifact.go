package ociattest

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/defilantech/socair/internal/registry"
	"github.com/defilantech/socair/internal/report"
)

// matchArtifact matches a manifest's layers to an attestation: raw model
// layers by their digests (MatchLayers), and an image's tar layers by the
// files inside them (MapTarLayers, streaming each layer from the registry).
func matchArtifact(ctx context.Context, repo *registry.Repo, mediaType string, m registry.Manifest, a report.ArtifactIdentity, o MapOptions) (*Match, error) {
	if manifestTypes[mediaType] && hasImageLayer(m) {
		open := func(ctx context.Context, l registry.Descriptor) (io.ReadCloser, error) {
			return repo.OpenBlob(ctx, l.Digest, l.Size)
		}
		return MapTarLayers(ctx, m, a, open, o)
	}
	return MatchLayers(mediaType, m, a)
}

func hasImageLayer(m registry.Manifest) bool {
	for _, l := range m.Layers {
		if isImageLayer(l.MediaType) {
			return true
		}
	}
	return false
}

// sameMatch checks that what a binding states about the artifact's layers
// is what matching them again found: a binding that misstates what it
// covers must not verify.
func sameMatch(b BoundArtifact, m *Match) error {
	type pair struct{ field, bound, actual string }
	for _, p := range []pair{
		{"match", b.Match, m.Kind},
		{"model_root", b.ModelRoot, m.ModelRoot},
		{"layer_rules", b.LayerRules, m.Rules},
	} {
		if p.bound != p.actual {
			if p.field == "layer_rules" {
				return fmt.Errorf("the binding was made under layer rules %q, and this socair maps layers under %q", p.bound, p.actual)
			}
			return fmt.Errorf("the binding states %s %q, but its layers match as %q", p.field, p.bound, p.actual)
		}
	}
	if len(b.Layers) != len(m.Layers) {
		return fmt.Errorf("the binding lists %d layers, and the manifest has %d", len(b.Layers), len(m.Layers))
	}
	for i, l := range b.Layers {
		w := m.Layers[i]
		if l.Digest != w.Digest || l.Size != w.Size || l.MediaType != w.MediaType || l.Path != w.Path ||
			l.Role != w.Role || l.Entries != w.Entries || !slices.Equal(l.Files, w.Files) {
			return fmt.Errorf("the binding states layer %d as %+v, but it matches as %+v", i, l, w)
		}
	}
	return nil
}
