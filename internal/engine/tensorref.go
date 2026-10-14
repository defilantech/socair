package engine

import (
	"fmt"

	"github.com/defilantech/socair/internal/checks"
	"github.com/defilantech/socair/internal/checks/tensorref"
	"github.com/defilantech/socair/internal/tensors"
)

// tensorReference is the model the operator says this artifact should be, as
// a socair.tensors/v1 manifest (SOCAIR_TENSOR_REFERENCE), and the name the
// report gives it: file name and hash, never a host path.
type tensorReference struct {
	manifest *tensors.Manifest
	name     string
}

// loadTensorReference reads one manifest file. A reference that cannot be
// read stops the scan: the row must not quietly lose what it compares with.
func loadTensorReference(p string) (*tensorReference, error) {
	files, _, err := readLocal(p, "", tensors.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if len(files) != 1 {
		return nil, fmt.Errorf("want one manifest file, found %d", len(files))
	}
	m, err := tensors.Load(files[0].data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", files[0].name, err)
	}
	return &tensorReference{manifest: m, name: files[0].String()}, nil
}

// tensorRow compares the artifact's tensors with the reference, when one is
// configured. read fingerprints the scanned bytes and is called only then:
// it reads every tensor's data, which no other row does.
func (r *references) tensorRow(read func() (*tensors.Manifest, error)) (checks.Result, bool) {
	if r.tensorRef == nil {
		return checks.Result{}, false
	}
	m, err := read()
	return tensorref.Inspect(m, err, r.tensorRef.manifest, "tensor reference "+r.tensorRef.name), true
}
