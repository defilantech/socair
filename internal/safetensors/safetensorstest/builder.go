// Package safetensorstest builds safetensors containers for tests.
//
// Fixtures are generated, not committed, so they cannot rot silently.
package safetensorstest

import (
	"encoding/binary"
	"encoding/json"
)

// TensorSpec is one tensor header entry for a generated fixture.
type TensorSpec struct {
	Name  string
	Start int64
	End   int64
	Dtype string
	Shape []int64
}

type jsonTensor struct {
	Dtype       string  `json:"dtype"`
	Shape       []int64 `json:"shape"`
	DataOffsets []int64 `json:"data_offsets"`
}

// Build assembles a safetensors container from tensor specs and metadata. The
// data section is zero-filled and sized to the largest offset.
func Build(meta map[string]string, tensors []TensorSpec) []byte {
	var dataLen int64
	for _, t := range tensors {
		if t.End > dataLen {
			dataLen = t.End
		}
	}
	return BuildWithDataLen(meta, tensors, dataLen)
}

// BuildWithDataLen assembles a container with an explicit data section length,
// so a fixture can declare tensor offsets that exceed the data it actually
// carries.
func BuildWithDataLen(meta map[string]string, tensors []TensorSpec, dataLen int64) []byte {
	header := map[string]any{}
	for _, t := range tensors {
		dtype := t.Dtype
		if dtype == "" {
			dtype = "F32"
		}
		shape := t.Shape
		if shape == nil {
			shape = []int64{1}
		}
		header[t.Name] = jsonTensor{
			Dtype:       dtype,
			Shape:       shape,
			DataOffsets: []int64{t.Start, t.End},
		}
	}
	if len(meta) > 0 {
		header["__metadata__"] = meta
	}

	raw, err := json.Marshal(header)
	if err != nil {
		panic("safetensorstest: marshal header: " + err.Error())
	}

	out := make([]byte, 8+len(raw)+int(dataLen))
	binary.LittleEndian.PutUint64(out[:8], uint64(len(raw)))
	copy(out[8:], raw)
	return out
}

// Clean is a small valid artifact.
func Clean() []byte {
	return Build(
		map[string]string{"format": "pt", "author": "fixture"},
		[]TensorSpec{
			{Name: "model.embed_tokens.weight", Start: 0, End: 64, Dtype: "F16", Shape: []int64{8, 8}},
			{Name: "model.norm.weight", Start: 64, End: 128, Dtype: "F32", Shape: []int64{16}},
		},
	)
}

// OutOfRangeOffsets produces a container whose tensor offsets exceed the data
// section it carries.
func OutOfRangeOffsets() []byte {
	return BuildWithDataLen(nil, []TensorSpec{{Name: "bad", Start: 0, End: 1_000_000}}, 16)
}
