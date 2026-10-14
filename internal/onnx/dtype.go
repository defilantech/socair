package onnx

// Field names a TensorProto data field.
type Field string

const (
	FieldRaw    Field = "raw_data"
	FieldFloat  Field = "float_data"
	FieldInt32  Field = "int32_data"
	FieldString Field = "string_data"
	FieldInt64  Field = "int64_data"
	FieldDouble Field = "double_data"
	FieldUint64 Field = "uint64_data"
)

// DType is one TensorProto.DataType: its size in raw_data and the typed
// field that holds it otherwise, as onnx.proto (v1.23.2) states them.
type DType struct {
	Name string
	// Bits is one element's width in raw_data: fixed-width, little-endian,
	// with sub-byte types packed (4-bit two to a byte, 2-bit four to a byte,
	// 6-bit four to three bytes). A tensor's raw_data is ceil(n*Bits/8)
	// bytes. 0 for STRING, which raw_data may not hold.
	Bits int64
	// Field is the typed field that holds it instead of raw_data, and
	// PerElement how many entries of that field one element takes (2 for
	// the complex types). PerElement 0 means onnx.proto and onnx's checker
	// disagree on the count (the 4-bit and 2-bit types in int32_data).
	Field      Field
	PerElement int64
}

// DTypes is onnx.proto v1.23.2's TensorProto.DataType, by value.
var DTypes = map[int32]DType{
	1:  {"FLOAT", 32, FieldFloat, 1},
	2:  {"UINT8", 8, FieldInt32, 1},
	3:  {"INT8", 8, FieldInt32, 1},
	4:  {"UINT16", 16, FieldInt32, 1},
	5:  {"INT16", 16, FieldInt32, 1},
	6:  {"INT32", 32, FieldInt32, 1},
	7:  {"INT64", 64, FieldInt64, 1},
	8:  {"STRING", 0, FieldString, 1},
	9:  {"BOOL", 8, FieldInt32, 1},
	10: {"FLOAT16", 16, FieldInt32, 1},
	11: {"DOUBLE", 64, FieldDouble, 1},
	12: {"UINT32", 32, FieldUint64, 1},
	13: {"UINT64", 64, FieldUint64, 1},
	14: {"COMPLEX64", 64, FieldFloat, 2},
	15: {"COMPLEX128", 128, FieldDouble, 2},
	16: {"BFLOAT16", 16, FieldInt32, 1},
	17: {"FLOAT8E4M3FN", 8, FieldInt32, 1},
	18: {"FLOAT8E4M3FNUZ", 8, FieldInt32, 1},
	19: {"FLOAT8E5M2", 8, FieldInt32, 1},
	20: {"FLOAT8E5M2FNUZ", 8, FieldInt32, 1},
	21: {"UINT4", 4, FieldInt32, 0},
	22: {"INT4", 4, FieldInt32, 0},
	23: {"FLOAT4E2M1", 4, FieldInt32, 0},
	24: {"FLOAT8E8M0", 8, FieldInt32, 1},
	25: {"UINT2", 2, FieldInt32, 0},
	26: {"INT2", 2, FieldInt32, 0},
	27: {"FLOAT6E2M3", 6, FieldInt32, 1},
	28: {"FLOAT6E3M2", 6, FieldInt32, 1},
}

// DataTypeString is STRING's value: its data is only in string_data.
const DataTypeString = 8

// Count returns how many entries a tensor holds in field f.
func (t *Tensor) Count(f Field) int64 {
	switch f {
	case FieldFloat:
		return t.Floats
	case FieldInt32:
		return t.Int32s
	case FieldString:
		return t.Strings
	case FieldInt64:
		return t.Int64s
	case FieldDouble:
		return t.Doubles
	case FieldUint64:
		return t.Uint64s
	}
	return 0
}

// TypedFields lists the typed data fields in onnx.proto's order.
var TypedFields = []Field{FieldFloat, FieldInt32, FieldString, FieldInt64, FieldDouble, FieldUint64}
