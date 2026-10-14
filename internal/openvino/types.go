package openvino

import "math"

// Packing says how a Const's elements are laid out in the .bin.
type Packing int

const (
	// Bytes: Bits/8 bytes an element.
	Bytes Packing = iota
	// SubByte: 1-, 2-, and 4-bit types, 8/Bits elements to a byte
	// (element::is_bit_type, is_nibble_type).
	SubByte
	// Split: the 3- and 6-bit types, 24/Bits elements to each 3-byte group
	// (element::is_split_bit_type).
	Split
	// Strings: element::string, a packed string tensor whose size depends
	// on its strings, not its shape.
	Strings
	// Dynamic: no element type, so no defined data.
	Dynamic
)

// ElementType is one value a Const's element_type may take.
type ElementType struct {
	Bits    int64
	Packing Packing
}

// ElementTypes are the element_type values OpenVINO 2026.4.1 reads for a
// Const: the names of element::Type_t (EnumNames<element::Type_t> in
// src/core/src/type/element_type.cpp; Constant::visit_attributes reads the
// attribute through it, so the aliases element::Type accepts elsewhere, such
// as FP32, are refused), with their widths (types_info in the same file) and
// packings (src/core/dev_api/openvino/core/type/element_iterator.hpp).
var ElementTypes = map[string]ElementType{
	"dynamic": {0, Dynamic}, "undefined": {0, Dynamic},
	"boolean": {8, Bytes},
	"bf16":    {16, Bytes}, "f16": {16, Bytes}, "f32": {32, Bytes}, "f64": {64, Bytes},
	"i4": {4, SubByte}, "i8": {8, Bytes}, "i16": {16, Bytes}, "i32": {32, Bytes}, "i64": {64, Bytes},
	"u1": {1, SubByte}, "u2": {2, SubByte}, "u3": {3, Split}, "u4": {4, SubByte}, "u6": {6, Split},
	"u8": {8, Bytes}, "u16": {16, Bytes}, "u32": {32, Bytes}, "u64": {64, Bytes},
	"nf4":    {4, SubByte},
	"f8e4m3": {8, Bytes}, "f8e5m2": {8, Bytes}, "f8e8m0": {8, Bytes},
	"f4e2m1": {4, SubByte},
	"string": {0, Strings},
}

// MemorySize is the number of bytes n elements of et occupy, as OpenVINO
// allocates a Constant and as its IR writer writes one: ov::util::get_memory_size
// (src/core/src/memory_util.cpp). It is false for a string or dynamic type,
// whose size n does not fix, and when the size overflows.
func MemorySize(et ElementType, n int64) (int64, bool) {
	if n < 0 {
		return 0, false
	}
	if n == 0 {
		return 0, et.Packing != Strings && et.Packing != Dynamic
	}
	switch et.Packing {
	case Bytes:
		w := et.Bits / 8
		if n > math.MaxInt64/w {
			return 0, false
		}
		return n * w, true
	case SubByte:
		per := 8 / et.Bits
		return n/per + boolInt(n%per != 0), true
	case Split:
		per := 24 / et.Bits
		groups := n/per + boolInt(n%per != 0)
		if groups > math.MaxInt64/3 {
			return 0, false
		}
		return groups * 3, true
	}
	return 0, false
}

// MinSize is the smallest size OpenVINO's IR reader accepts for a Const of n
// elements of et: ceil(n*bits/8), the check XmlDeserializer::
// set_constant_num_buffer makes before it refuses one as "Attribute and shape
// size are inconsistent". It equals MemorySize except for the split types,
// which a writer pads to whole 3-byte groups.
func MinSize(et ElementType, n int64) (int64, bool) {
	if n < 0 || et.Packing == Strings || et.Packing == Dynamic {
		return 0, false
	}
	if et.Bits != 0 && n > (math.MaxInt64-7)/et.Bits {
		return 0, false
	}
	return (n*et.Bits + 7) / 8, true
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
