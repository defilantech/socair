// Package gguftest builds GGUF containers for tests.
//
// Fixtures are generated, not committed, so they cannot rot silently and a
// check is proven against a container whose bytes the test controls.
package gguftest

import (
	"bytes"
	"encoding/binary"
)

const (
	typeUint16 = 2
	typeUint32 = 4
	typeInt32  = 5
	typeString = 8
	typeArray  = 9
)

// KV is one metadata pair.
type KV struct {
	key   string
	vtype uint32
	str   string
	u16   uint16
	u32   uint32
	i32   int32
	strs  []string
	i32s  []int32
}

// Str builds a string metadata pair.
func Str(key, val string) KV { return KV{key: key, vtype: typeString, str: val} }

// U16 builds a uint16 metadata pair. Real GGUF files store split metadata this
// narrow, so tests must cover it.
func U16(key string, v uint16) KV { return KV{key: key, vtype: typeUint16, u16: v} }

// U32 builds a uint32 metadata pair.
func U32(key string, v uint32) KV { return KV{key: key, vtype: typeUint32, u32: v} }

// I32 builds an int32 metadata pair.
func I32(key string, v int32) KV { return KV{key: key, vtype: typeInt32, i32: v} }

// StrArray builds an array-of-strings metadata pair.
func StrArray(key string, vals ...string) KV { return KV{key: key, vtype: typeArray, strs: vals} }

// I32Array builds an array-of-int32 metadata pair.
func I32Array(key string, vals ...int32) KV { return KV{key: key, vtype: typeArray, i32s: vals} }

// Vocab is a small consistent tokenizer: four tokens with their types and
// BOS/EOS ids in range.
func Vocab() []KV {
	return []KV{
		StrArray("tokenizer.ggml.tokens", "<s>", "</s>", "hello", "<|im_start|>"),
		I32Array("tokenizer.ggml.token_type", 3, 3, 1, 3),
		U32("tokenizer.ggml.bos_token_id", 0),
		U32("tokenizer.ggml.eos_token_id", 1),
	}
}

// Clean is a standard, benign metadata set for a small GGUF.
func Clean() []KV {
	return []KV{
		Str("general.name", "Fixture Model"),
		Str("general.architecture", "llama"),
		Str("general.size_label", "1B"),
		U32("general.file_type", 17),
		U32("general.quantization_version", 2),
		Str("tokenizer.ggml.model", "llama"),
		Str("tokenizer.chat_template", "{{ bos_token }}\n{%- for m in messages -%}{{ m['role'] }}{%- endfor -%}"),
	}
}

// BuildGGUF assembles a GGUF v3 container with the given metadata and no
// tensors.
func BuildGGUF(kvs []KV) []byte {
	var b bytes.Buffer
	b.WriteString("GGUF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	_ = binary.Write(&b, binary.LittleEndian, uint64(0)) // tensor count
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(kvs)))
	for _, p := range kvs {
		writeStr(&b, p.key)
		_ = binary.Write(&b, binary.LittleEndian, p.vtype)
		switch p.vtype {
		case typeString:
			writeStr(&b, p.str)
		case typeUint16:
			_ = binary.Write(&b, binary.LittleEndian, p.u16)
		case typeUint32:
			_ = binary.Write(&b, binary.LittleEndian, p.u32)
		case typeInt32:
			_ = binary.Write(&b, binary.LittleEndian, p.i32)
		case typeArray:
			if p.i32s != nil {
				_ = binary.Write(&b, binary.LittleEndian, uint32(typeInt32))
				_ = binary.Write(&b, binary.LittleEndian, uint64(len(p.i32s)))
				for _, v := range p.i32s {
					_ = binary.Write(&b, binary.LittleEndian, v)
				}
				break
			}
			_ = binary.Write(&b, binary.LittleEndian, uint32(typeString))
			_ = binary.Write(&b, binary.LittleEndian, uint64(len(p.strs)))
			for _, s := range p.strs {
				writeStr(&b, s)
			}
		default:
			panic("gguftest: unsupported type")
		}
	}
	return b.Bytes()
}

// Key returns the pair's metadata key.
func (p KV) Key() string { return p.key }

// WithMeta returns Clean() with one metadata pair added or replaced.
func WithMeta(key string, kv KV) []KV {
	out := Clean()
	for i := range out {
		if out[i].key == key {
			out[i] = kv
			return out
		}
	}
	return append(out, kv)
}

func writeStr(b *bytes.Buffer, s string) {
	_ = binary.Write(b, binary.LittleEndian, uint64(len(s)))
	b.WriteString(s)
}

// Tensor is one tensor-table entry for BuildWithTensors.
type Tensor struct {
	Name   string
	Dims   []uint64
	Type   uint32
	Offset uint64
}

// BuildWithTensors assembles a GGUF v3 with metadata, a tensor table, padding
// to 32-byte alignment, and dataLen bytes of tensor data.
func BuildWithTensors(kvs []KV, tensors []Tensor, dataLen int) []byte {
	var b bytes.Buffer
	b.WriteString("GGUF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(tensors)))
	_ = binary.Write(&b, binary.LittleEndian, uint64(len(kvs)))
	body := BuildGGUF(kvs)[24:] // the key-value section
	b.Write(body)
	for _, t := range tensors {
		writeStr(&b, t.Name)
		_ = binary.Write(&b, binary.LittleEndian, uint32(len(t.Dims)))
		for _, d := range t.Dims {
			_ = binary.Write(&b, binary.LittleEndian, d)
		}
		_ = binary.Write(&b, binary.LittleEndian, t.Type)
		_ = binary.Write(&b, binary.LittleEndian, t.Offset)
	}
	for b.Len()%32 != 0 {
		b.WriteByte(0)
	}
	b.Write(make([]byte, dataLen))
	return b.Bytes()
}
