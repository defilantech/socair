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
	typeString = 8
	typeUint32 = 4
)

// KV is one metadata pair.
type KV struct {
	key   string
	vtype uint32
	str   string
	u32   uint32
}

// Str builds a string metadata pair.
func Str(key, val string) KV { return KV{key: key, vtype: typeString, str: val} }

// U32 builds a uint32 metadata pair.
func U32(key string, v uint32) KV { return KV{key: key, vtype: typeUint32, u32: v} }

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
		case typeUint32:
			_ = binary.Write(&b, binary.LittleEndian, p.u32)
		default:
			panic("gguftest: unsupported type")
		}
	}
	return b.Bytes()
}

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
