// Package pyjson decodes the JSON a Python loader reads as Python's json
// module reads it. Hugging Face configs (config.json, tokenizer_config.json,
// adapter_config.json, a safetensors index) are written and read by Python,
// which writes NaN, Infinity, and -Infinity for those floats and reads them
// back; encoding/json refuses them, so a config a loader reads would be
// unreadable to the scan (#256). A file another loader reads keeps that
// loader's rules: tokenizer.json is read by the Rust tokenizers library,
// which refuses the constants, so it is decoded strictly.
package pyjson

import (
	"bytes"
	"encoding/json"
)

// Unmarshal decodes raw into v as Python's json.loads would: the constants
// NaN, Infinity, and -Infinity outside strings decode as null (a float field
// keeps its zero), and anything else that is not JSON fails as it does for
// encoding/json.
func Unmarshal(raw []byte, v any) error {
	return json.Unmarshal(pythonConstants(raw), v)
}

// pythonConstants replaces NaN, Infinity, and -Infinity outside strings with
// null, so encoding/json reads what Python's json.loads reads. Anything else
// that is not JSON stays as it is and fails to decode.
func pythonConstants(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("NaN")) && !bytes.Contains(raw, []byte("Infinity")) {
		return raw
	}
	out := make([]byte, 0, len(raw))
	inString, escaped := false, false
next:
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			out = append(out, c)
			continue
		}
		if c == '"' {
			inString = true
		}
		for _, k := range [][]byte{[]byte("-Infinity"), []byte("Infinity"), []byte("NaN")} {
			if bytes.HasPrefix(raw[i:], k) {
				out = append(out, "null"...)
				i += len(k) - 1
				continue next
			}
		}
		out = append(out, c)
	}
	return out
}
