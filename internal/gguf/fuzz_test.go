package gguf

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/defilantech/socair/internal/gguf/gguftest"
)

// FuzzGGUFHeader feeds arbitrary bytes to the header and inventory readers.
// They read untrusted artifacts, so neither may panic, and a parse that
// succeeds must not report more metadata pairs than the header declared.
func FuzzGGUFHeader(f *testing.F) {
	f.Add(gguftest.BuildGGUF(gguftest.Clean()))
	f.Add(gguftest.BuildGGUF(append(gguftest.Clean(),
		gguftest.Str("tokenizer.chat_template.tool_use", "{{ x }}"),
		gguftest.StrArray("tokenizer.ggml.tokens", "a", "b"))))
	f.Add(bigArrayGGUF(32))
	f.Add([]byte("GGUF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m := &Manifest{}
		if err := readHeader(bufio.NewReader(bytes.NewReader(data)), m); err == nil {
			if uint64(len(m.ChatTemplates)) > m.KVCount {
				t.Fatalf("%d templates from %d declared pairs", len(m.ChatTemplates), m.KVCount)
			}
		}
		_, _ = inventoryFrom(bufio.NewReader(bytes.NewReader(data)))
	})
}
