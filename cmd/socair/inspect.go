package main

import (
	"encoding/json"
	"fmt"

	"github.com/defilantech/socair/internal/gguf"
)

// inspect reads one artifact and prints its manifest as JSON. Same engine the
// report renderer will consume.
func inspect(path string) error {
	m, err := gguf.ReadArtifact(path)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
