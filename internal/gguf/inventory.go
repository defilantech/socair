package gguf

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// MetadataInventory is every string-valued metadata pair in a GGUF, for the
// file inventory check. It is capped so a hostile file cannot drive an
// unbounded allocation.
type MetadataInventory struct {
	Keys         []string
	Strings      []string
	TotalStrings int
	Truncated    bool
}

const (
	maxInvEntries = 20000
	maxInvBytes   = 8 << 20
)

// Inventory walks the metadata section and returns its string values.
func Inventory(path string) (*MetadataInventory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return inventoryFrom(bufio.NewReaderSize(f, readBufSize))
}

// inventoryFrom walks the metadata section read from r.
func inventoryFrom(r io.Reader) (*MetadataInventory, error) {
	var magicBuf [4]byte
	if _, err := io.ReadFull(r, magicBuf[:]); err != nil {
		return nil, fmt.Errorf("gguf: reading magic: %w", err)
	}
	if string(magicBuf[:]) != magic {
		return nil, ErrNotGGUF
	}
	if _, err := readU32(r); err != nil { // version
		return nil, err
	}
	if _, err := readU64(r); err != nil { // tensor count
		return nil, err
	}
	kv, err := readU64(r)
	if err != nil {
		return nil, err
	}

	inv := &MetadataInventory{}
	for i := uint64(0); i < kv; i++ {
		key, err := readString(r)
		if err != nil {
			return nil, fmt.Errorf("gguf: reading key %d: %w", i, err)
		}
		vtype, err := readU32(r)
		if err != nil {
			return nil, fmt.Errorf("gguf: reading type for %q: %w", key, err)
		}
		val, err := scanValue(r, vtype, vtype == typeString)
		if err != nil {
			return nil, fmt.Errorf("gguf: reading value for %q: %w", key, err)
		}

		if len(inv.Keys) < maxInvEntries {
			inv.Keys = append(inv.Keys, key)
		} else {
			inv.Truncated = true
		}

		if s, ok := val.(string); ok {
			inv.TotalStrings += len(s)
			if len(inv.Strings) < maxInvEntries && inv.TotalStrings < maxInvBytes {
				inv.Strings = append(inv.Strings, s)
			} else {
				inv.Truncated = true
			}
		}
	}
	return inv, nil
}
