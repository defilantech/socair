package gguf

import (
	"bufio"
	"bytes"
	"encoding/binary"
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
	// ArrayStrings are elements of string arrays long enough to carry a
	// payload (ArrayScanMin bytes or more). Short elements, such as the
	// vocabulary's tokens, cannot hold an executable or a long encoded blob,
	// so they are counted and not kept.
	ArrayStrings  []string
	ArrayElements int
	// Truncated reports that a cap was reached, so some values were not
	// collected and the inventory is incomplete.
	Truncated bool
}

const (
	maxInvEntries = 20000
	maxInvBytes   = 8 << 20
	// ArrayScanMin is the shortest string-array element the inventory keeps.
	ArrayScanMin = 64
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
		if vtype == typeArray {
			if err := inv.scanArray(r); err != nil {
				return nil, fmt.Errorf("gguf: reading value for %q: %w", key, err)
			}
			if len(inv.Keys) < maxInvEntries {
				inv.Keys = append(inv.Keys, key)
			} else {
				inv.Truncated = true
			}
			continue
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

// scanArray reads one array value. String elements long enough to carry a
// payload are kept, under the same caps as scalar strings; other elements are
// skipped exactly as the header reader skips them.
func (inv *MetadataInventory) scanArray(r io.Reader) error {
	elemType, err := readU32(r)
	if err != nil {
		return err
	}
	if elemType != typeString {
		// Put the element type back in front of the stream for skipArray.
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], elemType)
		return skipArray(io.MultiReader(bytes.NewReader(b[:]), r))
	}
	count, err := readU64(r)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		s, err := readString(r)
		if err != nil {
			return err
		}
		inv.ArrayElements++
		if len(s) < ArrayScanMin {
			continue
		}
		inv.TotalStrings += len(s)
		if len(inv.ArrayStrings) < maxInvEntries && inv.TotalStrings < maxInvBytes {
			inv.ArrayStrings = append(inv.ArrayStrings, s)
		} else {
			inv.Truncated = true
		}
	}
	return nil
}
