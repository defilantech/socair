package hdf5

import "math/bits"

// Checksum is the checksum HDF5 stores after a version 2 superblock, an
// OHDR or OCHK block, and other newer metadata: lookup3 of the bytes.
func Checksum(b []byte) uint32 { return lookup3(b) }

// lookup3 is Bob Jenkins' lookup3 hashlittle with an initial value of 0,
// which the HDF5 format uses for every metadata checksum (specification
// I.A; H5_checksum_lookup3 in src/H5checksum.c).
func lookup3(k []byte) uint32 {
	a := 0xdeadbeef + uint32(len(k))
	b, c := a, a
	for len(k) > 12 {
		a += uint32(k[0]) | uint32(k[1])<<8 | uint32(k[2])<<16 | uint32(k[3])<<24
		b += uint32(k[4]) | uint32(k[5])<<8 | uint32(k[6])<<16 | uint32(k[7])<<24
		c += uint32(k[8]) | uint32(k[9])<<8 | uint32(k[10])<<16 | uint32(k[11])<<24
		a, b, c = mix(a, b, c)
		k = k[12:]
	}
	if len(k) == 0 {
		return c
	}
	var tail [12]byte
	copy(tail[:], k)
	a += uint32(tail[0]) | uint32(tail[1])<<8 | uint32(tail[2])<<16 | uint32(tail[3])<<24
	b += uint32(tail[4]) | uint32(tail[5])<<8 | uint32(tail[6])<<16 | uint32(tail[7])<<24
	c += uint32(tail[8]) | uint32(tail[9])<<8 | uint32(tail[10])<<16 | uint32(tail[11])<<24
	return final(a, b, c)
}

func rot(x uint32, k int) uint32 { return bits.RotateLeft32(x, k) }

func mix(a, b, c uint32) (uint32, uint32, uint32) {
	a -= c
	a ^= rot(c, 4)
	c += b
	b -= a
	b ^= rot(a, 6)
	a += c
	c -= b
	c ^= rot(b, 8)
	b += a
	a -= c
	a ^= rot(c, 16)
	c += b
	b -= a
	b ^= rot(a, 19)
	a += c
	c -= b
	c ^= rot(b, 4)
	b += a
	return a, b, c
}

func final(a, b, c uint32) uint32 {
	c ^= b
	c -= rot(b, 14)
	a ^= c
	a -= rot(c, 11)
	b ^= a
	b -= rot(a, 25)
	c ^= b
	c -= rot(b, 16)
	a ^= c
	a -= rot(c, 4)
	b ^= a
	b -= rot(a, 14)
	c ^= b
	c -= rot(b, 24)
	return c
}
