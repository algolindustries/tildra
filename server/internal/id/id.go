// Package id generates the identifiers used across Tildra.
//
// Account IDs are 128 bits of CSPRNG output rendered in Crockford base32:
// 26 characters, no padding, no ambiguous glyphs (I/L/O/U are excluded), and
// case-insensitive on input. They are meant to be readable aloud over a phone
// call without a spelling alphabet.
package id

import (
	"crypto/rand"
	"strings"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a fresh 128-bit identifier.
func New() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the process has no entropy source. There
		// is no safe way to continue serving crypto traffic.
		panic("tildra: crypto/rand unavailable: " + err.Error())
	}
	return encode(b[:])
}

// NewToken returns 256 bits of randomness, for bearer tokens and challenges.
func NewToken() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("tildra: crypto/rand unavailable: " + err.Error())
	}
	return b
}

func encode(src []byte) string {
	var sb strings.Builder
	sb.Grow((len(src)*8 + 4) / 5)
	var acc, bits uint32
	for _, c := range src {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alphabet[(acc>>bits)&0x1f])
		}
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(acc<<(5-bits))&0x1f])
	}
	return sb.String()
}
