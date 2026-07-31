package id

import (
	"strings"
	"testing"
)

// Identifier generation, which had no tests.
//
// Two things matter here and neither is visible from a round trip, because
// there is no decoder: that the alphabet is the one the design says it is, and
// that every bit of the random input reaches the output. A base32 encoder that
// silently drops the tail still produces plausible-looking IDs.

func TestAlphabetIsCrockford(t *testing.T) {
	// The exclusions are the whole point: I, L, O and U are left out so the
	// glyphs people confuse can be mapped back rather than guessed at, which is
	// what makes an ID readable aloud over a phone call.
	if len(alphabet) != 32 {
		t.Fatalf("alphabet is %d characters, want 32", len(alphabet))
	}
	seen := map[rune]bool{}
	for _, r := range alphabet {
		if seen[r] {
			t.Fatalf("alphabet repeats %q", r)
		}
		seen[r] = true
	}
	for _, r := range "ILOU" {
		if strings.ContainsRune(alphabet, r) {
			t.Fatalf("alphabet contains %q, which the design excludes", r)
		}
	}
	if alphabet[:10] != "0123456789" {
		t.Fatalf("digits should sort first, got %q", alphabet[:10])
	}
}

func TestEncodeKnownVectors(t *testing.T) {
	// Hand-computed rather than produced by the code under test. 128 bits is
	// 25 full groups of five with three left over, so the last character
	// carries three bits padded with two zeros.
	zero := encode(make([]byte, 16))
	if zero != strings.Repeat("0", 26) {
		t.Fatalf("all-zero: got %q", zero)
	}

	ones := make([]byte, 16)
	for i := range ones {
		ones[i] = 0xFF
	}
	// 25 groups of 11111 -> 'Z', then 111 shifted up to 11100 = 28 -> 'W'.
	if got, want := encode(ones), strings.Repeat("Z", 25)+"W"; got != want {
		t.Fatalf("all-ones: got %q want %q", got, want)
	}
}

func TestEveryInputBitReachesTheOutput(t *testing.T) {
	// Exhaustive over the 128 bit positions rather than a few samples. An
	// encoder that drops the tail, or masks the accumulator one bit too far,
	// loses entropy without changing the shape of what it returns — and every
	// ID it produced would still look exactly right.
	base := make([]byte, 16)
	baseline := encode(base)

	for bit := 0; bit < 128; bit++ {
		flipped := make([]byte, 16)
		copy(flipped, base)
		flipped[bit/8] ^= 1 << (bit % 8)

		if got := encode(flipped); got == baseline {
			t.Fatalf("flipping bit %d changed nothing: the encoder is dropping it", bit)
		}
	}
}

func TestNewLooksLikeAnAccountID(t *testing.T) {
	for i := 0; i < 64; i++ {
		got := New()
		if len(got) != 26 {
			t.Fatalf("%q is %d characters, want 26", got, len(got))
		}
		for _, r := range got {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("%q contains %q, which is not in the alphabet", got, r)
			}
		}
	}
}

func TestNewDoesNotRepeat(t *testing.T) {
	// A repeat would mean the CSPRNG is not being read, which is the failure
	// that would not announce itself.
	seen := map[string]bool{}
	for i := 0; i < 4096; i++ {
		v := New()
		if seen[v] {
			t.Fatalf("New repeated %q after %d draws", v, i)
		}
		seen[v] = true
	}
}

func TestEveryPositionVaries(t *testing.T) {
	// A constant character anywhere means that slice of the input never made
	// it through. The last position is excluded: it carries three bits padded
	// with two zeros, so it only ever takes eight of the thirty-two values —
	// that is the encoding, not a bug.
	const draws = 512
	values := make([]map[byte]bool, 26)
	for i := range values {
		values[i] = map[byte]bool{}
	}
	for i := 0; i < draws; i++ {
		v := New()
		for pos := 0; pos < 26; pos++ {
			values[pos][v[pos]] = true
		}
	}
	for pos := 0; pos < 26; pos++ {
		if len(values[pos]) < 2 {
			t.Fatalf("position %d was always %q over %d draws", pos, v0(values[pos]), draws)
		}
	}
	if len(values[25]) > 8 {
		t.Fatalf("the last character took %d values; it should carry three bits", len(values[25]))
	}
}

func v0(set map[byte]bool) string {
	for b := range set {
		return string(rune(b))
	}
	return ""
}

func TestNewTokenIs256BitsAndDoesNotRepeat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1024; i++ {
		tok := NewToken()
		if len(tok) != 32 {
			t.Fatalf("token is %d bytes, want 32", len(tok))
		}
		key := string(tok)
		if seen[key] {
			t.Fatalf("NewToken repeated after %d draws", i)
		}
		seen[key] = true
	}
}

func TestNewTokenReturnsAFreshSlice(t *testing.T) {
	// Sharing a backing array between two tokens would make one challenge
	// change under the other's feet.
	a := NewToken()
	b := NewToken()
	before := string(a)
	for i := range b {
		b[i] = 0
	}
	if string(a) != before {
		t.Fatal("writing to one token changed another")
	}
}
