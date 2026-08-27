package transparency_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/algolindustries/tildra/server/internal/transparency"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = transparency.HashLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}
	return out
}

func TestEmptyTreeHasTheSpecifiedRoot(t *testing.T) {
	// A distinct value rather than zeros, so "empty log" and "uninitialised
	// memory" cannot be confused for each other.
	want := sha256.Sum256(nil)
	if !bytes.Equal(transparency.RootHash(nil), want[:]) {
		t.Error("empty tree root is not SHA-256 of the empty string")
	}
}

func TestLeafAndNodeHashingAreDomainSeparated(t *testing.T) {
	// Without the prefixes a leaf could be presented as an interior node and a
	// proof forged. This asserts the prefixes are actually applied.
	entry := []byte("x")
	plain := sha256.Sum256(entry)
	if bytes.Equal(transparency.HashLeaf(entry), plain[:]) {
		t.Error("leaf hash is a bare SHA-256; the 0x00 prefix is missing")
	}

	left, right := transparency.HashLeaf([]byte("l")), transparency.HashLeaf([]byte("r"))
	concat := sha256.Sum256(append(append([]byte(nil), left...), right...))
	if bytes.Equal(transparency.HashChildren(left, right), concat[:]) {
		t.Error("node hash is a bare SHA-256; the 0x01 prefix is missing")
	}
}

func TestRootIsStableAndSizeDependent(t *testing.T) {
	for n := 1; n <= 64; n++ {
		a := transparency.RootHash(leaves(n))
		b := transparency.RootHash(leaves(n))
		if !bytes.Equal(a, b) {
			t.Fatalf("root is not deterministic at size %d", n)
		}
		if n > 1 && bytes.Equal(a, transparency.RootHash(leaves(n-1))) {
			t.Fatalf("appending an entry did not change the root at size %d", n)
		}
	}
}

func TestInclusionProofsVerifyForEverySizeAndIndex(t *testing.T) {
	for size := 1; size <= 33; size++ {
		l := leaves(size)
		root := transparency.RootHash(l)
		for index := 0; index < size; index++ {
			path, err := transparency.InclusionProof(l, index)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if err := transparency.VerifyInclusion(l[index], index, size, path, root); err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
		}
	}
}

func TestInclusionProofRejectsTheWrongLeaf(t *testing.T) {
	l := leaves(9)
	root := transparency.RootHash(l)
	path, _ := transparency.InclusionProof(l, 3)

	// A different leaf at the same position is the substitution this whole
	// mechanism exists to catch.
	other := transparency.HashLeaf([]byte("a key the server swapped in"))
	if err := transparency.VerifyInclusion(other, 3, 9, path, root); err == nil {
		t.Fatal("a substituted leaf verified against the real root")
	}
}

func TestInclusionProofRejectsTampering(t *testing.T) {
	l := leaves(11)
	root := transparency.RootHash(l)
	path, _ := transparency.InclusionProof(l, 5)

	t.Run("altered sibling", func(t *testing.T) {
		tampered := make([][]byte, len(path))
		copy(tampered, path)
		tampered[0] = append([]byte(nil), path[0]...)
		tampered[0][0] ^= 0xff
		if err := transparency.VerifyInclusion(l[5], 5, 11, tampered, root); err == nil {
			t.Error("a tampered audit path verified")
		}
	})

	t.Run("wrong index", func(t *testing.T) {
		if err := transparency.VerifyInclusion(l[5], 6, 11, path, root); err == nil {
			t.Error("a proof verified at the wrong index")
		}
	})

	t.Run("truncated path", func(t *testing.T) {
		if err := transparency.VerifyInclusion(l[5], 5, 11, path[:len(path)-1], root); err == nil {
			t.Error("a truncated path verified")
		}
	})

	t.Run("extended path", func(t *testing.T) {
		extended := append(append([][]byte(nil), path...), make([]byte, transparency.HashSize))
		if err := transparency.VerifyInclusion(l[5], 5, 11, extended, root); err == nil {
			t.Error("an over-long path verified")
		}
	})

	t.Run("index out of range", func(t *testing.T) {
		if err := transparency.VerifyInclusion(l[5], 11, 11, path, root); err == nil {
			t.Error("an out-of-range index verified")
		}
	})
}

func TestConsistencyProofsVerifyForEveryPairOfSizes(t *testing.T) {
	const max = 24
	all := leaves(max)

	for first := 0; first <= max; first++ {
		for second := first; second <= max; second++ {
			path, err := transparency.ConsistencyProof(all, first, second)
			if err != nil {
				t.Fatalf("proof %d->%d: %v", first, second, err)
			}
			oldRoot := transparency.RootHash(all[:first])
			newRoot := transparency.RootHash(all[:second])

			if err := transparency.VerifyConsistency(first, second, path, oldRoot, newRoot); err != nil {
				t.Fatalf("verify %d->%d: %v", first, second, err)
			}
		}
	}
}

func TestConsistencyCatchesARewrittenLog(t *testing.T) {
	// The attack: a server that swapped somebody's key and then rebuilt the
	// log to hide it. The old root a client already saw can no longer be
	// reproduced, so the proof fails no matter what path is supplied.
	original := leaves(8)
	oldRoot := transparency.RootHash(original[:5])

	rewritten := leaves(8)
	rewritten[2] = transparency.HashLeaf([]byte("substituted key"))
	newRoot := transparency.RootHash(rewritten)

	path, err := transparency.ConsistencyProof(rewritten, 5, 8)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	if err := transparency.VerifyConsistency(5, 8, path, oldRoot, newRoot); err == nil {
		t.Fatal("a rewritten log passed the consistency check")
	}
}

func TestConsistencyCatchesATruncatedLog(t *testing.T) {
	// Dropping entries is a rewrite too: a client that saw size 6 must not
	// accept a later log claiming size 4.
	all := leaves(6)
	oldRoot := transparency.RootHash(all[:6])
	newRoot := transparency.RootHash(all[:4])

	if err := transparency.VerifyConsistency(6, 4, nil, oldRoot, newRoot); err == nil {
		t.Fatal("a shrinking log passed the consistency check")
	}
}

func TestConsistencyRejectsTampering(t *testing.T) {
	all := leaves(13)
	oldRoot := transparency.RootHash(all[:6])
	newRoot := transparency.RootHash(all[:13])
	path, _ := transparency.ConsistencyProof(all, 6, 13)

	t.Run("altered node", func(t *testing.T) {
		tampered := make([][]byte, len(path))
		copy(tampered, path)
		tampered[0] = append([]byte(nil), path[0]...)
		tampered[0][0] ^= 0xff
		if err := transparency.VerifyConsistency(6, 13, tampered, oldRoot, newRoot); err == nil {
			t.Error("a tampered consistency path verified")
		}
	})

	t.Run("missing path", func(t *testing.T) {
		if err := transparency.VerifyConsistency(6, 13, nil, oldRoot, newRoot); err == nil {
			t.Error("an absent path verified for a grown tree")
		}
	})

	t.Run("wrong old root", func(t *testing.T) {
		wrong := transparency.RootHash(all[:7])
		if err := transparency.VerifyConsistency(6, 13, path, wrong, newRoot); err == nil {
			t.Error("a mismatched old root verified")
		}
	})

	t.Run("unchanged size but different root", func(t *testing.T) {
		if err := transparency.VerifyConsistency(6, 6, nil, oldRoot, newRoot); err == nil {
			t.Error("a changed root at an unchanged size verified")
		}
	})
}

func TestConsistencyFromAnEmptyTreeIsFree(t *testing.T) {
	// A client's very first lookup has no prior tree head. Demanding a proof
	// there would make the mechanism impossible to bootstrap.
	all := leaves(5)
	if err := transparency.VerifyConsistency(0, 5, nil, nil, transparency.RootHash(all)); err != nil {
		t.Errorf("first lookup was rejected: %v", err)
	}
}
