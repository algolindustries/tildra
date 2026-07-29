// Package transparency implements the append-only log that makes key
// substitution detectable.
//
// docs/THREAT_MODEL.md calls undetectable MITM the most serious possible
// failure: a hostile server can hand Alice a key bundle it controls instead of
// Bob's, and safety numbers only catch it if two humans compare digits. This
// package is the structural half of the fix.
//
// Every binding of a handle to an identity key is appended to a Merkle log.
// The server publishes a signed tree head, and answers lookups with an
// inclusion proof. A client that has seen an earlier tree head also demands a
// consistency proof, which shows the new log is an extension of the old one
// rather than a rewrite. So a server that swaps a key must either publish that
// swap — where anyone can see it — or fork the log, which breaks consistency
// the moment its two views are compared.
//
// The hashing follows RFC 6962 (Certificate Transparency), including its
// domain separation between leaves and interior nodes. That prefix is not
// decoration: without it a leaf could be presented as an interior node and a
// proof forged.
package transparency

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrOutOfRange     = errors.New("index out of range for tree size")
	ErrProofFailed    = errors.New("proof does not verify")
	ErrInvalidSizes   = errors.New("invalid tree sizes for a consistency proof")
	ErrEmptyProofPath = errors.New("proof path is empty where one was required")
)

// HashSize is the width of every hash in the log.
const HashSize = sha256.Size

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// HashLeaf hashes one log entry.
func HashLeaf(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	return h.Sum(nil)
}

// HashChildren hashes an interior node.
func HashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// RootHash computes the Merkle root over a list of already-hashed leaves.
//
// The empty tree hashes to SHA-256 of the empty string, per RFC 6962 — a
// distinct value rather than zeros, so "empty log" and "uninitialised" cannot
// be confused.
func RootHash(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		empty := sha256.Sum256(nil)
		return empty[:]
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return HashChildren(RootHash(leaves[:k]), RootHash(leaves[k:]))
}

// splitPoint is the largest power of two strictly less than n.
//
// RFC 6962 splits there rather than in the middle, which is what makes the
// tree's shape depend only on its size — so two parties who agree on the size
// agree on the shape, and proofs are comparable.
func splitPoint(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// InclusionProof returns the audit path proving that the leaf at index is in a
// tree of the given leaves.
func InclusionProof(leaves [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("%w: index %d, size %d", ErrOutOfRange, index, len(leaves))
	}
	return inclusionPath(leaves, index), nil
}

func inclusionPath(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := splitPoint(len(leaves))
	if index < k {
		return append(inclusionPath(leaves[:k], index), RootHash(leaves[k:]))
	}
	return append(inclusionPath(leaves[k:], index-k), RootHash(leaves[:k]))
}

// VerifyInclusion checks an audit path against a root hash — RFC 6962 §2.1.1.
//
// The path is ordered bottom-up, closest sibling first, and is consumed in
// that order. A verifier that walks the tree top-down instead looks plausible
// and is wrong for any index that is a right child below the root; the
// exhaustive test over every size and index is what surfaced that.
func VerifyInclusion(leafHash []byte, index, size int, path [][]byte, root []byte) error {
	if index < 0 || size <= 0 || index >= size {
		return fmt.Errorf("%w: index %d, size %d", ErrOutOfRange, index, size)
	}

	computed := append([]byte(nil), leafHash...)
	fn, sn := index, size-1

	for _, sibling := range path {
		if len(sibling) != HashSize {
			return fmt.Errorf("%w: malformed sibling hash", ErrProofFailed)
		}
		if sn == 0 {
			return fmt.Errorf("%w: proof is longer than the tree is deep", ErrProofFailed)
		}
		if fn&1 == 1 || fn == sn {
			computed = HashChildren(sibling, computed)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			computed = HashChildren(computed, sibling)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return fmt.Errorf("%w: proof is shorter than the tree is deep", ErrProofFailed)
	}
	if !bytes.Equal(computed, root) {
		return fmt.Errorf("%w: computed root does not match", ErrProofFailed)
	}
	return nil
}

// ConsistencyProof shows that a tree of size `first` is a prefix of a tree of
// size `second` — that the log was appended to, not rewritten.
func ConsistencyProof(leaves [][]byte, first, second int) ([][]byte, error) {
	if first < 0 || second < first || second > len(leaves) {
		return nil, fmt.Errorf("%w: %d then %d, have %d", ErrInvalidSizes, first, second, len(leaves))
	}
	if first == 0 || first == second {
		// Nothing to prove: an empty prior tree is a prefix of anything, and a
		// tree is trivially a prefix of itself.
		return nil, nil
	}
	return consistencyPath(leaves[:second], first, true), nil
}

func consistencyPath(leaves [][]byte, first int, isCompleteSubtree bool) [][]byte {
	if first == len(leaves) {
		if isCompleteSubtree {
			// The old tree is exactly this subtree; the verifier already has
			// its root and does not need it repeated.
			return nil
		}
		return [][]byte{RootHash(leaves)}
	}

	k := splitPoint(len(leaves))
	if first <= k {
		return append(consistencyPath(leaves[:k], first, isCompleteSubtree), RootHash(leaves[k:]))
	}
	return append(consistencyPath(leaves[k:], first-k, false), RootHash(leaves[:k]))
}

// VerifyConsistency checks that oldRoot is the root of the first `first`
// entries of the tree whose root is newRoot — RFC 6962 §2.1.2.
func VerifyConsistency(first, second int, path [][]byte, oldRoot, newRoot []byte) error {
	switch {
	case first < 0 || second < first:
		return fmt.Errorf("%w: %d then %d", ErrInvalidSizes, first, second)
	case first == 0:
		// An empty tree is a prefix of every tree. Demanding a proof here
		// would make a client's very first lookup impossible.
		return nil
	case first == second:
		if len(path) != 0 {
			return fmt.Errorf("%w: unexpected path for an unchanged tree", ErrProofFailed)
		}
		if !bytes.Equal(oldRoot, newRoot) {
			return fmt.Errorf("%w: tree size unchanged but root differs", ErrProofFailed)
		}
		return nil
	case len(path) == 0:
		return ErrEmptyProofPath
	}

	// Shift both indices right until the old tree's last leaf sits on a left
	// edge; at that point the old tree aligns with a complete subtree.
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	// When fn reaches zero the old tree *is* a complete subtree, so its root is
	// not repeated in the path and the verifier supplies it. Otherwise the
	// path's first node is the seed.
	var seed []byte
	start := 0
	if fn == 0 {
		seed = oldRoot
	} else {
		seed = path[0]
		start = 1
	}

	fr := append([]byte(nil), seed...)
	sr := append([]byte(nil), seed...)

	for _, node := range path[start:] {
		if len(node) != HashSize {
			return fmt.Errorf("%w: malformed node hash", ErrProofFailed)
		}
		if sn == 0 {
			return fmt.Errorf("%w: path is longer than the tree is deep", ErrProofFailed)
		}
		if fn&1 == 1 || fn == sn {
			fr = HashChildren(node, fr)
			sr = HashChildren(node, sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = HashChildren(sr, node)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return fmt.Errorf("%w: path is shorter than the tree is deep", ErrProofFailed)
	}
	if !bytes.Equal(fr, oldRoot) {
		// This is the failure that matters: the server produced a log in which
		// the entries a client already saw are not the entries it now claims.
		return fmt.Errorf("%w: the old root was not reproduced; the log was rewritten", ErrProofFailed)
	}
	if !bytes.Equal(sr, newRoot) {
		return fmt.Errorf("%w: the new root was not reproduced", ErrProofFailed)
	}
	return nil
}
