package transparency

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Entry is one binding recorded in the log.
//
// It records what a client would otherwise have to take on trust: that this
// handle mapped to this account, holding this identity key, at this time. A
// server that later serves a different key for the same handle has to append
// a visible entry saying so.
type Entry struct {
	Index       int64     `json:"index"`
	Handle      string    `json:"handle"`
	AccountID   string    `json:"accountId"`
	IdentityKey []byte    `json:"identityKey"`
	RecordedAt  time.Time `json:"recordedAt"`
}

// Encode produces the canonical bytes that are hashed into the tree.
//
// Length-prefixed rather than delimited: without it, a handle containing the
// delimiter could be chosen so that two different entries encode identically,
// and the log would attest to something other than what it recorded.
func (e Entry) Encode() []byte {
	out := make([]byte, 0, 64+len(e.Handle)+len(e.AccountID)+len(e.IdentityKey))
	out = appendField(out, []byte(e.Handle))
	out = appendField(out, []byte(e.AccountID))
	out = appendField(out, e.IdentityKey)
	out = binary.BigEndian.AppendUint64(out, uint64(e.RecordedAt.UTC().Unix()))
	return out
}

func appendField(dst, field []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(field)))
	return append(dst, field...)
}

// SignedTreeHead is the log's public commitment to its current contents.
type SignedTreeHead struct {
	Size      int64     `json:"size"`
	RootHash  []byte    `json:"rootHash"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
	LogKey    []byte    `json:"logKey"`
}

const sthContext = "tildra-sth-v1:"

// sthBytes is what the log key signs. The context prefix keeps a tree head
// from being replayed as any other signature this project makes.
func sthBytes(size int64, root []byte, at time.Time) []byte {
	out := append([]byte(nil), sthContext...)
	out = binary.BigEndian.AppendUint64(out, uint64(size))
	out = append(out, root...)
	return binary.BigEndian.AppendUint64(out, uint64(at.UTC().Unix()))
}

// Verify checks a tree head's signature against the log's public key.
func (s SignedTreeHead) Verify(logKey ed25519.PublicKey) error {
	if len(logKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: malformed log key", ErrProofFailed)
	}
	if !ed25519.Verify(logKey, sthBytes(s.Size, s.RootHash, s.Timestamp), s.Signature) {
		return fmt.Errorf("%w: tree head signature", ErrProofFailed)
	}
	return nil
}

// Storage is the persistence the log needs. Kept narrow so the log's logic can
// be tested without a database.
type Storage interface {
	AppendEntry(ctx context.Context, e *Entry) error
	Entries(ctx context.Context, from, to int64) ([]*Entry, error)
	Size(ctx context.Context) (int64, error)
	LatestForHandle(ctx context.Context, handle string) (*Entry, error)
}

// Log appends bindings and answers proofs about them.
//
// Leaf hashes are cached in memory: proofs need the whole tree, and rebuilding
// it from storage on every lookup would make the mechanism too slow to leave
// switched on — which in practice means it would be switched off.
type Log struct {
	storage Storage
	signKey ed25519.PrivateKey

	mu     sync.RWMutex
	hashes [][]byte
}

func NewLog(storage Storage, signKey ed25519.PrivateKey) *Log {
	return &Log{storage: storage, signKey: signKey}
}

// PublicKey is the key clients verify tree heads against.
func (l *Log) PublicKey() ed25519.PublicKey {
	return l.signKey.Public().(ed25519.PublicKey)
}

// Load reads every entry into the in-memory hash list. Called at startup.
func (l *Log) Load(ctx context.Context) error {
	size, err := l.storage.Size(ctx)
	if err != nil {
		return err
	}
	entries, err := l.storage.Entries(ctx, 0, size)
	if err != nil {
		return err
	}

	hashes := make([][]byte, 0, len(entries))
	for _, e := range entries {
		hashes = append(hashes, HashLeaf(e.Encode()))
	}

	l.mu.Lock()
	l.hashes = hashes
	l.mu.Unlock()
	return nil
}

// Append records a binding and returns the entry as stored.
//
// Appending the same handle and key twice is a no-op: a re-registration that
// changes nothing should not grow the log, and a log that grows on every
// lookup is one nobody can audit.
func (l *Log) Append(ctx context.Context, handle, accountID string, identityKey []byte) (*Entry, error) {
	existing, err := l.storage.LatestForHandle(ctx, handle)
	if err == nil && existing != nil &&
		existing.AccountID == accountID &&
		string(existing.IdentityKey) == string(identityKey) {
		return existing, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := &Entry{
		Index:       int64(len(l.hashes)),
		Handle:      handle,
		AccountID:   accountID,
		IdentityKey: append([]byte(nil), identityKey...),
		RecordedAt:  time.Now().UTC().Truncate(time.Second),
	}
	if err := l.storage.AppendEntry(ctx, entry); err != nil {
		return nil, err
	}
	l.hashes = append(l.hashes, HashLeaf(entry.Encode()))
	return entry, nil
}

// Head returns the current signed tree head.
func (l *Log) Head() SignedTreeHead {
	l.mu.RLock()
	root := RootHash(l.hashes)
	size := int64(len(l.hashes))
	l.mu.RUnlock()

	at := time.Now().UTC().Truncate(time.Second)
	return SignedTreeHead{
		Size:      size,
		RootHash:  root,
		Timestamp: at,
		Signature: ed25519.Sign(l.signKey, sthBytes(size, root, at)),
		LogKey:    l.PublicKey(),
	}
}

// Lookup returns the current binding for a handle together with the proof that
// it is in the log.
func (l *Log) Lookup(ctx context.Context, handle string, since int64) (*Entry, [][]byte, [][]byte, SignedTreeHead, error) {
	entry, err := l.storage.LatestForHandle(ctx, handle)
	if err != nil {
		return nil, nil, nil, SignedTreeHead{}, err
	}

	head := l.Head()

	l.mu.RLock()
	defer l.mu.RUnlock()

	inclusion, err := InclusionProof(l.hashes, int(entry.Index))
	if err != nil {
		return nil, nil, nil, SignedTreeHead{}, err
	}

	// `since` is the size the client last saw. Proving the log grew from there
	// rather than being rebuilt is what makes a silent key swap impossible.
	consistency, err := ConsistencyProof(l.hashes, int(since), int(head.Size))
	if err != nil {
		return nil, nil, nil, SignedTreeHead{}, err
	}

	return entry, inclusion, consistency, head, nil
}

// Size reports the number of entries currently in the tree.
func (l *Log) Size() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return int64(len(l.hashes))
}
