package transparency_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/store"
	"github.com/tildra/tildra/server/internal/store/memory"
	"github.com/tildra/tildra/server/internal/transparency"
)

// logStorage adapts the production Store to the log's narrow storage
// interface, exactly as cmd/tildrad does. Using the real store rather than a
// double means the ordering the log depends on — an entry is visible to
// LatestForHandle only once AppendEntry has returned — is the ordering it has
// in production.
type logStorage struct{ st store.Store }

func (l *logStorage) AppendEntry(ctx context.Context, e *transparency.Entry) error {
	m := &model.LogEntry{
		Handle: e.Handle, AccountID: e.AccountID,
		IdentityKey: e.IdentityKey, RecordedAt: e.RecordedAt,
	}
	if err := l.st.AppendLogEntry(ctx, m); err != nil {
		return err
	}
	e.Index = m.Index
	return nil
}

func (l *logStorage) Entries(ctx context.Context, from, to int64) ([]*transparency.Entry, error) {
	rows, err := l.st.LogEntries(ctx, from, to)
	if err != nil {
		return nil, err
	}
	out := make([]*transparency.Entry, 0, len(rows))
	for _, r := range rows {
		out = append(out, &transparency.Entry{
			Index: r.Index, Handle: r.Handle, AccountID: r.AccountID,
			IdentityKey: r.IdentityKey, RecordedAt: r.RecordedAt,
		})
	}
	return out, nil
}

func (l *logStorage) Size(ctx context.Context) (int64, error) { return l.st.LogSize(ctx) }

func (l *logStorage) LatestForHandle(ctx context.Context, handle string) (*transparency.Entry, error) {
	r, err := l.st.LatestLogEntryForHandle(ctx, handle)
	if err != nil {
		return nil, err
	}
	return &transparency.Entry{
		Index: r.Index, Handle: r.Handle, AccountID: r.AccountID,
		IdentityKey: r.IdentityKey, RecordedAt: r.RecordedAt,
	}, nil
}

func newLog(t *testing.T) (*transparency.Log, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("log key: %v", err)
	}
	return transparency.NewLog(&logStorage{memory.New()}, priv), pub
}

func identityKey(n byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = n
	}
	return k
}

// TestLookupProofsVerifyAgainstTheHeadTheyCameWith is the invariant
// docs/PROTOCOL.md §7.1 states: a lookup returns "an inclusion proof against
// the current head". Both proofs and the head have to describe one tree.
//
// Registrations and lookups are ordinary concurrent HTTP requests
// (api.go registerHandle appends, resolveHandle looks up), so a lookup racing
// an append is the normal case on a live server, not an exotic one. If the
// head is snapshotted separately from the proofs, the client sees a proof that
// does not reproduce the signed root — which is the same signal it is supposed
// to read as an attack.
func TestLookupProofsVerifyAgainstTheHeadTheyCameWith(t *testing.T) {
	ctx := context.Background()
	log, _ := newLog(t)

	if _, err := log.Append(ctx, "alice", "acct-alice", identityKey(1)); err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	// A size and root the client has already verified, so the consistency half
	// of the answer is exercised too.
	seen := log.Head()

	const appends = 400
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < appends; i++ {
			if _, err := log.Append(ctx, fmt.Sprintf("filler-%d", i), "acct-filler", identityKey(byte(i))); err != nil {
				return
			}
		}
	}()

	var inclusionFailures, consistencyFailures, lookups int
	for {
		select {
		case <-done:
			wg.Wait()
			if lookups == 0 {
				t.Fatal("no lookups ran")
			}
			if inclusionFailures > 0 || consistencyFailures > 0 {
				t.Errorf("of %d lookups, %d returned an inclusion proof and %d a consistency proof that "+
					"does not verify against the head returned with it", lookups, inclusionFailures, consistencyFailures)
			}
			return
		default:
		}

		entry, inclusion, consistency, head, err := log.Lookup(ctx, "alice", seen.Size)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		lookups++

		if err := transparency.VerifyInclusion(
			transparency.HashLeaf(entry.Encode()),
			int(entry.Index), int(head.Size), inclusion, head.RootHash,
		); err != nil {
			inclusionFailures++
		}
		if err := transparency.VerifyConsistency(
			int(seen.Size), int(head.Size), consistency, seen.RootHash, head.RootHash,
		); err != nil {
			consistencyFailures++
		}
	}
}

// TestEntryEncodingIsTheDocumentedLayout pins the leaf encoding. The Go log
// produces these bytes and the TypeScript client re-derives them to check a
// proof; a change on either side that is not a change on both silently breaks
// every inclusion proof, and the failure looks like an attack.
func TestEntryEncodingIsTheDocumentedLayout(t *testing.T) {
	entry := transparency.Entry{
		Index:       7,
		Handle:      "alice",
		AccountID:   "TILDRA-ACCOUNT",
		IdentityKey: identityKey(0xAB),
		RecordedAt:  time.Unix(1_700_000_000, 0).UTC(),
	}

	var want []byte
	field := func(b []byte) {
		want = binary.BigEndian.AppendUint32(want, uint32(len(b)))
		want = append(want, b...)
	}
	field([]byte("alice"))
	field([]byte("TILDRA-ACCOUNT"))
	field(identityKey(0xAB))
	want = binary.BigEndian.AppendUint64(want, 1_700_000_000)

	if got := entry.Encode(); string(got) != string(want) {
		t.Errorf("entry encoding is not handle ‖ accountId ‖ identityKey ‖ u64(seconds), each length-prefixed\ngot  %x\nwant %x", got, want)
	}

	// The index is deliberately absent: it is the leaf's position in the tree,
	// which the proof already establishes. Encoding it would mean an entry
	// could not be re-derived from what a lookup returns.
	shifted := entry
	shifted.Index = 99
	if string(shifted.Encode()) != string(entry.Encode()) {
		t.Error("the index changed the encoded leaf")
	}

	// A recorded vector, so a refactor that keeps the shape but changes a
	// prefix width or the byte order still fails here.
	const wantLeaf = "8053a9a8bc33feb3440bc03d9ca7d1806a352891faaf949c12f868a3a585a6fe"
	if got := hex.EncodeToString(transparency.HashLeaf(entry.Encode())); got != wantLeaf {
		t.Errorf("leaf hash of the recorded entry = %s, want %s", got, wantLeaf)
	}
}

// TestEntryEncodingIsUnambiguous is why the fields are length-prefixed rather
// than delimited: two different bindings must never hash to the same leaf.
func TestEntryEncodingIsUnambiguous(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	a := transparency.Entry{Handle: "ab", AccountID: "c", IdentityKey: identityKey(1), RecordedAt: at}
	b := transparency.Entry{Handle: "a", AccountID: "bc", IdentityKey: identityKey(1), RecordedAt: at}
	if string(a.Encode()) == string(b.Encode()) {
		t.Error("two different bindings encode identically; the fields are not framed")
	}
}

// TestSignedTreeHeadCoversTheDocumentedBytes checks the STH construction in
// docs/PROTOCOL.md §7.1 field by field, by verifying the signature against
// bytes assembled here rather than by the log's own code.
func TestSignedTreeHeadCoversTheDocumentedBytes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	root := identityKey(0x5A)
	at := time.Unix(1_700_000_123, 456_000_000).UTC()
	head := transparency.SignTreeHead(priv, 42, root, at)

	want := []byte("tildra-sth-v1:")
	want = binary.BigEndian.AppendUint64(want, 42)
	want = append(want, root...)
	want = binary.BigEndian.AppendUint64(want, 1_700_000_123)

	if !ed25519.Verify(pub, want, head.Signature) {
		t.Error("the signature does not cover \"tildra-sth-v1:\" ‖ u64(size) ‖ root ‖ u64(seconds)")
	}
	if !head.Timestamp.Equal(time.Unix(1_700_000_123, 0).UTC()) {
		t.Errorf("timestamp = %v, want it truncated to the second it signs", head.Timestamp)
	}
	if err := head.Verify(pub); err != nil {
		t.Errorf("the log's own verifier rejects the head it just signed: %v", err)
	}
}

// TestTreeHeadSignatureIsBoundToItsFields — a head whose size, root or
// timestamp is edited in transit must stop verifying, or the signature is
// decoration.
func TestTreeHeadSignatureIsBoundToItsFields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	head := transparency.SignTreeHead(priv, 9, identityKey(3), time.Unix(1_700_000_000, 0))

	for _, tc := range []struct {
		name string
		edit func(h *transparency.SignedTreeHead)
	}{
		{"size", func(h *transparency.SignedTreeHead) { h.Size = 10 }},
		{"root", func(h *transparency.SignedTreeHead) { h.RootHash = identityKey(4) }},
		{"timestamp", func(h *transparency.SignedTreeHead) { h.Timestamp = h.Timestamp.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edited := head
			tc.edit(&edited)
			if err := edited.Verify(pub); err == nil {
				t.Errorf("a head with an edited %s still verifies", tc.name)
			}
		})
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := head.Verify(other); err == nil {
		t.Error("a head verifies under a key that did not sign it")
	}
}

// TestAppendIsIdempotentForAnUnchangedBinding — a log that grows every time
// someone re-registers the same key is a log nobody can audit.
func TestAppendIsIdempotentForAnUnchangedBinding(t *testing.T) {
	ctx := context.Background()
	log, _ := newLog(t)

	first, err := log.Append(ctx, "alice", "acct-alice", identityKey(1))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	again, err := log.Append(ctx, "alice", "acct-alice", identityKey(1))
	if err != nil {
		t.Fatalf("append again: %v", err)
	}
	if log.Size() != 1 {
		t.Errorf("re-registering an unchanged binding grew the log to %d", log.Size())
	}
	if again.Index != first.Index {
		t.Errorf("index %d != %d for the same binding", again.Index, first.Index)
	}

	// A changed key is the event the whole log exists to make visible.
	rebound, err := log.Append(ctx, "alice", "acct-alice", identityKey(2))
	if err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if log.Size() != 2 || rebound.Index != 1 {
		t.Errorf("a key change did not append: size %d, index %d", log.Size(), rebound.Index)
	}
}

// TestLoadRebuildsTheSameTree — the hashes are cached in memory and rebuilt at
// startup from storage. A restart that produces a different root would break
// every stored checkpoint on every device.
func TestLoadRebuildsTheSameTree(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	log := transparency.NewLog(&logStorage{st}, priv)
	for i := 0; i < 5; i++ {
		if _, err := log.Append(ctx, fmt.Sprintf("h-%d", i), "acct", identityKey(byte(i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	before := log.Head()

	restarted := transparency.NewLog(&logStorage{st}, priv)
	if err := restarted.Load(ctx); err != nil {
		t.Fatalf("load: %v", err)
	}
	after := restarted.Head()

	if after.Size != before.Size || string(after.RootHash) != string(before.RootHash) {
		t.Errorf("the log came back as a different tree: %d/%x, was %d/%x",
			after.Size, after.RootHash, before.Size, before.RootHash)
	}
}
