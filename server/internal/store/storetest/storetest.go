// Package storetest is the conformance suite for store.Store.
//
// Both implementations run the same tests. That is the point: the in-memory
// store backs development and the test suite, Postgres backs production, and
// a difference between them is a bug that only shows up in the environment
// where it costs the most.
package storetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/store"
)

// Factory builds a fresh, empty store for one test.
type Factory func(t *testing.T) store.Store

// Run executes the full conformance suite.
func Run(t *testing.T, newStore Factory) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"Accounts", testAccounts},
		{"Handles", testHandles},
		{"Devices", testDevices},
		{"Keys", testKeys},
		{"OneTimePreKeysAreExclusive", testOneTimePreKeysAreExclusive},
		{"OneTimePreKeysConcurrent", testOneTimePreKeysConcurrent},
		{"Mailboxes", testMailboxes},
		{"Envelopes", testEnvelopes},
		{"AckIsScopedToMailbox", testAckIsScopedToMailbox},
		{"Backups", testBackups},
		{"Attachments", testAttachments},
		{"AuthTokens", testAuthTokens},
		{"Sweep", testSweep},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			tc.fn(t, s)
		})
	}
}

func ctx() context.Context { return context.Background() }

// seed creates an account with one device, the common precondition.
func seed(t *testing.T, s store.Store, accountID, deviceID string) {
	t.Helper()
	if err := s.CreateAccount(ctx(), &model.Account{ID: accountID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	err := s.UpsertDevice(ctx(), &model.Device{
		AccountID:   accountID,
		DeviceID:    deviceID,
		Name:        "Test device",
		IdentityKey: make([]byte, 32),
		CreatedAt:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
}

func testAccounts(t *testing.T, s store.Store) {
	a := &model.Account{ID: "ACCOUNT1", CreatedAt: time.Now().UTC()}
	if err := s.CreateAccount(ctx(), a); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.CreateAccount(ctx(), a); err != store.ErrAlreadyExists {
		t.Errorf("duplicate create: got %v, want ErrAlreadyExists", err)
	}

	got, err := s.GetAccount(ctx(), "ACCOUNT1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != "ACCOUNT1" {
		t.Errorf("got id %q", got.ID)
	}

	if _, err := s.GetAccount(ctx(), "MISSING"); err != store.ErrNotFound {
		t.Errorf("missing account: got %v, want ErrNotFound", err)
	}
}

func testHandles(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	seed(t, s, "ACCOUNT2", "DEVICE1")

	if err := s.SetHandle(ctx(), "ACCOUNT1", "ayse"); err != nil {
		t.Fatalf("set handle: %v", err)
	}

	got, err := s.GetAccountByHandle(ctx(), "ayse")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != "ACCOUNT1" {
		t.Errorf("resolved to %q", got.ID)
	}

	// Case-insensitive both ways: lookups find it, and a second account
	// cannot claim a case variant.
	if _, err := s.GetAccountByHandle(ctx(), "AYSE"); err != nil {
		t.Errorf("uppercase lookup failed: %v", err)
	}
	if err := s.SetHandle(ctx(), "ACCOUNT2", "AYSE"); err != store.ErrHandleTaken {
		t.Errorf("case-variant claim: got %v, want ErrHandleTaken", err)
	}

	if _, err := s.GetAccountByHandle(ctx(), "nobody"); err != store.ErrNotFound {
		t.Errorf("unknown handle: got %v, want ErrNotFound", err)
	}
	if err := s.SetHandle(ctx(), "MISSING", "ghost"); err != store.ErrNotFound {
		t.Errorf("handle for missing account: got %v, want ErrNotFound", err)
	}
}

func testDevices(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")

	d, err := s.GetDevice(ctx(), "ACCOUNT1", "DEVICE1")
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if len(d.IdentityKey) != 32 {
		t.Errorf("identity key round-trip: got %d bytes", len(d.IdentityKey))
	}

	if _, err := s.GetDevice(ctx(), "ACCOUNT1", "MISSING"); err != store.ErrNotFound {
		t.Errorf("missing device: got %v, want ErrNotFound", err)
	}

	// A device for an account that does not exist must be refused, not
	// silently orphaned.
	err = s.UpsertDevice(ctx(), &model.Device{
		AccountID: "NOSUCH", DeviceID: "D", IdentityKey: make([]byte, 32),
		CreatedAt: time.Now(), LastSeen: time.Now(),
	})
	if err != store.ErrNotFound {
		t.Errorf("device for missing account: got %v, want ErrNotFound", err)
	}

	devices, err := s.ListDevices(ctx(), "ACCOUNT1")
	if err != nil || len(devices) != 1 {
		t.Fatalf("list devices: %v, %d devices", err, len(devices))
	}

	later := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	if err := s.TouchDevice(ctx(), "ACCOUNT1", "DEVICE1", later); err != nil {
		t.Fatalf("touch: %v", err)
	}
	d, _ = s.GetDevice(ctx(), "ACCOUNT1", "DEVICE1")
	if d.LastSeen.Before(later.Add(-time.Second)) {
		t.Errorf("last seen not updated: %v", d.LastSeen)
	}
}

func keyUpload(oneTimeCount int) *model.KeyUpload {
	up := &model.KeyUpload{
		IdentityKey:  bytesOf(32, 1),
		SignedPreKey: model.PreKey{ID: 1, PublicKey: bytesOf(32, 2), Signature: bytesOf(64, 3)},
		SignedPQKey:  model.PreKey{ID: 1, PublicKey: bytesOf(1184, 4), Signature: bytesOf(64, 5)},
	}
	for i := 0; i < oneTimeCount; i++ {
		up.OneTimeKeys = append(up.OneTimeKeys, model.PreKey{ID: uint32(100 + i), PublicKey: bytesOf(32, byte(i))})
		up.OneTimePQ = append(up.OneTimePQ, model.PreKey{ID: uint32(200 + i), PublicKey: bytesOf(1184, byte(i))})
	}
	return up
}

func bytesOf(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

func testKeys(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")

	if _, err := s.TakeBundle(ctx(), "ACCOUNT1", "DEVICE1"); err != store.ErrNoPreKeys {
		t.Errorf("bundle before upload: got %v, want ErrNoPreKeys", err)
	}

	if err := s.PutKeys(ctx(), "ACCOUNT1", "DEVICE1", keyUpload(3)); err != nil {
		t.Fatalf("put keys: %v", err)
	}

	ec, pq, err := s.PreKeyCount(ctx(), "ACCOUNT1", "DEVICE1")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if ec != 3 || pq != 3 {
		t.Errorf("counts: got ec=%d pq=%d, want 3 and 3", ec, pq)
	}

	b, err := s.TakeBundle(ctx(), "ACCOUNT1", "DEVICE1")
	if err != nil {
		t.Fatalf("take bundle: %v", err)
	}
	if len(b.IdentityKey) != 32 || len(b.SignedPQKey.PublicKey) != 1184 {
		t.Errorf("bundle sizes wrong: identity=%d pq=%d", len(b.IdentityKey), len(b.SignedPQKey.PublicKey))
	}
	if b.OneTimeKey == nil || b.OneTimePQKey == nil {
		t.Fatal("expected one-time keys")
	}

	// Topping up must not destroy keys senders may already be fetching.
	if err := s.PutKeys(ctx(), "ACCOUNT1", "DEVICE1", keyUpload(0)); err != nil {
		t.Fatalf("republish: %v", err)
	}
	ec, _, _ = s.PreKeyCount(ctx(), "ACCOUNT1", "DEVICE1")
	if ec != 2 {
		t.Errorf("after republish: got %d one-time keys, want the remaining 2", ec)
	}

	if err := s.PutKeys(ctx(), "MISSING", "DEVICE1", keyUpload(1)); err != store.ErrNotFound {
		t.Errorf("keys for missing device: got %v, want ErrNotFound", err)
	}
}

func testOneTimePreKeysAreExclusive(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	const count = 5
	if err := s.PutKeys(ctx(), "ACCOUNT1", "DEVICE1", keyUpload(count)); err != nil {
		t.Fatalf("put keys: %v", err)
	}

	seen := map[uint32]bool{}
	for i := 0; i < count; i++ {
		b, err := s.TakeBundle(ctx(), "ACCOUNT1", "DEVICE1")
		if err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		if b.OneTimeKey == nil {
			t.Fatalf("take %d: expected a one-time key", i)
		}
		if seen[b.OneTimeKey.ID] {
			t.Fatalf("one-time prekey %d handed out twice", b.OneTimeKey.ID)
		}
		seen[b.OneTimeKey.ID] = true
	}

	// Exhausted: still serve the bundle, degrading to the signed prekey.
	b, err := s.TakeBundle(ctx(), "ACCOUNT1", "DEVICE1")
	if err != nil {
		t.Fatalf("take after exhaustion: %v", err)
	}
	if b.OneTimeKey != nil {
		t.Error("expected no one-time key once the pool is empty")
	}
	if len(b.SignedPreKey.PublicKey) == 0 {
		t.Error("exhausted bundle must still carry the signed prekey")
	}
}

func testOneTimePreKeysConcurrent(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	const count = 20
	if err := s.PutKeys(ctx(), "ACCOUNT1", "DEVICE1", keyUpload(count)); err != nil {
		t.Fatalf("put keys: %v", err)
	}

	// Concurrent fetches must never receive the same one-time prekey. Two
	// senders sharing one would each think they had forward secrecy they do
	// not have.
	var mu sync.Mutex
	seen := map[uint32]int{}
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := s.TakeBundle(ctx(), "ACCOUNT1", "DEVICE1")
			if err != nil || b.OneTimeKey == nil {
				return
			}
			mu.Lock()
			seen[b.OneTimeKey.ID]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	for id, times := range seen {
		if times > 1 {
			t.Errorf("one-time prekey %d handed out %d times", id, times)
		}
	}
	if len(seen) == 0 {
		t.Error("no keys were handed out at all")
	}
}

func testMailboxes(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	seed(t, s, "ACCOUNT2", "DEVICE1")

	m := &model.Mailbox{ID: "mb_1", AccountID: "ACCOUNT1", DeviceID: "DEVICE1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.RegisterMailbox(ctx(), m); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Re-registering your own mailbox is a refresh, not a conflict.
	if err := s.RegisterMailbox(ctx(), m); err != nil {
		t.Errorf("re-register own mailbox: %v", err)
	}

	// Another account claiming it would redirect this device's mail.
	other := &model.Mailbox{ID: "mb_1", AccountID: "ACCOUNT2", DeviceID: "DEVICE1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.RegisterMailbox(ctx(), other); err != store.ErrAlreadyExists {
		t.Errorf("hijack attempt: got %v, want ErrAlreadyExists", err)
	}

	resolved, err := s.ResolveMailbox(ctx(), "mb_1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.AccountID != "ACCOUNT1" {
		t.Errorf("mailbox belongs to %q after hijack attempt", resolved.AccountID)
	}

	if _, err := s.ResolveMailbox(ctx(), "mb_unknown"); err != store.ErrNotFound {
		t.Errorf("unknown mailbox: got %v, want ErrNotFound", err)
	}

	list, err := s.MailboxesFor(ctx(), "ACCOUNT1", "DEVICE1")
	if err != nil || len(list) != 1 || list[0] != "mb_1" {
		t.Errorf("mailboxes for device: %v, %v", err, list)
	}
}

func testEnvelopes(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	_ = s.RegisterMailbox(ctx(), &model.Mailbox{
		ID: "mb_1", AccountID: "ACCOUNT1", DeviceID: "DEVICE1", ExpiresAt: time.Now().Add(time.Hour),
	})

	base := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 3; i++ {
		err := s.Enqueue(ctx(), &model.Envelope{
			ID:         fmt.Sprintf("env%d", i),
			Mailbox:    "mb_1",
			Ciphertext: []byte(fmt.Sprintf("ciphertext %d", i)),
			ServerTS:   base.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	queued, err := s.Dequeue(ctx(), "mb_1", 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(queued) != 3 {
		t.Fatalf("got %d envelopes, want 3", len(queued))
	}
	// Order matters: a client that sees a later message first ratchets out of
	// order.
	for i, e := range queued {
		if want := fmt.Sprintf("env%d", i); e.ID != want {
			t.Errorf("position %d: got %q, want %q", i, e.ID, want)
		}
	}
	if string(queued[0].Ciphertext) != "ciphertext 0" {
		t.Errorf("ciphertext altered: %q", queued[0].Ciphertext)
	}

	if limited, _ := s.Dequeue(ctx(), "mb_1", 2); len(limited) != 2 {
		t.Errorf("limit ignored: got %d", len(limited))
	}

	// Acking must delete, not tombstone — "destroyed on delivery" is a claim
	// the README makes.
	if err := s.Ack(ctx(), "mb_1", []string{"env0", "env1"}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	remaining, _ := s.Dequeue(ctx(), "mb_1", 10)
	if len(remaining) != 1 || remaining[0].ID != "env2" {
		t.Errorf("after ack: %v", remaining)
	}

	if err := s.Ack(ctx(), "mb_1", nil); err != nil {
		t.Errorf("empty ack should be a no-op: %v", err)
	}
}

func testAckIsScopedToMailbox(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	seed(t, s, "ACCOUNT2", "DEVICE1")
	for _, m := range []struct{ id, account string }{{"mb_a", "ACCOUNT1"}, {"mb_b", "ACCOUNT2"}} {
		_ = s.RegisterMailbox(ctx(), &model.Mailbox{
			ID: m.id, AccountID: m.account, DeviceID: "DEVICE1", ExpiresAt: time.Now().Add(time.Hour),
		})
	}
	_ = s.Enqueue(ctx(), &model.Envelope{ID: "shared-id", Mailbox: "mb_b", Ciphertext: []byte("x"), ServerTS: time.Now()})

	// Acking someone else's envelope ID from your own mailbox must not delete
	// it. Otherwise any authenticated account could destroy anyone's mail by
	// guessing IDs.
	if err := s.Ack(ctx(), "mb_a", []string{"shared-id"}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	left, _ := s.Dequeue(ctx(), "mb_b", 10)
	if len(left) != 1 {
		t.Error("an ack on one mailbox deleted an envelope in another")
	}
}

func testBackups(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")

	if _, err := s.GetBackup(ctx(), "ACCOUNT1"); err != store.ErrNotFound {
		t.Errorf("no backup yet: got %v, want ErrNotFound", err)
	}

	blob := []byte("encrypted-under-the-recovery-phrase")
	if err := s.PutBackup(ctx(), "ACCOUNT1", blob); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetBackup(ctx(), "ACCOUNT1")
	if err != nil || string(got) != string(blob) {
		t.Fatalf("get: %v, %q", err, got)
	}

	updated := []byte("a newer blob")
	if err := s.PutBackup(ctx(), "ACCOUNT1", updated); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _ = s.GetBackup(ctx(), "ACCOUNT1")
	if string(got) != string(updated) {
		t.Errorf("overwrite did not take: %q", got)
	}

	if err := s.PutBackup(ctx(), "MISSING", blob); err != store.ErrNotFound {
		t.Errorf("backup for missing account: got %v, want ErrNotFound", err)
	}
}

func testAttachments(t *testing.T, s store.Store) {
	now := time.Now().UTC()

	if _, err := s.GetAttachment(ctx(), "nope"); err != store.ErrNotFound {
		t.Errorf("unknown attachment: got %v, want ErrNotFound", err)
	}

	ciphertext := bytesOf(4096, 0xAB)
	a := &model.Attachment{
		ID:         "att-1",
		Ciphertext: ciphertext,
		Size:       int64(len(ciphertext)),
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}
	if err := s.PutAttachment(ctx(), a); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := s.GetAttachment(ctx(), "att-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Ciphertext) != len(ciphertext) || got.Ciphertext[0] != 0xAB {
		t.Error("ciphertext was altered in storage")
	}
	if got.Size != int64(len(ciphertext)) {
		t.Errorf("size: got %d, want %d", got.Size, len(ciphertext))
	}

	// IDs are server-generated and unique; a collision would let one upload
	// overwrite another's blob.
	if err := s.PutAttachment(ctx(), a); err != store.ErrAlreadyExists {
		t.Errorf("duplicate id: got %v, want ErrAlreadyExists", err)
	}

	// An expired blob is gone as far as callers are concerned, even before the
	// sweeper runs.
	expired := &model.Attachment{
		ID: "att-old", Ciphertext: bytesOf(16, 1), Size: 16,
		CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}
	if err := s.PutAttachment(ctx(), expired); err != nil {
		t.Fatalf("put expired: %v", err)
	}
	if _, err := s.GetAttachment(ctx(), "att-old"); err != store.ErrNotFound {
		t.Errorf("expired attachment: got %v, want ErrNotFound", err)
	}
}

func testAuthTokens(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	hash := bytesOf(32, 7)

	if _, _, err := s.LookupAuthToken(ctx(), hash); err != store.ErrNotFound {
		t.Errorf("unknown token: got %v, want ErrNotFound", err)
	}

	if err := s.PutAuthToken(ctx(), hash, "ACCOUNT1", "DEVICE1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("put: %v", err)
	}
	accountID, deviceID, err := s.LookupAuthToken(ctx(), hash)
	if err != nil || accountID != "ACCOUNT1" || deviceID != "DEVICE1" {
		t.Fatalf("lookup: %v, %q, %q", err, accountID, deviceID)
	}

	// An expired token must not authenticate, even before the sweeper runs.
	expired := bytesOf(32, 8)
	if err := s.PutAuthToken(ctx(), expired, "ACCOUNT1", "DEVICE1", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("put expired: %v", err)
	}
	if _, _, err := s.LookupAuthToken(ctx(), expired); err != store.ErrNotFound {
		t.Errorf("expired token: got %v, want ErrNotFound", err)
	}

	if err := s.RevokeAuthToken(ctx(), hash); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := s.LookupAuthToken(ctx(), hash); err != store.ErrNotFound {
		t.Errorf("revoked token still works: %v", err)
	}
}

func testSweep(t *testing.T, s store.Store) {
	seed(t, s, "ACCOUNT1", "DEVICE1")
	now := time.Now().UTC()

	_ = s.RegisterMailbox(ctx(), &model.Mailbox{
		ID: "mb_live", AccountID: "ACCOUNT1", DeviceID: "DEVICE1", ExpiresAt: now.Add(time.Hour),
	})
	_ = s.RegisterMailbox(ctx(), &model.Mailbox{
		ID: "mb_dead", AccountID: "ACCOUNT1", DeviceID: "DEVICE1", ExpiresAt: now.Add(-time.Hour),
	})
	_ = s.Enqueue(ctx(), &model.Envelope{ID: "old", Mailbox: "mb_live", Ciphertext: []byte("stale"), ServerTS: now.Add(-48 * time.Hour)})
	_ = s.Enqueue(ctx(), &model.Envelope{ID: "new", Mailbox: "mb_live", Ciphertext: []byte("recent"), ServerTS: now})
	_ = s.PutAuthToken(ctx(), bytesOf(32, 9), "ACCOUNT1", "DEVICE1", now.Add(-time.Hour))
	_ = s.PutAttachment(ctx(), &model.Attachment{
		ID: "att-live", Ciphertext: bytesOf(8, 1), Size: 8,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	_ = s.PutAttachment(ctx(), &model.Attachment{
		ID: "att-dead", Ciphertext: bytesOf(8, 2), Size: 8,
		CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	})

	destroyed, err := s.Sweep(ctx(), now, 24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if destroyed != 1 {
		t.Errorf("destroyed %d envelopes, want 1", destroyed)
	}

	left, _ := s.Dequeue(ctx(), "mb_live", 10)
	if len(left) != 1 || left[0].ID != "new" {
		t.Errorf("sweep kept the wrong envelopes: %v", left)
	}
	if _, err := s.ResolveMailbox(ctx(), "mb_dead"); err != store.ErrNotFound {
		t.Errorf("expired mailbox survived: %v", err)
	}
	if _, err := s.ResolveMailbox(ctx(), "mb_live"); err != nil {
		t.Errorf("live mailbox was swept: %v", err)
	}
	if _, _, err := s.LookupAuthToken(ctx(), bytesOf(32, 9)); err != store.ErrNotFound {
		t.Errorf("expired token survived: %v", err)
	}
	if _, err := s.GetAttachment(ctx(), "att-dead"); err != store.ErrNotFound {
		t.Errorf("expired attachment survived the sweep: %v", err)
	}
	if _, err := s.GetAttachment(ctx(), "att-live"); err != nil {
		t.Errorf("live attachment was swept: %v", err)
	}
}
