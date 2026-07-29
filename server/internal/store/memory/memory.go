// Package memory is an in-memory Store. It backs the test suite and lets
// `make dev` run without Postgres. It is not for production — everything is
// lost on restart, which for the message queue is arguably a feature but for
// accounts is not.
package memory

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/store"
)

type deviceKeys struct {
	identityKey []byte
	spk         model.PreKey
	pqspk       model.PreKey
	oneTime     []model.PreKey
	oneTimePQ   []model.PreKey
}

type tokenEntry struct {
	accountID string
	deviceID  string
	expires   time.Time
}

// Store is a concurrency-safe in-memory implementation.
type Store struct {
	mu sync.RWMutex

	accounts  map[string]*model.Account
	handles   map[string]string // lowercased handle -> accountID
	devices   map[string]*model.Device
	keys      map[string]*deviceKeys
	mailboxes map[string]*model.Mailbox
	queue     map[string][]*model.Envelope // mailboxID -> envelopes
	backups   map[string][]byte
	tokens    map[string]tokenEntry // hex(tokenHash) -> entry
	blobs     map[string]*model.Attachment
	push      map[string]*model.PushToken
	logs      []*model.LogEntry
	provision map[string]*model.Provisioning
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		accounts:  map[string]*model.Account{},
		handles:   map[string]string{},
		devices:   map[string]*model.Device{},
		keys:      map[string]*deviceKeys{},
		mailboxes: map[string]*model.Mailbox{},
		queue:     map[string][]*model.Envelope{},
		backups:   map[string][]byte{},
		tokens:    map[string]tokenEntry{},
		blobs:     map[string]*model.Attachment{},
		push:      map[string]*model.PushToken{},
		provision: map[string]*model.Provisioning{},
	}
}

func dk(accountID, deviceID string) string { return accountID + "/" + deviceID }

func (s *Store) CreateAccount(_ context.Context, a *model.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[a.ID]; ok {
		return store.ErrAlreadyExists
	}
	cp := *a
	s.accounts[a.ID] = &cp
	return nil
}

func (s *Store) GetAccount(_ context.Context, id string) (*model.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.accounts[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *Store) GetAccountByHandle(_ context.Context, handle string) (*model.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.handles[strings.ToLower(handle)]
	if !ok {
		return nil, store.ErrNotFound
	}
	a := s.accounts[id]
	if a == nil {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *Store) SetHandle(_ context.Context, accountID, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[accountID]
	if !ok {
		return store.ErrNotFound
	}
	lower := strings.ToLower(handle)
	if owner, taken := s.handles[lower]; taken && owner != accountID {
		return store.ErrHandleTaken
	}
	if a.Handle != "" {
		delete(s.handles, strings.ToLower(a.Handle))
	}
	s.handles[lower] = accountID
	a.Handle = handle
	return nil
}

func (s *Store) UpsertDevice(_ context.Context, d *model.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[d.AccountID]; !ok {
		return store.ErrNotFound
	}
	cp := *d
	s.devices[dk(d.AccountID, d.DeviceID)] = &cp
	return nil
}

func (s *Store) GetDevice(_ context.Context, accountID, deviceID string) (*model.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[dk(accountID, deviceID)]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *d
	return &cp, nil
}

func (s *Store) ListDevices(_ context.Context, accountID string) ([]*model.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*model.Device
	for _, d := range s.devices {
		if d.AccountID == accountID {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *Store) TouchDevice(_ context.Context, accountID, deviceID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[dk(accountID, deviceID)]
	if !ok {
		return store.ErrNotFound
	}
	d.LastSeen = at
	return nil
}

func (s *Store) PutKeys(_ context.Context, accountID, deviceID string, up *model.KeyUpload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := dk(accountID, deviceID)
	if _, ok := s.devices[k]; !ok {
		return store.ErrNotFound
	}
	existing := s.keys[k]
	if existing == nil {
		existing = &deviceKeys{}
		s.keys[k] = existing
	}
	existing.identityKey = append([]byte(nil), up.IdentityKey...)
	existing.spk = up.SignedPreKey
	existing.pqspk = up.SignedPQKey
	// One-time keys accumulate: a client topping up its pool must not wipe the
	// keys senders may already be about to fetch.
	existing.oneTime = append(existing.oneTime, up.OneTimeKeys...)
	existing.oneTimePQ = append(existing.oneTimePQ, up.OneTimePQ...)
	return nil
}

func (s *Store) TakeBundle(_ context.Context, accountID, deviceID string) (*model.PreKeyBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := dk(accountID, deviceID)
	kk, ok := s.keys[k]
	if !ok || len(kk.identityKey) == 0 {
		return nil, store.ErrNoPreKeys
	}
	b := &model.PreKeyBundle{
		AccountID:    accountID,
		DeviceID:     deviceID,
		IdentityKey:  append([]byte(nil), kk.identityKey...),
		SignedPreKey: kk.spk,
		SignedPQKey:  kk.pqspk,
	}
	// Pop one of each kind if available. Running out is not fatal — the
	// handshake degrades to the signed prekey, per PROTOCOL.md §2.
	if n := len(kk.oneTime); n > 0 {
		key := kk.oneTime[n-1]
		kk.oneTime = kk.oneTime[:n-1]
		b.OneTimeKey = &key
	}
	if n := len(kk.oneTimePQ); n > 0 {
		key := kk.oneTimePQ[n-1]
		kk.oneTimePQ = kk.oneTimePQ[:n-1]
		b.OneTimePQKey = &key
	}
	return b, nil
}

func (s *Store) PreKeyCount(_ context.Context, accountID, deviceID string) (int, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kk, ok := s.keys[dk(accountID, deviceID)]
	if !ok {
		return 0, 0, store.ErrNotFound
	}
	return len(kk.oneTime), len(kk.oneTimePQ), nil
}

func (s *Store) RegisterMailbox(_ context.Context, m *model.Mailbox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.mailboxes[m.ID]; ok && existing.AccountID != m.AccountID {
		// Mailbox IDs are derived from a shared secret; a collision across
		// accounts means either a bug or an attempt to hijack delivery.
		return store.ErrAlreadyExists
	}
	cp := *m
	s.mailboxes[m.ID] = &cp
	return nil
}

func (s *Store) ResolveMailbox(_ context.Context, mailboxID string) (*model.Mailbox, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.mailboxes[mailboxID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *m
	return &cp, nil
}

func (s *Store) MailboxesFor(_ context.Context, accountID, deviceID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, m := range s.mailboxes {
		if m.AccountID == accountID && m.DeviceID == deviceID {
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *Store) Enqueue(_ context.Context, e *model.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	s.queue[e.Mailbox] = append(s.queue[e.Mailbox], &cp)
	return nil
}

func (s *Store) Dequeue(_ context.Context, mailboxID string, limit int) ([]*model.Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q := s.queue[mailboxID]
	if limit > 0 && len(q) > limit {
		q = q[:limit]
	}
	out := make([]*model.Envelope, 0, len(q))
	for _, e := range q {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

func (s *Store) Ack(_ context.Context, mailboxID string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acked := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		acked[id] = struct{}{}
	}
	q := s.queue[mailboxID]
	kept := q[:0]
	for _, e := range q {
		if _, gone := acked[e.ID]; gone {
			// Overwrite before dropping the reference. Go's GC gives no
			// zeroing guarantee, and this is the one place ciphertext lives.
			for i := range e.Ciphertext {
				e.Ciphertext[i] = 0
			}
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) == 0 {
		delete(s.queue, mailboxID)
	} else {
		s.queue[mailboxID] = kept
	}
	return nil
}

func (s *Store) PutBackup(_ context.Context, accountID string, blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[accountID]; !ok {
		return store.ErrNotFound
	}
	s.backups[accountID] = append([]byte(nil), blob...)
	return nil
}

func (s *Store) GetBackup(_ context.Context, accountID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.backups[accountID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

func (s *Store) PutAttachment(_ context.Context, a *model.Attachment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.blobs[a.ID]; exists {
		return store.ErrAlreadyExists
	}
	cp := *a
	cp.Ciphertext = append([]byte(nil), a.Ciphertext...)
	s.blobs[a.ID] = &cp
	return nil
}

func (s *Store) GetAttachment(_ context.Context, id string) (*model.Attachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.blobs[id]
	if !ok || time.Now().After(a.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	cp := *a
	cp.Ciphertext = append([]byte(nil), a.Ciphertext...)
	return &cp, nil
}

func (s *Store) CreateProvisioning(_ context.Context, p *model.Provisioning) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.provision[p.ID]; exists {
		return store.ErrAlreadyExists
	}
	cp := *p
	s.provision[p.ID] = &cp
	return nil
}

func (s *Store) GetProvisioning(_ context.Context, id string) (*model.Provisioning, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.provision[id]
	if !ok || time.Now().After(p.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (s *Store) SetProvisioningApproval(_ context.Context, id string, approval []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.provision[id]
	if !ok || time.Now().After(p.ExpiresAt) {
		return store.ErrNotFound
	}
	if len(p.Approval) > 0 {
		// One approval per channel. A second would let a server that captured
		// the first replace it after the user had already compared codes.
		return store.ErrAlreadyExists
	}
	p.Approval = append([]byte(nil), approval...)
	return nil
}

func (s *Store) DeleteProvisioning(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.provision, id)
	return nil
}

func (s *Store) AppendLogEntry(_ context.Context, e *model.LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	cp.Index = int64(len(s.logs))
	cp.IdentityKey = append([]byte(nil), e.IdentityKey...)
	s.logs = append(s.logs, &cp)
	e.Index = cp.Index
	return nil
}

func (s *Store) LogEntries(_ context.Context, from, to int64) ([]*model.LogEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if from < 0 || to > int64(len(s.logs)) || from > to {
		return nil, store.ErrNotFound
	}
	out := make([]*model.LogEntry, 0, to-from)
	for _, e := range s.logs[from:to] {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

func (s *Store) LogSize(_ context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.logs)), nil
}

func (s *Store) LatestLogEntryForHandle(_ context.Context, handle string) (*model.LogEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.logs) - 1; i >= 0; i-- {
		if strings.EqualFold(s.logs[i].Handle, handle) {
			cp := *s.logs[i]
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) PutPushToken(_ context.Context, t *model.PushToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[dk(t.AccountID, t.DeviceID)]; !ok {
		return store.ErrNotFound
	}
	cp := *t
	s.push[dk(t.AccountID, t.DeviceID)] = &cp
	return nil
}

func (s *Store) GetPushToken(_ context.Context, accountID, deviceID string) (*model.PushToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.push[dk(accountID, deviceID)]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (s *Store) DeletePushToken(_ context.Context, accountID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.push, dk(accountID, deviceID))
	return nil
}

func (s *Store) PutAuthToken(_ context.Context, tokenHash []byte, accountID, deviceID string, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[hex.EncodeToString(tokenHash)] = tokenEntry{accountID, deviceID, expires}
	return nil
}

func (s *Store) LookupAuthToken(_ context.Context, tokenHash []byte) (string, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.tokens[hex.EncodeToString(tokenHash)]
	if !ok || time.Now().After(e.expires) {
		return "", "", store.ErrNotFound
	}
	return e.accountID, e.deviceID, nil
}

func (s *Store) RevokeAuthToken(_ context.Context, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, hex.EncodeToString(tokenHash))
	return nil
}

func (s *Store) Sweep(_ context.Context, now time.Time, envelopeTTL time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	destroyed := 0
	cutoff := now.Add(-envelopeTTL)
	for mb, q := range s.queue {
		kept := q[:0]
		for _, e := range q {
			if e.ServerTS.Before(cutoff) {
				for i := range e.Ciphertext {
					e.Ciphertext[i] = 0
				}
				destroyed++
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(s.queue, mb)
		} else {
			s.queue[mb] = kept
		}
	}
	for id, m := range s.mailboxes {
		if now.After(m.ExpiresAt) {
			delete(s.mailboxes, id)
		}
	}
	for h, t := range s.tokens {
		if now.After(t.expires) {
			delete(s.tokens, h)
		}
	}
	for id, p := range s.provision {
		if now.After(p.ExpiresAt) {
			delete(s.provision, id)
		}
	}
	for id, a := range s.blobs {
		if now.After(a.ExpiresAt) {
			for i := range a.Ciphertext {
				a.Ciphertext[i] = 0
			}
			delete(s.blobs, id)
		}
	}
	return destroyed, nil
}

func (s *Store) Close() error { return nil }
