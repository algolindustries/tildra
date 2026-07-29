// Package store defines persistence for the Tildra server.
//
// Two implementations exist: an in-memory one (tests, `make dev` without a
// database) and Postgres (production). Both must satisfy the same contract,
// including the deletion semantics — Dequeue followed by Ack must actually
// remove ciphertext, not tombstone it.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/tildra/tildra/server/internal/model"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrHandleTaken   = errors.New("handle already taken")
	ErrNoPreKeys     = errors.New("no prekeys available for device")
	ErrAlreadyExists = errors.New("already exists")
)

// Store is the full persistence surface. It is deliberately narrow: if a
// method would require the server to learn something it shouldn't, it doesn't
// belong here.
type Store interface {
	// Accounts
	CreateAccount(ctx context.Context, a *model.Account) error
	GetAccount(ctx context.Context, id string) (*model.Account, error)
	GetAccountByHandle(ctx context.Context, handle string) (*model.Account, error)
	SetHandle(ctx context.Context, accountID, handle string) error

	// Devices
	UpsertDevice(ctx context.Context, d *model.Device) error
	GetDevice(ctx context.Context, accountID, deviceID string) (*model.Device, error)
	ListDevices(ctx context.Context, accountID string) ([]*model.Device, error)
	TouchDevice(ctx context.Context, accountID, deviceID string, at time.Time) error

	// Keys
	PutKeys(ctx context.Context, accountID, deviceID string, up *model.KeyUpload) error
	TakeBundle(ctx context.Context, accountID, deviceID string) (*model.PreKeyBundle, error)
	PreKeyCount(ctx context.Context, accountID, deviceID string) (ec int, pq int, err error)

	// Mailboxes — the routing layer for sealed sender.
	RegisterMailbox(ctx context.Context, m *model.Mailbox) error
	ResolveMailbox(ctx context.Context, mailboxID string) (*model.Mailbox, error)
	MailboxesFor(ctx context.Context, accountID, deviceID string) ([]string, error)

	// Message queue. Envelopes live here only until delivered.
	Enqueue(ctx context.Context, e *model.Envelope) error
	Dequeue(ctx context.Context, mailboxID string, limit int) ([]*model.Envelope, error)
	Ack(ctx context.Context, mailboxID string, ids []string) error

	// Encrypted account backup — opaque bytes, keyed by the recovery phrase.
	PutBackup(ctx context.Context, accountID string, blob []byte) error
	GetBackup(ctx context.Context, accountID string) ([]byte, error)

	// Attachments. Ciphertext only; no owner is recorded, on purpose.
	PutAttachment(ctx context.Context, a *model.Attachment) error
	GetAttachment(ctx context.Context, id string) (*model.Attachment, error)

	// Key transparency log. Append-only by contract: there is no update or
	// delete, because the whole value of the log is that entries cannot be
	// changed after a client has seen them.
	AppendLogEntry(ctx context.Context, e *model.LogEntry) error
	LogEntries(ctx context.Context, from, to int64) ([]*model.LogEntry, error)
	LogSize(ctx context.Context) (int64, error)
	LatestLogEntryForHandle(ctx context.Context, handle string) (*model.LogEntry, error)

	// Push tokens, one per device.
	PutPushToken(ctx context.Context, t *model.PushToken) error
	GetPushToken(ctx context.Context, accountID, deviceID string) (*model.PushToken, error)
	DeletePushToken(ctx context.Context, accountID, deviceID string) error

	// Auth tokens. The stored value is a hash; the plaintext token never
	// touches disk.
	PutAuthToken(ctx context.Context, tokenHash []byte, accountID, deviceID string, expires time.Time) error
	LookupAuthToken(ctx context.Context, tokenHash []byte) (accountID, deviceID string, err error)
	RevokeAuthToken(ctx context.Context, tokenHash []byte) error

	// Housekeeping: drop expired envelopes, mailboxes, tokens and attachments.
	// Called on a timer; returns how many envelopes were destroyed.
	Sweep(ctx context.Context, now time.Time, envelopeTTL time.Duration) (int, error)

	Close() error
}
