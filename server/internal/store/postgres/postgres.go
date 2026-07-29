// Package postgres is the production Store.
//
// It satisfies the same contract as the in-memory implementation, including
// the deletion semantics: acking an envelope deletes the row, it does not
// mark it. A messaging server that quietly retains delivered ciphertext is
// making a different promise than the one in the README.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tildra/tildra/server/internal/model"
	"github.com/tildra/tildra/server/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is a Postgres-backed store.Store.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects, verifies the connection, and applies migrations.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	// A messaging gateway is connection-bound, not CPU-bound: many short
	// queries from many sockets.
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migrate applies every embedded migration in filename order, recording which
// have run. Migrations are expected to be idempotent, but the ledger means a
// future non-idempotent one is still safe.
func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	if err != nil {
		return err
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var applied bool
		err := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&applied)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("%s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

func (s *Store) CreateAccount(ctx context.Context, a *model.Account) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO accounts (id, handle, created_at) VALUES ($1, NULLIF($2, ''), $3)`,
		a.ID, a.Handle, a.CreatedAt)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

func (s *Store) GetAccount(ctx context.Context, id string) (*model.Account, error) {
	return s.scanAccount(s.pool.QueryRow(ctx,
		`SELECT id, COALESCE(handle, ''), created_at FROM accounts WHERE id = $1`, id))
}

func (s *Store) GetAccountByHandle(ctx context.Context, handle string) (*model.Account, error) {
	return s.scanAccount(s.pool.QueryRow(ctx,
		`SELECT id, COALESCE(handle, ''), created_at FROM accounts WHERE lower(handle) = lower($1)`,
		handle))
}

func (s *Store) scanAccount(row pgx.Row) (*model.Account, error) {
	var a model.Account
	if err := row.Scan(&a.ID, &a.Handle, &a.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func (s *Store) SetHandle(ctx context.Context, accountID, handle string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE accounts SET handle = $2 WHERE id = $1`, accountID, handle)
	if isUniqueViolation(err) {
		return store.ErrHandleTaken
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

func (s *Store) UpsertDevice(ctx context.Context, d *model.Device) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (account_id, device_id, name, identity_key, created_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (account_id, device_id) DO UPDATE
		SET name = EXCLUDED.name, identity_key = EXCLUDED.identity_key, last_seen = EXCLUDED.last_seen`,
		d.AccountID, d.DeviceID, d.Name, d.IdentityKey, d.CreatedAt, d.LastSeen)
	if isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) GetDevice(ctx context.Context, accountID, deviceID string) (*model.Device, error) {
	var d model.Device
	err := s.pool.QueryRow(ctx, `
		SELECT account_id, device_id, name, identity_key, created_at, last_seen
		FROM devices WHERE account_id = $1 AND device_id = $2`, accountID, deviceID).
		Scan(&d.AccountID, &d.DeviceID, &d.Name, &d.IdentityKey, &d.CreatedAt, &d.LastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) ListDevices(ctx context.Context, accountID string) ([]*model.Device, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT account_id, device_id, name, identity_key, created_at, last_seen
		FROM devices WHERE account_id = $1 ORDER BY created_at`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.Device
	for rows.Next() {
		var d model.Device
		if err := rows.Scan(&d.AccountID, &d.DeviceID, &d.Name, &d.IdentityKey, &d.CreatedAt, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, &d)
	}
	return out, rows.Err()
}

func (s *Store) TouchDevice(ctx context.Context, accountID, deviceID string, at time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE devices SET last_seen = $3 WHERE account_id = $1 AND device_id = $2`,
		accountID, deviceID, at)
	return err
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

func (s *Store) PutKeys(ctx context.Context, accountID, deviceID string, up *model.KeyUpload) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO signed_prekeys
			(account_id, device_id, identity_key, ec_id, ec_public, ec_signature,
			 pq_id, pq_public, pq_signature, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (account_id, device_id) DO UPDATE SET
			identity_key = EXCLUDED.identity_key,
			ec_id = EXCLUDED.ec_id, ec_public = EXCLUDED.ec_public, ec_signature = EXCLUDED.ec_signature,
			pq_id = EXCLUDED.pq_id, pq_public = EXCLUDED.pq_public, pq_signature = EXCLUDED.pq_signature,
			updated_at = now()`,
		accountID, deviceID, up.IdentityKey,
		up.SignedPreKey.ID, up.SignedPreKey.PublicKey, up.SignedPreKey.Signature,
		up.SignedPQKey.ID, up.SignedPQKey.PublicKey, up.SignedPQKey.Signature)
	if isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}

	// One-time keys accumulate. ON CONFLICT DO NOTHING rather than DO UPDATE:
	// a client retrying an upload must not overwrite a key another sender is
	// mid-handshake with.
	insert := func(kind string, keys []model.PreKey) error {
		for _, k := range keys {
			_, err := tx.Exec(ctx, `
				INSERT INTO one_time_prekeys (account_id, device_id, kind, key_id, public_key)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (account_id, device_id, kind, key_id) DO NOTHING`,
				accountID, deviceID, kind, int64(k.ID), k.PublicKey)
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := insert("ec", up.OneTimeKeys); err != nil {
		return err
	}
	if err := insert("pq", up.OneTimePQ); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) TakeBundle(ctx context.Context, accountID, deviceID string) (*model.PreKeyBundle, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	b := &model.PreKeyBundle{AccountID: accountID, DeviceID: deviceID}
	var ecID, pqID int64
	err = tx.QueryRow(ctx, `
		SELECT identity_key, ec_id, ec_public, ec_signature, pq_id, pq_public, pq_signature
		FROM signed_prekeys WHERE account_id = $1 AND device_id = $2`, accountID, deviceID).
		Scan(&b.IdentityKey, &ecID, &b.SignedPreKey.PublicKey, &b.SignedPreKey.Signature,
			&pqID, &b.SignedPQKey.PublicKey, &b.SignedPQKey.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNoPreKeys
	}
	if err != nil {
		return nil, err
	}
	b.SignedPreKey.ID = uint32(ecID)
	b.SignedPQKey.ID = uint32(pqID)

	// DELETE ... RETURNING pops a key atomically. Two concurrent fetches
	// cannot receive the same one-time prekey, which is the entire point of
	// calling it one-time.
	take := func(kind string) (*model.PreKey, error) {
		var k model.PreKey
		var id int64
		err := tx.QueryRow(ctx, `
			DELETE FROM one_time_prekeys
			WHERE ctid = (
				SELECT ctid FROM one_time_prekeys
				WHERE account_id = $1 AND device_id = $2 AND kind = $3
				ORDER BY key_id
				FOR UPDATE SKIP LOCKED
				LIMIT 1
			)
			RETURNING key_id, public_key`, accountID, deviceID, kind).Scan(&id, &k.PublicKey)
		if errors.Is(err, pgx.ErrNoRows) {
			// An exhausted pool is not an error: the handshake degrades to the
			// signed prekey, per docs/PROTOCOL.md §2.
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		k.ID = uint32(id)
		return &k, nil
	}

	if b.OneTimeKey, err = take("ec"); err != nil {
		return nil, err
	}
	if b.OneTimePQKey, err = take("pq"); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) PreKeyCount(ctx context.Context, accountID, deviceID string) (int, int, error) {
	var ec, pq int
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE kind = 'ec'),
			COUNT(*) FILTER (WHERE kind = 'pq')
		FROM one_time_prekeys WHERE account_id = $1 AND device_id = $2`,
		accountID, deviceID).Scan(&ec, &pq)
	if err != nil {
		return 0, 0, err
	}
	return ec, pq, nil
}

// ---------------------------------------------------------------------------
// Mailboxes
// ---------------------------------------------------------------------------

func (s *Store) RegisterMailbox(ctx context.Context, m *model.Mailbox) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO mailboxes (id, account_id, device_id, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE mailboxes.account_id = EXCLUDED.account_id
		  AND mailboxes.device_id = EXCLUDED.device_id`,
		m.ID, m.AccountID, m.DeviceID, m.ExpiresAt)
	if isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// The row exists and belongs to someone else. Mailbox IDs derive from
		// a shared secret, so this is either a collision or an attempt to
		// redirect another account's mail.
		return store.ErrAlreadyExists
	}
	return nil
}

func (s *Store) ResolveMailbox(ctx context.Context, mailboxID string) (*model.Mailbox, error) {
	var m model.Mailbox
	err := s.pool.QueryRow(ctx,
		`SELECT id, account_id, device_id, expires_at FROM mailboxes WHERE id = $1`, mailboxID).
		Scan(&m.ID, &m.AccountID, &m.DeviceID, &m.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) MailboxesFor(ctx context.Context, accountID, deviceID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id FROM mailboxes WHERE account_id = $1 AND device_id = $2`, accountID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

func (s *Store) Enqueue(ctx context.Context, e *model.Envelope) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO envelopes (id, mailbox, ciphertext, server_ts) VALUES ($1, $2, $3, $4)`,
		e.ID, e.Mailbox, e.Ciphertext, e.ServerTS)
	return err
}

func (s *Store) Dequeue(ctx context.Context, mailboxID string, limit int) ([]*model.Envelope, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, mailbox, ciphertext, server_ts FROM envelopes
		WHERE mailbox = $1 ORDER BY server_ts, id LIMIT $2`, mailboxID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.Envelope
	for rows.Next() {
		var e model.Envelope
		if err := rows.Scan(&e.ID, &e.Mailbox, &e.Ciphertext, &e.ServerTS); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (s *Store) Ack(ctx context.Context, mailboxID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	// Scoped to the mailbox, so an ack cannot delete an envelope in someone
	// else's queue even if the caller guesses an ID.
	_, err := s.pool.Exec(ctx,
		`DELETE FROM envelopes WHERE mailbox = $1 AND id = ANY($2)`, mailboxID, ids)
	return err
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

func (s *Store) PutBackup(ctx context.Context, accountID string, blob []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO backups (account_id, blob, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (account_id) DO UPDATE SET blob = EXCLUDED.blob, updated_at = now()`,
		accountID, blob)
	if isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) GetBackup(ctx context.Context, accountID string) ([]byte, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx, `SELECT blob FROM backups WHERE account_id = $1`, accountID).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return blob, err
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

func (s *Store) PutAttachment(ctx context.Context, a *model.Attachment) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO attachments (id, ciphertext, size_bytes, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		a.ID, a.Ciphertext, a.Size, a.CreatedAt, a.ExpiresAt)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

func (s *Store) GetAttachment(ctx context.Context, id string) (*model.Attachment, error) {
	var a model.Attachment
	err := s.pool.QueryRow(ctx, `
		SELECT id, ciphertext, size_bytes, created_at, expires_at
		FROM attachments WHERE id = $1 AND expires_at > now()`, id).
		Scan(&a.ID, &a.Ciphertext, &a.Size, &a.CreatedAt, &a.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ---------------------------------------------------------------------------
// Key transparency log
// ---------------------------------------------------------------------------

func (s *Store) AppendLogEntry(ctx context.Context, e *model.LogEntry) error {
	// The index comes from the database rather than the caller, so two
	// concurrent appends cannot claim the same position — which would give two
	// clients different trees of the same size.
	return s.pool.QueryRow(ctx, `
		INSERT INTO transparency_log (idx, handle, account_id, identity_key, recorded_at)
		VALUES ((SELECT COALESCE(MAX(idx) + 1, 0) FROM transparency_log), $1, $2, $3, $4)
		RETURNING idx`,
		e.Handle, e.AccountID, e.IdentityKey, e.RecordedAt).Scan(&e.Index)
}

func (s *Store) LogEntries(ctx context.Context, from, to int64) ([]*model.LogEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT idx, handle, account_id, identity_key, recorded_at
		FROM transparency_log WHERE idx >= $1 AND idx < $2 ORDER BY idx`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.LogEntry
	for rows.Next() {
		var e model.LogEntry
		if err := rows.Scan(&e.Index, &e.Handle, &e.AccountID, &e.IdentityKey, &e.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (s *Store) LogSize(ctx context.Context) (int64, error) {
	var size int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM transparency_log`).Scan(&size)
	return size, err
}

func (s *Store) LatestLogEntryForHandle(ctx context.Context, handle string) (*model.LogEntry, error) {
	var e model.LogEntry
	err := s.pool.QueryRow(ctx, `
		SELECT idx, handle, account_id, identity_key, recorded_at
		FROM transparency_log WHERE lower(handle) = lower($1)
		ORDER BY idx DESC LIMIT 1`, handle).
		Scan(&e.Index, &e.Handle, &e.AccountID, &e.IdentityKey, &e.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ---------------------------------------------------------------------------
// Push tokens
// ---------------------------------------------------------------------------

func (s *Store) PutPushToken(ctx context.Context, t *model.PushToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO push_tokens (account_id, device_id, platform, token, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (account_id, device_id) DO UPDATE
		SET platform = EXCLUDED.platform, token = EXCLUDED.token, updated_at = EXCLUDED.updated_at`,
		t.AccountID, t.DeviceID, t.Platform, t.Token, t.UpdatedAt)
	if isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) GetPushToken(ctx context.Context, accountID, deviceID string) (*model.PushToken, error) {
	var t model.PushToken
	err := s.pool.QueryRow(ctx, `
		SELECT account_id, device_id, platform, token, updated_at
		FROM push_tokens WHERE account_id = $1 AND device_id = $2`, accountID, deviceID).
		Scan(&t.AccountID, &t.DeviceID, &t.Platform, &t.Token, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) DeletePushToken(ctx context.Context, accountID, deviceID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM push_tokens WHERE account_id = $1 AND device_id = $2`, accountID, deviceID)
	return err
}

// ---------------------------------------------------------------------------
// Auth tokens
// ---------------------------------------------------------------------------

func (s *Store) PutAuthToken(ctx context.Context, tokenHash []byte, accountID, deviceID string, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth_tokens (token_hash, account_id, device_id, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
		tokenHash, accountID, deviceID, expires)
	return err
}

func (s *Store) LookupAuthToken(ctx context.Context, tokenHash []byte) (string, string, error) {
	var accountID, deviceID string
	err := s.pool.QueryRow(ctx, `
		SELECT account_id, device_id FROM auth_tokens
		WHERE token_hash = $1 AND expires_at > now()`, tokenHash).Scan(&accountID, &deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", store.ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	return accountID, deviceID, nil
}

func (s *Store) RevokeAuthToken(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM auth_tokens WHERE token_hash = $1`, tokenHash)
	return err
}

// ---------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------

func (s *Store) Sweep(ctx context.Context, now time.Time, envelopeTTL time.Duration) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM envelopes WHERE server_ts < $1`, now.Add(-envelopeTTL))
	if err != nil {
		return 0, err
	}
	destroyed := int(tag.RowsAffected())

	if _, err := s.pool.Exec(ctx, `DELETE FROM mailboxes WHERE expires_at < $1`, now); err != nil {
		return destroyed, err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM auth_tokens WHERE expires_at < $1`, now); err != nil {
		return destroyed, err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM attachments WHERE expires_at < $1`, now); err != nil {
		return destroyed, err
	}
	return destroyed, nil
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
