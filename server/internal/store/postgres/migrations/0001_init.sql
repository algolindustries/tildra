-- Tildra schema, revision 1.
--
-- Read this alongside docs/PROTOCOL.md §8. Every column here is either a
-- public key, a routing identifier, or a ciphertext the server cannot read.
-- If a future migration adds a column that is none of those, the privacy
-- claims in the README stop being true and need to change first.

CREATE TABLE IF NOT EXISTS accounts (
    id         TEXT PRIMARY KEY,
    handle     TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Handles are matched case-insensitively but displayed as chosen.
CREATE UNIQUE INDEX IF NOT EXISTS accounts_handle_lower ON accounts (lower(handle));

CREATE TABLE IF NOT EXISTS devices (
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    identity_key BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, device_id)
);

-- Signed prekeys: exactly one row per device, replaced on rotation.
CREATE TABLE IF NOT EXISTS signed_prekeys (
    account_id      TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    identity_key    BYTEA NOT NULL,
    ec_id           BIGINT NOT NULL,
    ec_public       BYTEA NOT NULL,
    ec_signature    BYTEA NOT NULL,
    pq_id           BIGINT NOT NULL,
    pq_public       BYTEA NOT NULL,
    pq_signature    BYTEA NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, device_id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);

-- One-time prekeys. `kind` is 'ec' or 'pq'. Rows are deleted when consumed —
-- a one-time prekey that survives its use is not one-time.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    account_id TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('ec', 'pq')),
    key_id     BIGINT NOT NULL,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, device_id, kind, key_id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS one_time_prekeys_pool
    ON one_time_prekeys (account_id, device_id, kind, key_id);

CREATE TABLE IF NOT EXISTS mailboxes (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS mailboxes_by_device ON mailboxes (account_id, device_id);
CREATE INDEX IF NOT EXISTS mailboxes_expiry ON mailboxes (expires_at);

-- The message queue. Rows live here only until delivered; the sweeper and the
-- ack path both delete rather than tombstone.
CREATE TABLE IF NOT EXISTS envelopes (
    id         TEXT PRIMARY KEY,
    mailbox    TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    server_ts  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS envelopes_by_mailbox ON envelopes (mailbox, server_ts);
CREATE INDEX IF NOT EXISTS envelopes_by_age ON envelopes (server_ts);

-- Deliberately not a foreign key to mailboxes: a mailbox may expire while an
-- envelope is still within its own TTL, and losing undelivered mail to a
-- cascade would be worse than briefly holding an envelope for an expired
-- address. The sweeper cleans both on their own schedules.

CREATE TABLE IF NOT EXISTS backups (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    blob       BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only the SHA-256 of a token is stored, so a database leak does not hand an
-- attacker live sessions.
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash BYTEA PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS auth_tokens_expiry ON auth_tokens (expires_at);
