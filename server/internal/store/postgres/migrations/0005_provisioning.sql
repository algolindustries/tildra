-- Short-lived channels for linking a new device to an existing account.
--
-- The server relays two opaque blobs. It learns the new device's identity key,
-- which it would learn on registration anyway, and cannot usefully interfere:
-- the key is committed to by a hash the user carried over a camera, and both
-- devices display a pairing code derived from the whole transcript.
--
-- approval is nullable and set once. The partial condition in the UPDATE is
-- what enforces "once", so two concurrent approvals cannot both land.
CREATE TABLE IF NOT EXISTS provisioning (
    id            TEXT PRIMARY KEY,
    identity_key  BYTEA NOT NULL,
    ephemeral_key BYTEA NOT NULL,
    approval      BYTEA,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS provisioning_expiry ON provisioning (expires_at);
