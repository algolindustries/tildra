-- Encrypted attachments.
--
-- Ciphertext and a size. No owner column, and no link to an account or a
-- message: an uploader-to-blob mapping would recreate exactly the metadata
-- that sealed sender exists to remove. The decryption key travels inside the
-- message that references the blob, so holding the blob alone is useless.
--
-- Bytea is adequate at this scale and deliberately simple. A deployment
-- carrying real volume should move the payload to object storage and keep
-- only the row; the store interface is the seam for that.
CREATE TABLE IF NOT EXISTS attachments (
    id         TEXT PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS attachments_expiry ON attachments (expires_at);
