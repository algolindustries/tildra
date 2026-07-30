-- Recovery blobs, addressed by a lookup id the client derives from its
-- recovery phrase rather than by an account. The whole point is to be readable
-- by somebody who has lost the device that knew their account id, so the read
-- path is unauthenticated; the blob is ciphertext the server cannot open.
--
-- The owner is recorded so the id cannot be taken over by another account if
-- it ever leaks. Writing at all requires knowing the id, which requires the
-- phrase.
CREATE TABLE IF NOT EXISTS recovery_blobs (
  lookup_id  TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  blob       BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
