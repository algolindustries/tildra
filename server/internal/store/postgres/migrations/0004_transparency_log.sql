-- The key transparency log.
--
-- Append-only by contract and by intent: no UPDATE or DELETE path exists in
-- the store interface, because the entire value of this table is that a client
-- can prove what the server said in the past and the server cannot take it
-- back. A migration that adds one is a change to the security model.
CREATE TABLE IF NOT EXISTS transparency_log (
    idx          BIGINT PRIMARY KEY,
    handle       TEXT NOT NULL,
    account_id   TEXT NOT NULL,
    identity_key BYTEA NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS transparency_log_handle ON transparency_log (lower(handle), idx DESC);
