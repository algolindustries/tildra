-- Push tokens, one per device.
--
-- The only durable device-linked identifier the server keeps beyond routing.
-- Deleted with the device, and replaced rather than accumulated: a device that
-- re-registers gets one row, not a history of every token it has ever held.
CREATE TABLE IF NOT EXISTS push_tokens (
    account_id TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    platform   TEXT NOT NULL,
    token      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, device_id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);
