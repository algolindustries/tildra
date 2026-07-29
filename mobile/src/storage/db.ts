/**
 * Local database.
 *
 * Every column that would tell a reader something about who this device talks
 * to is either encrypted through the vault or reduced to a blind index. What
 * is left in the clear is timestamps, counts and delivery state — enough for
 * SQLite to sort and join, not enough to reconstruct a conversation.
 *
 * A note on the threat this addresses: the server already cannot see this
 * data. This layer is about the phone itself — a forensic image, a backup
 * extraction, or another app exploiting a sandbox escape.
 */

import * as SQLite from 'expo-sqlite';

import { Vault } from './vault';
import { fromBase64, toBase64 } from '../crypto/primitives';
import {
  RatchetState,
  SerializedRatchet,
  deserializeRatchet,
  serializeRatchet,
} from '../crypto/ratchet';

export type MessageState = 'pending' | 'sent' | 'delivered' | 'failed';

export interface Conversation {
  accountId: string;
  handle?: string;
  displayName?: string;
  identityKey: Uint8Array;
  lastActivity: number;
  unreadCount: number;
  verified: boolean;
  /** Set when the peer's identity key changed — blocks sending until cleared. */
  identityChanged: boolean;
}

export interface Message {
  id: string;
  conversationId: string;
  text: string;
  outgoing: boolean;
  createdAt: number;
  state: MessageState;
}

export interface StoredSession {
  accountId: string;
  deviceId: string;
  ratchet: RatchetState;
  associatedData: Uint8Array;
  mailboxSecret: Uint8Array;
}

interface ConversationRow {
  id: string;
  meta_blob: string;
  last_activity: number;
  unread_count: number;
  verified: number;
  identity_changed: number;
}

interface MessageRow {
  id: string;
  conversation_id: string;
  body_blob: string;
  outgoing: number;
  created_at: number;
  state: MessageState;
}

interface SessionRow {
  id: string;
  account_ref: string;
  state_blob: string;
  updated_at: number;
}

interface ConversationMeta {
  accountId: string;
  handle?: string;
  displayName?: string;
  identityKey: string;
}

interface SessionBlob {
  accountId: string;
  deviceId: string;
  ratchet: SerializedRatchet;
  associatedData: string;
  mailboxSecret: string;
}

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS conversations (
  id              TEXT PRIMARY KEY,
  meta_blob       TEXT NOT NULL,
  last_activity   INTEGER NOT NULL,
  unread_count    INTEGER NOT NULL DEFAULT 0,
  verified        INTEGER NOT NULL DEFAULT 0,
  identity_changed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS messages (
  id              TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  body_blob       TEXT NOT NULL,
  outgoing        INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  state           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_by_conversation
  ON messages(conversation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  account_ref TEXT NOT NULL,
  state_blob  TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_by_account ON sessions(account_ref);

CREATE TABLE IF NOT EXISTS prekeys (
  id          INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  secret_blob TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (id, kind)
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

export class Database {
  private constructor(
    private readonly db: SQLite.SQLiteDatabase,
    private readonly vault: Vault,
  ) {}

  static async open(vault: Vault, name = 'tildra.db'): Promise<Database> {
    const db = await SQLite.openDatabaseAsync(name);
    await db.execAsync(SCHEMA);
    return new Database(db, vault);
  }

  // -------------------------------------------------------------------------
  // Conversations
  // -------------------------------------------------------------------------

  private conversationKey(accountId: string): string {
    return this.vault.blindIndex('contact', accountId);
  }

  async upsertConversation(conversation: Conversation): Promise<string> {
    const id = this.conversationKey(conversation.accountId);
    const meta: ConversationMeta = {
      accountId: conversation.accountId,
      handle: conversation.handle,
      displayName: conversation.displayName,
      identityKey: toBase64(conversation.identityKey),
    };
    await this.db.runAsync(
      `INSERT INTO conversations (id, meta_blob, last_activity, unread_count, verified, identity_changed)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         meta_blob = excluded.meta_blob,
         last_activity = MAX(conversations.last_activity, excluded.last_activity),
         verified = excluded.verified,
         identity_changed = excluded.identity_changed`,
      [
        id,
        this.vault.encryptJson('contact', id, meta),
        conversation.lastActivity,
        conversation.unreadCount,
        conversation.verified ? 1 : 0,
        conversation.identityChanged ? 1 : 0,
      ],
    );
    return id;
  }

  async listConversations(): Promise<(Conversation & { id: string })[]> {
    const rows = await this.db.getAllAsync<ConversationRow>(
      'SELECT * FROM conversations ORDER BY last_activity DESC',
    );
    return rows.map((row) => this.decodeConversation(row));
  }

  async getConversation(accountId: string): Promise<(Conversation & { id: string }) | null> {
    const row = await this.db.getFirstAsync<ConversationRow>(
      'SELECT * FROM conversations WHERE id = ?',
      [this.conversationKey(accountId)],
    );
    return row ? this.decodeConversation(row) : null;
  }

  private decodeConversation(row: ConversationRow): Conversation & { id: string } {
    const meta = this.vault.decryptJson<ConversationMeta>('contact', row.id, row.meta_blob);
    return {
      id: row.id,
      accountId: meta.accountId,
      handle: meta.handle,
      displayName: meta.displayName,
      identityKey: fromBase64(meta.identityKey),
      lastActivity: row.last_activity,
      unreadCount: row.unread_count,
      verified: row.verified === 1,
      identityChanged: row.identity_changed === 1,
    };
  }

  /**
   * Record that a contact's identity key changed.
   *
   * This is a security event, not a data update: the conversation is flagged
   * and the UI must block sending until the user acknowledges it. A silent
   * key change is what a successful server-side MITM looks like.
   */
  async flagIdentityChange(accountId: string, newIdentityKey: Uint8Array): Promise<void> {
    const existing = await this.getConversation(accountId);
    if (!existing) return;
    await this.upsertConversation({
      ...existing,
      identityKey: newIdentityKey,
      verified: false,
      identityChanged: true,
    });
  }

  async acknowledgeIdentityChange(accountId: string): Promise<void> {
    await this.db.runAsync('UPDATE conversations SET identity_changed = 0 WHERE id = ?', [
      this.conversationKey(accountId),
    ]);
  }

  async setVerified(accountId: string, verified: boolean): Promise<void> {
    await this.db.runAsync('UPDATE conversations SET verified = ? WHERE id = ?', [
      verified ? 1 : 0,
      this.conversationKey(accountId),
    ]);
  }

  async markRead(conversationId: string): Promise<void> {
    await this.db.runAsync('UPDATE conversations SET unread_count = 0 WHERE id = ?', [
      conversationId,
    ]);
  }

  // -------------------------------------------------------------------------
  // Messages
  // -------------------------------------------------------------------------

  async insertMessage(message: Message): Promise<void> {
    await this.db.withTransactionAsync(async () => {
      await this.db.runAsync(
        `INSERT OR REPLACE INTO messages (id, conversation_id, body_blob, outgoing, created_at, state)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          message.id,
          message.conversationId,
          this.vault.encryptJson('message', message.id, { text: message.text }),
          message.outgoing ? 1 : 0,
          message.createdAt,
          message.state,
        ],
      );
      await this.db.runAsync(
        `UPDATE conversations
            SET last_activity = MAX(last_activity, ?),
                unread_count = unread_count + ?
          WHERE id = ?`,
        [message.createdAt, message.outgoing ? 0 : 1, message.conversationId],
      );
    });
  }

  async listMessages(conversationId: string, limit = 100, before?: number): Promise<Message[]> {
    const rows = before
      ? await this.db.getAllAsync<MessageRow>(
          `SELECT * FROM messages WHERE conversation_id = ? AND created_at < ?
           ORDER BY created_at DESC LIMIT ?`,
          [conversationId, before, limit],
        )
      : await this.db.getAllAsync<MessageRow>(
          `SELECT * FROM messages WHERE conversation_id = ?
           ORDER BY created_at DESC LIMIT ?`,
          [conversationId, limit],
        );

    return rows
      .map((row) => ({
        id: row.id,
        conversationId: row.conversation_id,
        text: this.vault.decryptJson<{ text: string }>('message', row.id, row.body_blob).text,
        outgoing: row.outgoing === 1,
        createdAt: row.created_at,
        state: row.state,
      }))
      .reverse();
  }

  async setMessageState(id: string, state: MessageState): Promise<void> {
    await this.db.runAsync('UPDATE messages SET state = ? WHERE id = ?', [state, id]);
  }

  async deleteMessagesOlderThan(cutoff: number): Promise<number> {
    const result = await this.db.runAsync('DELETE FROM messages WHERE created_at < ?', [cutoff]);
    return result.changes;
  }

  // -------------------------------------------------------------------------
  // Sessions
  // -------------------------------------------------------------------------

  private sessionKey(accountId: string, deviceId: string): string {
    return this.vault.blindIndex('session', `${accountId}/${deviceId}`);
  }

  async saveSession(session: StoredSession): Promise<void> {
    const id = this.sessionKey(session.accountId, session.deviceId);
    const blob: SessionBlob = {
      accountId: session.accountId,
      deviceId: session.deviceId,
      ratchet: serializeRatchet(session.ratchet),
      associatedData: toBase64(session.associatedData),
      mailboxSecret: toBase64(session.mailboxSecret),
    };
    await this.db.runAsync(
      `INSERT INTO sessions (id, account_ref, state_blob, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET state_blob = excluded.state_blob, updated_at = excluded.updated_at`,
      [id, this.conversationKey(session.accountId), this.vault.encryptJson('session', id, blob), Date.now()],
    );
  }

  async loadSession(accountId: string, deviceId: string): Promise<StoredSession | null> {
    const id = this.sessionKey(accountId, deviceId);
    const row = await this.db.getFirstAsync<SessionRow>('SELECT * FROM sessions WHERE id = ?', [id]);
    return row ? this.decodeSession(row) : null;
  }

  /** Every session with an account — one per device it has registered. */
  async loadSessionsFor(accountId: string): Promise<StoredSession[]> {
    const rows = await this.db.getAllAsync<SessionRow>(
      'SELECT * FROM sessions WHERE account_ref = ?',
      [this.conversationKey(accountId)],
    );
    return rows.map((row) => this.decodeSession(row));
  }

  private decodeSession(row: SessionRow): StoredSession {
    const blob = this.vault.decryptJson<SessionBlob>('session', row.id, row.state_blob);
    return {
      accountId: blob.accountId,
      deviceId: blob.deviceId,
      ratchet: deserializeRatchet(blob.ratchet),
      associatedData: fromBase64(blob.associatedData),
      mailboxSecret: fromBase64(blob.mailboxSecret),
    };
  }

  /** Drop a session so the next message re-runs the handshake from scratch. */
  async deleteSessions(accountId: string): Promise<void> {
    await this.db.runAsync('DELETE FROM sessions WHERE account_ref = ?', [
      this.conversationKey(accountId),
    ]);
  }

  // -------------------------------------------------------------------------
  // Prekey secrets
  // -------------------------------------------------------------------------

  async savePreKeySecret(id: number, kind: string, secret: Uint8Array): Promise<void> {
    await this.db.runAsync(
      `INSERT OR REPLACE INTO prekeys (id, kind, secret_blob, created_at) VALUES (?, ?, ?, ?)`,
      [id, kind, this.vault.encrypt('prekeys', `${kind}:${id}`, secret), Date.now()],
    );
  }

  async loadPreKeySecret(id: number, kind: string): Promise<Uint8Array | null> {
    const row = await this.db.getFirstAsync<{ secret_blob: string }>(
      'SELECT secret_blob FROM prekeys WHERE id = ? AND kind = ?',
      [id, kind],
    );
    return row ? this.vault.decrypt('prekeys', `${kind}:${id}`, row.secret_blob) : null;
  }

  /**
   * Destroy a consumed one-time prekey.
   *
   * Called after a session is established. A one-time prekey that survives its
   * use is no longer one-time, and the forward secrecy it was there to provide
   * is gone.
   */
  async deletePreKeySecret(id: number, kind: string): Promise<void> {
    await this.db.runAsync('DELETE FROM prekeys WHERE id = ? AND kind = ?', [id, kind]);
  }

  async listPreKeyIds(kind: string): Promise<number[]> {
    const rows = await this.db.getAllAsync<{ id: number }>(
      'SELECT id FROM prekeys WHERE kind = ? ORDER BY id',
      [kind],
    );
    return rows.map((r) => r.id);
  }

  // -------------------------------------------------------------------------
  // Meta
  // -------------------------------------------------------------------------

  async setMeta(key: string, value: string): Promise<void> {
    await this.db.runAsync(
      'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
      [key, value],
    );
  }

  async getMeta(key: string): Promise<string | null> {
    const row = await this.db.getFirstAsync<{ value: string }>(
      'SELECT value FROM meta WHERE key = ?',
      [key],
    );
    return row?.value ?? null;
  }

  /** Wipe everything. Pairs with eraseKeystore() for a full account deletion. */
  async eraseAll(): Promise<void> {
    await this.db.execAsync(`
      DELETE FROM messages;
      DELETE FROM sessions;
      DELETE FROM prekeys;
      DELETE FROM conversations;
      DELETE FROM meta;
      VACUUM;
    `);
  }

  async close(): Promise<void> {
    await this.db.closeAsync();
  }
}
