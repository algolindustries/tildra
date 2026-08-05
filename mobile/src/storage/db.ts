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
import { MESSAGE_STATE_ORDER, MessageState } from './message-state';
import { fromBase64, toBase64 } from '../crypto/primitives';
import { SessionInit } from '../crypto/pqxdh';
import {
  ReceiverKeyState,
  SenderKeyState,
  SerializedReceiverKey,
  SerializedSenderKey,
  deserializeReceiverKey,
  deserializeSenderKey,
  serializeReceiverKey,
  serializeSenderKey,
} from '../crypto/group';
import type { StoredGroup } from '../session/manager';
import {
  AttachmentRef,
  SerializedAttachmentRef,
  deserializeAttachmentRef,
  serializeAttachmentRef,
} from '../crypto/attachment';
import {
  RatchetState,
  SerializedRatchet,
  deserializeRatchet,
  serializeRatchet,
} from '../crypto/ratchet';

// Re-exported so the many call sites that already import the message model
// from here keep working; the definitions live one file away because the
// session layer and its test double need the ordering as a *value*, and this
// module reaches `expo-sqlite`.
//
// `export { X } from './x'` rather than re-exporting the imported binding.
// Babel transforms this file without type information, so it cannot tell a
// value being re-exported from a type being re-exported and elides the import
// — `tsc` accepts the shorter form and Metro fails on it at runtime, which is
// the worst place to find out.
export { MESSAGE_STATE_ORDER } from './message-state';
export type { MessageState } from './message-state';

export interface Conversation {
  accountId: string;
  handle?: string;
  /** The name the contact chose, delivered over their pairwise session. */
  displayName?: string;
  about?: string;
  /** Encoded image bytes. Never leaves the device unencrypted. */
  avatar?: Uint8Array;
  /** When the stored profile was authored, so a stale one cannot overwrite. */
  profileUpdatedAt?: number;
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
  /** Caption for an attachment, or the message body. */
  text: string;
  outgoing: boolean;
  createdAt: number;
  state: MessageState;
  /** Present when the message carries a file. */
  attachment?: AttachmentRef;
  /**
   * Who sent it, for a conversation with more than two people in it.
   *
   * Absent in a pairwise chat, where the answer is "the other one" and storing
   * it would be a second place for the same fact to be wrong.
   */
  senderAccountId?: string;
  /**
   * For an incoming message, the id its *sender* gave it.
   *
   * Receipts name a message, and the two ends do not share an id — each
   * generates its own on the way into its own database. This is the sender's,
   * kept so a receipt going back can name something they will recognise.
   * Absent on outgoing messages, where `id` is already the shared name, and
   * absent on anything received from a peer too old to send one.
   */
  remoteId?: string;
}

export interface StoredSession {
  accountId: string;
  deviceId: string;
  ratchet: RatchetState;
  associatedData: Uint8Array;
  mailboxSecret: Uint8Array;
  /**
   * True once we have received a message over this session, which is the only
   * proof that the peer processed our handshake.
   *
   * Until then the initiator keeps addressing the stable contact inbox and
   * keeps attaching the session init — the peer has not yet registered the
   * per-session mailbox, so anything sent there is refused and lost.
   */
  confirmed: boolean;
  /**
   * Initiator side: the handshake header to keep attaching until the session
   * is confirmed, because the peer may not have received the first copy.
   */
  pendingInit?: SessionInit;
  /**
   * Responder side: identifies the handshake this session came from, so a
   * repeated init from the same handshake is recognised rather than
   * re-accepted. Re-accepting would fail — the one-time prekeys it names are
   * already consumed — and would discard a working session.
   */
  initFingerprint?: string;
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
  about?: string;
  avatar?: string;
  profileUpdatedAt?: number;
  identityKey: string;
}

interface SessionBlob {
  accountId: string;
  deviceId: string;
  ratchet: SerializedRatchet;
  associatedData: string;
  mailboxSecret: string;
  confirmed: boolean;
  initFingerprint?: string;
  pendingInit?: {
    identityKey: string;
    ephemeralKey: string;
    kemCiphertext: string;
    signedPreKeyId: number;
    pqPreKeyId: number;
    oneTimePreKeyId?: number;
    usedOneTimePq: boolean;
  };
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

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Group state. Membership lives here and nowhere else: the server is told how
-- many mailboxes to fan out to and never who is in the group.
CREATE TABLE IF NOT EXISTS groups (
  id         TEXT PRIMARY KEY,
  meta_blob  TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Our sending chain for a group. One row per group.
CREATE TABLE IF NOT EXISTS group_sender_keys (
  id         TEXT PRIMARY KEY,
  state_blob TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- A receiving chain per (group, member).
CREATE TABLE IF NOT EXISTS group_receiver_keys (
  id         TEXT PRIMARY KEY,
  group_ref  TEXT NOT NULL,
  state_blob TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS group_receiver_keys_by_group ON group_receiver_keys(group_ref);
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
      about: conversation.about,
      avatar: conversation.avatar ? toBase64(conversation.avatar) : undefined,
      profileUpdatedAt: conversation.profileUpdatedAt,
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
      about: meta.about,
      avatar: meta.avatar ? fromBase64(meta.avatar) : undefined,
      profileUpdatedAt: meta.profileUpdatedAt,
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
          this.vault.encryptJson('message', message.id, {
            text: message.text,
            attachment: message.attachment
              ? serializeAttachmentRef(message.attachment)
              : undefined,
            senderAccountId: message.senderAccountId,
            remoteId: message.remoteId,
          }),
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
      .map((row) => {
        const body = this.vault.decryptJson<{
          text: string;
          attachment?: SerializedAttachmentRef;
          senderAccountId?: string;
          remoteId?: string;
        }>('message', row.id, row.body_blob);
        return {
          id: row.id,
          conversationId: row.conversation_id,
          text: body.text,
          attachment: body.attachment ? deserializeAttachmentRef(body.attachment) : undefined,
          outgoing: row.outgoing === 1,
          createdAt: row.created_at,
          state: row.state,
          senderAccountId: body.senderAccountId,
          remoteId: body.remoteId,
        };
      })
      .reverse();
  }

  async setMessageState(id: string, state: MessageState): Promise<void> {
    await this.db.runAsync('UPDATE messages SET state = ? WHERE id = ?', [state, id]);
  }

  /**
   * Move a message forward, never back.
   *
   * Receipts cross the network independently, and the ratchet delivers what
   * arrives rather than what was sent first — so a `delivered` can land after
   * the `read` it precedes. Taking the later one on trust would flip a message
   * that has been read back to two grey ticks, which reads to the user as the
   * network having lost something.
   *
   * `failed` is the exception and is applied unconditionally by the send path:
   * it is this device's own observation that nothing went out, not a claim
   * from the other end.
   */
  async advanceMessageState(id: string, state: MessageState): Promise<void> {
    await this.db.runAsync(
      `UPDATE messages SET state = ?
        WHERE id = ?
          AND CASE state
                WHEN 'failed' THEN -1 WHEN 'pending' THEN 0 WHEN 'sent' THEN 1
                WHEN 'delivered' THEN 2 WHEN 'read' THEN 3 ELSE 0
              END < ?`,
      [state, id, MESSAGE_STATE_ORDER[state]],
    );
  }

  /**
   * Incoming messages in a conversation that the sender named, newest last.
   *
   * Used to build a read receipt when a conversation is opened. Only messages
   * carrying a `remoteId` can be acknowledged, because only those have a name
   * the sender would recognise.
   */
  async receiptableIncoming(conversationId: string, limit = 256): Promise<Message[]> {
    const messages = await this.listMessages(conversationId, limit);
    return messages.filter((m) => !m.outgoing && m.remoteId);
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
      confirmed: session.confirmed,
      initFingerprint: session.initFingerprint,
      pendingInit: session.pendingInit && {
        ...session.pendingInit,
        identityKey: toBase64(session.pendingInit.identityKey),
        ephemeralKey: toBase64(session.pendingInit.ephemeralKey),
        kemCiphertext: toBase64(session.pendingInit.kemCiphertext),
      },
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
      confirmed: blob.confirmed ?? false,
      initFingerprint: blob.initFingerprint,
      pendingInit: blob.pendingInit && {
        ...blob.pendingInit,
        identityKey: fromBase64(blob.pendingInit.identityKey),
        ephemeralKey: fromBase64(blob.pendingInit.ephemeralKey),
        kemCiphertext: fromBase64(blob.pendingInit.kemCiphertext),
      },
    };
  }

  /** Drop a session so the next message re-runs the handshake from scratch. */
  async deleteSessions(accountId: string): Promise<void> {
    await this.db.runAsync('DELETE FROM sessions WHERE account_ref = ?', [
      this.conversationKey(accountId),
    ]);
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

  // -------------------------------------------------------------------------
  // Groups
  // -------------------------------------------------------------------------

  private groupKey(groupId: string): string {
    return this.vault.blindIndex('contact', `group:${groupId}`);
  }

  async saveGroup(group: StoredGroup): Promise<void> {
    const id = this.groupKey(group.groupId);
    await this.db.runAsync(
      `INSERT INTO groups (id, meta_blob, created_at) VALUES (?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET meta_blob = excluded.meta_blob`,
      [id, this.vault.encryptJson('contact', id, group), group.createdAt],
    );
  }

  async loadGroup(groupId: string): Promise<StoredGroup | null> {
    const id = this.groupKey(groupId);
    const row = await this.db.getFirstAsync<{ meta_blob: string }>(
      'SELECT meta_blob FROM groups WHERE id = ?',
      [id],
    );
    return row ? this.vault.decryptJson<StoredGroup>('contact', id, row.meta_blob) : null;
  }

  async listGroups(): Promise<StoredGroup[]> {
    const rows = await this.db.getAllAsync<{ id: string; meta_blob: string }>(
      'SELECT id, meta_blob FROM groups ORDER BY created_at DESC',
    );
    return rows.map((r) => this.vault.decryptJson<StoredGroup>('contact', r.id, r.meta_blob));
  }

  async saveSenderKey(groupId: string, state: SenderKeyState): Promise<void> {
    const id = this.vault.blindIndex('session', `sender:${groupId}`);
    await this.db.runAsync(
      `INSERT INTO group_sender_keys (id, state_blob, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET state_blob = excluded.state_blob, updated_at = excluded.updated_at`,
      [id, this.vault.encryptJson('session', id, serializeSenderKey(state)), Date.now()],
    );
  }

  async loadSenderKey(groupId: string): Promise<SenderKeyState | null> {
    const id = this.vault.blindIndex('session', `sender:${groupId}`);
    const row = await this.db.getFirstAsync<{ state_blob: string }>(
      'SELECT state_blob FROM group_sender_keys WHERE id = ?',
      [id],
    );
    return row
      ? deserializeSenderKey(this.vault.decryptJson<SerializedSenderKey>('session', id, row.state_blob))
      : null;
  }

  async saveReceiverKey(groupId: string, memberId: string, state: ReceiverKeyState): Promise<void> {
    const id = this.vault.blindIndex('session', `receiver:${groupId}/${memberId}`);
    await this.db.runAsync(
      `INSERT INTO group_receiver_keys (id, group_ref, state_blob, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET state_blob = excluded.state_blob, updated_at = excluded.updated_at`,
      [
        id,
        this.groupKey(groupId),
        this.vault.encryptJson('session', id, serializeReceiverKey(state)),
        Date.now(),
      ],
    );
  }

  async loadReceiverKey(groupId: string, memberId: string): Promise<ReceiverKeyState | null> {
    const id = this.vault.blindIndex('session', `receiver:${groupId}/${memberId}`);
    const row = await this.db.getFirstAsync<{ state_blob: string }>(
      'SELECT state_blob FROM group_receiver_keys WHERE id = ?',
      [id],
    );
    return row
      ? deserializeReceiverKey(
          this.vault.decryptJson<SerializedReceiverKey>('session', id, row.state_blob),
        )
      : null;
  }

  /**
   * Forget one member's chain.
   *
   * What a removal actually needs. Dropping *every* receiver key instead —
   * which is what this used to do — throws away the chains of the members who
   * are staying, and they have no reason to send another distribution, so the
   * group goes permanently silent for whoever did the removing.
   */
  async deleteReceiverKey(groupId: string, memberId: string): Promise<void> {
    await this.db.runAsync('DELETE FROM group_receiver_keys WHERE id = ?', [
      this.vault.blindIndex('session', `receiver:${groupId}/${memberId}`),
    ]);
  }

  /**
   * Wipe everything. Pairs with eraseKeystore() for a full account deletion.
   *
   * The statement list named a `prekeys` table for a while. There is no such
   * table — prekeys live in `meta` — so SQLite stopped at that line and every
   * table after it survived, including the contact list and group membership.
   * Worse, it threw, and the caller reached this before erasing the keystore:
   * a user who asked to delete their account kept both the data and the key
   * to it. Adding a table to the schema means adding it here, which is why
   * the test asserts the database is empty afterwards rather than listing
   * tables it remembers.
   */
  async eraseAll(): Promise<void> {
    await this.db.execAsync(`
      DELETE FROM messages;
      DELETE FROM sessions;
      DELETE FROM conversations;
      DELETE FROM group_receiver_keys;
      DELETE FROM group_sender_keys;
      DELETE FROM groups;
      DELETE FROM meta;
      VACUUM;
    `);
  }

  async close(): Promise<void> {
    await this.db.closeAsync();
  }
}
