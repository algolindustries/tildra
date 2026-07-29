/**
 * In-memory SessionStore for tests.
 *
 * Mirrors the semantics of the SQLite implementation that matter to the
 * manager: conversations keyed by account, sessions keyed by account+device,
 * and identity changes that stick until acknowledged.
 */

import { Conversation, Message, MessageState, StoredSession } from '../../storage/db';
import { SessionStore } from '../manager';

export class MemorySessionStore implements SessionStore {
  readonly conversations = new Map<string, Conversation & { id: string }>();
  readonly messages: Message[] = [];
  readonly sessions = new Map<string, StoredSession>();
  readonly meta = new Map<string, string>();

  private key(accountId: string): string {
    return `conv:${accountId}`;
  }

  async upsertConversation(c: Conversation): Promise<string> {
    const id = this.key(c.accountId);
    this.conversations.set(c.accountId, { ...c, id });
    return id;
  }

  async getConversation(accountId: string): Promise<(Conversation & { id: string }) | null> {
    return this.conversations.get(accountId) ?? null;
  }

  async flagIdentityChange(accountId: string, newIdentityKey: Uint8Array): Promise<void> {
    const existing = this.conversations.get(accountId);
    if (!existing) return;
    this.conversations.set(accountId, {
      ...existing,
      identityKey: newIdentityKey,
      verified: false,
      identityChanged: true,
    });
  }

  async insertMessage(m: Message): Promise<void> {
    const index = this.messages.findIndex((existing) => existing.id === m.id);
    if (index >= 0) this.messages[index] = m;
    else this.messages.push(m);
  }

  async setMessageState(id: string, state: MessageState): Promise<void> {
    const message = this.messages.find((m) => m.id === id);
    if (message) message.state = state;
  }

  async saveSession(s: StoredSession): Promise<void> {
    this.sessions.set(`${s.accountId}/${s.deviceId}`, s);
  }

  async loadSession(accountId: string, deviceId: string): Promise<StoredSession | null> {
    return this.sessions.get(`${accountId}/${deviceId}`) ?? null;
  }

  async loadSessionsFor(accountId: string): Promise<StoredSession[]> {
    return [...this.sessions.values()].filter((s) => s.accountId === accountId);
  }

  async setMeta(key: string, value: string): Promise<void> {
    this.meta.set(key, value);
  }

  async getMeta(key: string): Promise<string | null> {
    return this.meta.get(key) ?? null;
  }
}
