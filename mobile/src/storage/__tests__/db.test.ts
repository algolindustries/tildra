import { DatabaseSync } from 'node:sqlite';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Vault } from '../vault';
import type { Conversation, Database as DatabaseType, Message } from '../db';
import { randomBytes, toBase64, toHex, utf8 } from '../../crypto/primitives';

/**
 * The local database, against real SQLite.
 *
 * `expo-sqlite` is a binding to SQLite; `node:sqlite` is a different binding
 * to the same engine. Swapping one for the other runs every statement, index
 * and constraint in this file for real — the schema, the cascade, the upsert
 * conflict clauses, the ordering. What it does not run is Expo's binding, so
 * a bug in how *that* marshals a parameter would not show up here.
 *
 * Everything else is real: a real vault with a real master key, so the rows
 * below contain the ciphertext the phone would actually hold.
 *
 * The property worth more than any of the round-trips is the one the file's
 * own header claims — that nothing in a row says who this device talks to. It
 * is asserted by dumping every table rather than by checking the columns
 * someone remembered.
 */

function bridge(): unknown {
  const db = new DatabaseSync(':memory:');
  return {
    async execAsync(sql: string) {
      // WAL is meaningless for an in-memory database and node:sqlite rejects
      // the journal_mode change; the rest of the schema is what matters.
      db.exec(sql.replace(/PRAGMA journal_mode = WAL;/, ''));
    },
    async runAsync(sql: string, params: unknown[] = []) {
      const result = db.prepare(sql).run(...(params as never[]));
      return { changes: Number(result.changes), lastInsertRowId: Number(result.lastInsertRowid) };
    },
    async getAllAsync(sql: string, params: unknown[] = []) {
      return db.prepare(sql).all(...(params as never[]));
    },
    async getFirstAsync(sql: string, params: unknown[] = []) {
      return db.prepare(sql).get(...(params as never[])) ?? null;
    },
    async withTransactionAsync(fn: () => Promise<void>) {
      db.exec('BEGIN');
      try {
        await fn();
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
    async closeAsync() {
      db.close();
    },
    /** Test-only: every row of every table, for the disclosure check. */
    dump() {
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .all() as { name: string }[];
      return tables.flatMap((t) => db.prepare(`SELECT * FROM "${t.name}"`).all());
    },
  };
}

let sqlite: ReturnType<typeof bridge>;

vi.mock('expo-sqlite', () => ({
  async openDatabaseAsync() {
    return sqlite;
  },
}));

const { Database } = await import('../db');

const CONTACT = 'ACCT0123456789ABCDEFGHJKMN';
const HANDLE = 'ayse';
const DISPLAY_NAME = 'Ayşe Kaya';

function contact(overrides: Partial<Conversation> = {}): Conversation {
  return {
    accountId: CONTACT,
    handle: HANDLE,
    displayName: DISPLAY_NAME,
    identityKey: randomBytes(32),
    lastActivity: 1_000,
    unreadCount: 0,
    verified: false,
    identityChanged: false,
    ...overrides,
  };
}

async function open(): Promise<DatabaseType> {
  sqlite = bridge() as never;
  return Database.open(new Vault(randomBytes(32)));
}

let db: DatabaseType;

beforeEach(async () => {
  db = await open();
});

describe('what a forensic image would see', () => {
  it('holds no plaintext about who this device talks to', async () => {
    // The claim at the top of db.ts, checked against every row of every table
    // rather than the columns someone thought to look at. A new column added
    // without encryption fails this without anyone updating the test.
    const id = await db.upsertConversation(contact({ about: 'kitap okur' }));
    await db.insertMessage({
      id: 'm1',
      conversationId: id,
      text: 'yarın buluşalım',
      outgoing: false,
      createdAt: 2_000,
      state: 'delivered',
      senderAccountId: CONTACT,
    });
    await db.saveGroup({
      groupId: 'GROUP-ONE',
      name: 'Kitap Kulübü',
      members: [{ accountId: CONTACT, deviceId: 'DEVICE-ONE' }],
      createdAt: 3_000,
    } as never);
    await db.setMeta('some.key', 'some value');

    const serialized = JSON.stringify((sqlite as { dump(): unknown[] }).dump());
    for (const secret of [
      CONTACT,
      HANDLE,
      DISPLAY_NAME,
      'kitap okur',
      'yarın buluşalım',
      'GROUP-ONE',
      'Kitap Kulübü',
      'DEVICE-ONE',
    ]) {
      expect(serialized.includes(secret), `plaintext in a row: ${secret}`).toBe(false);
    }
  });

  it('does not use the account id as the row key', async () => {
    // The row id is a blind index. If it were the account id, every table
    // keyed by it would name the contact regardless of what is encrypted.
    const id = await db.upsertConversation(contact());
    expect(id).not.toContain(CONTACT);
    expect(id).not.toBe(CONTACT);
  });

  it('gives the same contact the same key and different contacts different ones', async () => {
    const first = await db.upsertConversation(contact());
    const same = await db.upsertConversation(contact({ lastActivity: 2_000 }));
    const other = await db.upsertConversation(contact({ accountId: 'OTHER456789ABCDEFGHJKMNPQR' }));
    expect(same).toBe(first);
    expect(other).not.toBe(first);
    expect(await db.listConversations()).toHaveLength(2);
  });

  it('keys the same contact differently under a different master key', async () => {
    // A blind index that did not depend on the vault key would let anyone
    // holding a stolen database confirm a guess about who a row belongs to.
    const first = await db.upsertConversation(contact());
    const second = await open().then((other) => other.upsertConversation(contact()));
    expect(second).not.toBe(first);
  });
});

describe('conversations', () => {
  it('comes back with its bytes intact', async () => {
    const original = contact({
      identityKey: randomBytes(32),
      avatar: randomBytes(64),
      about: 'kitap okur',
      profileUpdatedAt: 4_000,
      verified: true,
    });
    await db.upsertConversation(original);

    const stored = await db.getConversation(CONTACT);
    expect(stored?.accountId).toBe(CONTACT);
    expect(stored?.handle).toBe(HANDLE);
    expect(stored?.displayName).toBe(DISPLAY_NAME);
    expect(stored?.about).toBe('kitap okur');
    expect(stored?.profileUpdatedAt).toBe(4_000);
    expect(stored?.verified).toBe(true);
    expect(toHex(stored!.identityKey)).toBe(toHex(original.identityKey));
    expect(toHex(stored!.avatar!)).toBe(toHex(original.avatar!));
  });

  it('is null for a contact that is not there', async () => {
    expect(await db.getConversation('NOBODY0123456789ABCDEFGHJ')).toBeNull();
  });

  it('does not let a stale profile drag the conversation down the list', async () => {
    // last_activity is MAX(), because a profile update carrying an old
    // timestamp would otherwise reorder the chat list under the user.
    await db.upsertConversation(contact({ lastActivity: 5_000 }));
    await db.upsertConversation(contact({ lastActivity: 1_000, displayName: 'Ayşe K.' }));

    const stored = await db.getConversation(CONTACT);
    expect(stored?.lastActivity).toBe(5_000);
    expect(stored?.displayName).toBe('Ayşe K.');
  });

  it('does not clear the unread count on a profile update', async () => {
    // The upsert deliberately leaves unread_count alone. A contact changing
    // their photo must not mark their messages read.
    const id = await db.upsertConversation(contact());
    await db.insertMessage({
      id: 'm1',
      conversationId: id,
      text: 'bir',
      outgoing: false,
      createdAt: 2_000,
      state: 'delivered',
    });
    expect((await db.getConversation(CONTACT))?.unreadCount).toBe(1);

    await db.upsertConversation(contact({ displayName: 'Yeni Ad' }));
    expect((await db.getConversation(CONTACT))?.unreadCount).toBe(1);
  });

  it('orders the list by most recent activity', async () => {
    await db.upsertConversation(contact({ accountId: 'AAA0123456789ABCDEFGHJKMNP', lastActivity: 1_000 }));
    await db.upsertConversation(contact({ accountId: 'BBB0123456789ABCDEFGHJKMNP', lastActivity: 3_000 }));
    await db.upsertConversation(contact({ accountId: 'CCC0123456789ABCDEFGHJKMNP', lastActivity: 2_000 }));

    const order = (await db.listConversations()).map((c) => c.accountId);
    expect(order).toEqual([
      'BBB0123456789ABCDEFGHJKMNP',
      'CCC0123456789ABCDEFGHJKMNP',
      'AAA0123456789ABCDEFGHJKMNP',
    ]);
  });

  it('records and clears an identity change', async () => {
    await db.upsertConversation(contact());
    const newKey = randomBytes(32);
    await db.flagIdentityChange(CONTACT, newKey);

    const flagged = await db.getConversation(CONTACT);
    expect(flagged?.identityChanged).toBe(true);
    expect(toHex(flagged!.identityKey)).toBe(toHex(newKey));

    await db.acknowledgeIdentityChange(CONTACT);
    expect((await db.getConversation(CONTACT))?.identityChanged).toBe(false);
  });
});

describe('messages', () => {
  let id: string;

  beforeEach(async () => {
    id = await db.upsertConversation(contact());
  });

  async function send(overrides: Partial<Message>): Promise<void> {
    await db.insertMessage({
      id: Math.random().toString(36).slice(2),
      conversationId: id,
      text: 'merhaba',
      outgoing: false,
      createdAt: 2_000,
      state: 'delivered',
      ...overrides,
    });
  }

  it('round-trips text and an attachment', async () => {
    await db.insertMessage({
      id: 'm1',
      conversationId: id,
      text: 'bak',
      outgoing: true,
      createdAt: 2_000,
      state: 'sent',
      attachment: {
        id: 'blob-1',
        key: randomBytes(32),
        nonce: randomBytes(24),
        digest: randomBytes(32),
        size: 1234,
        mimeType: 'image/jpeg',
      },
    });

    const [message] = await db.listMessages(id);
    expect(message.text).toBe('bak');
    expect(message.outgoing).toBe(true);
    expect(message.state).toBe('sent');
    expect(message.attachment?.size).toBe(1234);
    expect(message.attachment?.mimeType).toBe('image/jpeg');
  });

  it('returns oldest first, having selected the newest', async () => {
    // The query sorts DESC and takes a limit, then the result is reversed, so
    // asking for 2 of 3 gives the two newest in reading order — not the two
    // oldest, and not the newest two upside down.
    await send({ id: 'a', createdAt: 1_000, text: 'bir' });
    await send({ id: 'b', createdAt: 2_000, text: 'iki' });
    await send({ id: 'c', createdAt: 3_000, text: 'üç' });

    expect((await db.listMessages(id)).map((m) => m.text)).toEqual(['bir', 'iki', 'üç']);
    expect((await db.listMessages(id, 2)).map((m) => m.text)).toEqual(['iki', 'üç']);
  });

  it('pages backwards from a timestamp', async () => {
    await send({ id: 'a', createdAt: 1_000, text: 'bir' });
    await send({ id: 'b', createdAt: 2_000, text: 'iki' });
    await send({ id: 'c', createdAt: 3_000, text: 'üç' });

    expect((await db.listMessages(id, 100, 3_000)).map((m) => m.text)).toEqual(['bir', 'iki']);
    expect((await db.listMessages(id, 100, 1_000)).map((m) => m.text)).toEqual([]);
  });

  it('counts an incoming message as unread and an outgoing one as not', async () => {
    await send({ outgoing: false });
    await send({ outgoing: true });
    expect((await db.getConversation(CONTACT))?.unreadCount).toBe(1);

    await db.markRead(id);
    expect((await db.getConversation(CONTACT))?.unreadCount).toBe(0);
  });

  it('moves the conversation up when a message arrives', async () => {
    await send({ createdAt: 9_000 });
    expect((await db.getConversation(CONTACT))?.lastActivity).toBe(9_000);
  });

  it('changes a message state without touching the body', async () => {
    await send({ id: 'm1', text: 'gizli', state: 'pending' });
    await db.setMessageState('m1', 'delivered');
    const [message] = await db.listMessages(id);
    expect(message.state).toBe('delivered');
    expect(message.text).toBe('gizli');
  });

  it('deletes messages older than a cutoff and says how many', async () => {
    await send({ id: 'a', createdAt: 1_000 });
    await send({ id: 'b', createdAt: 2_000 });
    await send({ id: 'c', createdAt: 3_000 });

    expect(await db.deleteMessagesOlderThan(2_500)).toBe(2);
    expect((await db.listMessages(id)).map((m) => m.id)).toEqual(['c']);
  });

  it('leaves nothing behind when everything is erased', async () => {
    await send({ id: 'a', createdAt: 1_000 });
    await db.eraseAll();
    expect(await db.listMessages(id)).toEqual([]);
  });
});

describe('meta', () => {
  it('stores, reads back and overwrites', async () => {
    expect(await db.getMeta('missing')).toBeNull();
    await db.setMeta('k', 'first');
    expect(await db.getMeta('k')).toBe('first');
    await db.setMeta('k', 'second');
    expect(await db.getMeta('k')).toBe('second');
  });

  it('keeps values whose caller already encrypted them', async () => {
    // The identity and prekey rows are vault blobs written through here, so
    // this must be byte-exact rather than helpfully normalised.
    const blob = toBase64(utf8('{"not":"json to this table"}'));
    await db.setMeta('identity.v1', blob);
    expect(await db.getMeta('identity.v1')).toBe(blob);
  });
});

describe('groups', () => {
  const group = {
    groupId: 'GROUP-ONE',
    name: 'Kitap Kulübü',
    members: [{ accountId: CONTACT, deviceId: 'D1' }],
    createdAt: 3_000,
  };

  it('round-trips membership, which lives nowhere else', async () => {
    await db.saveGroup(group as never);
    const stored = await db.loadGroup('GROUP-ONE');
    expect(stored?.name).toBe('Kitap Kulübü');
    expect(stored?.members).toEqual([{ accountId: CONTACT, deviceId: 'D1' }]);
  });

  it('is null for a group that is not there', async () => {
    expect(await db.loadGroup('NOPE')).toBeNull();
  });

  it('replaces membership on save rather than accumulating it', async () => {
    // Removing a member has to actually remove them: a stale row means the
    // next sender-key rotation still fans out to somebody who was kicked.
    await db.saveGroup(group as never);
    await db.saveGroup({ ...group, members: [] } as never);
    expect((await db.loadGroup('GROUP-ONE'))?.members).toEqual([]);
    expect(await db.listGroups()).toHaveLength(1);
  });

  it('lists newest first', async () => {
    await db.saveGroup(group as never);
    await db.saveGroup({ ...group, groupId: 'GROUP-TWO', name: 'Yeni', createdAt: 9_000 } as never);
    expect((await db.listGroups()).map((g) => g.name)).toEqual(['Yeni', 'Kitap Kulübü']);
  });
});

describe('erasing the account', () => {
  it('empties every table it claims to', async () => {
    // "Wipe everything. Pairs with eraseKeystore() for a full account
    // deletion." Whatever survives this is data the user was told was gone.
    const id = await db.upsertConversation(contact());
    await db.insertMessage({
      id: 'm1',
      conversationId: id,
      text: 'gizli',
      outgoing: false,
      createdAt: 2_000,
      state: 'delivered',
    });
    await db.saveGroup({
      groupId: 'GROUP-ONE',
      name: 'Kitap Kulübü',
      members: [{ accountId: CONTACT, deviceId: 'D1' }],
      createdAt: 3_000,
    } as never);
    await db.setMeta('identity.v1', 'blob');

    await db.eraseAll();

    expect(await db.listConversations()).toEqual([]);
    expect(await db.listMessages(id)).toEqual([]);
    expect(await db.listGroups()).toEqual([]);
    expect(await db.getMeta('identity.v1')).toBeNull();
    expect((sqlite as { dump(): unknown[] }).dump()).toEqual([]);
  });

  it('does not throw part way through', async () => {
    // It used to: the statement list named a `prekeys` table the schema does
    // not have, so SQLite stopped there. Everything after that line survived,
    // and the caller never reached eraseKeystore().
    await db.upsertConversation(contact());
    await expect(db.eraseAll()).resolves.toBeUndefined();
  });
});
