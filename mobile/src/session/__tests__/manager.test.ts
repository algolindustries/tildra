/**
 * Two SessionManagers holding a conversation through the real Go server.
 *
 * This is the test that would catch a regression a user would actually
 * notice: messages not arriving, arriving twice, arriving out of order, or —
 * worst — arriving over a session whose identity key quietly changed.
 */

import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { TildraClient } from '../../api/client';
import { TildraSocket } from '../../api/socket';
import { IdentityChangedError, SessionManager } from '../manager';
import { MemorySessionStore } from './memory-store';
import { generateIdentity, generatePreKeys } from '../../crypto/identity';
import { randomBytes, toBase64 } from '../../crypto/primitives';

const SERVER_DIR = join(__dirname, '../../../../server');
const PORT = 8792;
const BASE_URL = `http://127.0.0.1:${PORT}`;

function goAvailable(): boolean {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return existsSync(join(SERVER_DIR, 'go.mod'));
  } catch {
    return false;
  }
}

const describeIntegration = goAvailable() ? describe : describe.skip;
let server: ChildProcess | null = null;

async function waitForHealth(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${BASE_URL}/healthz`)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('server did not start');
}

/** A fully wired device: identity, keys published, manager, live socket. */
interface Device {
  name: string;
  accountId: string;
  deviceId: string;
  manager: SessionManager;
  store: MemorySessionStore;
  client: TildraClient;
  identity: ReturnType<typeof generateIdentity>;
  socket: TildraSocket;
  received: string[];
  errors: Error[];
}

async function bringUp(name: string): Promise<Device> {
  const identity = generateIdentity();
  const client = new TildraClient({ baseUrl: BASE_URL });
  const { accountId, deviceId } = await client.register(identity, name);
  await client.login(identity, accountId, deviceId);

  const { secrets, upload } = generatePreKeys(identity, { count: 30 });
  await client.publishKeys(upload);

  const store = new MemorySessionStore();
  const received: string[] = [];
  const errors: Error[] = [];

  // The socket is created first so the manager can hand it new mailboxes as
  // sessions appear — the wiring the real app uses.
  let socket: TildraSocket | undefined;

  const manager = new SessionManager({
    identity,
    accountId,
    deviceId,
    client,
    store,
    preKeys: secrets,
    randomId: () => toBase64(randomBytes(16)),
    onMailboxesChanged: (mailboxes) => socket?.subscribe(mailboxes),
    events: {
      onMessage: (message) => received.push(message.text),
      onError: (error) => errors.push(error),
    },
  });

  await manager.publishMailboxes();

  socket = new TildraSocket(BASE_URL, client.getCredentials()!.token, {
    onEnvelope: (envelope) => manager.receiveEnvelope(envelope).then(() => undefined),
    onError: (error) => errors.push(error),
  });
  socket.connect();
  await new Promise((r) => setTimeout(r, 300));

  return { name, accountId, deviceId, manager, store, client, identity, socket, received, errors };
}

async function waitFor(predicate: () => boolean, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 50));
  }
}

describeIntegration('session manager', () => {
  beforeAll(async () => {
    const binary = join(mkdtempSync(join(tmpdir(), 'tildra-mgr-')), 'tildrad');
    execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], {
      cwd: SERVER_DIR,
      stdio: 'inherit',
    });
    server = spawn(binary, [], {
      env: { ...process.env, TILDRA_ADDR: `:${PORT}`, TILDRA_DATABASE_URL: '' },
      stdio: 'ignore',
    });
    await waitForHealth();
  }, 120_000);

  afterAll(() => server?.kill('SIGTERM'));

  it('delivers a first message from a cold start', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);

    expect(bob.received).toEqual(['merhaba']);
    expect(bob.errors).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 40_000);

  it('holds a back-and-forth conversation', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'nasılsın?');
    await waitFor(() => bob.received.length === 1);

    // Bob replies. This is the interesting direction: it uses the session Bob
    // built from Alice's init, and a mailbox derived from the shared secret
    // rather than the contact inbox.
    await bob.manager.sendMessage(alice.accountId, 'iyiyim, sen?');
    await waitFor(() => alice.received.length === 1);

    await alice.manager.sendMessage(bob.accountId, 'ben de');
    await waitFor(() => bob.received.length === 2);

    expect(bob.received).toEqual(['nasılsın?', 'ben de']);
    expect(alice.received).toEqual(['iyiyim, sen?']);
    expect([...alice.errors, ...bob.errors]).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 40_000);

  it('preserves order across a burst', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    for (let i = 0; i < 8; i++) {
      await alice.manager.sendMessage(bob.accountId, `mesaj ${i}`);
    }
    await waitFor(() => bob.received.length === 8, 20_000);

    expect(bob.received).toEqual([0, 1, 2, 3, 4, 5, 6, 7].map((i) => `mesaj ${i}`));

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('does not lose a second message sent before the peer has replied', async () => {
    // Regression, and the failure a user would hit first: message 1 opens the
    // session and goes to the contact inbox; message 2 used to go to the
    // per-session mailbox, which the recipient has not registered yet, so the
    // server refused it and the message vanished.
    //
    // Bob's socket is deliberately not connected while Alice sends, so there
    // is no chance he processes message 1 in between.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    bob.socket.close();
    await new Promise((r) => setTimeout(r, 200));

    await alice.manager.sendMessage(bob.accountId, 'bir');
    await alice.manager.sendMessage(bob.accountId, 'iki');
    await alice.manager.sendMessage(bob.accountId, 'üç');

    bob.socket.connect();
    await waitFor(() => bob.received.length === 3, 15_000);

    expect(bob.received).toEqual(['bir', 'iki', 'üç']);
    expect(bob.errors).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('records the conversation and message on both sides', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'kayıt');
    await waitFor(() => bob.received.length > 0);

    const aliceSide = await alice.store.getConversation(bob.accountId);
    const bobSide = await bob.store.getConversation(alice.accountId);
    expect(aliceSide).not.toBeNull();
    expect(bobSide).not.toBeNull();

    expect(alice.store.messages.filter((m) => m.outgoing)).toHaveLength(1);
    expect(alice.store.messages[0].state).toBe('sent');
    expect(bob.store.messages.filter((m) => !m.outgoing)).toHaveLength(1);

    alice.socket.close();
    bob.socket.close();
  }, 40_000);

  it('agrees on the safety number from both directions', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'doğrula');
    await waitFor(() => bob.received.length > 0);

    expect(await alice.manager.safetyNumberFor(bob.accountId)).toBe(
      await bob.manager.safetyNumberFor(alice.accountId),
    );

    alice.socket.close();
    bob.socket.close();
  }, 40_000);

  it('blocks sending when a contact identity key changes', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'ilk');
    await waitFor(() => bob.received.length > 0);

    // Simulate a server handing Alice a different identity key for Bob — the
    // shape a MITM takes in practice.
    const conversation = await alice.store.getConversation(bob.accountId);
    await alice.store.upsertConversation({
      ...conversation!,
      identityKey: generateIdentity().publicKey,
    });
    alice.store.sessions.clear();

    await expect(alice.manager.sendMessage(bob.accountId, 'ikinci')).rejects.toBeInstanceOf(
      IdentityChangedError,
    );

    // The conversation is flagged, and the failed message is not left looking
    // like it was sent.
    const flagged = await alice.store.getConversation(bob.accountId);
    expect(flagged?.identityChanged).toBe(true);
    expect(alice.store.messages.at(-1)?.state).toBe('failed');

    alice.socket.close();
    bob.socket.close();
  }, 40_000);

  it('refuses to send into a conversation flagged as changed', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.store.upsertConversation({
      accountId: bob.accountId,
      identityKey: bob.identity.publicKey,
      lastActivity: Date.now(),
      unreadCount: 0,
      verified: false,
      identityChanged: true,
    });

    await expect(alice.manager.sendMessage(bob.accountId, 'engellenmeli')).rejects.toBeInstanceOf(
      IdentityChangedError,
    );

    alice.socket.close();
    bob.socket.close();
  }, 40_000);

  it('unblocks the conversation once the user verifies', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.store.upsertConversation({
      accountId: bob.accountId,
      identityKey: bob.identity.publicKey,
      lastActivity: Date.now(),
      unreadCount: 0,
      verified: false,
      identityChanged: true,
    });

    await alice.manager.markVerified(bob.accountId);
    await alice.manager.sendMessage(bob.accountId, 'artık gönderebilirim');
    await waitFor(() => bob.received.length > 0);

    expect(bob.received).toEqual(['artık gönderebilirim']);

    alice.socket.close();
    bob.socket.close();
  }, 40_000);

  it('tops up one-time prekeys when the pool runs low', async () => {
    const device = await bringUp('Topper');

    // Drain the pool by fetching bundles as other accounts would.
    const drainer = new TildraClient({ baseUrl: BASE_URL });
    const drainerIdentity = generateIdentity();
    const registered = await drainer.register(drainerIdentity, 'Drainer');
    await drainer.login(drainerIdentity, registered.accountId, registered.deviceId);
    for (let i = 0; i < 25; i++) {
      await drainer.fetchBundle(device.accountId, device.deviceId);
    }

    const before = await device.client.preKeyCount();
    expect(before.oneTimePreKeys).toBeLessThan(20);

    expect(await device.manager.topUpPreKeysIfLow()).toBe(true);
    const after = await device.client.preKeyCount();
    expect(after.oneTimePreKeys).toBeGreaterThan(before.oneTimePreKeys);

    device.socket.close();
  }, 60_000);

  it('reports a send to an account with no devices instead of failing silently', async () => {
    const alice = await bringUp('Alice');
    await expect(
      alice.manager.sendMessage('0000000000000000000000000A', 'nowhere'),
    ).rejects.toThrow();
    alice.socket.close();
  }, 30_000);
});
