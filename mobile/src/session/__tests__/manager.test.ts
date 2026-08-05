/**
 * Two SessionManagers holding a conversation through the real Go server.
 *
 * This is the test that would catch a regression a user would actually
 * notice: messages not arriving, arriving twice, arriving out of order, or —
 * worst — arriving over a session whose identity key quietly changed.
 */

import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { ApiError, TildraClient } from '../../api/client';
import { TildraSocket } from '../../api/socket';
import {
  CHECKPOINT_META_KEY,
  IdentityChangedError,
  SIGNED_PREKEY_META_KEY,
  SessionManager,
  groupConversationKey,
} from '../manager';
import { MemorySessionStore } from './memory-store';
import { ReceiptKind } from '../../crypto/content';
import { freePort } from '../../__tests__/free-port';
import {
  SIGNED_PREKEY_ROTATION_MS,
  generateIdentity,
  generatePreKeys,
} from '../../crypto/identity';
import { acceptSession, initiateSession } from '../../crypto/pqxdh';
import { SerializedPreKeys, decodePreKeys, encodePreKeys } from '../../storage/prekeys';
import { equal, fromBase64, fromUtf8, randomBytes, toBase64, utf8 } from '../../crypto/primitives';
import { SplitViewError, serializeTreeHead, verifyHandleProof } from '../../crypto/transparency';
import {
  CallSession,
  CallSignal,
  CallSignalKind,
  encodeCallSignal,
  sdpFingerprint,
  signCallSdp,
} from '../../crypto/calling';
import { ContentType, callSignalContent, encodeContent, textContent } from '../../crypto/content';
import { createSenderKey, encodeGroupMessage, encryptGroupMessage } from '../../crypto/group';
import { readSafetyCode } from '../../crypto/scan';
import {
  generateRecoveryPhrase,
  openBackup,
  recoveryKeys,
  sealBackup,
} from '../../crypto/recovery';
import { encrypt } from '../../crypto/ratchet';
import { sealEnvelope } from '../../crypto/sealed';

const SERVER_DIR = join(__dirname, '../../../../server');
// Assigned in beforeAll from a port the OS hands out. A fixed one is fine
// until a killed run leaves its server behind holding it.
let BASE_URL = '';

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
  groupReceived: { groupId: string; text: string }[];
  incomingCalls: { call: CallSession; sdp: string }[];
  answers: { call: CallSession; sdp: string }[];
  candidates: string[];
  callChanges: CallSession[];
  renegotiations: { call: CallSession; sdp: string }[];
  renegotiationAnswers: { call: CallSession; sdp: string }[];
  splitViews: { source: string; error: SplitViewError }[];
  profileChanges: string[];
  receipts: { accountId: string; kind: ReceiptKind; messageIds: string[] }[];
  typing: { accountId: string; typing: boolean }[];
  member: () => { accountId: string; deviceId: string };
}

async function bringUp(
  name: string,
  options: { ringingTimeoutMs?: number } = {},
): Promise<Device> {
  const identity = generateIdentity();
  const client = new TildraClient({ baseUrl: BASE_URL });
  const { accountId, deviceId } = await client.register(identity, name);
  await client.login(identity, accountId, deviceId);

  const { secrets, upload } = generatePreKeys(identity, { count: 30 });
  await client.publishKeys(upload);

  const store = new MemorySessionStore();
  const received: string[] = [];
  const groupReceived: { groupId: string; text: string }[] = [];
  const errors: Error[] = [];
  const incomingCalls: { call: CallSession; sdp: string }[] = [];
  const answers: { call: CallSession; sdp: string }[] = [];
  const candidates: string[] = [];
  const callChanges: CallSession[] = [];
  const splitViews: { source: string; error: SplitViewError }[] = [];
  const profileChanges: string[] = [];
  const receipts: { accountId: string; kind: ReceiptKind; messageIds: string[] }[] = [];
  const typing: { accountId: string; typing: boolean }[] = [];
  const renegotiations: { call: CallSession; sdp: string }[] = [];
  const renegotiationAnswers: { call: CallSession; sdp: string }[] = [];

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
    stunUrls: ['stun:stun.test:3478'],
    // The real value is 45 seconds. Every device here used to get 700ms so
    // that one test could assert the give-up path without waiting three
    // quarters of a minute — and that killed every *other* call test whenever
    // a round trip through the real server took longer than 700ms, which on a
    // loaded machine it does. Six call tests failed that way while the rest of
    // the suite passed, and the failures looked like undelivered envelopes
    // rather than a call the manager had correctly given up on. The two tests
    // that are about the timeout ask for the short value; nothing else does.
    ringingTimeoutMs: options.ringingTimeoutMs ?? 30_000,
    onMailboxesChanged: (mailboxes) => socket?.subscribe(mailboxes),
    events: {
      onMessage: (message) => received.push(message.text),
      onGroupMessage: (groupId, message) => groupReceived.push({ groupId, text: message.text }),
      onIncomingCall: (call, sdp) => incomingCalls.push({ call, sdp }),
      onCallAnswer: (call, sdp) => answers.push({ call, sdp }),
      onCallCandidate: (_call, candidate) => candidates.push(candidate),
      onCallChange: (call) => callChanges.push(call),
      onCallRenegotiate: (call, sdp) => renegotiations.push({ call, sdp }),
      onCallRenegotiateAnswer: (call, sdp) => renegotiationAnswers.push({ call, sdp }),
      onSplitView: (source, error) => splitViews.push({ source, error }),
      onProfileChange: (accountId) => profileChanges.push(accountId),
      onReceipt: (accountId, kind, messageIds) => receipts.push({ accountId, kind, messageIds }),
      onTyping: (accountId, typing_) => typing.push({ accountId, typing: typing_ }),
      onError: (error) => errors.push(error),
    },
  });

  await manager.publishMailboxes();

  socket = new TildraSocket(BASE_URL, client.getCredentials()!.token, {
    onEnvelope: (envelope) => manager.receiveEnvelope(envelope).then(() => undefined),
    onError: (error) => errors.push(error),
  });
  socket.connect();
  // Waiting for the socket rather than guessing at it. A fixed 300ms here
  // meant every device in this file started its test on a socket that was
  // merely probably open, and on a loaded machine probably was not enough —
  // the same shape as the ringing timeout that broke six call tests.
  await waitFor(() => socket!.currentState === 'open');

  return {
    name,
    accountId,
    deviceId,
    manager,
    store,
    client,
    identity,
    socket,
    received,
    errors,
    groupReceived,
    incomingCalls,
    answers,
    candidates,
    callChanges,
    renegotiations,
    renegotiationAnswers,
    splitViews,
    profileChanges,
    receipts,
    typing,
    member: () => ({ accountId, deviceId }),
  };
}

/**
 * Wait for something to become true, and say so loudly when it does not.
 *
 * This used to return silently on timeout, which is the worst of both worlds.
 * A test whose assertion happened to hold anyway passed while measuring
 * nothing — one of mine did, for fifteen seconds — and a test whose assertion
 * then failed reported a value mismatch, which reads as a logic bug rather
 * than as "the reply never arrived". Both cost real time to diagnose.
 *
 * The predicate's own source goes in the message, so a timeout names what it
 * was waiting for without every call site having to describe itself.
 */
async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  // Thirty seconds against per-test budgets of sixty to a hundred and eighty.
  // Ten was chosen when the suite was fast, and on a loaded machine it turned
  // a slow round trip through a real server into what looked like a bug. A
  // wait returns the moment its predicate holds, so a generous ceiling costs
  // nothing when things work and only buys patience when they are slow.
  timeoutMs = 30_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for: ${predicate}`);
}

// One server for the whole file. Starting it inside a single describe block
// leaves every later block without one, which surfaces as an opaque
// "fetch failed" rather than as a missing-server error.
beforeAll(async () => {
  if (!goAvailable()) return;
  const port = await freePort();
  BASE_URL = `http://127.0.0.1:${port}`;
  const binary = join(mkdtempSync(join(tmpdir(), 'tildra-mgr-')), 'tildrad');
  execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], {
    cwd: SERVER_DIR,
    stdio: 'inherit',
  });
  server = spawn(binary, [], {
    env: {
      ...process.env,
      TILDRA_ADDR: `:${port}`,
      TILDRA_DATABASE_URL: '',
      // A relay, so the ICE configuration path is exercised against a real
      // /v1/turn rather than against a stub that agrees with itself.
      TILDRA_TURN_SECRET: 'test-shared-secret',
      TILDRA_TURN_URLS: 'turn:turn.test:3478?transport=udp',
      // Without a signing key the log is off and handle lookups carry no
      // proof, so there is nothing for an auditor to audit.
      TILDRA_TRANSPARENCY_KEY: toBase64(randomBytes(32)),
    },
    stdio: 'ignore',
  });
  await waitForHealth();
}, 120_000);

afterAll(() => server?.kill('SIGTERM'));

describeIntegration('session manager', () => {
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
    // No wait needed: close() takes effect on the client synchronously, and
    // an envelope the server pushes to the closing socket is ignored rather
    // than handled, so it stays unacked and arrives on reconnect. Before that
    // guard existed this was a 200ms sleep, and losing that race meant Bob
    // quietly processed message 1 live — the test still passed, having tested
    // something else.
    bob.socket.close();

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
    // `sent` is no longer where an outgoing message stops. Bob acknowledges it
    // on receipt, so this asserts the round trip rather than a snapshot taken
    // before the receipt has had a chance to land — which is a race, and was
    // one for exactly as long as it took to write the receipt path.
    await waitFor(() => alice.store.messages[0].state === 'delivered');
    expect(alice.store.messages[0].state).toBe('delivered');
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

describeIntegration('a message this build cannot read', () => {
  it('drops it instead of leaving the server retrying it forever', async () => {
    // The ordinary case, not a hostile one: a newer client sends a content type
    // this build does not have. decodeContent refuses it on purpose — rendering
    // something we cannot read is worse than not rendering it — and the refusal
    // used to throw out of receiveEnvelope, which leaves the envelope unacked.
    // The server then retries it for the whole of its lifetime, on every
    // reconnect, for every peer who has not upgraded yet.
    //
    // A decrypt failure can be transient. A decode failure cannot: the AEAD
    // verified, so these are the bytes the sender meant to send.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'once, so there is a session');
    await waitFor(() => bob.received.length > 0, 15_000);

    const session = await alice.store.loadSession(bob.accountId, bob.deviceId);
    if (!session) throw new Error('no session to send over');
    const fromTheFuture = encodeContent({ type: 99 as ContentType, payload: utf8('later') });
    const message = encrypt(session.ratchet, fromTheFuture, session.associatedData);
    await alice.store.saveSession(session);

    const envelope = {
      id: toBase64(randomBytes(12)),
      mailbox: 'direct',
      ciphertext: sealEnvelope(bob.identity.publicKey, {
        senderAccountId: alice.accountId,
        senderDeviceId: alice.deviceId,
        senderIdentityKey: alice.identity.publicKey,
        message,
      }),
      serverTs: new Date().toISOString(),
    };

    // Acked and dropped, and said out loud rather than swallowed.
    await expect(bob.manager.receiveEnvelope(envelope)).resolves.toBeNull();
    expect(bob.errors.map((e) => e.message).join(' ')).toMatch(/unsupported content type 99/);

    // And the conversation still works: the message after it arrives.
    const before = bob.received.length;
    await alice.manager.sendMessage(bob.accountId, 'and the next one still arrives');
    await waitFor(() => bob.received.length > before, 15_000);
    expect(bob.received).toContain('and the next one still arrives');

    alice.socket.close();
    bob.socket.close();
  }, 60_000);
});

describeIntegration('attachments', () => {
  it('sends a file the recipient can fetch and decrypt', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const file = randomBytes(20_000);
    await alice.manager.sendAttachment(
      bob.accountId,
      { bytes: file, mimeType: 'image/jpeg', fileName: 'photo.jpg', width: 1024, height: 768 },
      'bak buna',
    );
    await waitFor(() => bob.received.length > 0, 20_000);

    const message = bob.store.messages.find((m) => !m.outgoing);
    expect(message?.text).toBe('bak buna');
    expect(message?.attachment).toBeDefined();
    expect(message!.attachment!.mimeType).toBe('image/jpeg');
    expect(message!.attachment!.fileName).toBe('photo.jpg');
    expect(message!.attachment!.width).toBe(1024);

    const fetched = await bob.manager.fetchAttachment(message!.attachment!);
    expect(equal(fetched, file)).toBe(true);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('stores a blob the server cannot decrypt', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const secret = utf8('this text must never appear in the stored blob');
    await alice.manager.sendAttachment(bob.accountId, { bytes: secret, mimeType: 'text/plain' });
    await waitFor(() => bob.received.length > 0, 20_000);

    const ref = bob.store.messages.find((m) => !m.outgoing)?.attachment;
    expect(ref).toBeDefined();

    // Fetch the raw blob the way the server holds it. The plaintext must not
    // be in it, and it must not decrypt without the key from the message.
    const raw = await bob.client.downloadAttachment(ref!.id);
    expect(fromUtf8(raw)).not.toContain('must never appear');
    expect(raw.length).toBeGreaterThan(secret.length);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('rejects a blob that was substituted in transit', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendAttachment(bob.accountId, {
      bytes: randomBytes(4000),
      mimeType: 'application/octet-stream',
    });
    await waitFor(() => bob.received.length > 0, 20_000);
    const ref = bob.store.messages.find((m) => !m.outgoing)!.attachment!;

    // A hostile server hands back a different blob under the same ID. The
    // digest in the message is what catches it.
    const decoy = await alice.manager.sendAttachment(bob.accountId, {
      bytes: randomBytes(4000),
      mimeType: 'application/octet-stream',
    });
    await waitFor(() => bob.received.length > 1, 20_000);
    const otherId = bob.store.messages.filter((m) => !m.outgoing).at(-1)!.attachment!.id;
    expect(otherId).not.toBe(ref.id);
    void decoy;

    await expect(bob.manager.fetchAttachment({ ...ref, id: otherId })).rejects.toThrow(/digest/);

    alice.socket.close();
    bob.socket.close();
  }, 120_000);

  it('reports a missing attachment rather than hanging', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendAttachment(bob.accountId, {
      bytes: randomBytes(1000),
      mimeType: 'image/png',
    });
    await waitFor(() => bob.received.length > 0, 20_000);
    const ref = bob.store.messages.find((m) => !m.outgoing)!.attachment!;

    await expect(
      bob.manager.fetchAttachment({ ...ref, id: '0000000000000000000000000Z' }),
    ).rejects.toThrow();

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('carries a voice note with its waveform visible before download', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const audio = randomBytes(30_000);
    const waveform = new Uint8Array(48).map((_, i) => i % 16);
    await alice.manager.sendAttachment(bob.accountId, {
      bytes: audio,
      mimeType: 'audio/m4a',
      durationMs: 7_400,
      waveform,
    });
    await waitFor(() => bob.received.length > 0, 20_000);

    const received = bob.store.messages.find((m) => !m.outgoing)!;
    // The shape and length arrive with the message, so the bubble is complete
    // before a byte of audio is fetched.
    expect(received.attachment!.durationMs).toBe(7_400);
    expect(equal(received.attachment!.waveform!, waveform)).toBe(true);
    expect(received.attachment!.mimeType).toBe('audio/m4a');

    const fetched = await bob.manager.fetchAttachment(received.attachment!);
    expect(equal(fetched, audio)).toBe(true);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('uploads once and delivers the same reference to the recipient', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const file = randomBytes(8000);
    const sent = await alice.manager.sendAttachment(bob.accountId, {
      bytes: file,
      mimeType: 'image/webp',
    });
    await waitFor(() => bob.received.length > 0, 20_000);

    const received = bob.store.messages.find((m) => !m.outgoing)!;
    // Sender and receiver reference the same blob, so a multi-device recipient
    // never causes a second upload.
    expect(received.attachment!.id).toBe(sent.attachment!.id);
    expect(equal(received.attachment!.digest, sent.attachment!.digest)).toBe(true);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);
});

describeIntegration('profiles', () => {
  it('introduces both sides on first contact', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.setProfile({ displayName: 'Ayşe Kaya', about: 'İstanbul' });
    await bob.manager.setProfile({ displayName: 'Barış Yılmaz' });

    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0, 15_000);

    // Bob learned who Alice is from the introduction that preceded the message.
    const aliceAsBobSeesHer = await bob.store.getConversation(alice.accountId);
    expect(aliceAsBobSeesHer?.displayName).toBe('Ayşe Kaya');
    expect(aliceAsBobSeesHer?.about).toBe('İstanbul');

    // And the introduction is mutual: Bob's profile came back automatically.
    await waitFor(
      async () => (await alice.store.getConversation(bob.accountId))?.displayName !== undefined,
      15_000,
    );
    const bobAsAliceSeesHim = await alice.store.getConversation(bob.accountId);
    expect(bobAsAliceSeesHim?.displayName).toBe('Barış Yılmaz');

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('carries a picture', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const avatar = randomBytes(3000);
    await alice.manager.setProfile({ displayName: 'With picture', avatar });

    await alice.manager.sendMessage(bob.accountId, 'bak');
    await waitFor(() => bob.received.length > 0, 15_000);

    const stored = await bob.store.getConversation(alice.accountId);
    expect(stored?.avatar).toBeDefined();
    expect(stored!.avatar!.length).toBe(avatar.length);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('pushes an updated profile to existing contacts', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.setProfile({ displayName: 'Before' });
    await alice.manager.sendMessage(bob.accountId, 'ilk');
    await waitFor(() => bob.received.length > 0, 15_000);
    expect((await bob.store.getConversation(alice.accountId))?.displayName).toBe('Before');

    await alice.manager.setProfile({ displayName: 'After' });
    await waitFor(
      async () => (await bob.store.getConversation(alice.accountId))?.displayName === 'After',
      15_000,
    );

    expect((await bob.store.getConversation(alice.accountId))?.displayName).toBe('After');
    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('ignores a profile older than the one already stored', async () => {
    // Fanout plus redelivery means an update can arrive after a newer one. A
    // stale name silently replacing the current one would look to the user
    // like the contact renamed themselves back.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.setProfile({ displayName: 'Current' });
    await alice.manager.sendMessage(bob.accountId, 'x');
    await waitFor(() => bob.received.length > 0, 15_000);

    const conversation = await bob.store.getConversation(alice.accountId);
    await bob.store.upsertConversation({
      ...conversation!,
      displayName: 'Newer',
      profileUpdatedAt: Date.now() + 60_000,
    });

    await alice.manager.setProfile({ displayName: 'Stale arrival' });
    await new Promise((r) => setTimeout(r, 2_000));

    expect((await bob.store.getConversation(alice.accountId))?.displayName).toBe('Newer');
    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('keeps names and pictures off the server', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.setProfile({ displayName: 'Ayşe Kaya', avatar: randomBytes(2048) });
    await alice.manager.sendMessage(bob.accountId, 'x');
    await waitFor(() => bob.received.length > 0, 15_000);

    // The device list is the only place the server could plausibly leak a
    // name, and what it holds is the device label, never the profile.
    const devices = await bob.client.listDevices(alice.accountId);
    expect(devices.map((d) => d.name)).not.toContain('Ayşe Kaya');
    expect(JSON.stringify(devices)).not.toContain('Ayşe');

    alice.socket.close();
    bob.socket.close();
  }, 60_000);
});

describeIntegration('encrypted groups', () => {
  /** Three members with pairwise sessions and a group already distributed. */
  async function group(groupId: string) {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    const carol = await bringUp('Carol');
    const members = [alice.member(), bob.member(), carol.member()];

    await alice.manager.createGroup(groupId, members, 'Test group');
    // The sender key reaches each member over their pairwise session; wait for
    // both to have stored it before anyone sends to the group.
    await waitFor(
      () =>
        bob.store.receiverKeys.size > 0 && carol.store.receiverKeys.size > 0,
      15_000,
    );

    return { alice, bob, carol, members, close: () => [alice, bob, carol].forEach((m) => m.socket.close()) };
  }

  it('delivers a group message to every member', async () => {
    const g = await group('grp-basic');

    await g.alice.manager.sendGroupMessage('grp-basic', 'herkese selam');
    await waitFor(() => g.bob.groupReceived.length > 0 && g.carol.groupReceived.length > 0, 15_000);

    expect(g.bob.groupReceived.map((m) => m.text)).toEqual(['herkese selam']);
    expect(g.carol.groupReceived.map((m) => m.text)).toEqual(['herkese selam']);
    g.close();
  }, 90_000);

  it('lets a member who was invited send to the whole group', async () => {
    // Bob learned the group from Alice's distribution, including that Carol is
    // in it. Without the member list riding along, his message would reach
    // Alice and silently miss Carol.
    const g = await group('grp-reply');

    await g.alice.manager.sendGroupMessage('grp-reply', 'from alice');
    await waitFor(() => g.bob.groupReceived.length > 0, 15_000);

    await g.bob.manager.sendGroupMessage('grp-reply', 'from bob');
    await waitFor(
      () => g.alice.groupReceived.length > 0 && g.carol.groupReceived.length > 1,
      20_000,
    );

    expect(g.alice.groupReceived.map((m) => m.text)).toContain('from bob');
    expect(g.carol.groupReceived.map((m) => m.text)).toEqual(['from alice', 'from bob']);
    g.close();
  }, 120_000);

  it('encrypts once regardless of group size', async () => {
    // The economy sender keys buy: one encryption, N deliveries. If this ever
    // became one encryption per member, large groups would stop being viable
    // and the design would have quietly reverted to pairwise fanout.
    const g = await group('grp-once');
    const delivered = await g.alice.manager.sendGroupMessage('grp-once', 'one ciphertext');

    expect(delivered).toBe(2);
    await waitFor(() => g.bob.groupReceived.length > 0 && g.carol.groupReceived.length > 0, 15_000);
    g.close();
  }, 90_000);

  it('locks a removed member out of everything sent afterwards', async () => {
    const g = await group('grp-remove');

    await g.alice.manager.sendGroupMessage('grp-remove', 'while carol is here');
    await waitFor(() => g.carol.groupReceived.length > 0, 15_000);
    expect(g.carol.groupReceived.map((m) => m.text)).toEqual(['while carol is here']);

    // Removing rotates: Alice generates a fresh chain and distributes it only
    // to the remaining members.
    const bobKeyBefore = g.bob.store.receiverKeys.get(`grp-remove/${g.alice.accountId}/${g.alice.deviceId}`);
    await g.alice.manager.removeGroupMember('grp-remove', g.carol.member());
    await waitFor(
      () =>
        g.bob.store.receiverKeys.get(`grp-remove/${g.alice.accountId}/${g.alice.deviceId}`) !==
        bobKeyBefore,
      15_000,
    );

    const carolBefore = g.carol.groupReceived.length;
    await g.alice.manager.sendGroupMessage('grp-remove', 'carol must not read this');
    await waitFor(() => g.bob.groupReceived.length > 1, 15_000);

    expect(g.bob.groupReceived.map((m) => m.text)).toContain('carol must not read this');
    expect(g.carol.groupReceived).toHaveLength(carolBefore);
    g.close();
  }, 120_000);

  it('locks a removed member out of what the other members send, not only the remover', async () => {
    // §4: "every remaining member generates a fresh sender chain. A removed
    // member cannot read anything sent after their removal." The test above
    // only drives the remover's own messages, which is the half that works.
    //
    // Carol holds Bob's chain key too — that is what sender keys are. If
    // Bob's chain is not rotated, and if Carol is still on Bob's member list,
    // then Bob is still fanning out to her and she still decrypts it.
    const g = await group('grp-remove-all');

    // Bob sends first, so Carol has his chain and not just Alice's.
    await g.bob.manager.sendGroupMessage('grp-remove-all', 'bob while carol is here');
    await waitFor(() => g.carol.groupReceived.length > 0, 15_000);

    const bobKeyBefore = g.bob.store.receiverKeys.get(
      `grp-remove-all/${g.alice.accountId}/${g.alice.deviceId}`,
    );
    await g.alice.manager.removeGroupAccount('grp-remove-all', g.carol.accountId);
    await waitFor(
      () =>
        g.bob.store.receiverKeys.get(
          `grp-remove-all/${g.alice.accountId}/${g.alice.deviceId}`,
        ) !== bobKeyBefore,
      15_000,
    );

    const carolBefore = g.carol.groupReceived.length;
    await g.bob.manager.sendGroupMessage('grp-remove-all', 'carol must not read this either');
    // Wait for the message itself, not for the count to be non-zero: Alice
    // already holds Bob's first one, so `length > 0` is true before Bob has
    // sent anything and the wait returns immediately. That passed here and
    // went red in CI, which is what a wait on an already-satisfied condition
    // looks like.
    await waitFor(
      () => g.alice.groupReceived.some((m) => m.text === 'carol must not read this either'),
      15_000,
    );

    expect(g.alice.groupReceived.map((m) => m.text)).toContain('carol must not read this either');
    expect(g.carol.groupReceived).toHaveLength(carolBefore);
    // And she is no longer on the list Bob fans out to, so the envelope is not
    // even addressed to her.
    const bobGroup = await g.bob.store.loadGroup('grp-remove-all');
    expect(bobGroup?.members.map((m) => m.accountId)).not.toContain(g.carol.accountId);
    g.close();
  }, 120_000);

  it('drops a removed member\'s messages instead of retrying them forever', async () => {
    // A removed member is not told, and cannot be: there is no signal that
    // says "you are out" which somebody else could not also send. So they keep
    // writing to a group that has rotated away from them.
    //
    // Every one of those messages arrives at a device with no chain for them.
    // That case is answered by throwing, which is right when a distribution is
    // merely late — the envelope stays unacked and the server tries again. It
    // is wrong here: nothing will ever make it decryptable, so the retry is
    // for as long as the envelope lives.
    const g = await group('grp-dropped');
    // Carol writes once while she is still in, which is what gives her a chain
    // of her own to keep writing with afterwards.
    await g.carol.manager.sendGroupMessage('grp-dropped', 'buradayken');
    await waitFor(() => g.alice.groupReceived.length > 0, 15_000);

    await g.alice.manager.removeGroupAccount('grp-dropped', g.carol.accountId);

    const before = g.alice.store.messages.length;
    await expect(
      injectGroupMessage(g.carol, g.alice, 'grp-dropped', 'hâlâ buradayım'),
    ).resolves.toBeUndefined();
    expect(g.alice.store.messages).toHaveLength(before);

    // And the distinction the drop rests on: a member whose distribution has
    // not landed yet still gets the retry, because for them it will land.
    const dave = await bringUp('Dave');
    await g.alice.manager.addGroupAccount('grp-dropped', dave.accountId);
    await waitFor(() => dave.store.receiverKeys.size > 0, 15_000);

    // Dave is on Alice's member list and Alice has never seen his chain — he
    // has one only because he is about to write, and it has gone nowhere yet.
    dave.store.senderKeys.set('grp-dropped', createSenderKey('grp-dropped'));
    await expect(
      injectGroupMessage(dave, g.alice, 'grp-dropped', 'ben yeniyim'),
    ).rejects.toThrow(/no sender key/);

    dave.socket.close();
    g.close();
  }, 120_000);

  it('sanitizes and bounds a group name the way it does a display name', async () => {
    // The name rides in the invite and lands in the chat list, from a member
    // rather than from us — the same text from the same kind of sender as a
    // profile display name, and it was neither sanitized nor bounded because
    // the rule lived in content.ts where this file could not reach it.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0, 15_000);

    await alice.manager.createGroup(
      'grp-name',
      [alice.member(), bob.member()],
      `Kitap‮qilc⁠hars ${'x'.repeat(80)}`,
    );
    await waitFor(() => bob.store.groups.has('grp-name'), 15_000);

    const name = (await bob.store.loadGroup('grp-name'))!.name!;
    expect(name).not.toMatch(/\p{Cf}/u);
    expect(name).not.toMatch(/[\u0000-\u001F\u007F-\u009F]/);
    expect(name.length).toBeLessThanOrEqual(48);
    expect(name.startsWith('Kitapqilchars')).toBe(true);

    [alice, bob].forEach((d) => d.socket.close());
  }, 60_000);

  it('does not let a newly added member read the backlog', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    const dave = await bringUp('Dave');

    await alice.manager.createGroup('grp-add', [alice.member(), bob.member()]);
    await waitFor(() => bob.store.receiverKeys.size > 0, 15_000);

    await alice.manager.sendGroupMessage('grp-add', 'before dave arrived');
    await waitFor(() => bob.groupReceived.length > 0, 15_000);

    await alice.manager.addGroupMember('grp-add', dave.member());
    await waitFor(() => dave.store.receiverKeys.size > 0, 15_000);

    await alice.manager.sendGroupMessage('grp-add', 'after dave arrived');
    await waitFor(() => dave.groupReceived.length > 0, 15_000);

    // Dave receives the chain from its current position, so the earlier
    // message was never derivable by him.
    expect(dave.groupReceived.map((m) => m.text)).toEqual(['after dave arrived']);
    expect(bob.groupReceived.map((m) => m.text)).toEqual([
      'before dave arrived',
      'after dave arrived',
    ]);

    [alice, bob, dave].forEach((m) => m.socket.close());
  }, 120_000);

  it('keeps group membership off the server', async () => {
    const g = await group('grp-private');
    await g.alice.manager.sendGroupMessage('grp-private', 'private membership');
    await waitFor(() => g.bob.groupReceived.length > 0, 15_000);

    // The server has no group endpoint at all — the only thing it ever saw was
    // opaque envelopes addressed to mailboxes. This asserts the absence.
    const response = await fetch(`${BASE_URL}/v1/groups/grp-private`, {
      headers: { Authorization: `Bearer ${g.alice.client.getCredentials()!.token}` },
    });
    expect(response.status).toBe(404);

    const stored = await g.bob.store.loadGroup('grp-private');
    expect(stored?.members.length).toBe(3);
    g.close();
  }, 90_000);
});

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

/** An SDP with a distinct fingerprint per seed, so sides are distinguishable. */
function callSdp(seed: number): string {
  const bytes: string[] = [];
  for (let i = 0; i < 32; i++) {
    bytes.push(((i * 11 + seed * 41) % 256).toString(16).padStart(2, '0').toUpperCase());
  }
  return [
    'v=0',
    'o=- 1 2 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'm=audio 9 UDP/TLS/RTP/SAVPF 111',
    'c=IN IP4 0.0.0.0',
    'a=setup:actpass',
    `a=fingerprint:sha-256 ${bytes.join(':')}`,
    '',
  ].join('\r\n');
}

const HOST_CANDIDATE = 'candidate:1 1 UDP 2130706431 192.168.1.42 54321 typ host';
const RELAY_CANDIDATE = 'candidate:4 1 UDP 41885439 203.0.113.9 54324 typ relay';

/**
 * Hand a device an envelope directly, bypassing the socket.
 *
 * Used only for the offers a *malicious client* would send — ones this
 * codebase deliberately cannot produce, because `placeCall` signs the
 * fingerprint it is actually sending. The crypto is real: a real session, a
 * real ratchet step, a real sealed envelope. What is skipped is the network
 * hop, which has nothing to do with what these tests assert.
 */
async function injectSignal(from: Device, to: Device, signal: CallSignal): Promise<void> {
  const session = await from.store.loadSession(to.accountId, to.deviceId);
  if (!session) throw new Error('no session to inject over');

  const message = encrypt(
    session.ratchet,
    encodeContent(callSignalContent(encodeCallSignal(signal))),
    session.associatedData,
  );
  await from.store.saveSession(session);

  const ciphertext = sealEnvelope(to.identity.publicKey, {
    senderAccountId: from.accountId,
    senderDeviceId: from.deviceId,
    senderIdentityKey: from.identity.publicKey,
    sessionInit: session.confirmed ? undefined : session.pendingInit,
    message,
  });

  await to.manager.receiveEnvelope({
    id: toBase64(randomBytes(12)),
    mailbox: 'direct',
    ciphertext,
    serverTs: new Date().toISOString(),
  });
}

/**
 * Hand a device a group message directly, the way the socket would.
 *
 * Used where the point is what the *receiver* does with it, and waiting on a
 * socket would turn "was it dropped" into "has it not arrived yet". The
 * crypto is real: the sender's own chain, a real sealed envelope.
 */
async function injectGroupMessage(
  from: Device,
  to: Device,
  groupId: string,
  text: string,
): Promise<void> {
  const senderKey = from.store.senderKeys.get(groupId);
  if (!senderKey) throw new Error('sender has no group chain to send with');

  const groupMessage = encodeGroupMessage(
    encryptGroupMessage(senderKey, encodeContent(textContent(text))),
  );
  const ciphertext = sealEnvelope(to.identity.publicKey, {
    senderAccountId: from.accountId,
    senderDeviceId: from.deviceId,
    senderIdentityKey: from.identity.publicKey,
    groupMessage,
  });

  await to.manager.receiveEnvelope({
    id: toBase64(randomBytes(12)),
    mailbox: 'direct',
    ciphertext,
    serverTs: new Date().toISOString(),
  });
}

describeIntegration('calls', () => {
  it('rings the other side and pins the media to the caller fingerprint', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);

    expect(bob.incomingCalls).toHaveLength(1);
    const [ring] = bob.incomingCalls;
    expect(ring.call.direction).toBe('incoming');
    expect(ring.call.phase).toBe('ringing');
    expect(ring.call.peerAccountId).toBe(alice.accountId);
    expect(ring.call.peerDeviceId).toBe(alice.deviceId);
    // The fingerprint Bob will pin the DTLS handshake to is the one in the SDP
    // Alice actually sent, not a value carried alongside it.
    expect(ring.call.peerFingerprint).toEqual(sdpFingerprint(callSdp(1)));
    expect(ring.sdp).toBe(callSdp(1));
    expect([...alice.errors, ...bob.errors]).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('refuses to place or answer a call into a conversation flagged as changed', async () => {
    // §7 blocks a conversation from sending once a contact's key changes, and
    // the two message paths honoured it while neither call path did — which is
    // backwards, because a call is where a user is most likely to act on
    // believing they know who is on the other end.
    //
    // The state below is exactly what flagIdentityChange leaves behind: the
    // *new* key in the row, and the flag set. assertIdentityUnchanged compares
    // new against new and passes, so the flag is the only thing left saying no.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);

    const conversation = await alice.store.getConversation(bob.accountId);
    await alice.store.upsertConversation({ ...conversation!, identityChanged: true });

    await expect(
      alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) }),
    ).rejects.toBeInstanceOf(IdentityChangedError);
    // Nothing was started: no call session, and the other side never rang.
    expect(alice.manager.currentCall()).toBeNull();
    expect(bob.incomingCalls).toHaveLength(0);

    // The answering side is the same rule from the other end. Bob's phone rings
    // before he learns Alice's key changed, and the answer is what would sign
    // his fingerprint and open media to whoever holds the new key.
    const placed = await bob.manager.placeCall(alice.accountId, { sdp: callSdp(2) });
    await waitFor(() => alice.incomingCalls.length > 0);

    await expect(alice.manager.answerCall(placed.callId, callSdp(3))).rejects.toBeInstanceOf(
      IdentityChangedError,
    );
    expect(bob.answers).toHaveLength(0);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('completes an offer and answer between two real devices', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1), video: true });
    await waitFor(() => bob.incomingCalls.length > 0);
    expect(bob.incomingCalls[0].call.video).toBe(true);

    await bob.manager.answerCall(placed.callId, callSdp(2));
    await waitFor(() => alice.answers.length > 0);

    expect(alice.answers[0].sdp).toBe(callSdp(2));
    // Each side ends up pinned to the other's fingerprint, and neither to its
    // own — the check that would fail if the binding were self-referential.
    expect(alice.manager.currentCall()?.peerFingerprint).toEqual(sdpFingerprint(callSdp(2)));
    expect(bob.manager.currentCall()?.peerFingerprint).toEqual(sdpFingerprint(callSdp(1)));
    expect(alice.manager.currentCall()?.phase).toBe('connecting');
    expect(bob.manager.currentCall()?.phase).toBe('connecting');
    expect(alice.manager.currentCall()?.peerDeviceId).toBe(bob.deviceId);
    expect([...alice.errors, ...bob.errors]).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('does not ring for an offer whose fingerprint is not the one signed', async () => {
    // The attack the binding exists for, arriving from a client that lies. The
    // phone must stay silent: a user who answers believes the call is private.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'kuruyorum');
    await waitFor(() => bob.received.length > 0);

    const honest = signCallSdp(alice.identity, {
      kind: CallSignalKind.Offer,
      callId: 'call-tampered1',
      sdp: callSdp(1),
      fromAccountId: alice.accountId,
      toAccountId: bob.accountId,
    });
    await injectSignal(alice, bob, { ...honest, body: callSdp(9) });

    expect(bob.incomingCalls).toEqual([]);
    expect(bob.manager.currentCall()).toBeNull();
    expect(bob.errors.map((e) => e.message).join('\n')).toMatch(/not signed by the identity key/);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('does not ring for an offer signed by someone other than the caller', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'kuruyorum');
    await waitFor(() => bob.received.length > 0);

    const mallory = generateIdentity();
    const forged = signCallSdp(mallory, {
      kind: CallSignalKind.Offer,
      callId: 'call-forged123',
      sdp: callSdp(3),
      fromAccountId: alice.accountId,
      toAccountId: bob.accountId,
    });
    await injectSignal(alice, bob, forged);

    expect(bob.incomingCalls).toEqual([]);
    expect(bob.errors.map((e) => e.message).join('\n')).toMatch(/not signed by the identity key/);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('does not ring for an offer addressed to somebody else', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'kuruyorum');
    await waitFor(() => bob.received.length > 0);

    // Alice's genuine signature, for a call she meant for Carol. Relaying it
    // to Bob must not ring Bob.
    const forCarol = signCallSdp(alice.identity, {
      kind: CallSignalKind.Offer,
      callId: 'call-relayed12',
      sdp: callSdp(4),
      fromAccountId: alice.accountId,
      toAccountId: 'acct-carol',
    });
    await injectSignal(alice, bob, forCarol);

    expect(bob.incomingCalls).toEqual([]);
    expect(bob.manager.currentCall()).toBeNull();
    // Asserted, not just "nothing happened": a silently dropped injection
    // would satisfy the two checks above without exercising anything.
    expect(bob.errors.map((e) => e.message).join('\n')).toMatch(/not signed by the identity key/);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('withholds a direct address until the call is answered', async () => {
    // A call you never picked up must not tell the caller where you are — and
    // must not make your ICE agent probe an address they chose, which tells
    // them the same thing from the other direction.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);

    await alice.manager.sendCallCandidate(placed.callId, HOST_CANDIDATE);
    await alice.manager.sendCallCandidate(placed.callId, RELAY_CANDIDATE);
    await waitFor(() => bob.candidates.length > 0);
    expect(bob.candidates).toEqual([RELAY_CANDIDATE]);

    // Bob's own host candidate is withheld by the send-side policy too.
    expect(await bob.manager.sendCallCandidate(placed.callId, HOST_CANDIDATE)).toBe(false);

    await bob.manager.answerCall(placed.callId, callSdp(2));
    await waitFor(() => alice.answers.length > 0);

    expect(await bob.manager.sendCallCandidate(placed.callId, HOST_CANDIDATE)).toBe(true);
    await waitFor(() => alice.candidates.length > 0);
    expect(alice.candidates).toEqual([HOST_CANDIDATE]);

    await alice.manager.sendCallCandidate(placed.callId, HOST_CANDIDATE);
    await waitFor(() => bob.candidates.length > 1);
    expect(bob.candidates).toEqual([RELAY_CANDIDATE, HOST_CANDIDATE]);
    expect([...alice.errors, ...bob.errors]).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('tells a second caller the line is busy without ringing again', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    const carol = await bringUp('Carol');

    await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);

    await carol.manager.placeCall(bob.accountId, { sdp: callSdp(5) });
    await waitFor(() => carol.manager.currentCall() === null, 15_000);

    expect(bob.incomingCalls).toHaveLength(1);
    expect(bob.incomingCalls[0].call.peerAccountId).toBe(alice.accountId);
    expect(carol.callChanges.at(-1)?.endedReason).toBe('busy');
    expect(bob.manager.currentCall()?.peerAccountId).toBe(alice.accountId);

    [alice, bob, carol].forEach((d) => d.socket.close());
  }, 90_000);

  it('ends the call on both sides when one side hangs up', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);
    await bob.manager.answerCall(placed.callId, callSdp(2));
    await waitFor(() => alice.answers.length > 0);

    alice.manager.markCallConnected(placed.callId);
    expect(alice.manager.currentCall()?.phase).toBe('active');

    await alice.manager.endCall(placed.callId, 'hangup');
    expect(alice.manager.currentCall()).toBeNull();

    await waitFor(() => bob.manager.currentCall() === null);
    expect(bob.callChanges.at(-1)?.endedReason).toBe('hangup');
    expect([...alice.errors, ...bob.errors]).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('reads a declined call as declined rather than as a hangup', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);

    await bob.manager.endCall(placed.callId, 'declined');
    await waitFor(() => alice.manager.currentCall() === null);

    expect(alice.callChanges.at(-1)?.endedReason).toBe('declined');

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('ignores a signal for a call that is not happening', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'kuruyorum');
    await waitFor(() => bob.received.length > 0);

    await injectSignal(alice, bob, {
      kind: CallSignalKind.Candidate,
      callId: 'call-nothing12',
      body: RELAY_CANDIDATE,
    });
    await injectSignal(alice, bob, {
      kind: CallSignalKind.Hangup,
      callId: 'call-nothing12',
      body: 'hangup',
    });

    expect(bob.candidates).toEqual([]);
    expect(bob.manager.currentCall()).toBeNull();
    expect(bob.errors).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('does not resurrect a call with a late candidate', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);
    await bob.manager.answerCall(placed.callId, callSdp(2));
    await waitFor(() => alice.answers.length > 0);

    await bob.manager.endCall(placed.callId, 'hangup');
    await waitFor(() => alice.manager.currentCall() === null);

    await injectSignal(bob, alice, {
      kind: CallSignalKind.Candidate,
      callId: placed.callId,
      body: RELAY_CANDIDATE,
    });

    expect(alice.candidates).toEqual([]);
    expect(alice.manager.currentCall()).toBeNull();

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('refuses to place a second call while one is live', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    const carol = await bringUp('Carol');

    await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await expect(alice.manager.placeCall(carol.accountId, { sdp: callSdp(6) })).rejects.toThrow(
      /already in a call/,
    );

    [alice, bob, carol].forEach((d) => d.socket.close());
  }, 60_000);

  it('keeps the call off the server', async () => {
    // Signalling is content type 6 inside the same ratchet as chat, so what
    // the server sees is a handful of envelopes to a mailbox and nothing that
    // says a call happened. This asserts the absence of any call endpoint.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);

    for (const path of [`/v1/calls`, `/v1/calls/${placed.callId}`]) {
      const response = await fetch(`${BASE_URL}${path}`, {
        headers: { Authorization: `Bearer ${alice.client.getCredentials()!.token}` },
      });
      expect(response.status).toBe(404);
    }

    alice.socket.close();
    bob.socket.close();
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Safety-number QR
// ---------------------------------------------------------------------------

describeIntegration('safety number codes', () => {
  it('both sides produce the same code, and it survives the scanner', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);

    const aliceQr = await alice.manager.safetyQrFor(bob.accountId);
    const bobQr = await bob.manager.safetyQrFor(alice.accountId);
    expect(aliceQr).toBeTruthy();
    // Sorted before hashing, so neither side needs to know who is "first".
    expect(aliceQr).toBe(bobQr);

    // Through the scanner's validation, which is what the screen calls.
    expect(readSafetyCode(bobQr!)).toBe(bobQr);
    expect(await alice.manager.matchesSafetyCode(bob.accountId, bobQr!)).toBe(true);
    expect(await bob.manager.matchesSafetyCode(alice.accountId, aliceQr!)).toBe(true);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('refuses a code from a different pair of people', async () => {
    // Scanning the code off the wrong screen is the mistake this catches, and
    // a MITM presenting their own key is the attack.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    const carol = await bringUp('Carol');

    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);
    await alice.manager.sendMessage(carol.accountId, 'merhaba');
    await waitFor(() => carol.received.length > 0);

    const aliceCarol = await alice.manager.safetyQrFor(carol.accountId);
    expect(await alice.manager.matchesSafetyCode(bob.accountId, aliceCarol!)).toBe(false);
    expect(await bob.manager.matchesSafetyCode(alice.accountId, aliceCarol!)).toBe(false);

    [alice, bob, carol].forEach((d) => d.socket.close());
  }, 90_000);

  it('has no code for somebody we have never spoken to', async () => {
    const alice = await bringUp('Alice');
    expect(await alice.manager.safetyQrFor('acct-stranger')).toBeNull();
    expect(await alice.manager.matchesSafetyCode('acct-stranger', 'tildra:verify:1:aa:bb')).toBe(
      false,
    );
    alice.socket.close();
  }, 40_000);
});

// ---------------------------------------------------------------------------
// Relay credentials
// ---------------------------------------------------------------------------

describeIntegration('relay credentials', () => {
  it('fetches a relay the server would accept, and reuses it', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    const call = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    const config = await alice.manager.iceConfiguration(call);

    expect(config.relayAvailable).toBe(true);
    expect(config.iceServers[0].urls).toEqual(['turn:turn.test:3478?transport=udp']);
    expect(config.iceServers[0].username).toMatch(/^\d+:[0-9a-f]+$/);
    expect(config.iceServers[0].credential).toBeTruthy();

    // Cached: a fetch per call is a request the server can count and time.
    const again = await alice.manager.iceConfiguration(call);
    expect(again.iceServers[0].username).toBe(config.iceServers[0].username);
    expect([...alice.errors, ...bob.errors]).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('withholds STUN from a call that is still ringing', async () => {
    // The end-to-end version of the rule: a ringing incoming call gets the
    // relay and nothing that could reveal an address.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);

    const ringing = await bob.manager.iceConfiguration(bob.manager.currentCall()!);
    expect(ringing.iceTransportPolicy).toBe('relay');
    expect(ringing.iceServers.flatMap((s) => s.urls).some((u) => u.startsWith('stun'))).toBe(false);

    const answered = await bob.manager.answerCall(bob.manager.currentCall()!.callId, callSdp(2));
    const active = await bob.manager.iceConfiguration(answered);
    expect(active.iceTransportPolicy).toBe('all');
    expect(active.iceServers.flatMap((s) => s.urls)).toContain('stun:stun.test:3478');

    alice.socket.close();
    bob.socket.close();
  }, 60_000);

  it('reports no relay rather than falling back, when the deployment has none', async () => {
    // A second server, started without TURN — the default for a fresh
    // deployment, and the case where a silent downgrade would leak.
    const port = await freePort();
    const binary = join(mkdtempSync(join(tmpdir(), 'tildra-noturn-')), 'tildrad');
    execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], { cwd: SERVER_DIR, stdio: 'inherit' });
    const bare = spawn(binary, [], {
      env: { ...process.env, TILDRA_ADDR: `:${port}`, TILDRA_DATABASE_URL: '' },
      stdio: 'ignore',
    });
    try {
      const base = `http://127.0.0.1:${port}`;
      const deadline = Date.now() + 30_000;
      for (;;) {
        try {
          if ((await fetch(`${base}/healthz`)).ok) break;
        } catch {
          /* not up yet */
        }
        if (Date.now() > deadline) throw new Error('bare server did not start');
        await new Promise((r) => setTimeout(r, 100));
      }

      const client = new TildraClient({ baseUrl: base });
      const identity = generateIdentity();
      const { accountId, deviceId } = await client.register(identity, 'Solo');
      await client.login(identity, accountId, deviceId);

      expect(await client.turnCredentials()).toBeNull();
    } finally {
      bare.kill('SIGTERM');
    }
  }, 90_000);
});

// ---------------------------------------------------------------------------
// Auditors
// ---------------------------------------------------------------------------

/** Serve one file over HTTP, the way an auditor operator would publish it. */
async function servePublished(body: string): Promise<{ url: string; close: () => void }> {
  const http = await import('node:http');
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (typeof address === 'string' || address === null) throw new Error('no port');
  return {
    url: `http://127.0.0.1:${address.port}/checkpoint.json`,
    close: () => server.close(),
  };
}

function runRealAuditor(serverUrl: string): { published: string; publicKey: Uint8Array } {
  const binary = join(mkdtempSync(join(tmpdir(), 'tildra-mgr-aud-')), 'tildra-auditor');
  execFileSync('go', ['build', '-o', binary, './cmd/tildra-auditor'], {
    cwd: SERVER_DIR,
    stdio: 'inherit',
  });

  const out = execFileSync(binary, ['-genkey'], { encoding: 'utf8' });
  const seed = /^seed:\s*(\S+)$/m.exec(out)![1];
  const publicKey = fromBase64(/^publicKey:\s*(\S+)$/m.exec(out)![1]);

  const dir = mkdtempSync(join(tmpdir(), 'tildra-mgr-aud-run-'));
  const keyPath = join(dir, 'auditor.key');
  writeFileSync(keyPath, seed);
  execFileSync(
    binary,
    [
      '-server', serverUrl,
      '-state', join(dir, 'state.json'),
      '-key', keyPath,
      '-publish', join(dir, 'checkpoint.json'),
    ],
    { stdio: 'inherit' },
  );
  return { published: readFileSync(join(dir, 'checkpoint.json'), 'utf8'), publicKey };
}

describeIntegration('gossip', () => {
  /** Give a device the verified view it needs before it can gossip anything. */
  async function storeCheckpoint(
    device: Device,
    proof: { head: { size: number; rootHash: Uint8Array; logKey: Uint8Array } },
  ): Promise<void> {
    await device.store.setMeta(
      CHECKPOINT_META_KEY,
      JSON.stringify({
        size: proof.head.size,
        rootHash: toBase64(proof.head.rootHash),
        logKey: toBase64(proof.head.logKey),
        head: serializeTreeHead(proof.head as never),
      }),
    );
  }

  it('keeps gossiping as the log moves, not only on first contact', async () => {
    // §7.2 is a claim about catching a server that shows two people two
    // different logs. Gossip ran once, inside the first-contact branch, which
    // compares two views at the moment there is least to disagree about and
    // then never again — and a fork is something an operator starts when they
    // decide to, which is normally long after two people began talking.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.client.claimHandle('gossipone');
    const first = (await alice.client.resolveHandle('gossipone')).proof!;
    const firstView = verifyHandleProof(first, 'gossipone', null);
    await storeCheckpoint(alice, first);

    const key = `transparency.gossiped.v1:${bob.accountId}/${bob.deviceId}`;
    await alice.manager.sendMessage(bob.accountId, 'ilk');
    await waitFor(() => bob.received.length > 0, 15_000);
    expect(alice.store.meta.get(key)).toBe(String(first.head.size));

    // The log moves and Alice verifies the new view.
    await bob.client.claimHandle('gossiptwo');
    const second = (await alice.client.resolveHandle('gossiptwo', firstView.size)).proof!;
    verifyHandleProof(second, 'gossiptwo', firstView);
    expect(second.head.size).toBeGreaterThan(first.head.size);
    await storeCheckpoint(alice, second);

    await alice.manager.sendMessage(bob.accountId, 'ikinci');
    await waitFor(() => bob.received.length > 1, 15_000);
    expect(alice.store.meta.get(key)).toBe(String(second.head.size));

    // And a quiet log stays quiet: nothing new to say, nothing sent.
    await alice.manager.sendMessage(bob.accountId, 'ucuncu');
    await waitFor(() => bob.received.length > 2, 15_000);
    expect(alice.store.meta.get(key)).toBe(String(second.head.size));

    expect(alice.errors).toEqual([]);
    expect(bob.splitViews).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);
});

describeIntegration('auditors', () => {
  it('checks the log against a real auditor over the network', async () => {
    // The wiring, end to end: a Go auditor reads this server's log, signs what
    // it saw, publishes it over HTTP, and the client fetches and verifies it.
    const alice = await bringUp('Alice');
    await alice.client.publishKeys(generatePreKeys(alice.identity, { count: 2 }).upload);
    await alice.client.claimHandle('auditwire');

    // The client needs its own verified view before there is anything to
    // compare against.
    const proof = (await alice.client.resolveHandle('auditwire')).proof!;
    const ours = verifyHandleProof(proof, 'auditwire', null);
    await alice.store.setMeta(
      CHECKPOINT_META_KEY,
      JSON.stringify({
        size: ours.size,
        rootHash: toBase64(ours.rootHash),
        logKey: toBase64(ours.logKey),
      }),
    );

    const { published, publicKey } = runRealAuditor(BASE_URL);
    const hosted = await servePublished(published);
    try {
      const checked = await alice.manager.checkAuditors([
        { url: hosted.url, publicKey, name: 'test auditor' },
      ]);
      expect(checked).toBe(1);
      expect(alice.errors).toEqual([]);
      expect(alice.splitViews).toEqual([]);
    } finally {
      hosted.close();
      alice.socket.close();
    }
  }, 180_000);

  it('does not raise an alarm when an auditor is unreachable', async () => {
    // An alarm the server can trigger by dropping one request is an alarm
    // people learn to dismiss.
    const alice = await bringUp('Alice');
    await alice.client.publishKeys(generatePreKeys(alice.identity, { count: 2 }).upload);
    await alice.client.claimHandle('auditgone');
    const ours = verifyHandleProof(
      (await alice.client.resolveHandle('auditgone')).proof!,
      'auditgone',
      null,
    );
    await alice.store.setMeta(
      CHECKPOINT_META_KEY,
      JSON.stringify({
        size: ours.size,
        rootHash: toBase64(ours.rootHash),
        logKey: toBase64(ours.logKey),
      }),
    );

    const checked = await alice.manager.checkAuditors([
      { url: 'http://127.0.0.1:1/checkpoint.json', publicKey: randomBytes(32), name: 'offline' },
    ]);

    expect(checked).toBe(0);
    expect(alice.splitViews).toEqual([]);
    expect(alice.errors.map((e) => e.message).join()).toMatch(/could not reach offline/);

    alice.socket.close();
  }, 120_000);

  it('treats a forged checkpoint as a broken publisher, not as an attack on the log', async () => {
    // Anyone can serve a document. Confusing "this publisher is lying" with
    // "the operator forked the log" would make the alarm trivially forgeable.
    const alice = await bringUp('Alice');
    await alice.client.publishKeys(generatePreKeys(alice.identity, { count: 2 }).upload);
    await alice.client.claimHandle('auditforge');
    const ours = verifyHandleProof(
      (await alice.client.resolveHandle('auditforge')).proof!,
      'auditforge',
      null,
    );
    await alice.store.setMeta(
      CHECKPOINT_META_KEY,
      JSON.stringify({
        size: ours.size,
        rootHash: toBase64(ours.rootHash),
        logKey: toBase64(ours.logKey),
      }),
    );

    const { published } = runRealAuditor(BASE_URL);
    const hosted = await servePublished(published);
    try {
      // Pinned to a key that did not sign this.
      const checked = await alice.manager.checkAuditors([
        { url: hosted.url, publicKey: randomBytes(32), name: 'impostor' },
      ]);
      expect(checked).toBe(0);
      expect(alice.splitViews).toEqual([]);
      expect(alice.errors.map((e) => e.message).join()).toMatch(/different auditor/);
    } finally {
      hosted.close();
      alice.socket.close();
    }
  }, 180_000);
});

// ---------------------------------------------------------------------------
// Renegotiation
// ---------------------------------------------------------------------------

describeIntegration('renegotiation', () => {
  async function connectedPair() {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);
    await bob.manager.answerCall(placed.callId, callSdp(2));
    await waitFor(() => alice.answers.length > 0);
    return { alice, bob, callId: placed.callId };
  }

  it('carries a re-offer and its answer between two real devices', async () => {
    const { alice, bob, callId } = await connectedPair();

    // Same fingerprint, new ICE credentials — what an ICE restart looks like.
    await bob.manager.renegotiateCall(callId, callSdp(2));
    await waitFor(() => alice.renegotiations.length > 0);
    expect(alice.renegotiations[0].sdp).toBe(callSdp(2));

    await alice.manager.answerRenegotiation(callId, callSdp(1));
    await waitFor(() => bob.renegotiationAnswers.length > 0);

    expect(alice.manager.currentCall()?.phase).toBe('connecting');
    expect(bob.manager.currentCall()?.phase).toBe('connecting');
    expect([...alice.errors, ...bob.errors]).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('ends the call when a re-offer changes the DTLS fingerprint', async () => {
    // The attack the pin exists for. Bob's own key signs this perfectly well,
    // so the signature cannot catch it — only comparing against what the call
    // was pinned to can. Carrying on would mean media continuing under a
    // certificate the user never agreed to.
    const { alice, bob, callId } = await connectedPair();

    const forged = signCallSdp(bob.identity, {
      kind: CallSignalKind.Renegotiate,
      callId,
      sdp: callSdp(7),
      fromAccountId: bob.accountId,
      toAccountId: alice.accountId,
    });
    await injectSignal(bob, alice, forged);

    expect(alice.renegotiations).toEqual([]);
    expect(alice.manager.currentCall()).toBeNull();
    expect(alice.errors.map((e) => e.message).join('\n')).toMatch(
      /no longer be with the key this call was pinned to/,
    );

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('ends the call when a re-offer is signed by somebody else', async () => {
    const { alice, bob, callId } = await connectedPair();

    const mallory = generateIdentity();
    const forged = signCallSdp(mallory, {
      kind: CallSignalKind.Renegotiate,
      callId,
      sdp: callSdp(2),
      fromAccountId: bob.accountId,
      toAccountId: alice.accountId,
    });
    await injectSignal(bob, alice, forged);

    expect(alice.renegotiations).toEqual([]);
    expect(alice.manager.currentCall()).toBeNull();
    expect(alice.errors.map((e) => e.message).join('\n')).toMatch(/not signed by the identity key/);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('ignores a re-offer for a call that is not happening', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    await alice.manager.sendMessage(bob.accountId, 'kuruyorum');
    await waitFor(() => bob.received.length > 0);

    await injectSignal(alice, bob, {
      kind: CallSignalKind.Renegotiate,
      callId: 'call-nothing99',
      body: callSdp(1),
      signature: randomBytes(64),
      timestamp: Date.now(),
    });

    expect(bob.renegotiations).toEqual([]);
    expect(bob.errors).toEqual([]);

    alice.socket.close();
    bob.socket.close();
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Unanswered calls
// ---------------------------------------------------------------------------

describeIntegration('a call nobody answers', () => {
  it('gives up, and stops the other phone ringing', async () => {
    // CALL_RINGING_TIMEOUT_MS and callHasTimedOut existed for several commits
    // with nothing calling them, so a call rang forever: no missed-call entry,
    // the line held against a second call, and a notification on the other
    // side for something that had stopped being true.
    const alice = await bringUp('Alice', { ringingTimeoutMs: 700 });
    const bob = await bringUp('Bob', { ringingTimeoutMs: 700 });

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);

    await waitFor(() => alice.manager.currentCall() === null, 10_000);
    expect(alice.callChanges.at(-1)?.endedReason).toBe('unanswered');

    await waitFor(() => bob.manager.currentCall() === null, 10_000);
    expect(bob.manager.currentCall()).toBeNull();
    expect(placed.callId).toBeTruthy();

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('does not give up on a call that was answered', async () => {
    // This test has to lose a race to be wrong, and it has to win one to run
    // at all: the answer must arrive before the timeout it is asserting does
    // not fire. Ten seconds is the margin — enough that a round trip through
    // a real server on a busy machine cannot eat it, since the failures this
    // replaces happened at 700ms. The wait afterwards is longer than the
    // timeout, so surviving it means the timer was cleared rather than merely
    // slow.
    const RINGING = 10_000;
    const alice = await bringUp('Alice', { ringingTimeoutMs: RINGING });
    const bob = await bringUp('Bob', { ringingTimeoutMs: RINGING });

    const placed = await alice.manager.placeCall(bob.accountId, { sdp: callSdp(1) });
    await waitFor(() => bob.incomingCalls.length > 0);
    await bob.manager.answerCall(placed.callId, callSdp(2));
    await waitFor(() => alice.answers.length > 0);

    await new Promise((r) => setTimeout(r, RINGING + 2_000));
    expect(alice.manager.currentCall()?.phase).toBe('connecting');
    expect(bob.manager.currentCall()?.phase).toBe('connecting');

    await alice.manager.endCall(placed.callId);
    alice.socket.close();
    bob.socket.close();
  }, 90_000);
});

// ---------------------------------------------------------------------------
// Prekey rotation and persistence
// ---------------------------------------------------------------------------

describeIntegration('signed prekey rotation', () => {
  /** A device whose prekey secrets are captured the way the app persists them. */
  async function deviceWithPersistence(name: string) {
    const identity = generateIdentity();
    const client = new TildraClient({ baseUrl: BASE_URL });
    const { accountId, deviceId } = await client.register(identity, name);
    await client.login(identity, accountId, deviceId);

    const { secrets, upload } = generatePreKeys(identity, { count: 3 });
    await client.publishKeys(upload);

    const store = new MemorySessionStore();
    const errors: Error[] = [];
    const received: string[] = [];
    // Serialised on the way in, exactly as the vault stores it. Holding the
    // live object instead would make this test pass with the persistence call
    // deleted, because the top-up mutates the same maps in place — which is
    // what the first version of this test did.
    let persistedBlob: SerializedPreKeys = encodePreKeys(secrets);

    const manager = new SessionManager({
      identity,
      accountId,
      deviceId,
      client,
      store,
      preKeys: secrets,
      randomId: () => toBase64(randomBytes(16)),
      onPreKeysChanged: async (next) => {
        persistedBlob = encodePreKeys(next);
      },
      events: {
        onMessage: (message) => received.push(message.text),
        onError: (error) => errors.push(error),
      },
    });

    return {
      identity,
      accountId,
      deviceId,
      client,
      store,
      manager,
      errors,
      received,
      secrets,
      /** What a restart would load: only ever what was handed to the callback. */
      persisted: () => decodePreKeys(identity, persistedBlob),
    };
  }

  it('rotates once the signed prekey is old, and not before', async () => {
    const bob = await deviceWithPersistence('Bob');
    const before = bob.secrets.signedPreKey.id;

    // Fresh: nothing to rotate, and the clock starts.
    expect(await bob.manager.rotateSignedPreKeysIfStale()).toBe(false);
    expect(await bob.manager.rotateSignedPreKeysIfStale()).toBe(false);

    // Old enough.
    await bob.store.setMeta(
      SIGNED_PREKEY_META_KEY,
      String(Date.now() - SIGNED_PREKEY_ROTATION_MS - 1000),
    );
    expect(await bob.manager.rotateSignedPreKeysIfStale()).toBe(true);
    expect(bob.persisted().signedPreKey.id).toBe(before + 1);
    expect(bob.persisted().previousSignedPreKey?.id).toBe(before);
    expect(bob.errors).toEqual([]);
  }, 60_000);

  it('still accepts a handshake from somebody holding the old bundle', async () => {
    // Rotation is not instantaneous from outside: a sender may have fetched
    // the bundle a minute before it was replaced. Dropping the old secret
    // would turn their first message into one nobody can read.
    const alice = await bringUp('Alice');
    const bob = await deviceWithPersistence('Bob');

    // Alice fetches the bundle and builds a session against it...
    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    const oldSignedId = bundle.signedPreKey.id;

    // ...and Bob rotates before her first message lands.
    await bob.store.setMeta(
      SIGNED_PREKEY_META_KEY,
      String(Date.now() - SIGNED_PREKEY_ROTATION_MS - 1000),
    );
    expect(await bob.manager.rotateSignedPreKeysIfStale()).toBe(true);
    expect(bob.persisted().signedPreKey.id).not.toBe(oldSignedId);

    const init = initiateSession(alice.identity, bundle);
    expect(() => acceptSession(bob.persisted(), init.init)).not.toThrow();
  }, 60_000);

  it('refuses a signed prekey two rotations old', async () => {
    // One generation of grace, not two: a retained secret is a secret still
    // worth stealing, and the window is the thing rotation exists to shrink.
    const alice = await bringUp('Alice');
    const bob = await deviceWithPersistence('Bob');

    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    for (let i = 0; i < 2; i++) {
      await bob.store.setMeta(
        SIGNED_PREKEY_META_KEY,
        String(Date.now() - SIGNED_PREKEY_ROTATION_MS - 1000),
      );
      expect(await bob.manager.rotateSignedPreKeysIfStale()).toBe(true);
    }

    const init = initiateSession(alice.identity, bundle);
    expect(() => acceptSession(bob.persisted(), init.init)).toThrow(
      /signed prekey this device does not hold/,
    );
  }, 60_000);

  it('keeps the one-time secrets it already published across a rotation', async () => {
    // `rotateSignedPreKeys` builds the new bundle with `count: 0` and then
    // carries the existing pools over, with a comment saying the upload "must
    // not claim to replace them". Two halves to that, and only one is on the
    // server: the store accumulates one-time keys, so an empty list adds
    // nothing and destroys nothing, and the conformance suite covers it.
    //
    // The half here is the device's own. If a rotation dropped the pools, the
    // server would go on handing out public halves whose secrets this device
    // had forgotten, and every sender who drew one would get a first message
    // nobody can read — the same failure as publishing keys that never reached
    // disk.
    //
    // The control says this was already caught, by "still accepts a handshake
    // from somebody holding the old bundle": that test fetches a bundle, which
    // draws a one-time prekey, so dropping the pools fails it too — with an
    // error about a key its name says nothing about. Incidental coverage that
    // would go away the moment that fixture stopped drawing one. This asserts
    // the thing itself: the secret is still on disk under the id that was
    // handed out, both pools survived, and the handshake built before the
    // rotation completes after it.
    const alice = await bringUp('Alice');
    const bob = await deviceWithPersistence('Bob');

    // Alice draws a one-time prekey from the pool as it stands now.
    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    expect(bundle.oneTimePreKey, 'the pool should have handed one out').toBeDefined();
    const drawn = bundle.oneTimePreKey!.id;

    // Bob rotates his signed prekeys before her first message lands.
    await bob.store.setMeta(
      SIGNED_PREKEY_META_KEY,
      String(Date.now() - SIGNED_PREKEY_ROTATION_MS - 1000),
    );
    expect(await bob.manager.rotateSignedPreKeysIfStale()).toBe(true);

    // The secret behind the key she drew is still on disk, under its own id.
    expect(bob.persisted().oneTimePreKeys.has(drawn)).toBe(true);
    expect(bob.persisted().oneTimePqPreKeys.size).toBe(3);

    // And the handshake she built against the pre-rotation bundle completes,
    // which is the property rather than the bookkeeping.
    const init = initiateSession(alice.identity, bundle);
    expect(() => acceptSession(bob.persisted(), init.init)).not.toThrow();
    expect(bob.errors).toEqual([]);
  }, 60_000);

  it('writes down the one-time secrets it publishes', async () => {
    // The bug this callback exists for: the top-up generated a hundred new
    // one-time secrets, published their public halves, and nothing stored
    // them. After a restart the server was handing out keys this device no
    // longer held.
    const bob = await deviceWithPersistence('Bob');
    expect(bob.persisted().oneTimePreKeys.size).toBe(3);

    // Draw the pool down below the low-water mark.
    for (let i = 0; i < 3; i++) {
      const caller = await bringUp('Caller');
      await caller.manager.sendMessage(bob.accountId, `merhaba ${i}`);
      caller.socket.close();
    }

    expect(await bob.manager.topUpPreKeysIfLow()).toBe(true);
    expect(bob.persisted().oneTimePreKeys.size).toBeGreaterThan(3);

    // A device rebuilt from what was persisted — a restart — can still take a
    // handshake against a freshly published one-time key.
    const alice = await bringUp('Alice');
    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    expect(bundle.oneTimePreKey).toBeDefined();

    const init = initiateSession(alice.identity, bundle);
    expect(() => acceptSession(bob.persisted(), init.init)).not.toThrow();

    alice.socket.close();
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Where group messages live
// ---------------------------------------------------------------------------

describeIntegration('group conversations', () => {
  it('files a group message under the group, not under whoever sent it', async () => {
    // A group of five used to scatter its history across five one-to-one
    // chats, because a received group message was stored against the sender's
    // pairwise conversation. There was nothing a group screen could render.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    const carol = await bringUp('Carol');

    // Pairwise sessions first: sender keys travel over them.
    for (const other of [bob, carol]) {
      await alice.manager.sendMessage(other.accountId, 'merhaba');
      await waitFor(() => other.received.length > 0);
      await other.manager.sendMessage(alice.accountId, 'selam');
    }
    await waitFor(() => alice.received.length === 2);

    await alice.manager.createGroup(
      'grp-where',
      [alice.member(), bob.member(), carol.member()],
      'Kitap kulübü',
    );
    await alice.manager.sendGroupMessage('grp-where', 'herkese merhaba');
    await waitFor(() => bob.groupReceived.length > 0 && carol.groupReceived.length > 0);

    const key = groupConversationKey('grp-where');
    for (const device of [alice, bob, carol]) {
      const conversation = await device.store.getConversation(key);
      expect(conversation, `${device.name} has no group conversation`).toBeTruthy();

      const messages = device.store.listMessages(conversation!.id);
      expect(messages.map((m) => m.text)).toContain('herkese merhaba');
      expect(messages.find((m) => m.text === 'herkese merhaba')?.senderAccountId).toBe(
        alice.accountId,
      );
    }

    // And not in the one-to-one chat with Alice.
    const pairwise = await bob.store.getConversation(alice.accountId);
    const direct = bob.store.listMessages(pairwise!.id);
    expect(direct.map((m) => m.text)).not.toContain('herkese merhaba');

    [alice, bob, carol].forEach((d) => d.socket.close());
  }, 120_000);

  it('shows the sender their own group message', async () => {
    // Sending something and not seeing it is not a subtle bug, and until now
    // it was the behaviour: the outgoing message was never stored.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);
    await bob.manager.sendMessage(alice.accountId, 'selam');
    await waitFor(() => alice.received.length > 0);

    await alice.manager.createGroup('grp-echo', [alice.member(), bob.member()], 'İkili');
    await alice.manager.sendGroupMessage('grp-echo', 'benim mesajım');

    const conversation = await alice.store.getConversation(groupConversationKey('grp-echo'));
    const messages = alice.store.listMessages(conversation!.id);
    const own = messages.find((m) => m.text === 'benim mesajım');

    expect(own).toBeTruthy();
    expect(own!.outgoing).toBe(true);
    expect(own!.state).toBe('sent');
    expect(own!.senderAccountId).toBe(alice.accountId);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('keeps every member of a group in one thread', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);
    await bob.manager.sendMessage(alice.accountId, 'selam');
    await waitFor(() => alice.received.length > 0);

    await alice.manager.createGroup('grp-thread', [alice.member(), bob.member()], 'Sohbet');
    await alice.manager.sendGroupMessage('grp-thread', 'birinci');
    await waitFor(() => bob.groupReceived.length > 0);
    await bob.manager.sendGroupMessage('grp-thread', 'ikinci');
    await waitFor(() => alice.groupReceived.length > 1);

    const conversation = await alice.store.getConversation(groupConversationKey('grp-thread'));
    const messages = alice.store.listMessages(conversation!.id);
    expect(messages.map((m) => m.text).sort()).toEqual(['birinci', 'ikinci']);
    // One of each direction, in one place.
    expect(messages.filter((m) => m.outgoing)).toHaveLength(1);
    expect(messages.filter((m) => !m.outgoing)).toHaveLength(1);

    alice.socket.close();
    bob.socket.close();
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Group membership, in units of people
// ---------------------------------------------------------------------------

describeIntegration('changing who is in a group', () => {
  /** Alice and Bob, with sessions in both directions. */
  async function pair() {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);
    await bob.manager.sendMessage(alice.accountId, 'selam');
    await waitFor(() => alice.received.length > 0);
    return { alice, bob };
  }

  it('removes every device a person has, in one rotation', async () => {
    // Removing device by device rotates after each one and redistributes to
    // whoever is left — which still includes that person's other phones. They
    // are handed the new key on the way out and keep reading.
    const { alice, bob } = await pair();

    // Bob with two devices. The second is registered the way a linked device
    // is; what matters here is that the group holds two members for one
    // account.
    const secondDeviceId = `${bob.deviceId}-second`;
    await alice.manager.createGroup('grp-people', [
      alice.member(),
      bob.member(),
      { accountId: bob.accountId, deviceId: secondDeviceId },
    ]);

    const before = await alice.manager.listGroups();
    expect(before.find((g) => g.groupId === 'grp-people')?.members).toHaveLength(3);

    const after = await alice.manager.removeGroupAccount('grp-people', bob.accountId);
    expect(after.members.map((m) => m.accountId)).toEqual([alice.accountId]);
    expect(after.members.some((m) => m.deviceId === secondDeviceId)).toBe(false);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('leaves the group alone when the person is not in it', async () => {
    // Otherwise a mistaken tap rotates the sender keys for everyone, which is
    // a redistribution to every device for no reason.
    const { alice, bob } = await pair();
    await alice.manager.createGroup('grp-absent', [alice.member(), bob.member()]);

    const unchanged = await alice.manager.removeGroupAccount('grp-absent', 'acct-nobody');
    expect(unchanged.members).toHaveLength(2);

    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('adds every device the new member has', async () => {
    // Adding one device of somebody's two means half their messages arrive
    // and half do not, which reads as the app losing messages.
    const { alice, bob } = await pair();
    const carol = await bringUp('Carol');
    await alice.manager.sendMessage(carol.accountId, 'merhaba');
    await waitFor(() => carol.received.length > 0);
    await carol.manager.sendMessage(alice.accountId, 'selam');
    await waitFor(() => alice.received.length > 1);

    await alice.manager.createGroup('grp-add', [alice.member(), bob.member()]);
    const grown = await alice.manager.addGroupAccount('grp-add', carol.accountId);

    const carolDevices = await alice.client.listDevices(carol.accountId);
    expect(carolDevices.length).toBeGreaterThan(0);
    expect(grown.members.filter((m) => m.accountId === carol.accountId)).toHaveLength(
      carolDevices.length,
    );

    // And the newcomer can read what is sent after they joined.
    await alice.manager.sendGroupMessage('grp-add', 'hoş geldin');
    await waitFor(() => carol.groupReceived.length > 0);
    expect(carol.groupReceived.map((m) => m.text)).toContain('hoş geldin');

    [alice, bob, carol].forEach((d) => d.socket.close());
  }, 120_000);

  it('locks a removed person out of what is said afterwards', async () => {
    // The property removal exists for. Carol holds a sender key for the old
    // epoch; after the rotation it derives nothing that is sent.
    const { alice, bob } = await pair();
    const carol = await bringUp('Carol');
    await alice.manager.sendMessage(carol.accountId, 'merhaba');
    await waitFor(() => carol.received.length > 0);
    await carol.manager.sendMessage(alice.accountId, 'selam');
    await waitFor(() => alice.received.length > 1);

    await alice.manager.createGroup('grp-lock', [alice.member(), bob.member(), carol.member()]);
    await alice.manager.sendGroupMessage('grp-lock', 'carol buradayken');
    await waitFor(() => carol.groupReceived.length > 0 && bob.groupReceived.length > 0);

    await alice.manager.removeGroupAccount('grp-lock', carol.accountId);
    await alice.manager.sendGroupMessage('grp-lock', 'carol gittikten sonra');
    await waitFor(() => bob.groupReceived.length > 1);

    expect(bob.groupReceived.map((m) => m.text)).toContain('carol gittikten sonra');
    expect(carol.groupReceived.map((m) => m.text)).not.toContain('carol gittikten sonra');

    [alice, bob, carol].forEach((d) => d.socket.close());
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

describeIntegration('recovering from a phrase', () => {
  it('finds and opens a blob knowing only the phrase', async () => {
    // The circle this breaks: logging in needs an account id, and the account
    // id was on the device that is gone. The blob is addressed by something
    // the phrase produces, so a person with the phrase and nothing else can
    // reach it.
    const phrase = generateRecoveryPhrase();
    const { identity, backupKey, lookupId } = recoveryKeys(phrase);

    const client = new TildraClient({ baseUrl: BASE_URL });
    const { accountId, deviceId } = await client.register(identity, 'Phone');
    await client.login(identity, accountId, deviceId);

    await client.putRecoveryBlob(
      lookupId,
      sealBackup(backupKey, {
        accountId,
        deviceId,
        contacts: [{ accountId: 'acct-bob', displayName: 'Bob' }],
        groups: [],
        updatedAt: Date.now(),
      }),
    );

    // A new device, holding nothing but the words.
    const fresh = new TildraClient({ baseUrl: BASE_URL });
    const recovered = recoveryKeys(phrase);
    const sealed = await fresh.getRecoveryBlob(recovered.lookupId);
    expect(sealed).toBeTruthy();

    const backup = openBackup(recovered.backupKey, sealed!);
    expect(backup.contacts[0].displayName).toBe('Bob');

    // And the derived identity is the account's, so it can sign in again.
    const credentials = await fresh.login(recovered.identity, accountId, deviceId);
    expect(credentials.token).toBeTruthy();
  }, 90_000);

  it('gives nothing to a different phrase', async () => {
    const phrase = generateRecoveryPhrase();
    const { identity, backupKey, lookupId } = recoveryKeys(phrase);

    const client = new TildraClient({ baseUrl: BASE_URL });
    const { accountId, deviceId } = await client.register(identity, 'Phone');
    await client.login(identity, accountId, deviceId);
    await client.putRecoveryBlob(
      lookupId,
      sealBackup(backupKey, {
        accountId,
        deviceId, contacts: [], groups: [], updatedAt: Date.now() }),
    );

    const other = recoveryKeys(generateRecoveryPhrase());
    expect(await client.getRecoveryBlob(other.lookupId)).toBeNull();
  }, 90_000);

  it('names the account it belongs to, which is what the caller is missing', async () => {
    // The recovering device knows the phrase and nothing else. The account id
    // and device id it needs to sign in come out of the blob.
    const phrase = generateRecoveryPhrase();
    const { identity, backupKey, lookupId } = recoveryKeys(phrase);

    const client = new TildraClient({ baseUrl: BASE_URL });
    const { accountId, deviceId } = await client.register(identity, 'Phone');
    await client.login(identity, accountId, deviceId);
    await client.putRecoveryBlob(
      lookupId,
      sealBackup(backupKey, {
        accountId,
        deviceId, contacts: [], groups: [], updatedAt: Date.now() }),
    );

    const sealed = await client.getRecoveryBlob(lookupId);
    const backup = openBackup(backupKey, sealed!);
    expect(backup.accountId).toBe(accountId);
    expect(backup.deviceId).toBe(deviceId);
  }, 90_000);

  it('will not let another account take the id over', async () => {
    const phrase = generateRecoveryPhrase();
    const { identity, backupKey, lookupId } = recoveryKeys(phrase);

    const client = new TildraClient({ baseUrl: BASE_URL });
    const { accountId, deviceId } = await client.register(identity, 'Phone');
    await client.login(identity, accountId, deviceId);
    await client.putRecoveryBlob(
      lookupId,
      sealBackup(backupKey, {
        accountId,
        deviceId, contacts: [], groups: [], updatedAt: Date.now() }),
    );

    const attacker = await bringUp('Mallory');
    await expect(attacker.client.putRecoveryBlob(lookupId, utf8('mine now'))).rejects.toThrow();

    // And the original is untouched.
    const sealed = await client.getRecoveryBlob(lookupId);
    expect(openBackup(backupKey, sealed!).contacts).toEqual([]);

    attacker.socket.close();
  }, 90_000);
});

// ---------------------------------------------------------------------------
// Reaching somebody who lost their sessions
// ---------------------------------------------------------------------------

describeIntegration('receipts and typing', () => {
  it('marks a message delivered when it reaches the other end', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      const sent = await alice.manager.sendMessage(bob.accountId, 'ulaştı mı');
      await waitFor(() => bob.received.length > 0);

      // The id in the receipt is the one Alice chose. That is the whole point
      // of carrying it on the wire: the two stores generate different ids for
      // the same message, so a receipt naming Bob's would key nothing.
      await waitFor(() => alice.receipts.length > 0, 15_000);
      expect(alice.receipts[0].kind).toBe('delivered');
      expect(alice.receipts[0].messageIds).toContain(sent.id);
      expect(alice.store.messages.find((m) => m.id === sent.id)!.state).toBe('delivered');
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('marks it read when the other end opens the conversation', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      const sent = await alice.manager.sendMessage(bob.accountId, 'okundu mu');
      await waitFor(() => bob.received.length > 0);
      await waitFor(() => alice.store.messages.find((m) => m.id === sent.id)!.state === 'delivered');

      await bob.manager.sendReadReceipts(alice.accountId);
      await waitFor(
        () => alice.store.messages.find((m) => m.id === sent.id)!.state === 'read',
        15_000,
      );

      // And Bob's own copy is read too, so reopening does not re-announce the
      // same batch every time.
      const bobCopy = bob.store.messages.find((m) => !m.outgoing)!;
      expect(bobCopy.state).toBe('read');
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('sends nothing when there is nothing new to acknowledge', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      await alice.manager.sendMessage(bob.accountId, 'bir kere');
      await waitFor(() => bob.received.length > 0);
      await bob.manager.sendReadReceipts(alice.accountId);
      await waitFor(() => alice.receipts.some((r) => r.kind === 'read'), 15_000);

      const before = alice.receipts.length;
      await bob.manager.sendReadReceipts(alice.accountId);
      await bob.manager.sendReadReceipts(alice.accountId);
      // Nothing to say, so nothing sent. Without the `state !== 'read'` filter
      // every open of an old conversation would re-send the whole batch.
      await new Promise((r) => setTimeout(r, 1_000));
      expect(alice.receipts.length).toBe(before);
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('does not acknowledge an acknowledgement', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      await alice.manager.sendMessage(bob.accountId, 'yankı');
      await waitFor(() => alice.receipts.length > 0, 15_000);
      await new Promise((r) => setTimeout(r, 1_000));

      // Bob acknowledged one message. If a receipt were itself acknowledged
      // the two devices would trade them forever, and the count would climb
      // rather than settle at one.
      expect(alice.receipts).toHaveLength(1);
      expect(bob.receipts).toHaveLength(0);
      // And no receipt was ever rendered as a chat message on either side.
      expect(bob.received).toEqual(['yankı']);
      expect(alice.received).toEqual([]);
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('carries composing state, and taking it back', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      // A session has to exist first: typing is fire-and-forget, so it must
      // not be the thing that establishes one.
      await alice.manager.sendMessage(bob.accountId, 'merhaba');
      await waitFor(() => bob.received.length > 0);

      await alice.manager.sendTyping(bob.accountId, true);
      await waitFor(() => bob.typing.length > 0, 15_000);
      expect(bob.typing[0]).toEqual({ accountId: alice.accountId, typing: true });

      await alice.manager.sendTyping(bob.accountId, false);
      await waitFor(() => bob.typing.length > 1, 15_000);
      expect(bob.typing[1]).toEqual({ accountId: alice.accountId, typing: false });

      // Nothing about it reached the thread or the database.
      expect(bob.received).toEqual(['merhaba']);
      expect(bob.store.messages.filter((m) => !m.outgoing)).toHaveLength(1);
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('sends no read receipt when the setting is off, and still sends delivered', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      await bob.manager.setPrivacy({ readReceipts: false, typingIndicators: true });

      const sent = await alice.manager.sendMessage(bob.accountId, 'okuma bildirme');
      await waitFor(() => bob.received.length > 0);

      // Delivered is unaffected: it is a fact about the network rather than
      // about anybody's attention, and without it the tick means nothing.
      await waitFor(() => alice.receipts.some((r) => r.kind === 'delivered'), 15_000);

      await bob.manager.sendReadReceipts(alice.accountId);
      await new Promise((r) => setTimeout(r, 1_000));
      expect(alice.receipts.some((r) => r.kind === 'read')).toBe(false);
      expect(alice.store.messages.find((m) => m.id === sent.id)!.state).toBe('delivered');
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('does not display a read receipt it would not send', async () => {
    // The reciprocal half, and the one that makes the setting honest rather
    // than a way to take without giving.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      const sent = await alice.manager.sendMessage(bob.accountId, 'karşılıklı');
      await waitFor(() => bob.received.length > 0);
      await waitFor(() => alice.store.messages.find((m) => m.id === sent.id)!.state === 'delivered');

      // Alice turns hers off *after* the exchange, so Bob still sends one.
      await alice.manager.setPrivacy({ readReceipts: false, typingIndicators: true });
      await bob.manager.sendReadReceipts(alice.accountId);

      await new Promise((r) => setTimeout(r, 1_500));
      expect(alice.receipts.some((r) => r.kind === 'read')).toBe(false);
      expect(alice.store.messages.find((m) => m.id === sent.id)!.state).toBe('delivered');
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('sends and shows nothing when typing indicators are off', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      await alice.manager.sendMessage(bob.accountId, 'sessiz');
      await waitFor(() => bob.received.length > 0);

      await alice.manager.setPrivacy({ readReceipts: true, typingIndicators: false });
      await alice.manager.sendTyping(bob.accountId, true);
      await new Promise((r) => setTimeout(r, 1_000));
      expect(bob.typing).toEqual([]);

      // And the receiving half: Bob turns his off, Alice turns hers back on
      // and composes — Bob is told nothing.
      await alice.manager.setPrivacy({ readReceipts: true, typingIndicators: true });
      await bob.manager.setPrivacy({ readReceipts: true, typingIndicators: false });
      await alice.manager.sendTyping(bob.accountId, true);
      await new Promise((r) => setTimeout(r, 1_500));
      expect(bob.typing).toEqual([]);
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);

  it('defaults to on and survives a reload of the settings', async () => {
    const alice = await bringUp('Alice');
    try {
      expect(await alice.manager.getPrivacy()).toEqual({
        readReceipts: true,
        typingIndicators: true,
      });
      await alice.manager.setPrivacy({ readReceipts: false, typingIndicators: false });
      expect(await alice.manager.getPrivacy()).toEqual({
        readReceipts: false,
        typingIndicators: false,
      });
    } finally {
      alice.socket.close();
    }
  }, 40_000);

  it('does not tell a contact whose key changed that anybody is typing', async () => {
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    try {
      await alice.manager.sendMessage(bob.accountId, 'önce');
      await waitFor(() => bob.received.length > 0);

      // The identity-change block covers what a user sends, and composing
      // state is something they are sending. This is the third path to be
      // caught missing it — see STATUS on calls.
      //
      // Flagged while keeping Bob's *real* key, which is the shape that
      // matters and the one STATUS records as the trap: flagging adopts the
      // new key, so `assertIdentityUnchanged` compares the stored key against
      // the same key and passes. Only the flag itself stops this. Written the
      // obvious way first — a random key — the negative control passed,
      // because the key mismatch threw before the guard was ever reached.
      const conversation = (await alice.store.getConversation(bob.accountId))!;
      await alice.store.upsertConversation({
        ...conversation,
        identityKey: bob.identity.publicKey,
        identityChanged: true,
      });
      await alice.manager.sendTyping(bob.accountId, true);

      await new Promise((r) => setTimeout(r, 1_000));
      expect(bob.typing).toEqual([]);
    } finally {
      alice.socket.close();
      bob.socket.close();
    }
  }, 60_000);
});

describeIntegration('a contact whose session is gone', () => {
  /**
   * Rebuild a device the way recovery does: same account, same device, same
   * identity key, and an empty store. No ratchets, no per-session mailboxes.
   */
  async function afterRecovery(device: Device): Promise<Device> {
    const store = new MemorySessionStore();
    const received: string[] = [];
    const errors: Error[] = [];
    let socket: TildraSocket | undefined;

    const manager = new SessionManager({
      identity: device.identity,
      accountId: device.accountId,
      deviceId: device.deviceId,
      client: device.client,
      store,
      preKeys: generatePreKeys(device.identity, { count: 10 }).secrets,
      randomId: () => toBase64(randomBytes(16)),
      onMailboxesChanged: (mailboxes) => socket?.subscribe(mailboxes),
      events: {
        onMessage: (message) => received.push(message.text),
        onError: (error) => errors.push(error),
      },
    });
    await device.client.publishKeys(generatePreKeys(device.identity, { count: 10 }).upload);
    await manager.publishMailboxes();

    socket = new TildraSocket(BASE_URL, device.client.getCredentials()!.token, {
      onEnvelope: (envelope) => manager.receiveEnvelope(envelope).then(() => undefined),
      onError: (error) => errors.push(error),
    });
    socket.connect();
    await new Promise((r) => setTimeout(r, 300));

    return { ...device, store, manager, socket, received, errors };
  }

  it('repairs itself after one lost message rather than looping forever', async () => {
    // The recovery case, and it does not go the way it looks like it should.
    // Mailbox registration lives on the server, so Alice's address is still
    // valid and her send succeeds — the message arrives at a device that
    // cannot decrypt it. That used to throw, which left the envelope unacked
    // and the server redelivering it forever.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');

    await alice.manager.sendMessage(bob.accountId, 'önce');
    await waitFor(() => bob.received.length > 0);
    await bob.manager.sendMessage(alice.accountId, 'cevap');
    await waitFor(() => alice.received.length > 0);

    // Drain the receipts before taking Bob's session away.
    //
    // Every received message now sends one back, and a receipt still in flight
    // when the session is destroyed arrives at a device that cannot read it —
    // which triggers the same self-repair a lost *message* does, only earlier.
    // The scenario below depends on the repair happening after 'kayıp' is
    // sent, so this waits for the traffic that would otherwise cause it. Both
    // directions, because both ends received something.
    await waitFor(() => bob.store.messages.find((m) => m.outgoing)?.state === 'delivered');
    await waitFor(() => alice.store.messages.find((m) => m.outgoing)?.state === 'delivered');
    bob.socket.close();

    const recovered = await afterRecovery(bob);
    try {
      // The first one is lost. It was encrypted to a ratchet that no longer
      // exists and no amount of retrying changes that.
      await alice.manager.sendMessage(bob.accountId, 'kayıp');
      await waitFor(() => recovered.errors.length > 0, 15_000);
      expect(recovered.errors.map((e) => e.message).join()).toMatch(/no longer has/);

      // The repair handshakes at Alice — a profile, which is not a chat
      // message, so nothing new appears in her thread. Waiting on the profile
      // rather than on a timer is the difference between testing the
      // mechanism and testing that fifteen seconds is usually enough.
      await waitFor(() => alice.profileChanges.includes(bob.accountId), 15_000);
      expect(alice.profileChanges).toContain(bob.accountId);
      await alice.manager.sendMessage(bob.accountId, 'sonra');
      await waitFor(() => recovered.received.length > 0, 15_000);
      expect(recovered.received).toEqual(['sonra']);

      await recovered.manager.sendMessage(alice.accountId, 'ben de');
      await waitFor(() => alice.received.includes('ben de'), 15_000);
      expect(alice.received).toEqual(['cevap', 'ben de']);
    } finally {
      alice.socket.close();
      recovered.socket.close();
    }
  }, 150_000);

  it('does not spin when the server always says no', async () => {
    // One re-handshake, then the failure is the caller's. A server answering
    // 404 forever must not become an infinite loop that also drains the
    // one-time prekey pool.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);

    const realSend = alice.client.sendEnvelope.bind(alice.client);
    let attempts = 0;
    alice.client.sendEnvelope = async () => {
      attempts += 1;
      throw new ApiError(404, 'unknown mailbox');
    };

    await alice.manager.sendMessage(bob.accountId, 'bu gitmeyecek');
    expect(attempts).toBe(2);

    alice.client.sendEnvelope = realSend;
    alice.socket.close();
    bob.socket.close();
  }, 90_000);

  it('still delivers a group message to a device with no sessions', async () => {
    // A group message is sealed to the identity key rather than to a ratchet,
    // so it only needs an address that is listened on. The contact inbox is
    // derived from that same key and is what a device with no sessions has.
    const alice = await bringUp('Alice');
    const bob = await bringUp('Bob');
    await alice.manager.sendMessage(bob.accountId, 'merhaba');
    await waitFor(() => bob.received.length > 0);
    await bob.manager.sendMessage(alice.accountId, 'selam');
    await waitFor(() => alice.received.length > 0);

    await alice.manager.createGroup('grp-recovered', [alice.member(), bob.member()]);
    bob.socket.close();
    const recovered = await afterRecovery(bob);

    try {
      // Sending must not throw: the fallback address is used rather than the
      // dead per-session one.
      await expect(
        alice.manager.sendGroupMessage('grp-recovered', 'gruba'),
      ).resolves.toBeGreaterThan(0);
    } finally {
      alice.socket.close();
      recovered.socket.close();
    }
  }, 120_000);
});
