/**
 * End-to-end test against the real Go server.
 *
 * Unit tests prove each side is self-consistent. This proves the two sides
 * agree — that the registration proof Go verifies is the one TypeScript
 * produces, that base64 means the same thing in both, and that a message can
 * actually travel from one device to another through the server without the
 * server being able to read it.
 *
 * Skips itself if the Go toolchain is unavailable, so `npm test` still works
 * on a machine that only has Node.
 */

import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { ApiError, TildraClient } from '../client';
import { TildraSocket } from '../socket';
import { generateIdentity, generatePreKeys } from '../../crypto/identity';
import { acceptSession, initiateSession, verifyBundle } from '../../crypto/pqxdh';
import { decrypt, encrypt } from '../../crypto/ratchet';
import { openEnvelope, sealEnvelope } from '../../crypto/sealed';
import { currentMailboxes, deliveryMailbox } from '../../crypto/mailbox';
import { equal, fromUtf8, randomBytes, utf8 } from '../../crypto/primitives';
import { safetyNumber } from '../../crypto/safety';

const SERVER_DIR = join(__dirname, '../../../../server');
const PORT = 8791;
const BASE_URL = `http://127.0.0.1:${PORT}`;

function goAvailable(): boolean {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return existsSync(join(SERVER_DIR, 'go.mod'));
  } catch {
    return false;
  }
}

const canRun = goAvailable();
const describeIntegration = canRun ? describe : describe.skip;

let server: ChildProcess | null = null;

async function waitForHealth(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE_URL}/healthz`);
      if (res.ok) return;
    } catch {
      // Not up yet.
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Tildra server did not become healthy in time');
}

describeIntegration('client ↔ server integration', () => {
  beforeAll(async () => {
    // Build first so the spawn is fast and any compile error surfaces here
    // rather than as a mysterious connection refused.
    const binary = join(mkdtempSync(join(tmpdir(), 'tildra-')), 'tildrad');
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

  afterAll(() => {
    server?.kill('SIGTERM');
  });

  /** Register a device and publish its keys, as onboarding would. */
  async function onboard(name: string, preKeyCount = 5) {
    const identity = generateIdentity();
    const client = new TildraClient({ baseUrl: BASE_URL });
    const { accountId, deviceId } = await client.register(identity, name);
    await client.login(identity, accountId, deviceId);
    const { secrets, upload } = generatePreKeys(identity, { count: preKeyCount });
    await client.publishKeys(upload);
    return { identity, client, accountId, deviceId, secrets };
  }

  it('registers a device the Go server accepts', async () => {
    const alice = await onboard('Alice iPhone');
    expect(alice.accountId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(alice.client.getCredentials()?.token).toBeTruthy();
  });

  it('rejects a token the server never issued', async () => {
    const client = new TildraClient({ baseUrl: BASE_URL });
    client.setCredentials({ accountId: 'X', deviceId: 'Y', token: 'forged', expiresAt: '' });
    await expect(client.preKeyCount()).rejects.toSatisfy(
      (e: unknown) => e instanceof ApiError && e.status === 401,
    );
  });

  it('publishes and retrieves a prekey bundle that verifies', async () => {
    const bob = await onboard('Bob Pixel');
    const alice = await onboard('Alice iPhone');

    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    // If this throws, the server altered the keys in transit.
    expect(() => verifyBundle(bundle)).not.toThrow();
    expect(equal(bundle.identityKey, bob.identity.publicKey)).toBe(true);
    expect(bundle.oneTimePreKey).toBeDefined();
    expect(bundle.oneTimePqPreKey).toBeDefined();
  });

  it('consumes one-time prekeys, and the count the server reports drops', async () => {
    const bob = await onboard('Bob', 3);
    const alice = await onboard('Alice');

    const before = await bob.client.preKeyCount();
    expect(before.oneTimePreKeys).toBe(3);

    await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    const after = await bob.client.preKeyCount();
    expect(after.oneTimePreKeys).toBe(2);
    expect(after.oneTimePqPreKeys).toBe(2);
  });

  it('delivers a sealed message end to end without the server reading it', async () => {
    const bob = await onboard('Bob Pixel');
    const alice = await onboard('Alice iPhone');

    // In the real protocol this secret comes out of the session; here it
    // stands in for the value the two clients have already agreed on.
    const mailboxSecret = randomBytes(32);
    await bob.client.registerMailboxes(currentMailboxes(mailboxSecret));

    const received: string[] = [];
    const socket = new TildraSocket(BASE_URL, bob.client.getCredentials()!.token, {
      onEnvelope: (envelope) => {
        const opened = openEnvelope(bob.identity, envelope.ciphertext);
        expect(opened.sessionInit).toBeDefined();
        const session = acceptSession(bob.secrets, opened.sessionInit!);
        received.push(fromUtf8(decrypt(session.ratchet, opened.message, session.associatedData)));
      },
    });
    socket.connect();
    await new Promise((r) => setTimeout(r, 500));

    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    verifyBundle(bundle);
    const session = initiateSession(alice.identity, bundle);
    const message = encrypt(session.ratchet, utf8('gizli mesaj'), session.associatedData);
    const envelope = sealEnvelope(bundle.identityKey, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      senderIdentityKey: alice.identity.publicKey,
      sessionInit: session.init,
      message,
    });

    await alice.client.sendEnvelope(deliveryMailbox(mailboxSecret), envelope);

    const deadline = Date.now() + 10_000;
    while (received.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }
    socket.close();

    expect(received).toEqual(['gizli mesaj']);
  }, 30_000);

  it('queues messages for an offline device and delivers them on reconnect', async () => {
    const bob = await onboard('Bob Offline');
    const alice = await onboard('Alice');

    const mailboxSecret = randomBytes(32);
    await bob.client.registerMailboxes(currentMailboxes(mailboxSecret));

    // Bob is not connected. Alice sends anyway.
    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);
    verifyBundle(bundle);
    const session = initiateSession(alice.identity, bundle);
    const envelope = sealEnvelope(bundle.identityKey, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      senderIdentityKey: alice.identity.publicKey,
      sessionInit: session.init,
      message: encrypt(session.ratchet, utf8('while you were out'), session.associatedData),
    });
    await alice.client.sendEnvelope(deliveryMailbox(mailboxSecret), envelope);

    // Bob comes online and must receive the backlog.
    const received: string[] = [];
    const socket = new TildraSocket(BASE_URL, bob.client.getCredentials()!.token, {
      onEnvelope: (e) => {
        const opened = openEnvelope(bob.identity, e.ciphertext);
        const s = acceptSession(bob.secrets, opened.sessionInit!);
        received.push(fromUtf8(decrypt(s.ratchet, opened.message, s.associatedData)));
      },
    });
    socket.connect();

    const deadline = Date.now() + 10_000;
    while (received.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }
    socket.close();
    expect(received).toEqual(['while you were out']);
  }, 30_000);

  it('refuses to deliver to a mailbox nobody registered', async () => {
    const alice = await onboard('Alice');
    await expect(
      alice.client.sendEnvelope(`mb_${'0'.repeat(32)}`, randomBytes(64)),
    ).rejects.toSatisfy((e: unknown) => e instanceof ApiError && e.status === 404);
  });

  it('claims a handle and resolves it back to the account', async () => {
    const alice = await onboard('Alice');
    const handle = `ayse_${Math.floor(Number(process.hrtime.bigint() % 100000n))}`;
    await alice.client.claimHandle(handle);

    const resolved = await alice.client.resolveHandle(handle);
    expect(resolved.accountId).toBe(alice.accountId);
  });

  it('stores an encrypted backup the server cannot interpret', async () => {
    const alice = await onboard('Alice');
    const blob = randomBytes(1024);
    await alice.client.putBackup(blob);
    const fetched = await alice.client.getBackup();
    expect(fetched && equal(fetched, blob)).toBe(true);
  });

  it('computes a safety number both devices agree on', async () => {
    const bob = await onboard('Bob');
    const alice = await onboard('Alice');
    const bundle = await alice.client.fetchBundle(bob.accountId, bob.deviceId);

    // Alice derives it from the key the server gave her; Bob from his own.
    // A server that substituted keys would make these differ, which is
    // exactly what the in-person comparison is for.
    expect(safetyNumber(alice.identity.publicKey, bundle.identityKey)).toBe(
      safetyNumber(bob.identity.publicKey, alice.identity.publicKey),
    );
  });

  it('revokes the token on logout', async () => {
    const alice = await onboard('Alice');
    const credentials = alice.client.getCredentials()!;
    await alice.client.logout();

    const stale = new TildraClient({ baseUrl: BASE_URL });
    stale.setCredentials(credentials);
    await expect(stale.preKeyCount()).rejects.toSatisfy(
      (e: unknown) => e instanceof ApiError && e.status === 401,
    );
  });
});

if (!canRun) {
  // Make the skip visible rather than silently reporting a green suite.
  describe('client ↔ server integration', () => {
    it.skip('requires the Go toolchain — install Go to run these', () => {});
  });
}
