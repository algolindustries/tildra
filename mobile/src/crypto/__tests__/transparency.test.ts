/**
 * Key transparency, verified against proofs the real Go server produced.
 *
 * Two implementations of the same Merkle algorithm is a liability. Reading
 * both and concluding they agree is not evidence; making one produce proofs
 * the other must accept is. So this spawns the server with a transparency key,
 * claims handles through it, and verifies everything it returns.
 */

import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { TildraClient } from '../../api/client';
import { generateIdentity, generatePreKeys } from '../identity';
import { equal, randomBytes, toBase64 } from '../primitives';
import {
  LogCheckpoint,
  TransparencyError,
  encodeEntry,
  hashLeaf,
  verifyConsistency,
  verifyHandleProof,
  verifyInclusion,
  verifyTreeHead,
} from '../transparency';

const SERVER_DIR = join(__dirname, '../../../../server');
const PORT = 8793;
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

/** Register a device and claim a handle through the real server. */
async function claimHandle(handle: string) {
  const identity = generateIdentity();
  const client = new TildraClient({ baseUrl: BASE_URL });
  const { accountId, deviceId } = await client.register(identity, 'Device');
  await client.login(identity, accountId, deviceId);
  await client.publishKeys(generatePreKeys(identity, { count: 2 }).upload);
  await client.claimHandle(handle);
  return { identity, client, accountId, deviceId };
}

describeIntegration('key transparency against the Go log', () => {
  beforeAll(async () => {
    const binary = join(mkdtempSync(join(tmpdir(), 'tildra-kt-')), 'tildrad');
    execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], {
      cwd: SERVER_DIR,
      stdio: 'inherit',
    });
    server = spawn(binary, [], {
      env: {
        ...process.env,
        TILDRA_ADDR: `:${PORT}`,
        TILDRA_DATABASE_URL: '',
        // A throwaway log key. Real deployments hold this outside the database.
        TILDRA_TRANSPARENCY_KEY: toBase64(randomBytes(32)),
      },
      stdio: 'ignore',
    });
    await waitForHealth();
  }, 120_000);

  afterAll(() => server?.kill('SIGTERM'));

  it('verifies an inclusion proof the server produced', async () => {
    const alice = await claimHandle('alice');
    const resolved = await alice.client.resolveHandle('alice');

    expect(resolved.proof).toBeDefined();
    const proof = resolved.proof!;

    // The tree head is signed by the log key it names.
    expect(() => verifyTreeHead(proof.head)).not.toThrow();

    // And the entry really is in the tree that head commits to. If the two
    // languages disagreed about leaf encoding or hashing, this is where it
    // would show.
    expect(() =>
      verifyInclusion(
        hashLeaf(encodeEntry(proof.entry)),
        proof.entry.index,
        proof.head.size,
        proof.inclusion,
        proof.head.rootHash,
      ),
    ).not.toThrow();

    expect(proof.entry.accountId).toBe(alice.accountId);
    expect(equal(proof.entry.identityKey, alice.identity.publicKey)).toBe(true);
  }, 60_000);

  it('verifies consistency as the log grows', async () => {
    // Each new handle appends an entry; every earlier view must remain a
    // prefix of every later one.
    let checkpoint: LogCheckpoint | null = null;

    for (let i = 0; i < 6; i++) {
      const handle = `grow${i}`;
      const account = await claimHandle(handle);
      const resolved = await account.client.resolveHandle(handle, checkpoint?.size ?? 0);
      expect(resolved.proof).toBeDefined();

      checkpoint = verifyHandleProof(resolved.proof!, handle, checkpoint);
      expect(checkpoint.size).toBeGreaterThan(i);
    }
  }, 120_000);

  it('refuses a proof issued for a different handle', async () => {
    // Otherwise a server could answer any lookup with a proof for some other
    // handle it had legitimately logged.
    await claimHandle('realuser');
    const client = new TildraClient({ baseUrl: BASE_URL });
    const resolved = await client.resolveHandle('realuser');

    expect(() => verifyHandleProof(resolved.proof!, 'someoneelse', null)).toThrow(
      /different handle/,
    );
  }, 60_000);

  it('refuses a tampered inclusion path', async () => {
    await claimHandle('tamper');
    const client = new TildraClient({ baseUrl: BASE_URL });
    const resolved = await client.resolveHandle('tamper');
    const proof = resolved.proof!;

    if (proof.inclusion.length > 0) {
      const tampered = proof.inclusion.map((h) => h.slice());
      tampered[0][0] ^= 0xff;
      expect(() =>
        verifyInclusion(
          hashLeaf(encodeEntry(proof.entry)),
          proof.entry.index,
          proof.head.size,
          tampered,
          proof.head.rootHash,
        ),
      ).toThrow(TransparencyError);
    }

    // A tampered entry must fail regardless of tree size.
    const forged = { ...proof.entry, accountId: 'A_DIFFERENT_ACCOUNT' };
    expect(() =>
      verifyInclusion(
        hashLeaf(encodeEntry(forged)),
        proof.entry.index,
        proof.head.size,
        proof.inclusion,
        proof.head.rootHash,
      ),
    ).toThrow(TransparencyError);
  }, 60_000);

  it('refuses a tree head signed by a different key', async () => {
    await claimHandle('keyswap');
    const client = new TildraClient({ baseUrl: BASE_URL });
    const resolved = await client.resolveHandle('keyswap');
    const proof = resolved.proof!;

    // A server that rotates its log key is presenting a different log, and
    // accepting that would let it escape its own history.
    const otherKey = generateIdentity().publicKey;
    expect(() => verifyTreeHead(proof.head, otherKey)).toThrow(/different log/);

    const forged = { ...proof.head, size: proof.head.size + 1 };
    expect(() => verifyTreeHead(forged)).toThrow(/signature/);
  }, 60_000);

  it('detects a rewritten log', async () => {
    // The attack the whole mechanism exists to catch, simulated by keeping a
    // checkpoint from a real head and then presenting a root that is not an
    // extension of it.
    const account = await claimHandle('rewrite');
    const resolved = await account.client.resolveHandle('rewrite');
    const real = verifyHandleProof(resolved.proof!, 'rewrite', null);

    const forgedCheckpoint: LogCheckpoint = {
      ...real,
      rootHash: randomBytes(32),
    };
    const later = await account.client.resolveHandle('rewrite', forgedCheckpoint.size);

    expect(() => verifyHandleProof(later.proof!, 'rewrite', forgedCheckpoint)).toThrow(
      TransparencyError,
    );
  }, 60_000);

  it('publishes a tree head anyone can fetch and check', async () => {
    await claimHandle('watcher');
    // Unauthenticated client: a log only account holders can watch is not
    // much of a public log.
    const anonymous = new TildraClient({ baseUrl: BASE_URL });
    const head = await anonymous.transparencyHead();

    expect(head.size).toBeGreaterThan(0);
    expect(() => verifyTreeHead(head)).not.toThrow();
  }, 60_000);

  it('rejects a shrinking log', async () => {
    const account = await claimHandle('shrink');
    const resolved = await account.client.resolveHandle('shrink');
    const checkpoint = verifyHandleProof(resolved.proof!, 'shrink', null);

    const shrunk = {
      ...resolved.proof!,
      head: { ...resolved.proof!.head, size: checkpoint.size - 1 },
    };
    expect(() => verifyHandleProof(shrunk, 'shrink', checkpoint)).toThrow();
  }, 60_000);
});

describe('consistency verification', () => {
  it('accepts an empty prior tree so the first lookup can bootstrap', () => {
    expect(() => verifyConsistency(0, 5, [], new Uint8Array(32), randomBytes(32))).not.toThrow();
  });

  it('requires an unchanged root when the size is unchanged', () => {
    const root = randomBytes(32);
    expect(() => verifyConsistency(4, 4, [], root, root)).not.toThrow();
    expect(() => verifyConsistency(4, 4, [], root, randomBytes(32))).toThrow(/root differs/);
  });

  it('requires a path when the tree grew', () => {
    expect(() => verifyConsistency(3, 7, [], randomBytes(32), randomBytes(32))).toThrow(
      /requires a consistency path/,
    );
  });
});
