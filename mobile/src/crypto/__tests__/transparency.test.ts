/**
 * Key transparency, verified against proofs the real Go server produced.
 *
 * Two implementations of the same Merkle algorithm is a liability. Reading
 * both and concluding they agree is not evidence; making one produce proofs
 * the other must accept is. So this spawns the server with a transparency key,
 * claims handles through it, and verifies everything it returns.
 */

import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { TildraClient } from '../../api/client';
import { freePort } from '../../__tests__/free-port';
import { generateIdentity, generatePreKeys } from '../identity';
import { equal, fromBase64, randomBytes, toBase64 } from '../primitives';
import {
  LogCheckpoint,
  SplitViewError,
  TransparencyError,
  crossCheckTreeHead,
  deserializeTreeHead,
  serializeTreeHead,
  encodeEntry,
  hashLeaf,
  verifyConsistency,
  verifyHandleProof,
  verifyInclusion,
  verifyTreeHead,
} from '../transparency';
import { AuditorError, crossCheckAuditor, verifyAuditorCheckpoint } from '../auditor';

const SERVER_DIR = join(__dirname, '../../../../server');
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
/** Shared with the fork server in the split-view test. */
const logKeySeed = toBase64(randomBytes(32));

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

// One server for the whole file. Putting this inside a describe block leaves
// every later block without one, which surfaces as an opaque "fetch failed"
// rather than as a missing server — a mistake worth making only once.
beforeAll(async () => {
  if (!goAvailable()) return;
  const port = await freePort();
  BASE_URL = `http://127.0.0.1:${port}`;
  const binary = join(mkdtempSync(join(tmpdir(), 'tildra-kt-')), 'tildrad');
  execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], {
    cwd: SERVER_DIR,
    stdio: 'inherit',
  });
  server = spawn(binary, [], {
    env: {
      ...process.env,
      TILDRA_ADDR: `:${port}`,
      TILDRA_DATABASE_URL: '',
      // A throwaway log key. Real deployments hold this outside the database.
      TILDRA_TRANSPARENCY_KEY: logKeySeed,
    },
    stdio: 'ignore',
  });
  await waitForHealth();
}, 120_000);

afterAll(() => server?.kill('SIGTERM'));

describeIntegration('key transparency against the Go log', () => {
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

describeIntegration('gossip cross-checks', () => {
  it('accepts two heads from the same honest log', async () => {
    // Two clients, two independently verified heads, taken at different sizes
    // as the log grows. Both must be on the same log.
    const first = await claimHandle('gossipa');
    const a = verifyHandleProof(
      (await first.client.resolveHandle('gossipa')).proof!,
      'gossipa',
      null,
    );

    const second = await claimHandle('gossipb');
    const b = verifyHandleProof(
      (await second.client.resolveHandle('gossipb')).proof!,
      'gossipb',
      null,
    );

    expect(b.size).toBeGreaterThan(a.size);

    const anonymous = new TildraClient({ baseUrl: BASE_URL });
    const headB = await anonymous.transparencyHead();

    await expect(
      crossCheckTreeHead(a, { ...headB, size: b.size, rootHash: b.rootHash }, (f, sec) =>
        anonymous.transparencyConsistency(f, sec),
      ),
    ).resolves.toBeUndefined();
  }, 90_000);

  it('detects two heads that cannot both be true', async () => {
    // The split view: same size, different roots. No proof can reconcile
    // those, so this is caught without even asking the server.
    const account = await claimHandle('gossipfork');
    const real = verifyHandleProof(
      (await account.client.resolveHandle('gossipfork')).proof!,
      'gossipfork',
      null,
    );

    const anonymous = new TildraClient({ baseUrl: BASE_URL });
    const head = await anonymous.transparencyHead();
    const forged: LogCheckpoint = { ...real, rootHash: randomBytes(32) };

    await expect(
      crossCheckTreeHead(forged, { ...head, size: forged.size }, (f, sec) =>
        anonymous.transparencyConsistency(f, sec),
      ),
    ).rejects.toBeInstanceOf(SplitViewError);
  }, 90_000);

  it('detects a genuine fork: two valid heads, one log key, different histories', async () => {
    // The real attack, built properly. A second server runs with the *same*
    // log key but a separate store, so both produce validly signed heads that
    // describe different logs — which is exactly what a split view is.
    //
    // An invalidly signed head would not do: that is a contact sending
    // garbage, not the operator attacking someone, and treating the two the
    // same would let anyone trigger a false alarm on a contact's device.
    // A free port chosen at run time. A fixed one races with the previous
    // suite run's fork server, which is still releasing it — the resulting
    // failure looks like a flaky test and is really a port conflict.
    const forkPort = await freePort();
    const forkUrl = `http://127.0.0.1:${forkPort}`;
    const binary = join(mkdtempSync(join(tmpdir(), 'tildra-fork-')), 'tildrad');
    execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], {
      cwd: SERVER_DIR,
      stdio: 'inherit',
    });
    const fork = spawn(binary, [], {
      env: {
        ...process.env,
        TILDRA_ADDR: `:${forkPort}`,
        TILDRA_DATABASE_URL: '',
        TILDRA_TRANSPARENCY_KEY: logKeySeed,
      },
      stdio: 'ignore',
    });

    try {
      const deadline = Date.now() + 30_000;
      for (;;) {
        try {
          if ((await fetch(`${forkUrl}/healthz`)).ok) break;
        } catch {
          /* not up yet */
        }
        if (Date.now() > deadline) throw new Error('fork server did not start');
        await new Promise((r) => setTimeout(r, 250));
      }

      // Populate the fork with different entries.
      for (const handle of ['forkonly1', 'forkonly2', 'forkonly3']) {
        const identity = generateIdentity();
        const client = new TildraClient({ baseUrl: forkUrl });
        const { accountId, deviceId } = await client.register(identity, 'Fork');
        await client.login(identity, accountId, deviceId);
        await client.publishKeys(generatePreKeys(identity, { count: 1 }).upload);
        await client.claimHandle(handle);
      }

      const honest = await claimHandle('honestside');
      const ours = verifyHandleProof(
        (await honest.client.resolveHandle('honestside')).proof!,
        'honestside',
        null,
      );

      const forkClient = new TildraClient({ baseUrl: forkUrl });
      const theirs = await forkClient.transparencyHead();

      // Both heads verify on their own — same log key, valid signatures.
      expect(() => verifyTreeHead(theirs, ours.logKey)).not.toThrow();

      // And yet they cannot both be true. Whichever server is asked to bridge
      // them fails, because neither log contains the other.
      await expect(
        crossCheckTreeHead(ours, theirs, (first, second) =>
          honest.client.transparencyConsistency(first, second),
        ),
      ).rejects.toBeInstanceOf(SplitViewError);
    } finally {
      fork.kill('SIGTERM');
    }
  }, 180_000);

  it('does not cry split view over a badly signed head', async () => {
    // A contact sending a head that does not verify is a broken or malicious
    // *contact*, not evidence about the operator. Conflating the two would
    // make the alarm trivially forgeable and therefore worthless.
    const account = await claimHandle('badsig');
    const ours = verifyHandleProof(
      (await account.client.resolveHandle('badsig')).proof!,
      'badsig',
      null,
    );
    const anonymous = new TildraClient({ baseUrl: BASE_URL });
    const head = await anonymous.transparencyHead();

    const rejected = crossCheckTreeHead(ours, { ...head, rootHash: randomBytes(32) }, (f, sec) =>
      anonymous.transparencyConsistency(f, sec),
    );
    await expect(rejected).rejects.toBeInstanceOf(TransparencyError);
    await expect(rejected).rejects.not.toBeInstanceOf(SplitViewError);
  }, 90_000);

  it('treats a server that cannot link two valid heads as a split view', async () => {
    const account = await claimHandle('gossipnolink');
    const ours = verifyHandleProof(
      (await account.client.resolveHandle('gossipnolink')).proof!,
      'gossipnolink',
      null,
    );
    // Grow the log so the two heads differ in size; identical heads are
    // reconciled without the server being asked anything.
    await claimHandle('gossipnolink2');
    const anonymous = new TildraClient({ baseUrl: BASE_URL });
    const head = await anonymous.transparencyHead();
    expect(head.size).toBeGreaterThan(ours.size);

    // A validly signed head the server then refuses to link to ours.
    await expect(
      crossCheckTreeHead(ours, head, async () => {
        throw new Error('no such tree sizes');
      }),
    ).rejects.toBeInstanceOf(SplitViewError);
  }, 90_000);

  it('round-trips a gossiped tree head and rejects a malformed one', async () => {
    await claimHandle('gossipwire');
    const anonymous = new TildraClient({ baseUrl: BASE_URL });
    const head = await anonymous.transparencyHead();

    const revived = deserializeTreeHead(JSON.parse(JSON.stringify(serializeTreeHead(head))));
    expect(revived.size).toBe(head.size);
    expect(equal(revived.rootHash, head.rootHash)).toBe(true);
    expect(() => verifyTreeHead(revived)).not.toThrow();

    const wire = serializeTreeHead(head);
    expect(() => deserializeTreeHead({ ...wire, size: -1 })).toThrow(/invalid size/);
    expect(() => deserializeTreeHead({ ...wire, rootHash: 'AAAA' })).toThrow(/malformed/);
  }, 90_000);

  it('lets an auditor read the log', async () => {
    // A log nobody can enumerate is a log nobody can audit.
    await claimHandle('auditme');
    const response = await fetch(`${BASE_URL}/v1/transparency/entries?from=0&to=100`);
    expect(response.ok).toBe(true);

    const body = (await response.json()) as { entries: { handle: string }[] };
    expect(body.entries.length).toBeGreaterThan(0);
    expect(body.entries.map((e) => e.handle)).toContain('auditme');
  }, 90_000);
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

// ---------------------------------------------------------------------------
// Auditor checkpoints
// ---------------------------------------------------------------------------

/** Build tildra-auditor once and reuse it. */
let auditorBinary: string | null = null;
function buildAuditor(): string {
  if (auditorBinary) return auditorBinary;
  const binary = join(mkdtempSync(join(tmpdir(), 'tildra-aud-')), 'tildra-auditor');
  execFileSync('go', ['build', '-o', binary, './cmd/tildra-auditor'], {
    cwd: SERVER_DIR,
    stdio: 'inherit',
  });
  auditorBinary = binary;
  return binary;
}

/** Generate an auditor identity the way an operator would. */
function generateAuditorKey(): { seed: string; publicKey: Uint8Array } {
  const out = execFileSync(buildAuditor(), ['-genkey'], { encoding: 'utf8' });
  const seed = /^seed:\s*(\S+)$/m.exec(out)?.[1];
  const publicKey = /^publicKey:\s*(\S+)$/m.exec(out)?.[1];
  if (!seed || !publicKey) throw new Error(`unexpected -genkey output:\n${out}`);
  return { seed, publicKey: fromBase64(publicKey) };
}

/** Run the real auditor against the real server and publish a signed checkpoint. */
function runAuditor(dir: string, seed: string): string {
  const keyPath = join(dir, 'auditor.key');
  const statePath = join(dir, 'state.json');
  const publishPath = join(dir, 'checkpoint.json');
  writeFileSync(keyPath, seed);

  execFileSync(
    buildAuditor(),
    ['-server', BASE_URL, '-state', statePath, '-key', keyPath, '-publish', publishPath],
    { stdio: 'inherit' },
  );
  return readFileSync(publishPath, 'utf8');
}

describeIntegration('auditor checkpoints', () => {
  it('the client verifies what the real auditor signed', async () => {
    // Cross-language, and end to end: a Go binary reads the log this server
    // served, signs what it saw, and TypeScript checks the signature. Two
    // implementations of the same framing kept honest by making them agree
    // rather than by reading both files.
    await claimHandle('auditone');
    const { seed, publicKey } = generateAuditorKey();
    const dir = mkdtempSync(join(tmpdir(), 'tildra-aud-run-'));

    const published = runAuditor(dir, seed);
    const checkpoint = verifyAuditorCheckpoint(published, publicKey);

    expect(checkpoint.size).toBeGreaterThan(0);
    expect(checkpoint.rootHash).toHaveLength(32);
    expect(equal(checkpoint.auditorKey, publicKey)).toBe(true);
  }, 120_000);

  it('refuses a checkpoint from an auditor the client did not pin', async () => {
    // The key inside the document is a label. Anyone can generate a key, sign
    // a checkpoint, and publish both.
    await claimHandle('audittwo');
    const { seed } = generateAuditorKey();
    const other = generateAuditorKey();
    const dir = mkdtempSync(join(tmpdir(), 'tildra-aud-run-'));

    const published = runAuditor(dir, seed);
    expect(() => verifyAuditorCheckpoint(published, other.publicKey)).toThrow(AuditorError);
  }, 120_000);

  it('refuses a checkpoint whose root was edited after signing', async () => {
    await claimHandle('auditthree');
    const { seed, publicKey } = generateAuditorKey();
    const dir = mkdtempSync(join(tmpdir(), 'tildra-aud-run-'));

    const parsed = JSON.parse(runAuditor(dir, seed));
    const root = fromBase64(parsed.rootHash);
    root[0] ^= 0x01;
    parsed.rootHash = toBase64(root);

    expect(() => verifyAuditorCheckpoint(JSON.stringify(parsed), publicKey)).toThrow(
      /signature does not verify/,
    );
  }, 120_000);

  it('refuses a checkpoint whose size was edited after signing', async () => {
    await claimHandle('auditfour');
    const { seed, publicKey } = generateAuditorKey();
    const dir = mkdtempSync(join(tmpdir(), 'tildra-aud-run-'));

    const parsed = JSON.parse(runAuditor(dir, seed));
    parsed.size += 1;

    expect(() => verifyAuditorCheckpoint(JSON.stringify(parsed), publicKey)).toThrow(
      /signature does not verify/,
    );
  }, 120_000);

  it('agrees with a client that was shown the same log', async () => {
    const account = await claimHandle('auditfive');
    const ours = verifyHandleProof(
      (await account.client.resolveHandle('auditfive')).proof!,
      'auditfive',
      null,
    );

    const { seed, publicKey } = generateAuditorKey();
    const dir = mkdtempSync(join(tmpdir(), 'tildra-aud-run-'));
    const checkpoint = verifyAuditorCheckpoint(runAuditor(dir, seed), publicKey);

    // The auditor may be ahead or behind — other tests in this file are still
    // claiming handles — so this is a consistency check, not an equality one.
    await expect(
      crossCheckAuditor(ours, checkpoint, (first, second) =>
        account.client.transparencyConsistency(first, second),
      ),
    ).resolves.toBeUndefined();
  }, 120_000);

  it('raises a split view when the auditor watched a different log', async () => {
    // The case the auditor exists for, and the one gossip cannot reach: the
    // user has no contact who was targeted, but a third party watched all
    // along.
    const account = await claimHandle('auditsix');
    const ours = verifyHandleProof(
      (await account.client.resolveHandle('auditsix')).proof!,
      'auditsix',
      null,
    );

    const forkPort = await freePort();
    const forkUrl = `http://127.0.0.1:${forkPort}`;
    const binary = join(mkdtempSync(join(tmpdir(), 'tildra-aud-fork-')), 'tildrad');
    execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], {
      cwd: SERVER_DIR,
      stdio: 'inherit',
    });
    // Same log key, separate store: both logs are validly signed and describe
    // different histories, which is what a split view is.
    const fork = spawn(binary, [], {
      env: {
        ...process.env,
        TILDRA_ADDR: `:${forkPort}`,
        TILDRA_DATABASE_URL: '',
        TILDRA_TRANSPARENCY_KEY: logKeySeed,
      },
      stdio: 'ignore',
    });

    try {
      const deadline = Date.now() + 30_000;
      for (;;) {
        try {
          if ((await fetch(`${forkUrl}/healthz`)).ok) break;
        } catch {
          /* not up yet */
        }
        if (Date.now() > deadline) throw new Error('fork server did not start');
        await new Promise((r) => setTimeout(r, 250));
      }

      for (const handle of ['auditfork1', 'auditfork2']) {
        const identity = generateIdentity();
        const client = new TildraClient({ baseUrl: forkUrl });
        const { accountId, deviceId } = await client.register(identity, 'Fork');
        await client.login(identity, accountId, deviceId);
        await client.publishKeys(generatePreKeys(identity, { count: 1 }).upload);
        await client.claimHandle(handle);
      }

      // An auditor that watched the fork, publishing a genuinely signed
      // checkpoint. Nothing about it is forged; it is simply a different log.
      const { seed, publicKey } = generateAuditorKey();
      const dir = mkdtempSync(join(tmpdir(), 'tildra-aud-run-'));
      const keyPath = join(dir, 'auditor.key');
      writeFileSync(keyPath, seed);
      execFileSync(
        buildAuditor(),
        [
          '-server', forkUrl,
          '-state', join(dir, 'state.json'),
          '-key', keyPath,
          '-publish', join(dir, 'checkpoint.json'),
        ],
        { stdio: 'inherit' },
      );

      const checkpoint = verifyAuditorCheckpoint(
        readFileSync(join(dir, 'checkpoint.json'), 'utf8'),
        publicKey,
      );

      // It verifies — the auditor really signed it — and it still cannot be
      // reconciled with what this device was shown.
      await expect(
        crossCheckAuditor(ours, checkpoint, (first, second) =>
          account.client.transparencyConsistency(first, second),
        ),
      ).rejects.toBeInstanceOf(SplitViewError);
    } finally {
      fork.kill('SIGTERM');
    }
  }, 180_000);

  it('refuses to publish an unsigned checkpoint', async () => {
    // A published document that looks like an attestation and is not one is
    // worse than no document.
    const dir = mkdtempSync(join(tmpdir(), 'tildra-aud-run-'));
    expect(() =>
      execFileSync(
        buildAuditor(),
        ['-server', BASE_URL, '-state', join(dir, 's.json'), '-publish', join(dir, 'c.json')],
        { stdio: 'pipe' },
      ),
    ).toThrow();
  }, 120_000);
});
