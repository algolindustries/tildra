import { ChildProcess, execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { freePort } from '../../__tests__/free-port';

/**
 * `state/app.ts` against a real Go server.
 *
 * `bootstrap.test.ts` covers this file's offline half and says so in its own
 * header: "a device with credentials goes on to open a socket and publish
 * mailboxes, which belongs in the integration suite that already runs a real
 * server". This is that suite. It was the last thing on the list of code with
 * no tests, and it is the part where the client and the server have to agree.
 *
 * Everything here is real except the two native modules `app.ts` reaches
 * through — `expo-secure-store` is a map, and `expo-sqlite` is `node:sqlite`
 * over a file in a temp directory, so an "app restart" is a fresh module graph
 * opening the same database the last one wrote. Real registration, real
 * prekeys, real vault, real socket.
 */

const SERVER_DIR = join(__dirname, '../../../../server');

function goAvailable(): boolean {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return existsSync(join(SERVER_DIR, 'go.mod'));
  } catch {
    return false;
  }
}

const canRun = goAvailable();
const describeOnline = canRun ? describe : describe.skip;

// --------------------------------------------------------------------------
// The two native modules, and nothing else.
// --------------------------------------------------------------------------

/**
 * Which phone the next module graph belongs to.
 *
 * Both mock factories read these once, when the graph is created, rather than
 * on every call. That is what lets two devices exist in one process: each gets
 * the keychain and the database file that were current when it booted, and
 * neither can reach into the other's afterwards — which a lookup at call time
 * would allow the moment their sockets started interleaving.
 */
let activeKeystore = new Map<string, string>();
let activeDatabaseFile = '';

vi.mock('expo-secure-store', () => {
  const items = activeKeystore;
  return {
    WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY',
    async isAvailableAsync() {
      return true;
    },
    async getItemAsync(key: string) {
      return items.get(key) ?? null;
    },
    async setItemAsync(key: string, value: string) {
      items.set(key, value);
    },
    async deleteItemAsync(key: string) {
      items.delete(key);
    },
  };
});

function bridge(file: string): unknown {
  const db = new DatabaseSync(file);
  return {
    async execAsync(sql: string) {
      db.exec(sql);
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
  };
}

vi.mock('expo-sqlite', () => {
  const file = activeDatabaseFile;
  return {
    async openDatabaseAsync() {
      // A new connection per open, against the same file — an app restart, not
      // a handle handed round.
      return bridge(file);
    },
  };
});

vi.mock('../../push/register', () => ({
  PushError: class extends Error {},
  async registerForPush() {
    return false;
  },
  async unregisterForPush() {},
  async presentLocalNotification() {},
  async dismissWakeNotifications() {},
}));

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

let BASE_URL = '';
let server: ChildProcess | null = null;
let binaryPath = '';


async function waitForHealth(baseUrl: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseUrl}/healthz`);
      if (res.ok) return;
    } catch {
      // Not up yet.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`server at ${baseUrl} did not become healthy in time`);
}

/** Throws on timeout, naming what it was waiting for. */
async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs = 30_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for: ${predicate}`);
}

/**
 * A fixed ed25519 seed, so the server runs a key transparency log.
 *
 * Without `TILDRA_TRANSPARENCY_KEY` the server starts without a log and every
 * handle lookup comes back with no proof — which is deliberate and warned
 * about, and meant the downgrade test below could never arm: the client only
 * refuses an unproven answer once it has seen a proven one. The first version
 * of that test asserted a refusal that could not happen and blamed the client.
 */
const TRANSPARENCY_SEED = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=';

function startServer(port: number): ChildProcess {
  return spawn(binaryPath, [], {
    env: {
      ...process.env,
      TILDRA_ADDR: `:${port}`,
      TILDRA_DATABASE_URL: '',
      TILDRA_TRANSPARENCY_KEY: TRANSPARENCY_SEED,
    },
    stdio: 'ignore',
  });
}

/** One phone: its own keychain, its own database file. */
interface Device {
  keystore: Map<string, string>;
  databaseFile: string;
}

function newDevice(label: string): Device {
  return {
    keystore: new Map<string, string>(),
    databaseFile: join(mkdtempSync(join(tmpdir(), `tildra-${label}-`)), 'tildra.db'),
  };
}

/**
 * Boot a device: a fresh module graph over that device's disk.
 *
 * Called twice for the same device this is a cold start. Called for a second
 * device it is a second phone — the graph already imported keeps working, so
 * both stores are live at once and can talk to each other through the server.
 */
async function boot(device: Device) {
  activeKeystore = device.keystore;
  activeDatabaseFile = device.databaseFile;
  vi.resetModules();
  return import('../app');
}

beforeAll(async () => {
  if (!canRun) return;
  phone = newDevice('phone');
  binaryPath = join(mkdtempSync(join(tmpdir(), 'tildra-app-bin-')), 'tildrad');
  execFileSync('go', ['build', '-o', binaryPath, './cmd/tildrad'], {
    cwd: SERVER_DIR,
    stdio: 'inherit',
  });

  const port = await freePort();
  BASE_URL = `http://127.0.0.1:${port}`;
  server = startServer(port);
  await waitForHealth(BASE_URL);
}, 180_000);

afterAll(() => {
  server?.kill('SIGTERM');
});

/** The device the first two blocks share, so a cold start is the same phone. */
let phone: Device;

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

describeOnline('a real device against a real server', () => {
  let accountId = '';

  it('creates an account the server accepts, and writes it down', async () => {
    const { useApp } = await boot(phone);

    await useApp.getState().bootstrap({ serverUrl: BASE_URL });
    expect(useApp.getState().phase).toBe('onboarding');

    await useApp.getState().createAccount('Test iPhone', 'Ayşe');

    const state = useApp.getState();
    expect(state.phase).toBe('ready');
    expect(state.accountId).toMatch(ULID);
    expect(state.displayName).toBe('Ayşe');
    // The phrase is shown once, after the backup it recovers has been
    // published — a phrase with nothing behind it is worse than none.
    expect(state.pendingPhrase?.split(/\s+/)).toHaveLength(24);

    // Registered with the server means nothing if the device did not keep the
    // key. Both halves are on disk before this returns.
    expect(phone.keystore.has('tildra.master.v1')).toBe(true);
    expect(phone.keystore.has('tildra.credentials.v1')).toBe(true);

    accountId = state.accountId!;
  });

  it('gets its socket open, which is what makes it reachable', async () => {
    const { useApp } = await import('../app');

    await waitFor(() => useApp.getState().socketState === 'open');
    expect(useApp.getState().error).toBeNull();
  });

  it('comes back to the same account on a cold start, with no onboarding', async () => {
    // A fresh module graph, the same keychain and the same database file. This
    // is the path bootstrap.test.ts deliberately stops short of: credentials
    // and an identity on disk, a session started, mailboxes published.
    const { useApp } = await boot(phone);

    await useApp.getState().bootstrap({ serverUrl: BASE_URL });

    expect(useApp.getState().phase).toBe('ready');
    expect(useApp.getState().accountId).toBe(accountId);
    expect(useApp.getState().displayName).toBe('Ayşe');
    await waitFor(() => useApp.getState().socketState === 'open');
  });
});

describeOnline('a device with no network', () => {
  /**
   * The defect this suite was written for.
   *
   * Everything in `startSession` that touches the network is deliberately
   * non-blocking — the socket reconnects on its own, push registration is best
   * effort, the auditor check has a comment saying it must not hold up the app
   * — except `publishMailboxes`, which was awaited. So a plane, a tunnel or an
   * hour of server downtime looked exactly like a broken install: bootstrap
   * threw, the phase went to `error`, and the user could not read the messages
   * already sitting decryptable on their own device.
   */
  it('still starts, and knows whose account it is', async () => {
    const dead = await freePort();
    const { useApp } = await boot(phone);

    await useApp.getState().bootstrap({ serverUrl: `http://127.0.0.1:${dead}` });

    expect(useApp.getState().phase).toBe('ready');
    expect(useApp.getState().accountId).toMatch(ULID);
    expect(useApp.getState().displayName).toBe('Ayşe');
  });

  it('says it is not reachable rather than pretending it is', async () => {
    // Starting anyway is right. Doing it silently is not: until the addresses
    // are registered nobody can send to this device, and the user is the only
    // one who can decide whether that matters right now.
    const dead = await freePort();
    const { useApp } = await boot(phone);

    await useApp.getState().bootstrap({ serverUrl: `http://127.0.0.1:${dead}` });

    // Waited for rather than read straight after bootstrap: the publish is
    // deliberately not on the startup path any more, so its failure lands a
    // moment later. Asserting immediately passed against a build with no
    // reporting at all, which is the wrong kind of green.
    await waitFor(() => useApp.getState().error !== null, 10_000);
    expect(useApp.getState().socketState).not.toBe('open');
    // And the app is still usable while it says so. Without this the test
    // passes against the version that threw, because a bootstrap that fails
    // sets an error too — it just sets `phase: 'error'` with it, and the
    // negative control is how that came out.
    expect(useApp.getState().phase).toBe('ready');
  });

  it('reports a refusal the socket cannot see', async () => {
    // The case that isolates this path. With a dead server the socket reports
    // the outage itself, so removing the publish's own error reporting changes
    // nothing observable — the negative control proved exactly that. A server
    // that answers, opens the socket and then refuses the registration is the
    // one situation where nothing else is watching, and it is the one where
    // the device is silently unreachable.
    const { useApp } = await boot(phone);
    const { TildraClient } = await import('../../api/client');
    const spy = vi
      .spyOn(TildraClient.prototype, 'registerMailboxes')
      .mockRejectedValue(new Error('mailbox registration refused'));

    try {
      await useApp.getState().bootstrap({ serverUrl: BASE_URL });

      expect(useApp.getState().phase).toBe('ready');
      await waitFor(() => useApp.getState().socketState === 'open');
      await waitFor(
        () => (useApp.getState().error ?? '').includes('mailbox registration refused'),
        10_000,
      );
    } finally {
      spy.mockRestore();
    }
  });

  it('registers its addresses on the next time the socket opens', async () => {
    // Starting offline is only acceptable if the device becomes reachable
    // without being restarted. The socket reaching 'open' is the app's existing
    // signal that the network came back, and the retry hangs off it.
    //
    // The first version of this test pointed the app at a dead port and then
    // opened a TCP proxy to the real server, which is the honest shape of
    // "the network came back" and is not a test: it depends on the socket's
    // reconnect backoff, which escalates to 20 and 30 second delays, so on a
    // slower machine the wait expired before the next attempt was even due. It
    // passed here and timed out in CI.
    //
    // So the failure is injected instead of arranged. The first registration is
    // refused and every one after it is real, against a server that is up the
    // whole time — which exercises the same wiring, in about a second, with
    // nothing racing.
    const { useApp } = await boot(phone);
    const { TildraClient } = await import('../../api/client');

    let attempts = 0;
    let published = 0;
    const original = TildraClient.prototype.registerMailboxes;
    const spy = vi
      .spyOn(TildraClient.prototype, 'registerMailboxes')
      .mockImplementation(async function (this: InstanceType<typeof TildraClient>, mailboxes) {
        attempts += 1;
        if (attempts === 1) throw new Error('mailbox registration refused');
        const result = await original.call(this, mailboxes);
        published += 1;
        return result;
      });

    try {
      await useApp.getState().bootstrap({ serverUrl: BASE_URL });
      expect(useApp.getState().phase).toBe('ready');

      await waitFor(() => attempts >= 1);
      await waitFor(() => useApp.getState().socketState === 'open');
      // The device is on file despite the first attempt failing, and without
      // anyone restarting the app.
      await waitFor(() => published > 0);
    } finally {
      spy.mockRestore();
    }
  });
});

describeOnline('two devices through the real server', () => {
  /**
   * The half of `app.ts` the offline suite cannot reach at all.
   *
   * `integration.test.ts` already proves a sealed message survives the round
   * trip, but it does that by driving the crypto directly. Nothing had ever
   * driven `startConversation`, `send`, and the socket's delivery path through
   * the store the screens actually call — which is where the wiring between
   * them lives, and where two components can each be right while nothing
   * arrives.
   */
  async function signedUp(device: Device, deviceName: string, displayName: string) {
    const app = await boot(device);
    // From the same graph, so a spy on it reaches the client this store uses.
    // Every boot resets the registry, so this has to happen before the next one.
    const { TildraClient } = await import('../../api/client');
    await app.useApp.getState().bootstrap({ serverUrl: BASE_URL });
    await app.useApp.getState().createAccount(deviceName, displayName);
    await waitFor(() => app.useApp.getState().socketState === 'open');
    return { app, client: TildraClient, accountId: app.useApp.getState().accountId! };
  }

  it('carries a message from one store to the other', async () => {
    const alice = await signedUp(newDevice('alice'), 'Alice iPhone', 'Ayşe');
    const bob = await signedUp(newDevice('bob'), 'Bob Pixel', 'Bora');

    // Alice looks Bob up by account id, which is the path that fetches his
    // devices and creates the conversation row with a real identity key.
    const resolved = await alice.app.useApp.getState().startConversation(bob.accountId);
    expect(resolved).toBe(bob.accountId);

    await alice.app.useApp.getState().openConversation(bob.accountId);
    await alice.app.useApp.getState().send('merhaba');

    // Alice's own copy is on her device, and actually went out. The row alone
    // proves nothing: `send` says in its own comment that a failed send still
    // leaves a message, marked failed, so the user can see what did not go.
    // Asserting the store's `error` instead looked equivalent and is not — that
    // field collects anything from a prekey rotation to a socket blip, and a
    // run where one of those fired failed a test that was about the send.
    const mine = alice.app.useApp.getState().messages;
    const sent = mine.find((m) => m.text === 'merhaba');
    expect(sent).toBeDefined();
    expect(sent!.outgoing).toBe(true);
    expect(sent!.state).not.toBe('failed');

    // And Bob's socket brings it to him without anyone asking it to: the
    // conversation appears in a store that never heard of Alice.
    await waitFor(() =>
      bob.app.useApp.getState().conversations.some((c) => c.accountId === alice.accountId),
    );

    await bob.app.useApp.getState().openConversation(alice.accountId);
    expect(bob.app.useApp.getState().messages.map((m) => m.text)).toContain('merhaba');

    // And back, which is the direction nothing had exercised. Bob accepted the
    // session rather than initiating it, so his side runs different code, and a
    // messenger that only works one way is the kind of thing unit tests on both
    // halves are happy to let through.
    await bob.app.useApp.getState().send('merhaba Ayşe');

    await waitFor(() => {
      const texts = alice.app.useApp.getState().messages.map((m) => m.text);
      return texts.includes('merhaba Ayşe');
    });
  }, 90_000);

  it('gives both ends the same safety number', async () => {
    // The number the two people are told to compare. If the two stores derive
    // it differently, every verification in the product is theatre — and it is
    // derived from what each side stored about the other, which is exactly
    // what a store-level test can get wrong and a crypto-level one cannot.
    const alice = await signedUp(newDevice('alice2'), 'Alice iPhone', 'Ayşe');
    const bob = await signedUp(newDevice('bob2'), 'Bob Pixel', 'Bora');

    await alice.app.useApp.getState().startConversation(bob.accountId);
    await alice.app.useApp.getState().openConversation(bob.accountId);
    await alice.app.useApp.getState().send('merhaba');

    await waitFor(() =>
      bob.app.useApp.getState().conversations.some((c) => c.accountId === alice.accountId),
    );
    await bob.app.useApp.getState().openConversation(alice.accountId);

    const hers = alice.app.useApp.getState().safetyNumber;
    const his = bob.app.useApp.getState().safetyNumber;

    expect(hers).toBeTruthy();
    expect(his).toBe(hers);
  }, 90_000);

  it('follows a handle, and refuses to once the server stops proving them', async () => {
    // A handle is a pointer the server controls, so it is only worth following
    // if the server can prove what it published. The store-level path — resolve,
    // verify the inclusion and consistency proofs, write the checkpoint down,
    // and refuse a later answer that arrives without one — had no test at any
    // level above the crypto.
    const bob = await signedUp(newDevice('bob3'), 'Bob Pixel', 'Bora');
    await bob.app.useApp.getState().claimHandle('bora');
    expect(bob.app.useApp.getState().handle).toBe('bora');

    const alice = await signedUp(newDevice('alice3'), 'Alice iPhone', 'Ayşe');

    // The proof verifies, and the checkpoint it establishes is now on Alice's
    // device.
    expect(await alice.app.useApp.getState().startConversation('@bora')).toBe(bob.accountId);

    // Now the server answers without one. Having verified this log before,
    // accepting that silently would undo every check made so far — it is the
    // downgrade that makes a later key swap invisible.
    const original = alice.client.prototype.resolveHandle;
    const spy = vi
      .spyOn(alice.client.prototype, 'resolveHandle')
      .mockImplementation(async function (
        this: InstanceType<typeof alice.client>,
        handle: string,
        since?: number,
      ) {
        const { accountId, handle: name } = await original.call(this, handle, since);
        return { accountId, handle: name };
      });

    try {
      await expect(
        alice.app.useApp.getState().startConversation('@bora'),
      ).rejects.toThrow(/stopped providing key transparency proofs/);
    } finally {
      spy.mockRestore();
    }
  }, 90_000);
});
