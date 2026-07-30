import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Vault } from '../../storage/vault';
import { encodeIdentity } from '../../storage/identity';
import { generateIdentity } from '../../crypto/identity';
import { randomBytes } from '../../crypto/primitives';
import { strings } from '../../i18n';

/**
 * Startup, which `app.ts` says is not incidental: nothing can be decrypted
 * before the master key is loaded, and no message can be sent before the
 * manager has published mailboxes. Until now nothing checked that, because
 * `app.ts` could not be imported by a test at all — it reaches
 * `react-native` through `expo-secure-store` and `expo-sqlite`.
 *
 * Those two are the only native modules in its graph, so both are replaced
 * here and everything else is real: a real `Vault` with a real master key, a
 * real identity, real decryption. The database is a double, because
 * `db.test.ts` already drives the real one and what is under test here is the
 * order things happen in, not SQL.
 *
 * Scope: the paths that do not reach the network. A device with credentials
 * goes on to open a socket and publish mailboxes, which belongs in the
 * integration suite that already runs a real server.
 */

// The keys bootstrap reads. Written out rather than imported because they are
// private to app.ts; if either is renamed, `getMeta` returns null here and the
// tests below fail loudly rather than silently covering nothing.
const IDENTITY_META_KEY = 'identity.v1';
const PREKEYS_META_KEY = 'prekeys.v1';

const secureStore = {
  items: new Map<string, string>(),
  failWith: null as Error | null,
  available: true,
};

vi.mock('expo-secure-store', () => ({
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY',
  async isAvailableAsync() {
    return secureStore.available;
  },
  async getItemAsync(key: string) {
    if (secureStore.failWith) throw secureStore.failWith;
    return secureStore.items.get(key) ?? null;
  },
  async setItemAsync(key: string, value: string) {
    if (secureStore.failWith) throw secureStore.failWith;
    secureStore.items.set(key, value);
  },
  async deleteItemAsync(key: string) {
    secureStore.items.delete(key);
  },
}));

const meta = new Map<string, string>();
const dbOpens: number[] = [];

class FakeDatabase {
  static async open(): Promise<FakeDatabase> {
    dbOpens.push(dbOpens.length + 1);
    return new FakeDatabase();
  }
  async getMeta(key: string): Promise<string | null> {
    return meta.get(key) ?? null;
  }
  async setMeta(key: string, value: string): Promise<void> {
    meta.set(key, value);
  }
  async listConversations(): Promise<unknown[]> {
    return [];
  }
  async listGroups(): Promise<unknown[]> {
    return [];
  }
}

vi.mock('../../storage/db', () => ({ Database: FakeDatabase }));

/**
 * A fresh module instance per test.
 *
 * `app.ts` keeps the runtime in a module-level variable, so without this a
 * store left half-built by one test is the starting state of the next — which
 * is the kind of coupling that makes a suite pass in one order and fail in
 * another.
 */
async function freshApp() {
  vi.resetModules();
  const mod = await import('../app');
  return mod;
}

/** Put a device's stored state where bootstrap will look for it. */
function storedDevice(masterKey: Uint8Array, options: { prekeys?: boolean } = {}) {
  const vault = new Vault(masterKey);
  const identity = generateIdentity();
  meta.set(IDENTITY_META_KEY, vault.encrypt('identity', IDENTITY_META_KEY, encodeIdentity(identity)));
  if (options.prekeys) {
    meta.set(PREKEYS_META_KEY, vault.encryptJson('prekeys', PREKEYS_META_KEY, { nonsense: true }));
  }
  return identity;
}

const MASTER_KEY_ITEM = 'tildra.master.v1';

beforeEach(() => {
  secureStore.items.clear();
  secureStore.failWith = null;
  secureStore.available = true;
  meta.clear();
  dbOpens.length = 0;
});

describe('a device with no account yet', () => {
  it('stops at onboarding and keeps what onboarding will need', () => {
    // The vault and the database are built before it is known whether there
    // is an account, and deliberately kept: createAccount runs seconds later
    // and would otherwise have to build them again, at the point where a
    // failure is least recoverable.
    return freshApp().then(async ({ useApp, currentRuntime }) => {
      await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });

      expect(useApp.getState().phase).toBe('onboarding');
      expect(useApp.getState().error).toBeNull();
      expect(dbOpens).toHaveLength(1);

      // Not just "a runtime exists" — the two things createAccount cannot
      // build for itself. An earlier version of this test asserted only that
      // the object was there, and a deliberate break that nulled the database
      // sailed through it.
      // Checked by capability rather than by class: `vi.resetModules` gives
      // app.ts its own copy of every module, so `instanceof Vault` compares
      // against a different class object and is false for a perfectly good
      // vault.
      const runtime = currentRuntime();
      expect(typeof runtime?.vault.decrypt).toBe('function');
      expect(typeof runtime?.db.getMeta).toBe('function');
      expect(runtime?.serverUrl).toBe('http://server.test');
    });
  });

  it('goes to onboarding when there are credentials but no identity', async () => {
    // Half a device. Treating it as ready would mean signing with a key that
    // is not there; treating it as onboarding is the recoverable answer.
    const { useApp } = await freshApp();
    secureStore.items.set('tildra.credentials.v1', JSON.stringify({ accountId: 'a', deviceId: 'd', token: 't' }));

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    expect(useApp.getState().phase).toBe('onboarding');
  });
});

describe('a device whose storage is damaged', () => {
  it('reports an identity blob of the wrong length instead of using it', async () => {
    // The check added to decodeIdentity, exercised where it actually runs.
    // Without it this decodes into a 32-byte "key pair" and the first symptom
    // is a signature failing somewhere else entirely.
    const { useApp } = await freshApp();
    const masterKey = randomBytes(32);
    secureStore.items.set(MASTER_KEY_ITEM, Buffer.from(masterKey).toString('base64'));
    secureStore.items.set('tildra.credentials.v1', JSON.stringify({ accountId: 'a', deviceId: 'd', token: 't' }));

    const vault = new Vault(masterKey);
    meta.set(IDENTITY_META_KEY, vault.encrypt('identity', IDENTITY_META_KEY, randomBytes(32)));

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    expect(useApp.getState().phase).toBe('error');
    expect(useApp.getState().error).toMatch(/is 32 bytes, expected 64/);
  });

  it('says the prekeys are missing rather than starting without them', async () => {
    // A device that reached this point has an account and an identity. Coming
    // up anyway would mean nobody can start a session with it, silently.
    const { useApp } = await freshApp();
    const masterKey = randomBytes(32);
    secureStore.items.set(MASTER_KEY_ITEM, Buffer.from(masterKey).toString('base64'));
    secureStore.items.set('tildra.credentials.v1', JSON.stringify({ accountId: 'a', deviceId: 'd', token: 't' }));
    storedDevice(masterKey);

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    expect(useApp.getState().phase).toBe('error');
    expect(useApp.getState().error).toMatch(/prekey material is missing/);
  });

  it('reports an identity that will not decrypt', async () => {
    // Encrypted under a different master key: what a restored backup or a
    // half-migrated device looks like.
    const { useApp } = await freshApp();
    const masterKey = randomBytes(32);
    secureStore.items.set(MASTER_KEY_ITEM, Buffer.from(masterKey).toString('base64'));
    secureStore.items.set('tildra.credentials.v1', JSON.stringify({ accountId: 'a', deviceId: 'd', token: 't' }));
    storedDevice(randomBytes(32));

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    expect(useApp.getState().phase).toBe('error');
    expect(useApp.getState().error).toMatch(/failed to decrypt identity/);
  });
});

describe('when the keystore itself will not answer', () => {
  it('ends in error rather than starting forever', async () => {
    // The worst outcome is not an error screen, it is a spinner: nothing
    // times out a bootstrap, so a phase left at 'starting' is permanent.
    const { useApp } = await freshApp();
    secureStore.failWith = new Error('keychain unavailable');

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    expect(useApp.getState().phase).toBe('error');
    expect(useApp.getState().error).toBeTruthy();
  });

  it('reports a device with no secure storage at all', async () => {
    // An emulator, or a device whose keychain is unavailable. Everything in
    // the app is encrypted under a key that lives there, so there is no
    // degraded mode to fall back to — saying so is the only honest answer.
    const { useApp } = await freshApp();
    secureStore.available = false;

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    expect(useApp.getState().phase).toBe('error');
    expect(useApp.getState().error).toBeTruthy();
  });

  it('does not claim a runtime it never finished building', async () => {
    const { useApp, currentRuntime } = await freshApp();
    secureStore.failWith = new Error('keychain unavailable');

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    expect(currentRuntime()).toBeNull();
  });
});

describe('language', () => {
  it('is resolved before anything that can fail', async () => {
    // The error a failed bootstrap shows is written in the user's language,
    // which means the locale has to be applied before the first await, not
    // after the sequence succeeds.
    const { useApp } = await freshApp();
    secureStore.failWith = new Error('keychain unavailable');

    await useApp.getState().bootstrap({ localeTag: 'tr-TR', serverUrl: 'http://server.test' });
    expect(useApp.getState().locale).toBe('tr');
    expect(useApp.getState().phase).toBe('error');
  });

  it('falls back to English for a language we do not ship', async () => {
    const { useApp } = await freshApp();
    await useApp.getState().bootstrap({ localeTag: 'de-DE', serverUrl: 'http://server.test' });
    expect(useApp.getState().locale).toBe('en');
    expect(useApp.getState().t.appName).toBe(strings('en').appName);
  });

  it('marks itself starting before it does any work', async () => {
    const { useApp } = await freshApp();
    const phases: string[] = [];
    const stop = useApp.subscribe((s) => phases.push(s.phase));

    await useApp.getState().bootstrap({ serverUrl: 'http://server.test' });
    stop();
    expect(phases[0]).toBe('starting');
    expect(phases.at(-1)).toBe('onboarding');
  });
});
