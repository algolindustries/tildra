import { beforeEach, describe, expect, it, vi } from 'vitest';

import { toBase64 } from '../../crypto/primitives';
import { MASTER_KEY_BYTES } from '../vault';
import {
  KeystoreUnavailableError,
  eraseKeystore,
  loadCredentials,
  loadOrCreateMasterKey,
  saveCredentials,
} from '../keystore';

/**
 * The one secret that lives in the platform keystore, which until now had no
 * test of its own — it was only ever exercised sideways, through `app.ts`'s
 * bootstrap, where what is under test is the order things happen in.
 *
 * Three things are worth pinning here and are pinned nowhere else. That a
 * second run returns the *same* key, because a function named
 * `loadOrCreateMasterKey` that quietly creates a second one turns every byte
 * on the device into noise. That every call carries
 * `WHEN_UNLOCKED_THIS_DEVICE_ONLY`, which is the whole of the file's claim
 * that the key never reaches iCloud Keychain or an encrypted backup — a claim
 * that until now lived only in a comment. And that erasing gets both secrets
 * out even when the platform fights back.
 */

type Call = { method: string; key: string; options: unknown };

const store = {
  items: new Map<string, string>(),
  calls: [] as Call[],
  available: true,
  /** Keys whose deleteItemAsync should throw, by item id. */
  deleteFailures: new Set<string>(),
};

vi.mock('expo-secure-store', () => ({
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY',
  async isAvailableAsync() {
    return store.available;
  },
  async getItemAsync(key: string, options: unknown) {
    store.calls.push({ method: 'get', key, options });
    return store.items.get(key) ?? null;
  },
  async setItemAsync(key: string, value: string, options: unknown) {
    store.calls.push({ method: 'set', key, options });
    store.items.set(key, value);
  },
  async deleteItemAsync(key: string, options: unknown) {
    store.calls.push({ method: 'delete', key, options });
    if (store.deleteFailures.has(key)) throw new Error(`keychain refused to delete ${key}`);
    store.items.delete(key);
  },
}));

// Written out rather than imported: these are private to keystore.ts, and if
// either is renamed these tests should fail loudly rather than quietly stop
// covering the thing they name.
const MASTER_KEY_ITEM = 'tildra.master.v1';
const CREDENTIALS_ITEM = 'tildra.credentials.v1';

beforeEach(() => {
  store.items.clear();
  store.calls.length = 0;
  store.available = true;
  store.deleteFailures.clear();
});

describe('the device master key', () => {
  it('is created on first run, at the length the vault requires', async () => {
    const key = await loadOrCreateMasterKey();

    expect(key.length).toBe(MASTER_KEY_BYTES);
    expect(store.items.has(MASTER_KEY_ITEM)).toBe(true);
  });

  it('is the same key on the next run, not a new one', async () => {
    // The failure this guards against is total: a second key means every row
    // already written under the first is undecryptable, with no error at the
    // point where it happens and no way back.
    const first = await loadOrCreateMasterKey();
    const second = await loadOrCreateMasterKey();

    expect(Array.from(second)).toEqual(Array.from(first));
    expect(store.calls.filter((c) => c.method === 'set' && c.key === MASTER_KEY_ITEM)).toHaveLength(1);
  });

  it('is not generated at all when the keystore is unavailable', async () => {
    // No degraded mode: an app that silently falls back to plaintext when the
    // secure path is missing is worse than one that refuses to start, because
    // the user cannot tell the difference.
    store.available = false;

    await expect(loadOrCreateMasterKey()).rejects.toBeInstanceOf(KeystoreUnavailableError);
    expect(store.items.size).toBe(0);
    expect(store.calls).toEqual([]);
  });

  it('refuses a stored key of the wrong length instead of handing it to the vault', async () => {
    // The Vault constructor would throw on this too, but later and further
    // from the cause. Truncated keychain data should be named where it is read.
    store.items.set(MASTER_KEY_ITEM, toBase64(new Uint8Array(16)));

    await expect(loadOrCreateMasterKey()).rejects.toBeInstanceOf(KeystoreUnavailableError);
  });

  it('does not quietly replace a stored key it cannot read', async () => {
    // Corrupt is not the same as absent. Overwriting here would destroy the
    // only copy of the key that might still be recoverable by other means.
    store.items.set(MASTER_KEY_ITEM, 'not base64 at all!!');

    await expect(loadOrCreateMasterKey()).rejects.toThrow();
    expect(store.items.get(MASTER_KEY_ITEM)).toBe('not base64 at all!!');
  });
});

describe('the accessibility option', () => {
  /**
   * The file's claim is that the key is unavailable while the device is locked
   * and never leaves it via iCloud Keychain or an encrypted backup. All of
   * that is `keychainAccessible: WHEN_UNLOCKED_THIS_DEVICE_ONLY`, passed on
   * every single call. Nothing enforced it before this test: dropping the
   * argument from one call site changes no type and breaks no other test, and
   * the key would start syncing.
   */
  it('is passed on every read, write and delete the module makes', async () => {
    await loadOrCreateMasterKey();
    await loadOrCreateMasterKey();
    await saveCredentials({ token: 'a' });
    await loadCredentials();
    await eraseKeystore();

    expect(store.calls.length).toBeGreaterThanOrEqual(7);
    for (const call of store.calls) {
      expect(call.options).toEqual({ keychainAccessible: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY' });
    }
  });
});

describe('server credentials', () => {
  it('come back as they went in', async () => {
    await saveCredentials({ accountId: 'acct-1', token: 'secret' });

    expect(await loadCredentials()).toEqual({ accountId: 'acct-1', token: 'secret' });
  });

  it('are null on a device that has none, rather than an error', async () => {
    // A fresh install takes this path on every start.
    expect(await loadCredentials()).toBeNull();
  });
});

describe('erasing', () => {
  async function aSignedInDevice() {
    await loadOrCreateMasterKey();
    await saveCredentials({ token: 'secret' });
    expect(store.items.size).toBe(2);
  }

  it('removes both secrets', async () => {
    await aSignedInDevice();

    await eraseKeystore();

    expect(store.items.size).toBe(0);
  });

  it('removes the credentials even when the master key will not delete', async () => {
    // This is what used to go wrong. Two bare awaits in a row: the first
    // throwing meant the second never ran, so a keychain that refused one
    // call kept a live server session on a device the user had just asked to
    // wipe. Credentials go first now, and neither cancels the other.
    await aSignedInDevice();
    store.deleteFailures.add(MASTER_KEY_ITEM);

    await expect(eraseKeystore()).rejects.toBeInstanceOf(KeystoreUnavailableError);

    expect(store.items.has(CREDENTIALS_ITEM)).toBe(false);
  });

  it('removes the master key even when the credentials will not delete', async () => {
    await aSignedInDevice();
    store.deleteFailures.add(CREDENTIALS_ITEM);

    await expect(eraseKeystore()).rejects.toBeInstanceOf(KeystoreUnavailableError);

    expect(store.items.has(MASTER_KEY_ITEM)).toBe(false);
  });

  it('says what it failed to erase rather than reporting success', async () => {
    // Silently swallowing would be the worst option available: the user is
    // told the device is wiped while a secret is still on it.
    await aSignedInDevice();
    store.deleteFailures.add(CREDENTIALS_ITEM);

    // Specifically its own sentence, naming what is left. The platform's
    // exception happens to contain the item id too, so matching on that alone
    // passed against the old code that never reached the second delete.
    await expect(eraseKeystore()).rejects.toThrow(/keystore did not erase, and still holds/);
  });

  it('is silent on a device with nothing to erase', async () => {
    // Sign-out runs on devices that never finished starting.
    await expect(eraseKeystore()).resolves.toBeUndefined();
  });
});
