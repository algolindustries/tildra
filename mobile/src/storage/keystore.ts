/**
 * The one secret that lives in the platform keystore.
 *
 * iOS: Keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — the key is
 * unavailable while the device is locked and never leaves the device via
 * iCloud Keychain or an encrypted backup.
 *
 * Android: Keystore, hardware-backed where the device provides it.
 *
 * Everything else Tildra stores is encrypted under a subkey of this one — see
 * vault.ts for why bulk secrets are not put here directly.
 */

import * as SecureStore from 'expo-secure-store';

import { fromBase64, toBase64 } from '../crypto/primitives';
import { MASTER_KEY_BYTES, generateMasterKey } from './vault';

const MASTER_KEY_ID = 'tildra.master.v1';
const CREDENTIALS_ID = 'tildra.credentials.v1';

const OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export class KeystoreUnavailableError extends Error {}

/**
 * Fetch the device master key, creating it on first run.
 *
 * If the keystore is unavailable we fail rather than falling back to
 * unencrypted storage. An app that silently degrades to plaintext when the
 * secure path is missing is worse than one that refuses to start, because the
 * user cannot tell the difference.
 */
export async function loadOrCreateMasterKey(): Promise<Uint8Array> {
  if (!(await SecureStore.isAvailableAsync())) {
    throw new KeystoreUnavailableError(
      'Tildra: the device keystore is unavailable, so keys cannot be stored securely',
    );
  }

  const existing = await SecureStore.getItemAsync(MASTER_KEY_ID, OPTIONS);
  if (existing) {
    const key = fromBase64(existing);
    if (key.length !== MASTER_KEY_BYTES) {
      throw new KeystoreUnavailableError('Tildra: stored master key has the wrong length');
    }
    return key;
  }

  const key = generateMasterKey();
  await SecureStore.setItemAsync(MASTER_KEY_ID, toBase64(key), OPTIONS);
  return key;
}

export async function hasMasterKey(): Promise<boolean> {
  return (await SecureStore.getItemAsync(MASTER_KEY_ID, OPTIONS)) !== null;
}

/** Server credentials. Small, and useless without the device identity key. */
export async function saveCredentials(credentials: unknown): Promise<void> {
  await SecureStore.setItemAsync(CREDENTIALS_ID, JSON.stringify(credentials), OPTIONS);
}

export async function loadCredentials<T>(): Promise<T | null> {
  const raw = await SecureStore.getItemAsync(CREDENTIALS_ID, OPTIONS);
  return raw ? (JSON.parse(raw) as T) : null;
}

/**
 * Erase everything. Used by "delete account" and by the panic path when the
 * device is being handed to someone else.
 *
 * The SQLite file must be deleted separately — dropping the master key makes
 * its contents undecryptable, but undecryptable is not the same as gone.
 */
export async function eraseKeystore(): Promise<void> {
  await SecureStore.deleteItemAsync(MASTER_KEY_ID, OPTIONS);
  await SecureStore.deleteItemAsync(CREDENTIALS_ID, OPTIONS);
}
