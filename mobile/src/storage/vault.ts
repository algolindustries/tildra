/**
 * Encryption for everything stored on disk.
 *
 * The device holds one 32-byte master key in the platform keystore (iOS
 * Keychain / Android Keystore). Everything else — prekey secrets, ratchet
 * session state, message bodies — lives in SQLite encrypted under a subkey
 * derived from it.
 *
 * Why not put the secrets in the keystore directly: expo-secure-store caps
 * values at about 2 KiB on Android, and a single ML-KEM-768 secret key is
 * 2400 bytes. A hundred of them is a quarter of a megabyte. The keystore is
 * the right place for one small key and the wrong place for bulk data, so it
 * gets exactly one small key.
 *
 * This module is deliberately free of Expo imports so it can be tested in
 * Node. The platform-specific parts live in keystore.ts.
 */

import {
  concat,
  fromBase64,
  kdf,
  open,
  randomBytes,
  seal,
  toBase64,
  utf8,
  wipe,
} from '../crypto/primitives';

export const MASTER_KEY_BYTES = 32;

/**
 * Storage domains. Each gets its own subkey, so a bug that leaks a decryption
 * oracle for one kind of record cannot be turned on another.
 */
export type VaultDomain =
  | 'identity'
  | 'prekeys'
  | 'session'
  | 'message'
  | 'contact'
  | 'backup'
  | 'meta';

const DOMAIN_INFO: Record<VaultDomain, string> = {
  identity: 'Tildra_Vault_Identity_v1',
  prekeys: 'Tildra_Vault_PreKeys_v1',
  session: 'Tildra_Vault_Session_v1',
  message: 'Tildra_Vault_Message_v1',
  contact: 'Tildra_Vault_Contact_v1',
  backup: 'Tildra_Vault_Backup_v1',
  meta: 'Tildra_Vault_Meta_v1',
};

export function generateMasterKey(): Uint8Array {
  return randomBytes(MASTER_KEY_BYTES);
}

export class Vault {
  private readonly subkeys = new Map<VaultDomain, Uint8Array>();

  constructor(private readonly masterKey: Uint8Array) {
    if (masterKey.length !== MASTER_KEY_BYTES) {
      throw new Error(`Tildra: master key must be ${MASTER_KEY_BYTES} bytes`);
    }
  }

  private subkey(domain: VaultDomain): Uint8Array {
    let key = this.subkeys.get(domain);
    if (!key) {
      key = kdf(this.masterKey, undefined, DOMAIN_INFO[domain], 32);
      this.subkeys.set(domain, key);
    }
    return key;
  }

  /**
   * Encrypt a record. `recordId` is authenticated but not encrypted, so a
   * record cannot be moved to a different row and still decrypt — without
   * this, an attacker with write access to the database could swap one
   * conversation's messages into another.
   */
  encrypt(domain: VaultDomain, recordId: string, plaintext: Uint8Array): string {
    return toBase64(seal(this.subkey(domain), plaintext, utf8(`${domain}:${recordId}`)));
  }

  decrypt(domain: VaultDomain, recordId: string, stored: string): Uint8Array {
    const plaintext = open(this.subkey(domain), fromBase64(stored), utf8(`${domain}:${recordId}`));
    if (!plaintext) {
      throw new VaultError(`failed to decrypt ${domain} record ${recordId}`);
    }
    return plaintext;
  }

  encryptJson(domain: VaultDomain, recordId: string, value: unknown): string {
    return this.encrypt(domain, recordId, utf8(JSON.stringify(value)));
  }

  decryptJson<T>(domain: VaultDomain, recordId: string, stored: string): T {
    return JSON.parse(new TextDecoder().decode(this.decrypt(domain, recordId, stored))) as T;
  }

  /**
   * Derive a deterministic, non-reversible index key.
   *
   * Used for lookup columns — a conversation ID stored in the clear would let
   * anyone reading the database file see which accounts this device talks to,
   * which is precisely the metadata the server is not allowed to have either.
   */
  blindIndex(domain: VaultDomain, value: string): string {
    return toBase64(kdf(concat(this.subkey(domain), utf8(value)), undefined, 'Tildra_BlindIndex_v1', 16));
  }

  /** Drop cached subkeys. The master key belongs to the caller. */
  close(): void {
    for (const key of this.subkeys.values()) wipe(key);
    this.subkeys.clear();
  }
}

export class VaultError extends Error {}
