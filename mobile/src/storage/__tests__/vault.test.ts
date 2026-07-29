import { describe, expect, it } from 'vitest';

import { Vault, VaultError, generateMasterKey } from '../vault';
import { equal, fromUtf8, randomBytes, utf8 } from '../../crypto/primitives';
import {
  decrypt,
  deserializeRatchet,
  encrypt,
  initInitiator,
  initResponder,
  serializeRatchet,
} from '../../crypto/ratchet';
import { generateDhKeyPair } from '../../crypto/primitives';

describe('vault', () => {
  it('round-trips a record', () => {
    const vault = new Vault(generateMasterKey());
    const secret = randomBytes(256);
    const stored = vault.encrypt('session', 'conv-1', secret);
    expect(equal(vault.decrypt('session', 'conv-1', stored), secret)).toBe(true);
  });

  it('round-trips JSON', () => {
    const vault = new Vault(generateMasterKey());
    const value = { text: 'merhaba', at: 1735689600000, nested: { ok: true } };
    const stored = vault.encryptJson('message', 'msg-1', value);
    expect(vault.decryptJson('message', 'msg-1', stored)).toEqual(value);
  });

  it('refuses a master key of the wrong length', () => {
    expect(() => new Vault(randomBytes(16))).toThrow(/32 bytes/);
  });

  it('does not decrypt under a different master key', () => {
    const stored = new Vault(generateMasterKey()).encrypt('session', 'c', utf8('secret'));
    expect(() => new Vault(generateMasterKey()).decrypt('session', 'c', stored)).toThrow(VaultError);
  });

  it('refuses a record moved to a different row', () => {
    // Without record binding, someone with write access to the database could
    // graft one conversation's history onto another.
    const vault = new Vault(generateMasterKey());
    const stored = vault.encrypt('message', 'conversation-a', utf8('for A'));
    expect(() => vault.decrypt('message', 'conversation-b', stored)).toThrow(VaultError);
  });

  it('refuses a record moved to a different domain', () => {
    const vault = new Vault(generateMasterKey());
    const stored = vault.encrypt('message', 'x', utf8('a message'));
    expect(() => vault.decrypt('session', 'x', stored)).toThrow(VaultError);
  });

  it('detects tampering', () => {
    const vault = new Vault(generateMasterKey());
    const stored = vault.encrypt('message', 'x', utf8('original'));
    const bytes = [...atob(stored)].map((c) => c.charCodeAt(0));
    bytes[bytes.length - 1] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...bytes));
    expect(() => vault.decrypt('message', 'x', tampered)).toThrow(VaultError);
  });

  it('encrypts the same value differently each time', () => {
    const vault = new Vault(generateMasterKey());
    expect(vault.encrypt('message', 'x', utf8('same'))).not.toBe(
      vault.encrypt('message', 'x', utf8('same')),
    );
  });

  it('produces stable, non-reversible blind indexes', () => {
    const vault = new Vault(generateMasterKey());
    const index = vault.blindIndex('contact', 'ACCOUNT123');

    expect(vault.blindIndex('contact', 'ACCOUNT123')).toBe(index);
    expect(vault.blindIndex('contact', 'ACCOUNT124')).not.toBe(index);
    // The plaintext must not be recoverable by eye from the index.
    expect(index).not.toContain('ACCOUNT');
  });

  it('gives different vaults different blind indexes for the same value', () => {
    const a = new Vault(generateMasterKey());
    const b = new Vault(generateMasterKey());
    expect(a.blindIndex('contact', 'X')).not.toBe(b.blindIndex('contact', 'X'));
  });
});

describe('ratchet persistence', () => {
  function pair() {
    const shared = randomBytes(32);
    const bobKeys = generateDhKeyPair();
    return { alice: initInitiator(shared, bobKeys.publicKey), bob: initResponder(shared, bobKeys) };
  }

  it('survives a round trip through serialization', () => {
    const { alice, bob } = pair();

    // Exchange enough traffic that the state is non-trivial.
    decrypt(bob, encrypt(alice, utf8('one')));
    decrypt(alice, encrypt(bob, utf8('two')));

    const revived = deserializeRatchet(JSON.parse(JSON.stringify(serializeRatchet(alice))));
    const message = encrypt(revived, utf8('after restart'));
    expect(fromUtf8(decrypt(bob, message))).toBe('after restart');
  });

  it('preserves skipped message keys across a restart', () => {
    const { alice, bob } = pair();
    const messages = [0, 1, 2, 3].map((i) => encrypt(alice, utf8(`m${i}`)));

    // Deliver out of order so Bob caches skipped keys, then restart Bob.
    expect(fromUtf8(decrypt(bob, messages[3]))).toBe('m3');
    const revived = deserializeRatchet(JSON.parse(JSON.stringify(serializeRatchet(bob))));

    expect(revived.skipped.size).toBe(3);
    expect(fromUtf8(decrypt(revived, messages[0]))).toBe('m0');
    expect(fromUtf8(decrypt(revived, messages[1]))).toBe('m1');
  });

  it('rejects an unknown state version', () => {
    const { alice } = pair();
    const serialized = { ...serializeRatchet(alice), v: 99 as unknown as 1 };
    expect(() => deserializeRatchet(serialized)).toThrow(/version/);
  });

  it('stores ratchet state only through the vault', () => {
    // The serialized form contains live chain keys. This test documents the
    // rule the storage layer must follow: it never touches disk in the clear.
    const { alice } = pair();
    const vault = new Vault(generateMasterKey());
    const stored = vault.encryptJson('session', 'conv', serializeRatchet(alice));

    expect(stored).not.toContain(serializeRatchet(alice).rootKey);
    const revived = deserializeRatchet(vault.decryptJson('session', 'conv', stored));
    expect(equal(revived.rootKey, alice.rootKey)).toBe(true);
  });
});
