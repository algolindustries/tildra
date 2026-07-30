import { describe, expect, it } from 'vitest';

import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  RecoveryBackup,
  RecoveryError,
  backupKeyFromSeed,
  generateRecoveryPhrase,
  identityFromSeed,
  isValidRecoveryPhrase,
  normalizeRecoveryPhrase,
  openBackup,
  phraseEntropyBits,
  phraseRows,
  recoveryKeys,
  recoverySeed,
  sealBackup,
} from '../recovery';
import { equal, randomBytes, toHex } from '../primitives';

// One phrase, stretched once. Argon2id at 64 MiB is slow on purpose, and
// deriving it per test would make this file take a minute for no extra
// coverage.
const PHRASE = generateRecoveryPhrase();
const SEED = recoverySeed(PHRASE);

const BACKUP: RecoveryBackup = {
  contacts: [{ accountId: 'acct-bob', displayName: 'Bob', handle: 'bob' }],
  groups: [{ groupId: 'grp-1', name: 'Kitap', members: [{ accountId: 'acct-bob', deviceId: 'd1' }] }],
  updatedAt: 1_770_000_000_000,
};

describe('the phrase', () => {
  it('is 24 words carrying 256 bits', () => {
    expect(PHRASE.split(' ')).toHaveLength(24);
    expect(phraseEntropyBits(PHRASE)).toBe(256);
  });

  it('is different every time', () => {
    expect(generateRecoveryPhrase()).not.toBe(generateRecoveryPhrase());
  });

  it('accepts what a keyboard does to it', () => {
    // Case, stray whitespace and the normalisation form are things a keyboard
    // decides and a user cannot see. Refusing a correct phrase over one of
    // them would be the cruellest available bug.
    const mangled = `  ${PHRASE.toUpperCase().replace(/ /g, '   ')}\n`;
    expect(normalizeRecoveryPhrase(mangled)).toBe(PHRASE);
    expect(isValidRecoveryPhrase(mangled)).toBe(true);
    expect(equal(recoverySeed(mangled), SEED)).toBe(true);
  });

  it('rejects a phrase that fails its checksum', () => {
    // BIP-39's checksum is what turns a typo into an immediate no rather than
    // a silent wrong account.
    const words = PHRASE.split(' ');
    const swapped = [...words.slice(0, 22), words[23], words[22]].join(' ');
    expect(isValidRecoveryPhrase(swapped)).toBe(false);
    expect(() => recoverySeed(swapped)).toThrow(RecoveryError);
  });

  it('rejects words that are not in the list', () => {
    expect(isValidRecoveryPhrase(PHRASE.replace(/^\S+/, 'tildra'))).toBe(false);
    expect(isValidRecoveryPhrase('')).toBe(false);
    expect(() => recoverySeed('not a phrase at all')).toThrow(/not a valid recovery phrase/);
  });

  it('is laid out for copying onto paper', () => {
    // Numbered, because order matters and a phrase copied out of order fails a
    // checksum with no clue as to why.
    const rows = phraseRows(PHRASE);
    expect(rows).toHaveLength(8);
    expect(rows[0].map((w) => w.index)).toEqual([1, 2, 3]);
    expect(rows.at(-1)!.at(-1)!.index).toBe(24);
    expect(rows.flat().map((w) => w.word).join(' ')).toBe(PHRASE);
  });
});

describe('what the phrase derives', () => {
  it('gives the same account back', () => {
    // The whole point: recover on a new device and be the same person, rather
    // than a stranger with the right contact list.
    const first = identityFromSeed(SEED);
    const second = identityFromSeed(recoverySeed(PHRASE));
    expect(toHex(second.publicKey)).toBe(toHex(first.publicKey));
    expect(toHex(second.secretKey)).toBe(toHex(first.secretKey));
  });

  it('gives a different account for a different phrase', () => {
    const other = recoveryKeys(generateRecoveryPhrase());
    expect(toHex(other.identity.publicKey)).not.toBe(toHex(identityFromSeed(SEED).publicKey));
  });

  it('keeps the identity and the backup key apart', () => {
    // Two paths from one seed, so handing the backup key to something does not
    // hand it the identity.
    const identity = identityFromSeed(SEED);
    const backupKey = backupKeyFromSeed(SEED);
    expect(toHex(backupKey)).not.toBe(toHex(identity.secretKey));
    expect(toHex(backupKey)).not.toBe(toHex(SEED));
    expect(toHex(identity.secretKey)).not.toBe(toHex(SEED));
  });

  it('produces a usable Ed25519 key', () => {
    const identity = identityFromSeed(SEED);
    expect(identity.publicKey).toHaveLength(32);
    expect(identity.secretKey).toHaveLength(32);
  });

  it('states the parameters the protocol document does', () => {
    expect(ARGON2_MEMORY_KIB).toBe(64 * 1024);
    expect(ARGON2_ITERATIONS).toBe(3);
    expect(ARGON2_PARALLELISM).toBe(4);
  });
});

describe('the backup blob', () => {
  const backupKey = backupKeyFromSeed(SEED);

  it('round-trips', () => {
    const restored = openBackup(backupKey, 'acct-me', sealBackup(backupKey, 'acct-me', BACKUP));
    expect(restored).toEqual(BACKUP);
  });

  it('refuses the wrong phrase', () => {
    const other = backupKeyFromSeed(recoverySeed(generateRecoveryPhrase()));
    expect(() => openBackup(other, 'acct-me', sealBackup(backupKey, 'acct-me', BACKUP))).toThrow(
      /could not be decrypted/,
    );
  });

  it('refuses a blob served for a different account', () => {
    // Bound as associated data, so a server handing over somebody else's blob
    // fails to authenticate rather than restoring their contact list.
    const sealed = sealBackup(backupKey, 'acct-me', BACKUP);
    expect(() => openBackup(backupKey, 'acct-someone-else', sealed)).toThrow(
      /could not be decrypted/,
    );
  });

  it('refuses a blob that was edited', () => {
    const sealed = sealBackup(backupKey, 'acct-me', BACKUP);
    sealed[sealed.length - 1] ^= 0x01;
    expect(() => openBackup(backupKey, 'acct-me', sealed)).toThrow(RecoveryError);
  });

  it('refuses random bytes', () => {
    expect(() => openBackup(backupKey, 'acct-me', randomBytes(120))).toThrow(RecoveryError);
  });

  it('refuses something that decrypts but is not a backup', () => {
    const notABackup = sealBackup(backupKey, 'acct-me', { updatedAt: 1 } as RecoveryBackup);
    expect(() => openBackup(backupKey, 'acct-me', notABackup)).toThrow(/missing fields/);
  });

  it('carries no messages', () => {
    // Chat history is not in the backup and this asserts it stays that way:
    // a blob on a server that holds what was said is the thing the whole
    // design is arranged to avoid.
    const sealed = sealBackup(backupKey, 'acct-me', BACKUP);
    const restored = openBackup(backupKey, 'acct-me', sealed);
    expect(Object.keys(restored).sort()).toEqual(['contacts', 'groups', 'updatedAt']);
  });
});
