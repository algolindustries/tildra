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
  recoveryLookupId,
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
  accountId: 'acct-me',
  deviceId: 'dev-1',
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
    const restored = openBackup(backupKey, sealBackup(backupKey, BACKUP));
    expect(restored).toEqual(BACKUP);
  });

  it('refuses the wrong phrase', () => {
    const other = backupKeyFromSeed(recoverySeed(generateRecoveryPhrase()));
    expect(() => openBackup(other, sealBackup(backupKey, BACKUP))).toThrow(
      /could not be decrypted/,
    );
  });

  it('names the account inside the ciphertext, not beside it', () => {
    // The account id is the one thing the recovering device does not have —
    // it was on the phone they lost — so it has to come out of the blob. An
    // earlier version bound it in as associated data instead, which is the
    // obvious thing to do and made recovery impossible: you would have to
    // know the account id in order to decrypt the thing that tells you it.
    const restored = openBackup(backupKey, sealBackup(backupKey, BACKUP));
    expect(restored.accountId).toBe('acct-me');
    expect(restored.deviceId).toBe('dev-1');
  });

  it('refuses a blob that was edited', () => {
    const sealed = sealBackup(backupKey, BACKUP);
    sealed[sealed.length - 1] ^= 0x01;
    expect(() => openBackup(backupKey, sealed)).toThrow(RecoveryError);
  });

  it('refuses random bytes', () => {
    expect(() => openBackup(backupKey, randomBytes(120))).toThrow(RecoveryError);
  });

  it('refuses something that decrypts but is not a backup', () => {
    const notABackup = sealBackup(backupKey, { updatedAt: 1 } as unknown as RecoveryBackup);
    expect(() => openBackup(backupKey, notABackup)).toThrow(/missing fields/);
  });

  it('carries no messages', () => {
    // Chat history is not in the backup and this asserts it stays that way:
    // a blob on a server that holds what was said is the thing the whole
    // design is arranged to avoid.
    const sealed = sealBackup(backupKey, BACKUP);
    const restored = openBackup(backupKey, sealed);
    expect(Object.keys(restored).sort()).toEqual([
      'accountId',
      'contacts',
      'deviceId',
      'groups',
      'updatedAt',
    ]);
  });
});

describe('where the blob is published', () => {
  it('comes out of the phrase and nothing else', () => {
    // This is what breaks the circle: recovery needs the account id to log in,
    // and the account id was on the device that is gone.
    expect(recoveryLookupId(SEED)).toBe(recoveryLookupId(recoverySeed(PHRASE)));
    expect(recoveryLookupId(SEED)).not.toBe(recoveryLookupId(recoverySeed(generateRecoveryPhrase())));
  });

  it('is a shape the server can validate', () => {
    // Hex, because a shape worth validating is one that cannot contain a path.
    expect(recoveryLookupId(SEED)).toMatch(/^[0-9a-f]{32}$/);
  });

  it('is not either of the keys', () => {
    // An id that leaks must yield ciphertext and nothing else.
    const { identity, backupKey, lookupId } = recoveryKeys(PHRASE);
    expect(lookupId).not.toBe(toHex(backupKey));
    expect(lookupId).not.toBe(toHex(identity.secretKey));
    expect(lookupId).not.toBe(toHex(SEED).slice(0, 32));
  });
});

describe('what recovery can and cannot bring back', () => {
  const backupKey = backupKeyFromSeed(SEED);

  it('carries group membership, so a restored device knows its groups', () => {
    const restored = openBackup(backupKey, sealBackup(backupKey, BACKUP));
    expect(restored.groups[0].groupId).toBe('grp-1');
    expect(restored.groups[0].members).toEqual([{ accountId: 'acct-bob', deviceId: 'd1' }]);
  });

  it('carries no keys of any kind', () => {
    // Not contact identity keys — a stolen phrase could otherwise pin somebody
    // to a key of the thief's choosing — and not sender keys, which belong to
    // an epoch that ended with the device.
    const serialised = JSON.stringify(openBackup(backupKey, sealBackup(backupKey, BACKUP)));
    for (const field of ['identityKey', 'senderKey', 'ratchet', 'secretKey', 'chainKey']) {
      expect(serialised, `backup mentions ${field}`).not.toContain(field);
    }
  });
});
