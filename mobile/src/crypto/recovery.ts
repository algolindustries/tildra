/**
 * Account recovery — docs/PROTOCOL.md §1.1.
 *
 * **The phrase is the account.** A Tildra account is a key, so a recovery that
 * does not restore the key is not recovery: the user would get their contact
 * list back under a new identity, and every contact would see a key change —
 * indistinguishable from the attack the app exists to warn about. Recovery
 * that fires the alarm is not a feature.
 *
 * The protocol previously sketched a different design, where the blob carried
 * a "device-provisioning secret" and the identity was not recoverable. That
 * needs the server to let a device join an account without an existing device
 * approving it, which is a second way into an account, and a second way into
 * an account is a second thing to attack. Not building it is the safer answer.
 *
 * The cost is stated rather than hidden: **anyone holding the phrase is you.**
 * It is exactly as powerful as an unlocked device, and the onboarding screen
 * has to say so in those words.
 *
 * Two keys come out of one phrase, by different paths, and neither can be used
 * to find the other:
 *
 *   seed        = Argon2id(phrase, salt = "Tildra_Recovery_v1", 64 MiB, t=3, p=4)
 *   identity    = Ed25519 from HKDF(seed, info = "Tildra_RecoveryIdentity_v1")
 *   backup key  = HKDF(seed, info = "Tildra_RecoveryBackup_v1")
 *
 * Argon2id is doing the work that matters. A 24-word phrase has 256 bits of
 * entropy and does not need stretching; the parameters are there for the
 * shorter phrases a future version might allow, and for the case where someone
 * writes down twelve words instead of twenty-four. Choosing them now means not
 * choosing them under pressure later.
 */

import { argon2id } from '@noble/hashes/argon2.js';
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { KeyPair, fromUtf8, kdf, open, seal, utf8 } from './primitives';
import { ed25519 } from '@noble/curves/ed25519.js';

export class RecoveryError extends Error {}

/** 256 bits, which is 24 words. */
const PHRASE_STRENGTH = 256;

/**
 * Argon2id parameters, from the protocol document. Chosen for the case where
 * the input is weaker than a 24-word phrase — which is the case worth being
 * ready for, since it is the one a user creates by writing down half of it.
 */
export const ARGON2_MEMORY_KIB = 64 * 1024;
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 4;

const ARGON2_SALT = 'Tildra_Recovery_v1';
const IDENTITY_INFO = 'Tildra_RecoveryIdentity_v1';
const BACKUP_INFO = 'Tildra_RecoveryBackup_v1';

/** What the backup blob carries. Deliberately not messages. */
export interface RecoveryBackup {
  /** Accounts this device talks to, so a restored device is not empty. */
  contacts: { accountId: string; handle?: string; displayName?: string }[];
  groups: { groupId: string; name?: string; members: { accountId: string; deviceId: string }[] }[];
  /** Milliseconds, so an older blob cannot overwrite a newer one. */
  updatedAt: number;
}

/**
 * A fresh 24-word phrase.
 *
 * BIP-39's wordlist rather than one of our own: the words are chosen so that
 * four letters identify each uniquely and no two are easily confused when
 * spoken or written by hand, and reproducing that badly is a way to lose an
 * account to a smudged letter.
 */
export function generateRecoveryPhrase(): string {
  return generateMnemonic(wordlist, PHRASE_STRENGTH);
}

/**
 * Tidy what a person typed.
 *
 * Case, stray whitespace and the Unicode normalisation form are all things a
 * keyboard decides and a user cannot see. Refusing a correct phrase because it
 * arrived as NFC rather than NFKD would be the cruellest possible bug.
 */
export function normalizeRecoveryPhrase(input: string): string {
  return input.normalize('NFKD').trim().toLowerCase().replace(/\s+/g, ' ');
}

export function isValidRecoveryPhrase(input: string): boolean {
  return validateMnemonic(normalizeRecoveryPhrase(input), wordlist);
}

/**
 * Stretch a phrase into the seed both keys come from.
 *
 * Slow on purpose — this is the one call in the app that is allowed to take a
 * second, and it takes one on a phone.
 */
export function recoverySeed(phrase: string): Uint8Array {
  const normalized = normalizeRecoveryPhrase(phrase);
  if (!validateMnemonic(normalized, wordlist)) {
    // Checked before the expensive part: a typo should come back immediately,
    // and BIP-39's checksum catches most of them.
    throw new RecoveryError('that is not a valid recovery phrase');
  }

  return argon2id(utf8(normalized), utf8(ARGON2_SALT), {
    m: ARGON2_MEMORY_KIB,
    t: ARGON2_ITERATIONS,
    p: ARGON2_PARALLELISM,
    dkLen: 32,
  });
}

/** The account's identity key, derived from the phrase and nothing else. */
export function identityFromSeed(seed: Uint8Array): KeyPair {
  const secretKey = kdf(seed, undefined, IDENTITY_INFO, 32);
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

/**
 * The key the backup blob is encrypted under.
 *
 * A separate derivation from the same seed, so that handing the backup key to
 * something — a future selective-restore tool, a debugging path — does not
 * hand it the identity.
 */
export function backupKeyFromSeed(seed: Uint8Array): Uint8Array {
  return kdf(seed, undefined, BACKUP_INFO, 32);
}

/**
 * Encrypt a backup for upload.
 *
 * The account id is bound in as associated data: a blob is only meaningful for
 * the account it was made for, and a server that served the wrong one should
 * fail to authenticate rather than restore somebody else's contact list.
 */
export function sealBackup(
  backupKey: Uint8Array,
  accountId: string,
  backup: RecoveryBackup,
): Uint8Array {
  return seal(backupKey, utf8(JSON.stringify(backup)), utf8(accountId));
}

export function openBackup(
  backupKey: Uint8Array,
  accountId: string,
  sealed: Uint8Array,
): RecoveryBackup {
  const plaintext = open(backupKey, sealed, utf8(accountId));
  if (!plaintext) {
    throw new RecoveryError('the backup could not be decrypted with that phrase');
  }

  let parsed: RecoveryBackup;
  try {
    parsed = JSON.parse(fromUtf8(plaintext)) as RecoveryBackup;
  } catch {
    throw new RecoveryError('the backup decrypted to something that is not a backup');
  }
  if (!Array.isArray(parsed.contacts) || !Array.isArray(parsed.groups)) {
    throw new RecoveryError('the backup is missing fields');
  }
  return parsed;
}

/**
 * The words, grouped for reading off a screen and onto paper.
 *
 * Numbered because the order matters and a phrase copied out of order is a
 * phrase that fails a checksum with no clue as to why.
 */
export function phraseRows(phrase: string, perRow = 3): { index: number; word: string }[][] {
  const words = normalizeRecoveryPhrase(phrase).split(' ');
  const rows: { index: number; word: string }[][] = [];
  for (let i = 0; i < words.length; i += perRow) {
    rows.push(words.slice(i, i + perRow).map((word, j) => ({ index: i + j + 1, word })));
  }
  return rows;
}

/** Exposed so a test can assert the phrase carries the entropy it claims. */
export function phraseEntropyBits(phrase: string): number {
  return mnemonicToEntropy(normalizeRecoveryPhrase(phrase), wordlist).length * 8;
}

/** Bind two derivations together so a caller cannot use one without the other. */
export function recoveryKeys(phrase: string): { identity: KeyPair; backupKey: Uint8Array } {
  const seed = recoverySeed(phrase);
  return { identity: identityFromSeed(seed), backupKey: backupKeyFromSeed(seed) };
}
