/**
 * Safety numbers — docs/PROTOCOL.md §7.
 *
 * The only defence against a server that substitutes keys is two humans
 * comparing a value out of band. Everything about this module is in service of
 * making that comparison short enough that people actually do it.
 */

import { INFO, concat, kdf, toHex } from './primitives';

/** 60 digits, shown as 12 groups of 5. */
const DIGIT_GROUPS = 12;
const DIGITS_PER_GROUP = 5;

/**
 * Derive the shared safety number for a pair of identity keys.
 *
 * The keys are sorted before hashing so both sides compute the same value
 * without needing to agree on who is "first".
 */
export function safetyNumber(ourIdentityKey: Uint8Array, theirIdentityKey: Uint8Array): string {
  const [first, second] = sortKeys(ourIdentityKey, theirIdentityKey);
  const digest = kdf(concat(first, second), undefined, INFO.safetyNumber, 30);

  const groups: string[] = [];
  for (let i = 0; i < DIGIT_GROUPS; i++) {
    // Each group reads 24 bits at a two-byte stride, so consecutive groups
    // overlap by one byte and only the first 25 of the 30 digest bytes are
    // read at all.
    //
    // That is not what the digest was sized for: twelve disjoint 20-bit fields
    // is exactly 30 bytes, and this comment used to say 20 bits and quote the
    // bias for it. The code has always done the above.
    //
    // It stays. Changing the extraction changes every safety number anyone has
    // compared and written down, and the app's own words for a number that no
    // longer matches are "this is what a key substitution looks like" — a real
    // alarm, raised by a cosmetic edit. There is nothing to gain either: 25
    // bytes is 200 bits reaching a 60-digit output that can express about 199,
    // so the comparison is as strong as its length allows whichever way the
    // bits are cut. The modulo bias is 2^24 / 100000 ≈ 167.8, which is
    // negligible for a value that is a comparison aid rather than a key.
    //
    // `safety.test.ts` pins the result so this cannot drift by accident.
    const chunk = (digest[i * 2] << 16) | (digest[i * 2 + 1] << 8) | digest[i * 2 + 2];
    groups.push((chunk % 100000).toString().padStart(DIGITS_PER_GROUP, '0'));
  }
  return groups.join(' ');
}

/** The payload encoded into the verification QR code. */
export function safetyQrPayload(
  ourIdentityKey: Uint8Array,
  theirIdentityKey: Uint8Array,
): string {
  const [first, second] = sortKeys(ourIdentityKey, theirIdentityKey);
  return `tildra:verify:1:${toHex(first)}:${toHex(second)}`;
}

/**
 * Check a scanned QR payload against the locally computed pair.
 *
 * A mismatch means the person you are looking at is not the person you have a
 * session with. The UI must treat that as an attack in progress, not a
 * scanning error.
 */
export function verifyQrPayload(
  payload: string,
  ourIdentityKey: Uint8Array,
  theirIdentityKey: Uint8Array,
): boolean {
  return payload.trim() === safetyQrPayload(ourIdentityKey, theirIdentityKey);
}

function sortKeys(a: Uint8Array, b: Uint8Array): [Uint8Array, Uint8Array] {
  const ah = toHex(a);
  const bh = toHex(b);
  return ah <= bh ? [a, b] : [b, a];
}
