import { describe, expect, it } from 'vitest';

import { safetyNumber, safetyQrPayload, verifyQrPayload } from '../safety';

/**
 * Safety numbers — `docs/PROTOCOL.md` §7.
 *
 * The only defence against a server that substitutes keys is two humans
 * comparing a value out of band, so this module has no fallback: if it is
 * wrong, verification is theatre and nothing else in the stack notices.
 *
 * `crypto.test.ts` already checks symmetry, the group count and that different
 * peers differ. What nothing pinned is the *construction* — which bytes of the
 * digest reach which digits — so a change to the extraction would alter every
 * number in the world and no test would say a word. That is what the vector
 * below is for.
 */

/** Two fixed keys, so the vector is reproducible. */
const KEY_A = new Uint8Array(32).fill(0x01);
const KEY_B = new Uint8Array(32).fill(0x02);

/**
 * A characterisation vector, not an independently derived one.
 *
 * It was produced by running this code, which makes it worth exactly one
 * thing and worth saying plainly: it locks the construction in place. It is
 * not evidence that the construction is the one `docs/PROTOCOL.md` §7
 * intended — the doc gives the KDF and its label, and stops short of the digit
 * extraction. What it catches is a silent change, which for a value people
 * write on paper and read to each other over the phone is the failure that
 * matters.
 */
const VECTOR = '48579 21522 41832 22852 94737 47020 25416 59385 75805 21692 20359 00189';

describe('the safety number', () => {
  it('is sixty digits in twelve groups of five', () => {
    const groups = safetyNumber(KEY_A, KEY_B).split(' ');
    expect(groups).toHaveLength(12);
    for (const g of groups) {
      expect(g).toMatch(/^\d{5}$/);
    }
  });

  it('is the same value whichever side computes it', () => {
    // The keys are sorted before hashing precisely so the two people do not
    // have to agree on who is "first". If this ever stopped holding, every
    // verification in the product would fail and read as an attack.
    expect(safetyNumber(KEY_A, KEY_B)).toBe(safetyNumber(KEY_B, KEY_A));
  });

  it('matches the recorded vector', () => {
    expect(safetyNumber(KEY_A, KEY_B)).toBe(VECTOR);
    expect(safetyNumber(KEY_B, KEY_A)).toBe(VECTOR);
  });

  it('changes when any single byte of either key changes', () => {
    // Exhaustive over both keys' bytes rather than a couple of samples. A
    // construction that dropped part of the input — the tail of a key, say —
    // would let a substituted key produce the same number for the bytes it
    // still read, and two people comparing digits would confirm an imposter.
    const baseline = safetyNumber(KEY_A, KEY_B);

    for (let i = 0; i < 32; i++) {
      const a = Uint8Array.from(KEY_A);
      a[i] ^= 0xff;
      expect(safetyNumber(a, KEY_B), `byte ${i} of the first key`).not.toBe(baseline);

      const b = Uint8Array.from(KEY_B);
      b[i] ^= 0xff;
      expect(safetyNumber(KEY_A, b), `byte ${i} of the second key`).not.toBe(baseline);
    }
  });

  it('separates a pair from either key on its own', () => {
    // A number derived from one key alone would be the same for every contact
    // that key ever verifies with.
    const c = new Uint8Array(32).fill(0x03);
    expect(safetyNumber(KEY_A, KEY_B)).not.toBe(safetyNumber(KEY_A, c));
    expect(safetyNumber(KEY_A, KEY_B)).not.toBe(safetyNumber(c, KEY_B));
  });
});

describe('the verification QR payload', () => {
  it('names its kind and carries both keys in sorted order', () => {
    // The kind matters: the link screen refuses a safety code and the
    // verification screen refuses a link code, each by name. A payload that
    // did not say which it was would let the two flows be confused.
    const payload = safetyQrPayload(KEY_A, KEY_B);
    expect(payload).toBe(
      'tildra:verify:1:' + '01'.repeat(32) + ':' + '02'.repeat(32),
    );
  });

  it('is the same string whichever side renders it', () => {
    expect(safetyQrPayload(KEY_A, KEY_B)).toBe(safetyQrPayload(KEY_B, KEY_A));
  });

  it('verifies against the pair it was made from, either way round', () => {
    const payload = safetyQrPayload(KEY_A, KEY_B);
    expect(verifyQrPayload(payload, KEY_A, KEY_B)).toBe(true);
    expect(verifyQrPayload(payload, KEY_B, KEY_A)).toBe(true);
  });

  it('refuses a payload for a different peer', () => {
    // The case the UI is told to treat as an attack in progress rather than a
    // scanning error.
    const mallory = new Uint8Array(32).fill(0x03);
    const payload = safetyQrPayload(KEY_A, KEY_B);
    expect(verifyQrPayload(payload, KEY_A, mallory)).toBe(false);
    expect(verifyQrPayload(payload, mallory, KEY_B)).toBe(false);
  });

  it('refuses an edited payload', () => {
    const payload = safetyQrPayload(KEY_A, KEY_B);
    expect(verifyQrPayload(payload.replace('verify', 'link'), KEY_A, KEY_B)).toBe(false);
    expect(verifyQrPayload(payload.replace(':1:', ':2:'), KEY_A, KEY_B)).toBe(false);
    expect(verifyQrPayload(payload.slice(0, -2), KEY_A, KEY_B)).toBe(false);
    expect(verifyQrPayload(payload + '00', KEY_A, KEY_B)).toBe(false);
  });

  it('tolerates the whitespace a camera or a paste adds', () => {
    const payload = safetyQrPayload(KEY_A, KEY_B);
    expect(verifyQrPayload(`  ${payload}\n`, KEY_A, KEY_B)).toBe(true);
  });
});
