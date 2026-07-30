import { describe, expect, it } from 'vitest';

import { decodeIdentity, encodeIdentity } from '../identity';
import { generateIdentity } from '../../crypto/identity';
import { randomBytes, toHex } from '../../crypto/primitives';

/**
 * The bytes a device is. Getting this wrong does not lose a message, it loses
 * the account — and the way it goes wrong matters: a decode that silently
 * returns keys of the wrong length fails later, somewhere else, as a
 * signature that does not verify.
 */

describe('the stored identity', () => {
  it('comes back exactly as it went in', () => {
    const identity = generateIdentity();
    const restored = decodeIdentity(encodeIdentity(identity));
    expect(toHex(restored.publicKey)).toBe(toHex(identity.publicKey));
    expect(toHex(restored.secretKey)).toBe(toHex(identity.secretKey));
  });

  it('is 64 bytes: public key first, then secret key', () => {
    // Pinned because the order is not recoverable from the bytes. Writing
    // them the other way round would round-trip perfectly and produce a
    // different account on every device that read it.
    const identity = generateIdentity();
    const encoded = encodeIdentity(identity);
    expect(encoded).toHaveLength(64);
    expect(toHex(encoded.slice(0, 32))).toBe(toHex(identity.publicKey));
    expect(toHex(encoded.slice(32))).toBe(toHex(identity.secretKey));
  });

  it('refuses a blob that is not the right length', () => {
    // A truncated or rewritten vault entry. Silently slicing it produced a
    // key pair of the wrong size, and the first symptom was a signature
    // failing far from the cause.
    for (const length of [0, 1, 31, 32, 63, 65, 128]) {
      expect(() => decodeIdentity(randomBytes(length)), `${length} bytes`).toThrow(
        /stored identity is/,
      );
    }
  });

  it('says how long the blob actually was', () => {
    // The number is the whole diagnostic: 32 says a half was lost, 0 says the
    // entry is gone, 128 says something wrote twice.
    expect(() => decodeIdentity(randomBytes(32))).toThrow(/is 32 bytes, expected 64/);
  });

  it('does not alias the buffer it was handed', () => {
    // slice copies and subarray does not. A key pair that shares memory with
    // the decrypted vault blob changes underneath the caller when that buffer
    // is reused or wiped.
    const identity = generateIdentity();
    const encoded = encodeIdentity(identity);
    const restored = decodeIdentity(encoded);
    encoded.fill(0);
    expect(toHex(restored.publicKey)).toBe(toHex(identity.publicKey));
    expect(toHex(restored.secretKey)).toBe(toHex(identity.secretKey));
  });

  it('does not alias the identity it was given', () => {
    const identity = generateIdentity();
    const before = toHex(identity.publicKey);
    const encoded = encodeIdentity(identity);
    encoded.fill(0);
    expect(toHex(identity.publicKey)).toBe(before);
  });
});
