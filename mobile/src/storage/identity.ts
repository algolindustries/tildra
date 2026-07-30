/**
 * The identity key pair as it is stored.
 *
 * Alongside `prekeys.ts` because it is the same job — turning long-lived key
 * material into bytes and back — and because keeping it out of `app.ts` is
 * what makes it testable at all: `app.ts` reaches `react-native`.
 */

import { KeyPair } from '../crypto/primitives';

/** Public key then secret key, both Ed25519, both 32 bytes. */
const IDENTITY_BYTES = 64;

export function encodeIdentity(identity: KeyPair): Uint8Array {
  const out = new Uint8Array(identity.publicKey.length + identity.secretKey.length);
  out.set(identity.publicKey, 0);
  out.set(identity.secretKey, identity.publicKey.length);
  return out;
}

/**
 * Read the identity back off disk.
 *
 * The length is checked because this is the one direction where the input is
 * not ours: a truncated or rewritten vault entry used to yield a key pair of
 * the wrong size rather than an error, and the first sign of it was a
 * signature failing somewhere far away from the cause.
 */
export function decodeIdentity(bytes: Uint8Array): KeyPair {
  if (bytes.length !== IDENTITY_BYTES) {
    throw new Error(
      `Tildra: the stored identity is ${bytes.length} bytes, expected ${IDENTITY_BYTES}`,
    );
  }
  return { publicKey: bytes.slice(0, IDENTITY_BYTES / 2), secretKey: bytes.slice(IDENTITY_BYTES / 2) };
}
