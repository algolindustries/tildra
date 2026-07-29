/**
 * Cryptographic primitives.
 *
 * Everything here is a thin wrapper over audited libraries (@noble/*). The
 * wrappers exist for two reasons: to give every derivation a domain-separated
 * `info` string, and to make it impossible to call a KDF without one. There is
 * no novel cryptography in this file and there should never be.
 *
 * See docs/PROTOCOL.md §9 for the primitive choices and why.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export const AEAD_KEY_BYTES = 32;
export const AEAD_NONCE_BYTES = 24;
export const AEAD_TAG_BYTES = 16;
export const PUBLIC_KEY_BYTES = 32;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** All domain separators used by the protocol, in one place so collisions are visible. */
export const INFO = {
  pqxdh: 'Tildra_PQXDH_v1_25519_MLKEM768',
  rootKey: 'Tildra_RootKey_v1',
  messageKey: 'Tildra_MsgKey_v1',
  headerKeys: 'Tildra_HeaderKeys_v1',
  safetyNumber: 'Tildra_SafetyNumber_v1',
  mailbox: 'Tildra_Mailbox_v1',
  sealedSender: 'Tildra_SealedSender_v1',
  groupSender: 'Tildra_GroupSenderKey_v1',
} as const;

/** Signature contexts. A signature made for one purpose must never verify for another. */
export const SIG_CONTEXT = {
  registration: 'tildra-account-create-v1:',
  authChallenge: 'tildra-auth-challenge-v1:',
} as const;

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/**
 * CSPRNG bytes. On React Native this is backed by the
 * react-native-get-random-values polyfill, which must be imported at app entry
 * before anything in this module runs; in Node and the browser it is the
 * platform WebCrypto.
 *
 * Throwing rather than falling back is deliberate. A silent downgrade to
 * Math.random here would compromise every key the app ever generates, and it
 * would do so invisibly.
 */
export function randomBytes(length: number): Uint8Array {
  const g = globalThis as { crypto?: Crypto };
  if (!g.crypto?.getRandomValues) {
    throw new Error(
      'Tildra: no CSPRNG available. Import "react-native-get-random-values" at app entry.',
    );
  }
  // getRandomValues refuses requests over 65536 bytes. Padding a large
  // attachment to a bucket is a legitimate reason to ask for more, so fill in
  // chunks rather than making the caller know about the limit.
  const out = new Uint8Array(length);
  const MAX_CHUNK = 65536;
  for (let offset = 0; offset < length; offset += MAX_CHUNK) {
    g.crypto.getRandomValues(out.subarray(offset, Math.min(offset + MAX_CHUNK, length)));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hashing and key derivation
// ---------------------------------------------------------------------------

export function hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/** HKDF-SHA256. `info` is required — see the note at the top of this file. */
export function kdf(
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: string,
  length: number,
): Uint8Array {
  return hkdf(sha256, ikm, salt, utf8(info), length);
}

export function mac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

// ---------------------------------------------------------------------------
// Signatures — Ed25519
// ---------------------------------------------------------------------------

export function generateSigningKeyPair(): KeyPair {
  const secretKey = ed25519.utils.randomSecretKey();
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

export function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    // A malformed key or signature is a verification failure, not a crash.
    // Callers treat `false` as "reject this bundle", which is the right
    // outcome either way.
    return false;
  }
}

/** Sign with a context prefix so a signature is only valid for one purpose. */
export function signWithContext(
  secretKey: Uint8Array,
  context: string,
  message: Uint8Array,
): Uint8Array {
  return sign(secretKey, concat(utf8(context), message));
}

// ---------------------------------------------------------------------------
// Key agreement — X25519
// ---------------------------------------------------------------------------

export function generateDhKeyPair(): KeyPair {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

export function dh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secretKey, publicKey);
  // X25519 with a low-order point yields an all-zero shared secret. RFC 7748
  // says implementations MAY check for this; for a messaging handshake it is a
  // "must" — an attacker who can force a known shared secret can hijack the
  // session.
  if (shared.every((b) => b === 0)) {
    throw new Error('Tildra: X25519 produced an all-zero shared secret (low-order point)');
  }
  return shared;
}

/**
 * Map an Ed25519 identity key onto Curve25519 so one identity key serves both
 * signing and key agreement. This is the standard birational map; noble
 * implements it, we do not.
 */
export function identityToDhPublic(ed25519PublicKey: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomery(ed25519PublicKey);
}

export function identityToDhSecret(ed25519SecretKey: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomerySecret(ed25519SecretKey);
}

// ---------------------------------------------------------------------------
// Post-quantum KEM — ML-KEM-768 (FIPS 203)
// ---------------------------------------------------------------------------

export function generateKemKeyPair(): KeyPair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}

export function kemEncapsulate(publicKey: Uint8Array): {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
} {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  return { ciphertext: cipherText, sharedSecret };
}

export function kemDecapsulate(
  secretKey: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

// ---------------------------------------------------------------------------
// AEAD — XChaCha20-Poly1305
// ---------------------------------------------------------------------------

export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(key, nonce, associatedData).encrypt(plaintext);
}

/** Returns null on authentication failure rather than throwing. */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array | null {
  try {
    return xchacha20poly1305(key, nonce, associatedData).decrypt(ciphertext);
  } catch {
    return null;
  }
}

/**
 * Encrypt with a fresh random nonce prepended to the ciphertext. Safe here
 * because XChaCha20's 192-bit nonce makes random generation collision-free in
 * practice; this would be reckless with a 96-bit nonce.
 */
export function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  const nonce = randomBytes(AEAD_NONCE_BYTES);
  return concat(nonce, aeadEncrypt(key, nonce, plaintext, associatedData));
}

export function open(
  key: Uint8Array,
  sealed: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array | null {
  if (sealed.length < AEAD_NONCE_BYTES + AEAD_TAG_BYTES) return null;
  const nonce = sealed.subarray(0, AEAD_NONCE_BYTES);
  const ciphertext = sealed.subarray(AEAD_NONCE_BYTES);
  return aeadDecrypt(key, nonce, ciphertext, associatedData);
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** Constant-time comparison. Used wherever a mismatch is attacker-observable. */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Overwrite a secret in place. JavaScript gives no guarantee this defeats a
 * determined memory-forensics attack — the runtime may have copied the buffer
 * already — but it does bound how long key material sits in a live heap.
 */
export function wipe(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const b of buffers) b?.fill(0);
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return globalThis.btoa(binary);
}

export function fromBase64(s: string): Uint8Array {
  const binary = globalThis.atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** Big-endian uint32, used for ratchet counters in message headers. */
export function u32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function readU32(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}
