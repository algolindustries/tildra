/**
 * Identity and prekey management — docs/PROTOCOL.md §1.
 *
 * A Tildra account is a key. This module makes the keys, signs the ones that
 * need signing, and produces the payload the server publishes on the device's
 * behalf. It never sends anything itself; that is the API layer's job.
 */

import {
  KeyPair,
  SIG_CONTEXT,
  generateDhKeyPair,
  generateKemKeyPair,
  generateSigningKeyPair,
  sign,
  signWithContext,
  toBase64,
  utf8,
} from './primitives';
import { PreKeySecrets } from './pqxdh';

/** How many one-time prekeys to publish, and when to top up. */
export const ONE_TIME_PREKEY_TARGET = 100;
export const ONE_TIME_PREKEY_LOW_WATER = 20;

/** Signed prekeys rotate on this interval — docs/PROTOCOL.md §0. */
export const SIGNED_PREKEY_ROTATION_MS = 48 * 60 * 60 * 1000;

/** The JSON body PUT to /v1/keys. Byte fields are base64, matching Go's []byte. */
export interface KeyUploadPayload {
  identityKey: string;
  signedPreKey: { id: number; publicKey: string; signature: string };
  signedPqPreKey: { id: number; publicKey: string; signature: string };
  oneTimePreKeys: { id: number; publicKey: string }[];
  oneTimePqPreKeys: { id: number; publicKey: string }[];
}

export function generateIdentity(): KeyPair {
  return generateSigningKeyPair();
}

/** The proof of key possession that /v1/accounts requires at registration. */
export function registrationProof(identity: KeyPair, at: Date = new Date()): {
  proofTs: string;
  proof: string;
} {
  // Second precision, no milliseconds — the server parses RFC3339 and
  // reconstructs this exact string to verify, so the two must agree byte for
  // byte.
  const proofTs = at.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const proof = signWithContext(identity.secretKey, SIG_CONTEXT.registration, utf8(proofTs));
  return { proofTs, proof: toBase64(proof) };
}

/** Sign the login challenge issued by /v1/auth/challenge. */
export function signAuthChallenge(identity: KeyPair, challenge: Uint8Array): string {
  return toBase64(signWithContext(identity.secretKey, SIG_CONTEXT.authChallenge, challenge));
}

/**
 * Generate a full set of prekeys.
 *
 * `startId` lets a top-up continue the ID sequence instead of restarting it.
 * Reusing an ID would make the server hand out one key while the client looks
 * up a different secret, and the handshake would fail in a way that looks like
 * an attack.
 */
export function generatePreKeys(
  identity: KeyPair,
  options: { count?: number; startId?: number; signedPreKeyId?: number } = {},
): { secrets: PreKeySecrets; upload: KeyUploadPayload } {
  const count = options.count ?? ONE_TIME_PREKEY_TARGET;
  const startId = options.startId ?? 1;
  const signedId = options.signedPreKeyId ?? 1;

  const signedPreKey = generateDhKeyPair();
  const signedPqPreKey = generateKemKeyPair();

  const oneTimePreKeys = new Map<number, Uint8Array>();
  const oneTimePqPreKeys = new Map<number, Uint8Array>();
  const uploadOneTime: { id: number; publicKey: string }[] = [];
  const uploadOneTimePq: { id: number; publicKey: string }[] = [];

  for (let i = 0; i < count; i++) {
    const id = startId + i;
    const ec = generateDhKeyPair();
    oneTimePreKeys.set(id, ec.secretKey);
    uploadOneTime.push({ id, publicKey: toBase64(ec.publicKey) });

    const pq = generateKemKeyPair();
    oneTimePqPreKeys.set(id, pq.secretKey);
    uploadOneTimePq.push({ id, publicKey: toBase64(pq.publicKey) });
  }

  const signedPreKeySignature = sign(identity.secretKey, signedPreKey.publicKey);
  const signedPqPreKeySignature = sign(identity.secretKey, signedPqPreKey.publicKey);

  const secrets: PreKeySecrets = {
    identity,
    signedPreKey: { ...signedPreKey, id: signedId, signature: signedPreKeySignature },
    signedPqPreKey: { ...signedPqPreKey, id: signedId, signature: signedPqPreKeySignature },
    oneTimePreKeys,
    oneTimePqPreKeys,
  };

  const upload: KeyUploadPayload = {
    identityKey: toBase64(identity.publicKey),
    signedPreKey: {
      id: signedId,
      publicKey: toBase64(signedPreKey.publicKey),
      signature: toBase64(signedPreKeySignature),
    },
    signedPqPreKey: {
      id: signedId,
      publicKey: toBase64(signedPqPreKey.publicKey),
      signature: toBase64(signedPqPreKeySignature),
    },
    oneTimePreKeys: uploadOneTime,
    oneTimePqPreKeys: uploadOneTimePq,
  };

  return { secrets, upload };
}

/** Whether the pool has run low enough to warrant a top-up. */
export function needsPreKeyTopUp(remaining: number): boolean {
  return remaining < ONE_TIME_PREKEY_LOW_WATER;
}

export function signedPreKeyIsStale(generatedAt: number, now: number = Date.now()): boolean {
  return now - generatedAt > SIGNED_PREKEY_ROTATION_MS;
}
