/**
 * PQXDH-hybrid session establishment — docs/PROTOCOL.md §2.
 *
 * Three or four X25519 agreements are combined with one ML-KEM-768
 * encapsulation. Both must be broken for the session to be broken, which is
 * the whole point: X25519 is trusted and quantum-vulnerable, ML-KEM is
 * quantum-resistant and young. Neither is asked to stand alone.
 */

import {
  INFO,
  KeyPair,
  concat,
  dh,
  generateDhKeyPair,
  identityToDhPublic,
  identityToDhSecret,
  kdf,
  kemDecapsulate,
  kemEncapsulate,
  verify,
  wipe,
} from './primitives';
import { RatchetState, initInitiator, initResponder } from './ratchet';

export interface SignedPreKey {
  id: number;
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export interface OneTimePreKey {
  id: number;
  publicKey: Uint8Array;
}

/** What the server hands out for a device. Every signature in it is checked. */
export interface PreKeyBundle {
  accountId: string;
  deviceId: string;
  identityKey: Uint8Array;
  signedPreKey: SignedPreKey;
  signedPqPreKey: SignedPreKey;
  oneTimePreKey?: OneTimePreKey;
  oneTimePqPreKey?: OneTimePreKey;
}

/**
 * Our own secret material for a published bundle. Never leaves the device.
 *
 * The signed prekeys keep their signature alongside the key pair: republishing
 * the bundle (to top up one-time keys, say) must send the *same* public key
 * and the *same* signature. Re-signing is not equivalent — the pair has to
 * match, and generating a fresh signature for an old key is how you end up
 * publishing a bundle the server rejects.
 */
export interface PreKeySecrets {
  identity: KeyPair;
  signedPreKey: KeyPair & { id: number; signature: Uint8Array };
  signedPqPreKey: KeyPair & { id: number; signature: Uint8Array };
  /**
   * The signed prekeys this device published before the last rotation.
   *
   * Kept because rotation is not instantaneous from the outside: somebody may
   * have fetched the old bundle a minute before it was replaced and be about
   * to send with it. Dropping the old secret the moment a new one is published
   * turns every such handshake into an undecryptable first message, which
   * looks to the sender like the recipient does not exist.
   *
   * Exactly one generation is retained. Two would double the window in which
   * a stolen prekey is still useful, which is the thing rotation exists to
   * shrink.
   */
  previousSignedPreKey?: KeyPair & { id: number; signature: Uint8Array };
  previousSignedPqPreKey?: KeyPair & { id: number; signature: Uint8Array };
  oneTimePreKeys: Map<number, Uint8Array>;
  oneTimePqPreKeys: Map<number, Uint8Array>;
}

/** The header that rides on the first message of a session. */
export interface SessionInit {
  identityKey: Uint8Array;
  ephemeralKey: Uint8Array;
  kemCiphertext: Uint8Array;
  signedPreKeyId: number;
  pqPreKeyId: number;
  oneTimePreKeyId?: number;
  /** Whether pqPreKeyId refers to a one-time PQ key or the signed one. */
  usedOneTimePq: boolean;
}

export class BundleVerificationError extends Error {}

/**
 * Verify a bundle before touching it.
 *
 * A bundle that fails here is either a corrupted response or a server trying
 * to substitute keys. Both are fatal — there is no "warn and continue" path,
 * because continuing means establishing a session with whoever forged it.
 */
export function verifyBundle(bundle: PreKeyBundle): void {
  if (bundle.identityKey.length !== 32) {
    throw new BundleVerificationError('identity key is not 32 bytes');
  }
  if (!verify(bundle.identityKey, bundle.signedPreKey.publicKey, bundle.signedPreKey.signature)) {
    throw new BundleVerificationError('signed prekey signature does not verify');
  }
  if (
    !verify(bundle.identityKey, bundle.signedPqPreKey.publicKey, bundle.signedPqPreKey.signature)
  ) {
    throw new BundleVerificationError('signed PQ prekey signature does not verify');
  }
}

/** Associated data binds the handshake to both identities. */
export function associatedData(
  initiatorIdentity: Uint8Array,
  responderIdentity: Uint8Array,
): Uint8Array {
  return concat(initiatorIdentity, responderIdentity);
}

/**
 * Initiator side. Returns the ratchet ready to send, plus the header the first
 * message must carry so the responder can derive the same secret.
 */
export function initiateSession(
  identity: KeyPair,
  bundle: PreKeyBundle,
): {
  ratchet: RatchetState;
  init: SessionInit;
  associatedData: Uint8Array;
  sessionSecret: Uint8Array;
} {
  verifyBundle(bundle);

  const ephemeral = generateDhKeyPair();
  const identityDhSecret = identityToDhSecret(identity.secretKey);
  const responderIdentityDh = identityToDhPublic(bundle.identityKey);

  const dh1 = dh(identityDhSecret, bundle.signedPreKey.publicKey);
  const dh2 = dh(ephemeral.secretKey, responderIdentityDh);
  const dh3 = dh(ephemeral.secretKey, bundle.signedPreKey.publicKey);
  const dh4 = bundle.oneTimePreKey
    ? dh(ephemeral.secretKey, bundle.oneTimePreKey.publicKey)
    : new Uint8Array(0);

  // Prefer a one-time PQ key. Falling back to the signed one costs replay
  // resistance for this single handshake, not confidentiality.
  const pqTarget = bundle.oneTimePqPreKey ?? bundle.signedPqPreKey;
  const { ciphertext, sharedSecret: kemSecret } = kemEncapsulate(pqTarget.publicKey);

  const sharedSecret = deriveSharedSecret([dh1, dh2, dh3, dh4, kemSecret]);

  wipe(dh1, dh2, dh3, dh4, kemSecret, identityDhSecret, ephemeral.secretKey);

  const ratchet = initInitiator(sharedSecret, bundle.signedPreKey.publicKey);

  return {
    ratchet,
    init: {
      identityKey: identity.publicKey,
      ephemeralKey: ephemeral.publicKey,
      kemCiphertext: ciphertext,
      signedPreKeyId: bundle.signedPreKey.id,
      pqPreKeyId: pqTarget.id,
      oneTimePreKeyId: bundle.oneTimePreKey?.id,
      usedOneTimePq: bundle.oneTimePqPreKey !== undefined,
    },
    associatedData: associatedData(identity.publicKey, bundle.identityKey),
    sessionSecret: deriveSessionSecret(sharedSecret),
  };
}

/**
 * Responder side. Consumes the one-time keys named in the header — a one-time
 * key that is used twice is not one-time, so this deletes them even if the
 * message later fails to decrypt.
 */
export function acceptSession(
  secrets: PreKeySecrets,
  init: SessionInit,
): { ratchet: RatchetState; associatedData: Uint8Array; sessionSecret: Uint8Array } {
  // Either the current signed prekey or the one it replaced. See
  // `previousSignedPreKey` for why the old one is still here.
  const signedPreKey =
    init.signedPreKeyId === secrets.signedPreKey.id
      ? secrets.signedPreKey
      : init.signedPreKeyId === secrets.previousSignedPreKey?.id
        ? secrets.previousSignedPreKey
        : undefined;
  if (!signedPreKey) {
    throw new BundleVerificationError(
      'initial message references a signed prekey this device does not hold',
    );
  }

  const identityDhSecret = identityToDhSecret(secrets.identity.secretKey);
  const initiatorIdentityDh = identityToDhPublic(init.identityKey);

  const dh1 = dh(signedPreKey.secretKey, initiatorIdentityDh);
  const dh2 = dh(identityDhSecret, init.ephemeralKey);
  const dh3 = dh(signedPreKey.secretKey, init.ephemeralKey);

  let dh4: Uint8Array = new Uint8Array(0);
  if (init.oneTimePreKeyId !== undefined) {
    const oneTime = secrets.oneTimePreKeys.get(init.oneTimePreKeyId);
    if (!oneTime) {
      throw new BundleVerificationError('one-time prekey already used or unknown');
    }
    dh4 = dh(oneTime, init.ephemeralKey);
    wipe(oneTime);
    secrets.oneTimePreKeys.delete(init.oneTimePreKeyId);
  }

  let kemSecret: Uint8Array;
  if (init.usedOneTimePq) {
    const pqSecret = secrets.oneTimePqPreKeys.get(init.pqPreKeyId);
    if (!pqSecret) {
      throw new BundleVerificationError('one-time PQ prekey already used or unknown');
    }
    kemSecret = kemDecapsulate(pqSecret, init.kemCiphertext);
    wipe(pqSecret);
    secrets.oneTimePqPreKeys.delete(init.pqPreKeyId);
  } else {
    const signedPqPreKey =
      init.pqPreKeyId === secrets.signedPqPreKey.id
        ? secrets.signedPqPreKey
        : init.pqPreKeyId === secrets.previousSignedPqPreKey?.id
          ? secrets.previousSignedPqPreKey
          : undefined;
    if (!signedPqPreKey) {
      throw new BundleVerificationError(
        'initial message references a PQ prekey this device does not hold',
      );
    }
    kemSecret = kemDecapsulate(signedPqPreKey.secretKey, init.kemCiphertext);
  }

  const sharedSecret = deriveSharedSecret([dh1, dh2, dh3, dh4, kemSecret]);
  wipe(dh1, dh2, dh3, dh4, kemSecret, identityDhSecret);

  // The ratchet owns — and eventually wipes — the key pair it is given. The
  // signed prekey outlives any single session and serves every sender who
  // fetches this bundle, so it must be copied, never handed over. Passing the
  // original destroys the prekey the moment this session's first DH ratchet
  // step runs, silently breaking every other session using the same bundle.
  const ratchet = initResponder(sharedSecret, {
    publicKey: signedPreKey.publicKey.slice(),
    secretKey: signedPreKey.secretKey.slice(),
  });

  return {
    ratchet,
    associatedData: associatedData(init.identityKey, secrets.identity.publicKey),
    sessionSecret: deriveSessionSecret(sharedSecret),
  };
}

/**
 * A secret both sides derive identically from the handshake, used for mailbox
 * addressing and nothing else.
 *
 * Kept distinct from the ratchet's root key so that a mailbox secret — which
 * is shared with the sender by necessity — can never be walked back into
 * message keys.
 */
function deriveSessionSecret(sharedSecret: Uint8Array): Uint8Array {
  return kdf(sharedSecret, undefined, INFO.sessionSecret, 32);
}

/**
 * The 0xFF-filled prefix is the X3DH convention: it domain-separates this KDF
 * input from any raw DH output, so a shared secret can never be confused for
 * one of its own inputs.
 */
function deriveSharedSecret(parts: Uint8Array[]): Uint8Array {
  const prefix = new Uint8Array(32).fill(0xff);
  return kdf(concat(prefix, ...parts), undefined, INFO.pqxdh, 32);
}
