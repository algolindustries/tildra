/**
 * Group messaging — docs/PROTOCOL.md §4.
 *
 * Telegram has no end-to-end encrypted groups at all. This is the design that
 * fixes that, and the shape of it is worth stating plainly:
 *
 * Each member holds one *sending* chain and one *receiving* chain per other
 * member. A message is encrypted once with the sender's own chain and fanned
 * out by the server as opaque bytes. Distributing a chain key costs one
 * pairwise Double Ratchet message per member, once — not per message.
 *
 * The subtle part, and the one that is easy to get wrong: receivers are given
 * the sender's chain key, so a receiver can derive every message key that
 * sender will ever use. Without more, any member could forge a message
 * appearing to come from any other member. Every sender therefore also holds
 * an Ed25519 signing key whose private half never leaves the device, and every
 * message is signed. Possessing the chain key lets you *read*; only the
 * signing key lets you *write*.
 */

import {
  AEAD_KEY_BYTES,
  AEAD_NONCE_BYTES,
  INFO,
  KeyPair,
  aeadDecrypt,
  aeadEncrypt,
  concat,
  generateSigningKeyPair,
  kdf,
  mac,
  randomBytes,
  readU32,
  sign,
  toBase64,
  fromBase64,
  u32,
  utf8,
  verify,
  wipe,
} from './primitives';
import { frame, unframe } from './wire';

const VERSION = 1;

/** Bounds on the out-of-order cache, mirroring the pairwise ratchet. */
export const MAX_GROUP_SKIP = 1000;
export const MAX_GROUP_SKIPPED_KEYS = 1000;
export const GROUP_SKIPPED_KEY_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export class GroupError extends Error {}

/**
 * Our own sending state for one group. The signing secret key is the thing
 * that must never be shared — it is what makes a message ours.
 */
export interface SenderKeyState {
  groupId: string;
  chainKey: Uint8Array;
  iteration: number;
  signing: KeyPair;
}

/** What we hold for another member: their chain, and their public signing key. */
export interface ReceiverKeyState {
  groupId: string;
  memberId: string;
  chainKey: Uint8Array;
  iteration: number;
  signingPublicKey: Uint8Array;
  skipped: Map<number, { messageKey: Uint8Array; storedAt: number }>;
}

/** A wire message. `iteration` is the position in the sender's chain. */
export interface GroupMessage {
  groupId: string;
  iteration: number;
  ciphertext: Uint8Array;
  signature: Uint8Array;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

function advanceChain(chainKey: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  return {
    messageKey: mac(chainKey, new Uint8Array([0x01])),
    chainKey: mac(chainKey, new Uint8Array([0x02])),
  };
}

function expandMessageKey(messageKey: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const out = kdf(messageKey, undefined, INFO.groupSender, AEAD_KEY_BYTES + AEAD_NONCE_BYTES);
  return {
    key: out.slice(0, AEAD_KEY_BYTES),
    nonce: out.slice(AEAD_KEY_BYTES, AEAD_KEY_BYTES + AEAD_NONCE_BYTES),
  };
}

/**
 * Associated data for the AEAD.
 *
 * Binding the group, the position in the chain and the sender's signing key
 * into the ciphertext means a message cannot be replayed into another group,
 * moved to a different position, or attributed to a different sender without
 * the authentication failing.
 */
function messageAd(groupId: string, iteration: number, signingPublicKey: Uint8Array): Uint8Array {
  return concat(utf8(groupId), u32(iteration), signingPublicKey);
}

function signedBytes(groupId: string, iteration: number, ciphertext: Uint8Array): Uint8Array {
  return concat(utf8('Tildra_GroupMsg_v1:'), utf8(groupId), u32(iteration), ciphertext);
}

// ---------------------------------------------------------------------------
// Creating and distributing sender keys
// ---------------------------------------------------------------------------

/** Start a fresh sending chain for a group. */
export function createSenderKey(groupId: string): SenderKeyState {
  return {
    groupId,
    chainKey: randomBytes(32),
    iteration: 0,
    signing: generateSigningKeyPair(),
  };
}

/**
 * The blob handed to each other member over the pairwise session.
 *
 * It carries the chain key from its *current* position, not from the start, so
 * a member added mid-conversation cannot decrypt anything sent before they
 * joined. That property is why the iteration travels with the key.
 */
export function encodeDistribution(state: SenderKeyState): Uint8Array {
  return frame(
    new Uint8Array([VERSION]),
    utf8(state.groupId),
    u32(state.iteration),
    state.chainKey,
    state.signing.publicKey,
  );
}

export function decodeDistribution(memberId: string, data: Uint8Array): ReceiverKeyState {
  const [version, groupId, iteration, chainKey, signingPublicKey] = unframe(data, 5);
  if (version.length !== 1 || version[0] !== VERSION) {
    throw new GroupError(`unsupported sender key distribution version ${version[0]}`);
  }
  if (chainKey.length !== 32 || signingPublicKey.length !== 32) {
    throw new GroupError('malformed sender key distribution');
  }
  return {
    groupId: new TextDecoder().decode(groupId),
    memberId,
    chainKey,
    iteration: readU32(iteration, 0),
    signingPublicKey,
    skipped: new Map(),
  };
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt
// ---------------------------------------------------------------------------

export function encryptGroupMessage(state: SenderKeyState, plaintext: Uint8Array): GroupMessage {
  const step = advanceChain(state.chainKey);
  wipe(state.chainKey);
  state.chainKey = step.chainKey;

  const iteration = state.iteration;
  state.iteration += 1;

  const { key, nonce } = expandMessageKey(step.messageKey);
  const ciphertext = aeadEncrypt(
    key,
    nonce,
    plaintext,
    messageAd(state.groupId, iteration, state.signing.publicKey),
  );
  wipe(step.messageKey, key);

  return {
    groupId: state.groupId,
    iteration,
    ciphertext,
    signature: sign(state.signing.secretKey, signedBytes(state.groupId, iteration, ciphertext)),
  };
}

export function decryptGroupMessage(state: ReceiverKeyState, message: GroupMessage): Uint8Array {
  if (message.groupId !== state.groupId) {
    throw new GroupError('message is for a different group');
  }

  // Signature first, before any key material is derived. A member who holds
  // the chain key but not the signing key must be stopped here, and stopped
  // before we do any work on their input.
  if (
    !verify(
      state.signingPublicKey,
      signedBytes(message.groupId, message.iteration, message.ciphertext),
      message.signature,
    )
  ) {
    throw new GroupError('group message signature does not verify');
  }

  const messageKey = takeMessageKey(state, message.iteration);
  const { key, nonce } = expandMessageKey(messageKey);
  const plaintext = aeadDecrypt(
    key,
    nonce,
    message.ciphertext,
    messageAd(message.groupId, message.iteration, state.signingPublicKey),
  );
  wipe(messageKey, key);

  if (!plaintext) {
    throw new GroupError('group message failed to authenticate');
  }
  return plaintext;
}

/**
 * Derive the key for a given position, caching any skipped along the way.
 *
 * Group fanout reorders more than a pairwise session does — the server
 * delivers to every member independently — so out-of-order arrival is normal
 * rather than exceptional.
 */
function takeMessageKey(state: ReceiverKeyState, iteration: number): Uint8Array {
  const cached = state.skipped.get(iteration);
  if (cached) {
    state.skipped.delete(iteration);
    return cached.messageKey;
  }

  if (iteration < state.iteration) {
    // Already consumed and evicted. Accepting it would mean deriving a key we
    // deliberately dropped; refusing is what makes the cache bound meaningful.
    throw new GroupError(`group message ${iteration} is older than the retained window`);
  }
  if (iteration - state.iteration > MAX_GROUP_SKIP) {
    throw new GroupError(`refusing to skip more than ${MAX_GROUP_SKIP} group messages`);
  }

  let messageKey: Uint8Array | null = null;
  while (state.iteration <= iteration) {
    const step = advanceChain(state.chainKey);
    wipe(state.chainKey);
    state.chainKey = step.chainKey;

    if (state.iteration === iteration) {
      messageKey = step.messageKey;
    } else {
      state.skipped.set(state.iteration, { messageKey: step.messageKey, storedAt: Date.now() });
    }
    state.iteration += 1;
  }

  pruneSkipped(state);
  if (!messageKey) throw new GroupError('failed to derive a group message key');
  return messageKey;
}

function pruneSkipped(state: ReceiverKeyState): void {
  const cutoff = Date.now() - GROUP_SKIPPED_KEY_TTL_MS;
  for (const [iteration, entry] of state.skipped) {
    if (entry.storedAt < cutoff) {
      wipe(entry.messageKey);
      state.skipped.delete(iteration);
    }
  }
  while (state.skipped.size > MAX_GROUP_SKIPPED_KEYS) {
    const oldest = state.skipped.keys().next();
    if (oldest.done) break;
    wipe(state.skipped.get(oldest.value)?.messageKey);
    state.skipped.delete(oldest.value);
  }
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

export function encodeGroupMessage(message: GroupMessage): Uint8Array {
  return frame(
    new Uint8Array([VERSION]),
    utf8(message.groupId),
    u32(message.iteration),
    message.ciphertext,
    message.signature,
  );
}

export function decodeGroupMessage(data: Uint8Array): GroupMessage {
  const [version, groupId, iteration, ciphertext, signature] = unframe(data, 5);
  if (version.length !== 1 || version[0] !== VERSION) {
    throw new GroupError(`unsupported group message version ${version[0]}`);
  }
  return {
    groupId: new TextDecoder().decode(groupId),
    iteration: readU32(iteration, 0),
    ciphertext,
    signature,
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export interface SerializedSenderKey {
  v: 1;
  groupId: string;
  chainKey: string;
  iteration: number;
  signingPublic: string;
  signingSecret: string;
}

export interface SerializedReceiverKey {
  v: 1;
  groupId: string;
  memberId: string;
  chainKey: string;
  iteration: number;
  signingPublicKey: string;
  skipped: [number, { messageKey: string; storedAt: number }][];
}

export function serializeSenderKey(state: SenderKeyState): SerializedSenderKey {
  return {
    v: 1,
    groupId: state.groupId,
    chainKey: toBase64(state.chainKey),
    iteration: state.iteration,
    signingPublic: toBase64(state.signing.publicKey),
    signingSecret: toBase64(state.signing.secretKey),
  };
}

export function deserializeSenderKey(data: SerializedSenderKey): SenderKeyState {
  if (data.v !== 1) throw new GroupError(`unsupported sender key version ${data.v}`);
  return {
    groupId: data.groupId,
    chainKey: fromBase64(data.chainKey),
    iteration: data.iteration,
    signing: {
      publicKey: fromBase64(data.signingPublic),
      secretKey: fromBase64(data.signingSecret),
    },
  };
}

export function serializeReceiverKey(state: ReceiverKeyState): SerializedReceiverKey {
  return {
    v: 1,
    groupId: state.groupId,
    memberId: state.memberId,
    chainKey: toBase64(state.chainKey),
    iteration: state.iteration,
    signingPublicKey: toBase64(state.signingPublicKey),
    skipped: [...state.skipped].map(([i, e]) => [
      i,
      { messageKey: toBase64(e.messageKey), storedAt: e.storedAt },
    ]),
  };
}

export function deserializeReceiverKey(data: SerializedReceiverKey): ReceiverKeyState {
  if (data.v !== 1) throw new GroupError(`unsupported receiver key version ${data.v}`);
  return {
    groupId: data.groupId,
    memberId: data.memberId,
    chainKey: fromBase64(data.chainKey),
    iteration: data.iteration,
    signingPublicKey: fromBase64(data.signingPublicKey),
    skipped: new Map(
      data.skipped.map(([i, e]) => [i, { messageKey: fromBase64(e.messageKey), storedAt: e.storedAt }]),
    ),
  };
}
