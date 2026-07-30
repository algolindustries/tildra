/**
 * Double Ratchet with header encryption.
 *
 * This is the Signal Double Ratchet, HE variant, as specified at
 * https://signal.org/docs/specifications/doubleratchet/ — with the KDF
 * domain separators and the 56-byte message-key expansion described in
 * docs/PROTOCOL.md §3.
 *
 * Header encryption is not optional in Tildra. Without it, a passive observer
 * can group messages into conversations by watching ratchet public keys, which
 * hands them the social graph that sealed sender exists to hide.
 */

import {
  AEAD_KEY_BYTES,
  AEAD_NONCE_BYTES,
  INFO,
  KeyPair,
  aeadDecrypt,
  aeadEncrypt,
  concat,
  dh,
  fromBase64,
  generateDhKeyPair,
  kdf,
  mac,
  open,
  readU32,
  seal,
  toBase64,
  u32,
  wipe,
} from './primitives';

/** Refuse to derive more than this many skipped keys in one step. */
export const MAX_SKIP = 1000;
/** Drop cached skipped keys after this long — see docs/THREAT_MODEL.md, A3. */
export const SKIPPED_KEY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Total cached skipped keys per session. */
export const MAX_SKIPPED_KEYS = 1000;

const HEADER_BYTES = 40; // ratchet public key (32) ‖ PN (4) ‖ N (4)

export interface RatchetHeader {
  ratchetKey: Uint8Array;
  previousChainLength: number;
  messageNumber: number;
}

export interface RatchetMessage {
  /** Encrypted header: nonce ‖ ciphertext ‖ tag. */
  header: Uint8Array;
  /** Encrypted body, authenticated over the encrypted header. */
  body: Uint8Array;
}

interface SkippedKey {
  messageKey: Uint8Array;
  storedAt: number;
}

export interface RatchetState {
  sending: KeyPair;
  receiving: Uint8Array | null;
  rootKey: Uint8Array;
  sendingChain: Uint8Array | null;
  receivingChain: Uint8Array | null;
  sentCount: number;
  receivedCount: number;
  previousChainLength: number;
  headerKeySending: Uint8Array | null;
  headerKeyReceiving: Uint8Array | null;
  nextHeaderKeySending: Uint8Array;
  nextHeaderKeyReceiving: Uint8Array;
  /** key: base64(headerKey) ‖ ":" ‖ messageNumber */
  skipped: Map<string, SkippedKey>;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/** Root KDF: advances the root key and produces a chain key and the next header key. */
function kdfRootKey(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): { rootKey: Uint8Array; chainKey: Uint8Array; nextHeaderKey: Uint8Array } {
  const out = kdf(dhOutput, rootKey, INFO.rootKey, 96);
  return {
    rootKey: out.slice(0, 32),
    chainKey: out.slice(32, 64),
    nextHeaderKey: out.slice(64, 96),
  };
}

/**
 * Symmetric chain step. The constants are domain separators, not magic: a
 * chain key and a message key derived from the same input must never collide.
 */
function kdfChainKey(chainKey: Uint8Array): {
  chainKey: Uint8Array;
  messageKey: Uint8Array;
} {
  return {
    messageKey: mac(chainKey, new Uint8Array([0x01])),
    chainKey: mac(chainKey, new Uint8Array([0x02])),
  };
}

/** Expand a message key into the AEAD key and nonce actually used. */
function expandMessageKey(messageKey: Uint8Array): {
  key: Uint8Array;
  nonce: Uint8Array;
} {
  const out = kdf(messageKey, undefined, INFO.messageKey, AEAD_KEY_BYTES + AEAD_NONCE_BYTES);
  return {
    key: out.slice(0, AEAD_KEY_BYTES),
    nonce: out.slice(AEAD_KEY_BYTES, AEAD_KEY_BYTES + AEAD_NONCE_BYTES),
  };
}

/**
 * Derive the two shared header keys both sides need before the first ratchet
 * step, from the handshake's shared secret.
 */
export function deriveSharedHeaderKeys(sharedSecret: Uint8Array): {
  initiatorHeaderKey: Uint8Array;
  responderNextHeaderKey: Uint8Array;
} {
  const out = kdf(sharedSecret, undefined, INFO.headerKeys, 64);
  return {
    initiatorHeaderKey: out.slice(0, 32),
    responderNextHeaderKey: out.slice(32, 64),
  };
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/** The side that sent the first message (Alice in the spec). */
export function initInitiator(
  sharedSecret: Uint8Array,
  responderRatchetKey: Uint8Array,
): RatchetState {
  const { initiatorHeaderKey, responderNextHeaderKey } = deriveSharedHeaderKeys(sharedSecret);
  const sending = generateDhKeyPair();
  const step = kdfRootKey(sharedSecret, dh(sending.secretKey, responderRatchetKey));

  return {
    sending,
    receiving: responderRatchetKey,
    rootKey: step.rootKey,
    sendingChain: step.chainKey,
    receivingChain: null,
    sentCount: 0,
    receivedCount: 0,
    previousChainLength: 0,
    headerKeySending: initiatorHeaderKey,
    headerKeyReceiving: null,
    nextHeaderKeySending: step.nextHeaderKey,
    nextHeaderKeyReceiving: responderNextHeaderKey,
    skipped: new Map(),
  };
}

/** The side that published the prekey bundle (Bob in the spec). */
export function initResponder(
  sharedSecret: Uint8Array,
  ownRatchetKeyPair: KeyPair,
): RatchetState {
  const { initiatorHeaderKey, responderNextHeaderKey } = deriveSharedHeaderKeys(sharedSecret);
  return {
    sending: ownRatchetKeyPair,
    receiving: null,
    rootKey: sharedSecret,
    sendingChain: null,
    receivingChain: null,
    sentCount: 0,
    receivedCount: 0,
    previousChainLength: 0,
    headerKeySending: null,
    headerKeyReceiving: null,
    nextHeaderKeySending: responderNextHeaderKey,
    nextHeaderKeyReceiving: initiatorHeaderKey,
    skipped: new Map(),
  };
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt
// ---------------------------------------------------------------------------

function encodeHeader(h: RatchetHeader): Uint8Array {
  return concat(h.ratchetKey, u32(h.previousChainLength), u32(h.messageNumber));
}

function decodeHeader(bytes: Uint8Array): RatchetHeader | null {
  if (bytes.length !== HEADER_BYTES) return null;
  return {
    ratchetKey: bytes.slice(0, 32),
    previousChainLength: readU32(bytes, 32),
    messageNumber: readU32(bytes, 36),
  };
}

export function encrypt(
  state: RatchetState,
  plaintext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0),
): RatchetMessage {
  // The bound used to be enforced from the receive path alone, so a session
  // that only sent kept its cache for as long as the other side stayed quiet
  // — and docs/PROTOCOL.md §3 is a claim about how long a stolen device is
  // worth reading. Sending is activity too.
  pruneSkipped(state);
  if (!state.sendingChain || !state.headerKeySending) {
    throw new Error('Tildra: cannot send before the first ratchet step completes');
  }

  const step = kdfChainKey(state.sendingChain);
  wipe(state.sendingChain);
  state.sendingChain = step.chainKey;

  const header = encodeHeader({
    ratchetKey: state.sending.publicKey,
    previousChainLength: state.previousChainLength,
    messageNumber: state.sentCount,
  });
  const encryptedHeader = seal(state.headerKeySending, header);

  // The nonce is derived alongside the key, so it is never transmitted. The
  // encrypted header is authenticated as associated data, so a body cannot be
  // moved onto a different header.
  const { key, nonce } = expandMessageKey(step.messageKey);
  const body = aeadEncrypt(key, nonce, plaintext, concat(associatedData, encryptedHeader));

  wipe(step.messageKey, key);
  state.sentCount += 1;

  return { header: encryptedHeader, body };
}

export function decrypt(
  state: RatchetState,
  message: RatchetMessage,
  associatedData: Uint8Array = new Uint8Array(0),
): Uint8Array {
  // Pruning also happens inside skipMessageKeys, which every decrypt reaches;
  // this is here so the bound does not depend on that being true tomorrow.
  pruneSkipped(state);

  const fromSkipped = trySkippedKeys(state, message, associatedData);
  if (fromSkipped) return fromSkipped;

  const decrypted = decryptHeader(state, message.header);
  if (!decrypted) {
    throw new Error('Tildra: message header failed to decrypt (wrong session or tampered)');
  }
  const { header, needsRatchet } = decrypted;

  if (needsRatchet) {
    skipMessageKeys(state, header.previousChainLength);
    dhRatchet(state, header);
  }
  skipMessageKeys(state, header.messageNumber);

  if (!state.receivingChain) {
    throw new Error('Tildra: no receiving chain established');
  }
  const step = kdfChainKey(state.receivingChain);
  wipe(state.receivingChain);
  state.receivingChain = step.chainKey;
  state.receivedCount += 1;

  const plaintext = decryptBody(step.messageKey, message, associatedData);
  wipe(step.messageKey);
  if (!plaintext) {
    throw new Error('Tildra: message body failed to authenticate');
  }
  return plaintext;
}

function decryptBody(
  messageKey: Uint8Array,
  message: RatchetMessage,
  associatedData: Uint8Array,
): Uint8Array | null {
  const { key, nonce } = expandMessageKey(messageKey);
  const out = aeadDecrypt(key, nonce, message.body, concat(associatedData, message.header));
  wipe(key);
  return out;
}

/**
 * Try the current and next header keys. Which one works tells us whether the
 * sender has stepped the DH ratchet — that is the entire purpose of keeping
 * two header keys around.
 */
function decryptHeader(
  state: RatchetState,
  encryptedHeader: Uint8Array,
): { header: RatchetHeader; needsRatchet: boolean } | null {
  if (state.headerKeyReceiving) {
    const plain = open(state.headerKeyReceiving, encryptedHeader);
    if (plain) {
      const header = decodeHeader(plain);
      if (header) return { header, needsRatchet: false };
    }
  }
  const plain = open(state.nextHeaderKeyReceiving, encryptedHeader);
  if (plain) {
    const header = decodeHeader(plain);
    if (header) return { header, needsRatchet: true };
  }
  return null;
}

function dhRatchet(state: RatchetState, header: RatchetHeader): void {
  state.previousChainLength = state.sentCount;
  state.sentCount = 0;
  state.receivedCount = 0;
  state.headerKeySending = state.nextHeaderKeySending;
  state.headerKeyReceiving = state.nextHeaderKeyReceiving;
  state.receiving = header.ratchetKey;

  const incoming = kdfRootKey(state.rootKey, dh(state.sending.secretKey, state.receiving));
  wipe(state.rootKey);
  state.rootKey = incoming.rootKey;
  state.receivingChain = incoming.chainKey;
  state.nextHeaderKeyReceiving = incoming.nextHeaderKey;

  // New ratchet key pair, then a second root step for the sending side. This
  // is what gives post-compromise security: an attacker who does not observe
  // this new private key loses the session from here on.
  wipe(state.sending.secretKey);
  state.sending = generateDhKeyPair();
  const outgoing = kdfRootKey(state.rootKey, dh(state.sending.secretKey, state.receiving));
  wipe(state.rootKey);
  state.rootKey = outgoing.rootKey;
  state.sendingChain = outgoing.chainKey;
  state.nextHeaderKeySending = outgoing.nextHeaderKey;
}

function skippedKeyId(headerKey: Uint8Array, messageNumber: number): string {
  return `${toBase64(headerKey)}:${messageNumber}`;
}

/**
 * Derive and cache the keys for messages that arrived out of order. Bounded in
 * both count and age — an unbounded cache is a memory-exhaustion vector and
 * keeps old message keys recoverable long after they should be gone.
 */
function skipMessageKeys(state: RatchetState, until: number): void {
  if (state.receivedCount + MAX_SKIP < until) {
    throw new Error(`Tildra: refusing to skip more than ${MAX_SKIP} messages`);
  }
  if (!state.receivingChain || !state.headerKeyReceiving) return;

  while (state.receivedCount < until) {
    const step = kdfChainKey(state.receivingChain);
    wipe(state.receivingChain);
    state.receivingChain = step.chainKey;
    state.skipped.set(skippedKeyId(state.headerKeyReceiving, state.receivedCount), {
      messageKey: step.messageKey,
      storedAt: Date.now(),
    });
    state.receivedCount += 1;
  }
  pruneSkipped(state);
}

function pruneSkipped(state: RatchetState): void {
  const cutoff = Date.now() - SKIPPED_KEY_TTL_MS;
  for (const [id, entry] of state.skipped) {
    if (entry.storedAt < cutoff) {
      wipe(entry.messageKey);
      state.skipped.delete(id);
    }
  }
  // Map iteration is insertion-ordered, so this evicts oldest-first.
  while (state.skipped.size > MAX_SKIPPED_KEYS) {
    const oldest = state.skipped.keys().next();
    if (oldest.done) break;
    wipe(state.skipped.get(oldest.value)?.messageKey);
    state.skipped.delete(oldest.value);
  }
}

function trySkippedKeys(
  state: RatchetState,
  message: RatchetMessage,
  associatedData: Uint8Array,
): Uint8Array | null {
  for (const [id, entry] of state.skipped) {
    const headerKey = id.slice(0, id.lastIndexOf(':'));
    const plainHeader = open(fromBase64Cached(headerKey), message.header);
    if (!plainHeader) continue;
    const header = decodeHeader(plainHeader);
    if (!header || `${headerKey}:${header.messageNumber}` !== id) continue;

    const plaintext = decryptBody(entry.messageKey, message, associatedData);
    if (!plaintext) continue;
    wipe(entry.messageKey);
    state.skipped.delete(id);
    return plaintext;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/**
 * Serialised ratchet state.
 *
 * This is the most sensitive structure the app writes to disk — it contains
 * live chain keys. It is only ever stored through the vault, never raw. The
 * shape is versioned so a future protocol change can migrate rather than
 * silently misread old rows.
 */
export interface SerializedRatchet {
  v: 1;
  sendingPublic: string;
  sendingSecret: string;
  receiving: string | null;
  rootKey: string;
  sendingChain: string | null;
  receivingChain: string | null;
  sentCount: number;
  receivedCount: number;
  previousChainLength: number;
  headerKeySending: string | null;
  headerKeyReceiving: string | null;
  nextHeaderKeySending: string;
  nextHeaderKeyReceiving: string;
  skipped: [string, { messageKey: string; storedAt: number }][];
}

export function serializeRatchet(state: RatchetState): SerializedRatchet {
  return {
    v: 1,
    sendingPublic: toBase64(state.sending.publicKey),
    sendingSecret: toBase64(state.sending.secretKey),
    receiving: state.receiving ? toBase64(state.receiving) : null,
    rootKey: toBase64(state.rootKey),
    sendingChain: state.sendingChain ? toBase64(state.sendingChain) : null,
    receivingChain: state.receivingChain ? toBase64(state.receivingChain) : null,
    sentCount: state.sentCount,
    receivedCount: state.receivedCount,
    previousChainLength: state.previousChainLength,
    headerKeySending: state.headerKeySending ? toBase64(state.headerKeySending) : null,
    headerKeyReceiving: state.headerKeyReceiving ? toBase64(state.headerKeyReceiving) : null,
    nextHeaderKeySending: toBase64(state.nextHeaderKeySending),
    nextHeaderKeyReceiving: toBase64(state.nextHeaderKeyReceiving),
    skipped: [...state.skipped].map(([id, entry]) => [
      id,
      { messageKey: toBase64(entry.messageKey), storedAt: entry.storedAt },
    ]),
  };
}

export function deserializeRatchet(data: SerializedRatchet): RatchetState {
  if (data.v !== 1) {
    throw new Error(`Tildra: unsupported ratchet state version ${data.v}`);
  }
  return {
    sending: { publicKey: fromBase64(data.sendingPublic), secretKey: fromBase64(data.sendingSecret) },
    receiving: data.receiving ? fromBase64(data.receiving) : null,
    rootKey: fromBase64(data.rootKey),
    sendingChain: data.sendingChain ? fromBase64(data.sendingChain) : null,
    receivingChain: data.receivingChain ? fromBase64(data.receivingChain) : null,
    sentCount: data.sentCount,
    receivedCount: data.receivedCount,
    previousChainLength: data.previousChainLength,
    headerKeySending: data.headerKeySending ? fromBase64(data.headerKeySending) : null,
    headerKeyReceiving: data.headerKeyReceiving ? fromBase64(data.headerKeyReceiving) : null,
    nextHeaderKeySending: fromBase64(data.nextHeaderKeySending),
    nextHeaderKeyReceiving: fromBase64(data.nextHeaderKeyReceiving),
    skipped: new Map(
      data.skipped.map(([id, entry]) => [
        id,
        { messageKey: fromBase64(entry.messageKey), storedAt: entry.storedAt },
      ]),
    ),
  };
}

// Decoding the same handful of header keys on every out-of-order message adds
// up when a client drains a large backlog, so the results are memoised.
const base64Cache = new Map<string, Uint8Array>();
function fromBase64Cached(s: string): Uint8Array {
  let v = base64Cache.get(s);
  if (!v) {
    v = fromBase64(s);
    if (base64Cache.size > 4096) base64Cache.clear();
    base64Cache.set(s, v);
  }
  return v;
}
