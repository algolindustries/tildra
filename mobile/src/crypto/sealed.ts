/**
 * Sealed sender — docs/PROTOCOL.md §5.
 *
 * The server sees a mailbox ID and a blob. Who sent the message is inside the
 * blob, encrypted to the recipient's identity key. This is what stops the
 * server from reconstructing the social graph even though it routes every
 * message.
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
  open,
  seal,
  u32,
  utf8,
  wipe,
  fromUtf8,
  readU32,
} from './primitives';
import { RatchetMessage } from './ratchet';
import { SessionInit } from './pqxdh';
import { frame, pad, unframe, unpad } from './wire';

const VERSION = 1;

export interface SealedContent {
  senderAccountId: string;
  senderDeviceId: string;
  senderIdentityKey: Uint8Array;
  /** Present only on the first message of a session. */
  sessionInit?: SessionInit;
  message: RatchetMessage;
}

/**
 * Encrypt an envelope to a recipient identity key.
 *
 * Uses an ephemeral X25519 key per envelope, so two envelopes to the same
 * recipient are unlinkable to anyone but that recipient.
 */
export function sealEnvelope(
  recipientIdentityKey: Uint8Array,
  content: SealedContent,
): Uint8Array {
  const ephemeral = generateDhKeyPair();
  const recipientDh = identityToDhPublic(recipientIdentityKey);
  const shared = dh(ephemeral.secretKey, recipientDh);

  // Binding the ephemeral and recipient public keys into the salt stops an
  // attacker from replaying a captured shared secret against a different pair.
  const key = kdf(shared, concat(ephemeral.publicKey, recipientDh), INFO.sealedSender, 32);
  const payload = pad(encodeContent(content));
  const ciphertext = seal(key, payload, ephemeral.publicKey);

  wipe(shared, key, ephemeral.secretKey);
  return concat(new Uint8Array([VERSION]), ephemeral.publicKey, ciphertext);
}

export class SealedEnvelopeError extends Error {}

/** Decrypt an envelope addressed to us. */
export function openEnvelope(identity: KeyPair, envelope: Uint8Array): SealedContent {
  if (envelope.length < 1 + 32) {
    throw new SealedEnvelopeError('envelope is too short');
  }
  if (envelope[0] !== VERSION) {
    throw new SealedEnvelopeError(`unsupported envelope version ${envelope[0]}`);
  }
  const ephemeralPublic = envelope.slice(1, 33);
  const ciphertext = envelope.slice(33);

  const ourDhSecret = identityToDhSecret(identity.secretKey);
  const ourDhPublic = identityToDhPublic(identity.publicKey);
  const shared = dh(ourDhSecret, ephemeralPublic);
  const key = kdf(shared, concat(ephemeralPublic, ourDhPublic), INFO.sealedSender, 32);

  const payload = open(key, ciphertext, ephemeralPublic);
  wipe(shared, key, ourDhSecret);

  if (!payload) {
    // Either not addressed to us, or tampered with. We cannot tell which, and
    // it does not matter — both mean "drop it".
    throw new SealedEnvelopeError('envelope failed to authenticate');
  }
  return decodeContent(unpad(payload));
}

// ---------------------------------------------------------------------------
// Content encoding
// ---------------------------------------------------------------------------

function encodeContent(c: SealedContent): Uint8Array {
  return frame(
    utf8(c.senderAccountId),
    utf8(c.senderDeviceId),
    c.senderIdentityKey,
    c.sessionInit ? encodeSessionInit(c.sessionInit) : new Uint8Array(0),
    c.message.header,
    c.message.body,
  );
}

function decodeContent(data: Uint8Array): SealedContent {
  const [accountId, deviceId, identityKey, sessionInit, header, body] = unframe(data, 6);
  return {
    senderAccountId: fromUtf8(accountId),
    senderDeviceId: fromUtf8(deviceId),
    senderIdentityKey: identityKey,
    sessionInit: sessionInit.length > 0 ? decodeSessionInit(sessionInit) : undefined,
    message: { header, body },
  };
}

/**
 * The one-time prekey ID is optional, so it is encoded as a presence flag plus
 * a value rather than a sentinel — sentinels in wire formats become bugs the
 * first time a legitimate value collides with them.
 */
function encodeSessionInit(init: SessionInit): Uint8Array {
  const flags = new Uint8Array([
    init.usedOneTimePq ? 1 : 0,
    init.oneTimePreKeyId !== undefined ? 1 : 0,
  ]);
  return frame(
    flags,
    init.identityKey,
    init.ephemeralKey,
    init.kemCiphertext,
    u32(init.signedPreKeyId),
    u32(init.pqPreKeyId),
    u32(init.oneTimePreKeyId ?? 0),
  );
}

function decodeSessionInit(data: Uint8Array): SessionInit {
  const [flags, identityKey, ephemeralKey, kemCiphertext, spkId, pqId, otpkId] = unframe(data, 7);
  if (flags.length !== 2) {
    throw new SealedEnvelopeError('malformed session init flags');
  }
  return {
    identityKey,
    ephemeralKey,
    kemCiphertext,
    signedPreKeyId: readU32(spkId, 0),
    pqPreKeyId: readU32(pqId, 0),
    oneTimePreKeyId: flags[1] === 1 ? readU32(otpkId, 0) : undefined,
    usedOneTimePq: flags[0] === 1,
  };
}
