/**
 * Attachment encryption.
 *
 * A file gets its own key, generated per attachment and never reused. The
 * ciphertext goes to the server, which sees an opaque blob and a size; the key
 * and a digest travel inside the message that references it, encrypted with
 * everything else. The server therefore cannot decrypt an attachment even if
 * it keeps every blob it ever received.
 *
 * The digest is over the *ciphertext*, so it can be checked before decryption
 * — a corrupted or substituted download is rejected without feeding attacker
 * bytes to the AEAD at all.
 */

import {
  AEAD_KEY_BYTES,
  aeadDecrypt,
  aeadEncrypt,
  concat,
  equal,
  hash,
  randomBytes,
  toBase64,
  fromBase64,
  utf8,
  wipe,
} from './primitives';
import { bucketSize } from './wire';

export class AttachmentError extends Error {}

/** What the sender learns after encrypting, and what the message must carry. */
export interface AttachmentKey {
  key: Uint8Array;
  nonce: Uint8Array;
  /** SHA-256 of the ciphertext, checked before decryption. */
  digest: Uint8Array;
  /** Plaintext length, so padding can be removed exactly. */
  size: number;
}

/** The reference a message carries once the blob is uploaded. */
export interface AttachmentRef extends AttachmentKey {
  id: string;
  mimeType: string;
  fileName?: string;
  width?: number;
  height?: number;
}

/** Nonce is 24 bytes for XChaCha20; random is safe at that width. */
const NONCE_BYTES = 24;

/**
 * Encrypt a file.
 *
 * The plaintext is padded to a size bucket first. Without it the encrypted
 * length is the file's length, and file size alone identifies a surprising
 * amount — a specific photo, a specific document, whether a voice note was two
 * seconds or two minutes.
 */
export function encryptAttachment(plaintext: Uint8Array): {
  ciphertext: Uint8Array;
  key: AttachmentKey;
} {
  const key = randomBytes(AEAD_KEY_BYTES);
  const nonce = randomBytes(NONCE_BYTES);

  const padded = padTo(plaintext, bucketSize(plaintext.length));
  const ciphertext = aeadEncrypt(key, nonce, padded, utf8('Tildra_Attachment_v1'));
  wipe(padded);

  return {
    ciphertext,
    key: { key, nonce, digest: hash(ciphertext), size: plaintext.length },
  };
}

export function decryptAttachment(ciphertext: Uint8Array, key: AttachmentKey): Uint8Array {
  // Digest first. A substituted blob is rejected here, before its bytes reach
  // the cipher.
  if (!equal(hash(ciphertext), key.digest)) {
    throw new AttachmentError('attachment digest does not match; the download was altered');
  }

  const padded = aeadDecrypt(key.key, key.nonce, ciphertext, utf8('Tildra_Attachment_v1'));
  if (!padded) {
    throw new AttachmentError('attachment failed to authenticate');
  }
  if (key.size > padded.length) {
    throw new AttachmentError('attachment claims to be larger than its plaintext');
  }
  return padded.slice(0, key.size);
}

/**
 * Pad with random bytes rather than zeros.
 *
 * Zero padding is fine for confidentiality here — it is inside the AEAD — but
 * random padding keeps the plaintext free of long predictable runs, which
 * costs nothing and removes a class of assumptions.
 */
function padTo(payload: Uint8Array, target: number): Uint8Array {
  if (target <= payload.length) return payload.slice();
  return concat(payload, randomBytes(target - payload.length));
}

// ---------------------------------------------------------------------------
// Wire form
// ---------------------------------------------------------------------------

export interface SerializedAttachmentRef {
  id: string;
  key: string;
  nonce: string;
  digest: string;
  size: number;
  mimeType: string;
  fileName?: string;
  width?: number;
  height?: number;
}

export function serializeAttachmentRef(ref: AttachmentRef): SerializedAttachmentRef {
  return {
    id: ref.id,
    key: toBase64(ref.key),
    nonce: toBase64(ref.nonce),
    digest: toBase64(ref.digest),
    size: ref.size,
    mimeType: ref.mimeType,
    fileName: ref.fileName,
    width: ref.width,
    height: ref.height,
  };
}

export function deserializeAttachmentRef(data: SerializedAttachmentRef): AttachmentRef {
  const ref: AttachmentRef = {
    id: data.id,
    key: fromBase64(data.key),
    nonce: fromBase64(data.nonce),
    digest: fromBase64(data.digest),
    size: data.size,
    mimeType: data.mimeType,
    fileName: data.fileName,
    width: data.width,
    height: data.height,
  };
  if (ref.key.length !== AEAD_KEY_BYTES || ref.nonce.length !== NONCE_BYTES) {
    throw new AttachmentError('attachment reference has malformed key material');
  }
  if (ref.digest.length !== 32) {
    throw new AttachmentError('attachment reference has a malformed digest');
  }
  if (!Number.isInteger(ref.size) || ref.size < 0) {
    throw new AttachmentError('attachment reference has an invalid size');
  }
  return ref;
}
