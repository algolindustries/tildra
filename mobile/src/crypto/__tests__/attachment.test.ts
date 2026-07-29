import { describe, expect, it } from 'vitest';

import {
  AttachmentError,
  decryptAttachment,
  deserializeAttachmentRef,
  encryptAttachment,
  serializeAttachmentRef,
} from '../attachment';
import { equal, randomBytes, utf8 } from '../primitives';
import { bucketSize } from '../wire';

describe('attachment encryption', () => {
  it('round-trips a file', () => {
    const file = randomBytes(5000);
    const { ciphertext, key } = encryptAttachment(file);
    expect(equal(decryptAttachment(ciphertext, key), file)).toBe(true);
  });

  it('round-trips an empty file', () => {
    const { ciphertext, key } = encryptAttachment(new Uint8Array(0));
    expect(decryptAttachment(ciphertext, key)).toHaveLength(0);
  });

  it('pads to a size bucket so the file length does not leak', () => {
    // Two files of different sizes in the same bucket must produce ciphertext
    // of identical length. File size alone identifies a lot: a specific photo,
    // whether a voice note was two seconds or two minutes.
    const small = encryptAttachment(randomBytes(300));
    const larger = encryptAttachment(randomBytes(900));
    expect(small.ciphertext.length).toBe(larger.ciphertext.length);
    expect(small.ciphertext.length).toBeGreaterThan(bucketSize(900));
  });

  it('recovers the exact plaintext length despite padding', () => {
    for (const size of [1, 255, 256, 1000, 40_000]) {
      const file = randomBytes(size);
      const { ciphertext, key } = encryptAttachment(file);
      const out = decryptAttachment(ciphertext, key);
      expect(out.length).toBe(size);
      expect(equal(out, file)).toBe(true);
    }
  });

  it('uses a fresh key for every attachment', () => {
    const file = utf8('the same file twice');
    const a = encryptAttachment(file);
    const b = encryptAttachment(file);

    expect(equal(a.key.key, b.key.key)).toBe(false);
    expect(equal(a.key.nonce, b.key.nonce)).toBe(false);
    expect(equal(a.ciphertext, b.ciphertext)).toBe(false);
  });

  it('rejects a substituted blob before decrypting it', () => {
    const { key } = encryptAttachment(randomBytes(1000));
    const other = encryptAttachment(randomBytes(1000));

    expect(() => decryptAttachment(other.ciphertext, key)).toThrow(/digest/);
  });

  it('rejects a tampered blob', () => {
    const { ciphertext, key } = encryptAttachment(randomBytes(1000));
    ciphertext[10] ^= 0xff;
    expect(() => decryptAttachment(ciphertext, key)).toThrow(AttachmentError);
  });

  it('rejects a correct blob under the wrong key', () => {
    const { ciphertext, key } = encryptAttachment(randomBytes(1000));
    const other = encryptAttachment(randomBytes(1000));
    expect(() =>
      decryptAttachment(ciphertext, { ...other.key, digest: key.digest }),
    ).toThrow(/authenticate/);
  });

  it('rejects a reference claiming a size larger than the plaintext', () => {
    // Otherwise a hostile reference could make the client read past the end of
    // what was actually sent.
    const { ciphertext, key } = encryptAttachment(randomBytes(100));
    expect(() => decryptAttachment(ciphertext, { ...key, size: 999_999 })).toThrow(/larger/);
  });
});

describe('attachment references', () => {
  it('round-trips through the wire form', () => {
    const { key } = encryptAttachment(randomBytes(500));
    const ref = { ...key, id: 'ATT1', mimeType: 'image/jpeg', width: 800, height: 600 };

    const revived = deserializeAttachmentRef(
      JSON.parse(JSON.stringify(serializeAttachmentRef(ref))),
    );

    expect(revived.id).toBe('ATT1');
    expect(revived.mimeType).toBe('image/jpeg');
    expect(revived.width).toBe(800);
    expect(equal(revived.key, ref.key)).toBe(true);
    expect(equal(revived.digest, ref.digest)).toBe(true);
    expect(revived.size).toBe(ref.size);
  });

  it('rejects malformed key material', () => {
    const { key } = encryptAttachment(randomBytes(10));
    const good = serializeAttachmentRef({ ...key, id: 'A', mimeType: 'image/png' });

    expect(() => deserializeAttachmentRef({ ...good, key: 'AAAA' })).toThrow(/key material/);
    expect(() => deserializeAttachmentRef({ ...good, nonce: 'AAAA' })).toThrow(/key material/);
    expect(() => deserializeAttachmentRef({ ...good, digest: 'AAAA' })).toThrow(/digest/);
    expect(() => deserializeAttachmentRef({ ...good, size: -1 })).toThrow(/size/);
  });

  it('keeps the decryption key out of anything the server sees', () => {
    // The blob is what gets uploaded; the key must not be derivable from it.
    const file = utf8('sensitive');
    const { ciphertext, key } = encryptAttachment(file);

    const haystack = Array.from(ciphertext).join(',');
    expect(haystack).not.toContain(Array.from(key.key).join(','));
    expect(haystack).not.toContain(Array.from(key.nonce).join(','));
  });
});
