import { describe, expect, it } from 'vitest';

import {
  AttachmentError,
  decryptAttachment,
  deserializeAttachmentRef,
  encryptAttachment,
  serializeAttachmentRef,
} from '../attachment';
import { equal, randomBytes, toBase64, utf8 } from '../primitives';
import { bucketSize } from '../wire';
// The encoder lives outside crypto/ and the bound that has to match it lives
// inside. Importing both here is what stops them drifting apart again.
import { WAVEFORM_BUCKETS, WAVEFORM_MAX, buildWaveform } from '../../media/waveform';

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

describe('voice metadata', () => {
  it('round-trips duration and waveform', () => {
    const { key } = encryptAttachment(randomBytes(500));
    const waveform = new Uint8Array([0, 5, 15, 9, 2]);
    const ref = { ...key, id: 'V1', mimeType: 'audio/m4a', durationMs: 4200, waveform };

    const revived = deserializeAttachmentRef(
      JSON.parse(JSON.stringify(serializeAttachmentRef(ref))),
    );
    expect(revived.durationMs).toBe(4200);
    expect(equal(revived.waveform!, waveform)).toBe(true);
  });

  it('leaves them undefined for a non-voice attachment', () => {
    const { key } = encryptAttachment(randomBytes(100));
    const revived = deserializeAttachmentRef(
      serializeAttachmentRef({ ...key, id: 'P1', mimeType: 'image/jpeg' }),
    );
    expect(revived.durationMs).toBeUndefined();
    expect(revived.waveform).toBeUndefined();
  });

  it('rejects a hostile duration or waveform', () => {
    // These come from the sender and are rendered directly, so they are
    // bounded on receipt rather than trusted.
    const { key } = encryptAttachment(randomBytes(10));
    const good = serializeAttachmentRef({ ...key, id: 'V', mimeType: 'audio/m4a' });

    expect(() =>
      deserializeAttachmentRef({ ...good, waveform: toBase64(new Uint8Array(500)) }),
    ).toThrow(/waveform/);
    expect(() => deserializeAttachmentRef({ ...good, durationMs: -1 })).toThrow(/duration/);
    expect(() => deserializeAttachmentRef({ ...good, durationMs: 1e12 })).toThrow(/duration/);
  });

  it('rejects a bar louder than a bar can be', () => {
    // The length was bounded and the values were not, and the value is the one
    // that is rendered: each bar becomes a fraction of the bubble's height, so
    // a byte above the documented four bits is a bar taller than the bubble,
    // drawn over the conversation by whoever sent the message.
    const { key } = encryptAttachment(randomBytes(10));
    const good = serializeAttachmentRef({ ...key, id: 'V', mimeType: 'audio/m4a' });

    expect(() =>
      deserializeAttachmentRef({ ...good, waveform: toBase64(new Uint8Array([0, 8, 16])) }),
    ).toThrow(/waveform bar/);
    expect(() =>
      deserializeAttachmentRef({ ...good, waveform: toBase64(new Uint8Array([255])) }),
    ).toThrow(/waveform bar/);
  });

  it('accepts exactly what the encoder produces', () => {
    // The bound and the encoder are declared in different modules, which is how
    // the last one drifted. This fails if either moves without the other.
    const { key } = encryptAttachment(randomBytes(10));
    const good = serializeAttachmentRef({ ...key, id: 'V', mimeType: 'audio/m4a' });

    const loudest = buildWaveform(new Array(WAVEFORM_BUCKETS * 4).fill(1));
    expect(loudest).toHaveLength(WAVEFORM_BUCKETS);
    expect(Math.max(...loudest)).toBe(WAVEFORM_MAX);

    const revived = deserializeAttachmentRef({ ...good, waveform: toBase64(loudest) });
    expect(equal(revived.waveform!, loudest)).toBe(true);
  });
});
