import { describe, expect, it } from 'vitest';

import {
  SIG_CONTEXT,
  concat,
  equal,
  fromBase64,
  fromUtf8,
  generateDhKeyPair,
  generateSigningKeyPair,
  randomBytes,
  sign,
  toBase64,
  utf8,
  verify,
} from '../primitives';
import {
  MAX_SKIP,
  RatchetState,
  decrypt,
  encrypt,
  initInitiator,
  initResponder,
} from '../ratchet';
import { acceptSession, initiateSession, PreKeyBundle, verifyBundle } from '../pqxdh';
import { generateIdentity, generatePreKeys, registrationProof } from '../identity';
import { openEnvelope, sealEnvelope, SealedEnvelopeError } from '../sealed';
import { safetyNumber, safetyQrPayload, verifyQrPayload } from '../safety';
import { currentMailboxes, dayNumber, deliveryMailbox, mailboxFor } from '../mailbox';
import { bucketSize, frame, pad, unframe, unpad } from '../wire';

/** Build the bundle the server would publish from a device's generated keys. */
function bundleFrom(
  identity: ReturnType<typeof generateIdentity>,
  upload: ReturnType<typeof generatePreKeys>['upload'],
  opts: { withOneTime?: boolean; oneTimeIndex?: number } = {},
): PreKeyBundle {
  const withOneTime = opts.withOneTime ?? true;
  // The server pops a distinct one-time key per bundle it hands out; the
  // index mirrors that so two callers never receive the same key.
  const i = opts.oneTimeIndex ?? 0;
  return {
    accountId: 'ACCT',
    deviceId: 'DEV',
    identityKey: fromBase64(upload.identityKey),
    signedPreKey: {
      id: upload.signedPreKey.id,
      publicKey: fromBase64(upload.signedPreKey.publicKey),
      signature: fromBase64(upload.signedPreKey.signature),
    },
    signedPqPreKey: {
      id: upload.signedPqPreKey.id,
      publicKey: fromBase64(upload.signedPqPreKey.publicKey),
      signature: fromBase64(upload.signedPqPreKey.signature),
    },
    oneTimePreKey: withOneTime
      ? {
          id: upload.oneTimePreKeys[i].id,
          publicKey: fromBase64(upload.oneTimePreKeys[i].publicKey),
        }
      : undefined,
    oneTimePqPreKey: withOneTime
      ? {
          id: upload.oneTimePqPreKeys[i].id,
          publicKey: fromBase64(upload.oneTimePqPreKeys[i].publicKey),
        }
      : undefined,
  };
}

/** A pair of ratchets sharing a secret, as PQXDH would leave them. */
function ratchetPair(): { alice: RatchetState; bob: RatchetState } {
  const shared = randomBytes(32);
  const bobKeys = generateDhKeyPair();
  return {
    alice: initInitiator(shared, bobKeys.publicKey),
    bob: initResponder(shared, bobKeys),
  };
}

describe('primitives', () => {
  it('round-trips base64 and utf8', () => {
    const bytes = randomBytes(64);
    expect(equal(fromBase64(toBase64(bytes)), bytes)).toBe(true);
    expect(fromUtf8(utf8('merhaba dünya 🌍'))).toBe('merhaba dünya 🌍');
  });

  it('verifies its own signatures and rejects tampered ones', () => {
    const kp = generateSigningKeyPair();
    const msg = utf8('the quick brown fox');
    const sig = sign(kp.secretKey, msg);

    expect(verify(kp.publicKey, msg, sig)).toBe(true);

    const tampered = sig.slice();
    tampered[0] ^= 0xff;
    expect(verify(kp.publicKey, msg, tampered)).toBe(false);
    expect(verify(kp.publicKey, utf8('a different message'), sig)).toBe(false);
    expect(verify(generateSigningKeyPair().publicKey, msg, sig)).toBe(false);
  });

  it('returns false rather than throwing on malformed input', () => {
    expect(verify(new Uint8Array(5), utf8('x'), new Uint8Array(64))).toBe(false);
  });

  it('compares in constant time without false positives', () => {
    const a = randomBytes(32);
    expect(equal(a, a.slice())).toBe(true);
    expect(equal(a, randomBytes(32))).toBe(false);
    expect(equal(a, a.slice(0, 31))).toBe(false);
  });
});

describe('wire format', () => {
  it('round-trips framed fields', () => {
    const fields = [utf8('alice'), randomBytes(32), new Uint8Array(0), randomBytes(1000)];
    const decoded = unframe(frame(...fields), 4);
    expect(decoded).toHaveLength(4);
    fields.forEach((f, i) => expect(equal(decoded[i], f)).toBe(true));
  });

  it('rejects truncated and over-long input', () => {
    const framed = frame(utf8('a'), utf8('b'));
    expect(() => unframe(framed.slice(0, framed.length - 1), 2)).toThrow();
    expect(() => unframe(framed, 1)).toThrow(/trailing/);
    expect(() => unframe(framed, 3)).toThrow(/truncated/);
  });

  it('pads to size buckets and recovers the exact payload', () => {
    for (const size of [0, 1, 100, 252, 253, 1000, 5000, 70000]) {
      const payload = randomBytes(size);
      const padded = pad(payload);
      expect(padded.length).toBe(bucketSize(size + 4));
      expect(equal(unpad(padded), payload)).toBe(true);
    }
  });

  it('maps a range of lengths onto the same bucket', () => {
    // This is the property that makes padding worth its bandwidth: two
    // different message lengths must be indistinguishable on the wire.
    expect(bucketSize(300)).toBe(bucketSize(1000));
    expect(bucketSize(5)).toBe(bucketSize(250));
    expect(bucketSize(70000)).toBe(131072);
  });
});

describe('double ratchet', () => {
  it('carries a message from initiator to responder', () => {
    const { alice, bob } = ratchetPair();
    const plaintext = utf8('first message');
    const decrypted = decrypt(bob, encrypt(alice, plaintext));
    expect(fromUtf8(decrypted)).toBe('first message');
  });

  it('ratchets in both directions across many turns', () => {
    const { alice, bob } = ratchetPair();
    for (let round = 0; round < 12; round++) {
      const fromAlice = `alice ${round}`;
      expect(fromUtf8(decrypt(bob, encrypt(alice, utf8(fromAlice))))).toBe(fromAlice);
      const fromBob = `bob ${round}`;
      expect(fromUtf8(decrypt(alice, encrypt(bob, utf8(fromBob))))).toBe(fromBob);
    }
  });

  it('handles a burst in one direction without a reply', () => {
    const { alice, bob } = ratchetPair();
    const sent = Array.from({ length: 25 }, (_, i) => encrypt(alice, utf8(`burst ${i}`)));
    sent.forEach((m, i) => {
      expect(fromUtf8(decrypt(bob, m))).toBe(`burst ${i}`);
    });
  });

  it('decrypts messages that arrive out of order', () => {
    const { alice, bob } = ratchetPair();
    const messages = Array.from({ length: 6 }, (_, i) => encrypt(alice, utf8(`ooo ${i}`)));

    // Deliver 5, 3, 0, 4, 1, 2 — a plausible mobile-network reordering.
    for (const i of [5, 3, 0, 4, 1, 2]) {
      expect(fromUtf8(decrypt(bob, messages[i]))).toBe(`ooo ${i}`);
    }
  });

  it('recovers a message that arrives after the conversation moved on', () => {
    const { alice, bob } = ratchetPair();
    const delayed = encrypt(alice, utf8('delayed'));

    // A full round trip happens first, stepping the DH ratchet past the
    // delayed message's chain.
    expect(fromUtf8(decrypt(bob, encrypt(alice, utf8('arrives first'))))).toBe('arrives first');
    expect(fromUtf8(decrypt(alice, encrypt(bob, utf8('reply'))))).toBe('reply');
    expect(fromUtf8(decrypt(bob, encrypt(alice, utf8('after reply'))))).toBe('after reply');

    expect(fromUtf8(decrypt(bob, delayed))).toBe('delayed');
  });

  it('rejects a tampered body', () => {
    const { alice, bob } = ratchetPair();
    const message = encrypt(alice, utf8('authentic'));
    message.body[0] ^= 0xff;
    expect(() => decrypt(bob, message)).toThrow(/authenticate/);
  });

  it('rejects a tampered header', () => {
    const { alice, bob } = ratchetPair();
    const message = encrypt(alice, utf8('authentic'));
    message.header[30] ^= 0xff;
    expect(() => decrypt(bob, message)).toThrow(/header/);
  });

  it('rejects a body swapped onto another header', () => {
    // Header and body are bound by the AEAD's associated data, so a body
    // cannot be relocated onto a different header without detection.
    const { alice, bob } = ratchetPair();
    const first = encrypt(alice, utf8('one'));
    const second = encrypt(alice, utf8('two'));
    expect(() => decrypt(bob, { header: first.header, body: second.body })).toThrow();
  });

  it('cannot be decrypted by a third party with the same-shaped state', () => {
    const { alice } = ratchetPair();
    const { bob: unrelated } = ratchetPair();
    expect(() => decrypt(unrelated, encrypt(alice, utf8('secret')))).toThrow();
  });

  it('refuses to skip more than MAX_SKIP messages', () => {
    const { alice, bob } = ratchetPair();
    // Advance Alice's chain far past what Bob will tolerate skipping.
    for (let i = 0; i < MAX_SKIP + 2; i++) encrypt(alice, utf8('x'));
    const farAhead = encrypt(alice, utf8('too far'));
    expect(() => decrypt(bob, farAhead)).toThrow(/skip/);
  });

  it('produces different ciphertext for identical plaintext', () => {
    const { alice } = ratchetPair();
    const a = encrypt(alice, utf8('same'));
    const b = encrypt(alice, utf8('same'));
    expect(equal(a.body, b.body)).toBe(false);
    expect(equal(a.header, b.header)).toBe(false);
  });
});

describe('PQXDH session establishment', () => {
  it('establishes a session and exchanges messages both ways', () => {
    const bobIdentity = generateIdentity();
    const { secrets, upload } = generatePreKeys(bobIdentity, { count: 4 });
    const bundle = bundleFrom(bobIdentity, upload);

    const aliceIdentity = generateIdentity();
    const alice = initiateSession(aliceIdentity, bundle);
    const bob = acceptSession(secrets, alice.init);

    expect(equal(alice.associatedData, bob.associatedData)).toBe(true);

    const first = encrypt(alice.ratchet, utf8('hello bob'), alice.associatedData);
    expect(fromUtf8(decrypt(bob.ratchet, first, bob.associatedData))).toBe('hello bob');

    const reply = encrypt(bob.ratchet, utf8('hello alice'), bob.associatedData);
    expect(fromUtf8(decrypt(alice.ratchet, reply, alice.associatedData))).toBe('hello alice');
  });

  it('works without one-time prekeys, degrading to the signed prekey', () => {
    const bobIdentity = generateIdentity();
    const { secrets, upload } = generatePreKeys(bobIdentity, { count: 1 });
    const bundle = bundleFrom(bobIdentity, upload, { withOneTime: false });

    const aliceIdentity = generateIdentity();
    const alice = initiateSession(aliceIdentity, bundle);
    const bob = acceptSession(secrets, alice.init);

    const msg = encrypt(alice.ratchet, utf8('no one-time keys'), alice.associatedData);
    expect(fromUtf8(decrypt(bob.ratchet, msg, bob.associatedData))).toBe('no one-time keys');
  });

  it('consumes one-time prekeys exactly once', () => {
    const bobIdentity = generateIdentity();
    const { secrets, upload } = generatePreKeys(bobIdentity, { count: 2 });
    const bundle = bundleFrom(bobIdentity, upload);

    const alice = initiateSession(generateIdentity(), bundle);
    acceptSession(secrets, alice.init);

    // Replaying the same init must fail: the one-time keys are gone.
    expect(() => acceptSession(secrets, alice.init)).toThrow(/already used/);
  });

  it('rejects a bundle whose signed prekey signature was forged', () => {
    const bobIdentity = generateIdentity();
    const { upload } = generatePreKeys(bobIdentity, { count: 1 });
    const bundle = bundleFrom(bobIdentity, upload);
    bundle.signedPreKey.signature[0] ^= 0xff;

    expect(() => verifyBundle(bundle)).toThrow(/signed prekey/);
    expect(() => initiateSession(generateIdentity(), bundle)).toThrow();
  });

  it('rejects a bundle whose identity key was substituted', () => {
    // This is the server-MITM attack: swap the identity key, keep the rest.
    // The signatures no longer verify under the new key, so it is caught.
    const bobIdentity = generateIdentity();
    const { upload } = generatePreKeys(bobIdentity, { count: 1 });
    const bundle = bundleFrom(bobIdentity, upload);
    bundle.identityKey = generateIdentity().publicKey;

    expect(() => verifyBundle(bundle)).toThrow();
  });

  it('rejects a PQ prekey signature that does not verify', () => {
    const bobIdentity = generateIdentity();
    const { upload } = generatePreKeys(bobIdentity, { count: 1 });
    const bundle = bundleFrom(bobIdentity, upload);
    bundle.signedPqPreKey.signature[10] ^= 0xff;
    expect(() => verifyBundle(bundle)).toThrow(/PQ prekey/);
  });

  it('derives different secrets for different initiators', () => {
    const bobIdentity = generateIdentity();
    const { secrets, upload } = generatePreKeys(bobIdentity, { count: 4 });

    const a = initiateSession(generateIdentity(), bundleFrom(bobIdentity, upload, { oneTimeIndex: 0 }));
    const b = initiateSession(generateIdentity(), bundleFrom(bobIdentity, upload, { oneTimeIndex: 1 }));

    const bobWithA = acceptSession(secrets, a.init);
    const fromA = encrypt(a.ratchet, utf8('from alice'), a.associatedData);
    expect(fromUtf8(decrypt(bobWithA.ratchet, fromA, bobWithA.associatedData))).toBe('from alice');

    // B's session must not decrypt A's traffic.
    const bobWithB = acceptSession(secrets, b.init);
    const fromB = encrypt(b.ratchet, utf8('from carol'), b.associatedData);
    expect(() => decrypt(bobWithA.ratchet, fromB, bobWithA.associatedData)).toThrow();
    expect(fromUtf8(decrypt(bobWithB.ratchet, fromB, bobWithB.associatedData))).toBe('from carol');
  });

  it('keeps the signed prekey usable across concurrent sessions', () => {
    // Regression: the ratchet wipes the key pair it is handed on its first DH
    // step. Passing the signed prekey by reference destroyed it, breaking
    // every other sender who had fetched the same bundle — which, since a
    // signed prekey serves all senders for 48 hours, is most of them.
    const bobIdentity = generateIdentity();
    const { secrets, upload } = generatePreKeys(bobIdentity, { count: 4 });

    const first = initiateSession(generateIdentity(), bundleFrom(bobIdentity, upload, { oneTimeIndex: 0 }));
    const bobWithFirst = acceptSession(secrets, first.init);

    // Drive a full round trip so the responder's DH ratchet actually steps.
    decrypt(bobWithFirst.ratchet, encrypt(first.ratchet, utf8('one'), first.associatedData), bobWithFirst.associatedData);
    decrypt(first.ratchet, encrypt(bobWithFirst.ratchet, utf8('reply'), bobWithFirst.associatedData), first.associatedData);

    // A second sender using the same signed prekey must still work.
    const second = initiateSession(generateIdentity(), bundleFrom(bobIdentity, upload, { oneTimeIndex: 1 }));
    const bobWithSecond = acceptSession(secrets, second.init);
    const msg = encrypt(second.ratchet, utf8('still works'), second.associatedData);
    expect(fromUtf8(decrypt(bobWithSecond.ratchet, msg, bobWithSecond.associatedData))).toBe('still works');
  });

  it('includes a real ML-KEM-768 ciphertext in the session init', () => {
    // Guards against the hybrid silently degrading to classical-only, which
    // would still pass every functional test above.
    const bobIdentity = generateIdentity();
    const { upload } = generatePreKeys(bobIdentity, { count: 1 });
    const alice = initiateSession(generateIdentity(), bundleFrom(bobIdentity, upload));
    expect(alice.init.kemCiphertext.length).toBe(1088); // ML-KEM-768 ciphertext
    expect(alice.init.kemCiphertext.every((b) => b === 0)).toBe(false);
  });
});

describe('sealed sender', () => {
  const content = (extra: Partial<Parameters<typeof sealEnvelope>[1]> = {}) => ({
    senderAccountId: '0123456789ABCDEFGHJKMNPQRS',
    senderDeviceId: 'DEVICE0123456789ABCDEFGHJK',
    senderIdentityKey: randomBytes(32),
    message: { header: randomBytes(80), body: randomBytes(120) },
    ...extra,
  });

  it('round-trips an envelope to the intended recipient', () => {
    const recipient = generateIdentity();
    const original = content();
    const opened = openEnvelope(recipient, sealEnvelope(recipient.publicKey, original));

    expect(opened.senderAccountId).toBe(original.senderAccountId);
    expect(opened.senderDeviceId).toBe(original.senderDeviceId);
    expect(equal(opened.senderIdentityKey, original.senderIdentityKey)).toBe(true);
    expect(equal(opened.message!.header, original.message.header)).toBe(true);
    expect(equal(opened.message!.body, original.message.body)).toBe(true);
    expect(opened.sessionInit).toBeUndefined();
  });

  it('carries a session init when one is present', () => {
    const recipient = generateIdentity();
    const init = {
      identityKey: randomBytes(32),
      ephemeralKey: randomBytes(32),
      kemCiphertext: randomBytes(1088),
      signedPreKeyId: 7,
      pqPreKeyId: 42,
      oneTimePreKeyId: 13,
      usedOneTimePq: true,
    };
    const opened = openEnvelope(
      recipient,
      sealEnvelope(recipient.publicKey, content({ sessionInit: init })),
    );
    expect(opened.sessionInit).toBeDefined();
    expect(opened.sessionInit!.signedPreKeyId).toBe(7);
    expect(opened.sessionInit!.pqPreKeyId).toBe(42);
    expect(opened.sessionInit!.oneTimePreKeyId).toBe(13);
    expect(opened.sessionInit!.usedOneTimePq).toBe(true);
    expect(equal(opened.sessionInit!.kemCiphertext, init.kemCiphertext)).toBe(true);
  });

  it('distinguishes an absent one-time prekey id from id zero', () => {
    const recipient = generateIdentity();
    const init = {
      identityKey: randomBytes(32),
      ephemeralKey: randomBytes(32),
      kemCiphertext: randomBytes(1088),
      signedPreKeyId: 1,
      pqPreKeyId: 1,
      oneTimePreKeyId: undefined,
      usedOneTimePq: false,
    };
    const opened = openEnvelope(
      recipient,
      sealEnvelope(recipient.publicKey, content({ sessionInit: init })),
    );
    expect(opened.sessionInit!.oneTimePreKeyId).toBeUndefined();
  });

  it('cannot be opened by anyone else', () => {
    const recipient = generateIdentity();
    const eavesdropper = generateIdentity();
    const envelope = sealEnvelope(recipient.publicKey, content());
    expect(() => openEnvelope(eavesdropper, envelope)).toThrow(SealedEnvelopeError);
  });

  it('rejects a tampered envelope', () => {
    const recipient = generateIdentity();
    const envelope = sealEnvelope(recipient.publicKey, content());
    envelope[envelope.length - 1] ^= 0xff;
    expect(() => openEnvelope(recipient, envelope)).toThrow(SealedEnvelopeError);
  });

  it('hides the sender from the ciphertext', () => {
    // The sender's account ID must not appear in the bytes the server sees.
    const recipient = generateIdentity();
    const c = content();
    const envelope = sealEnvelope(recipient.publicKey, c);
    const asText = Array.from(envelope)
      .map((b) => String.fromCharCode(b))
      .join('');
    expect(asText).not.toContain(c.senderAccountId);
  });

  it('pads envelopes so different message sizes look alike', () => {
    const recipient = generateIdentity();
    const small = sealEnvelope(recipient.publicKey, content({ message: { header: randomBytes(80), body: randomBytes(10) } }));
    const larger = sealEnvelope(recipient.publicKey, content({ message: { header: randomBytes(80), body: randomBytes(60) } }));
    expect(small.length).toBe(larger.length);
  });
});

describe('safety numbers', () => {
  it('is the same for both parties', () => {
    const a = generateIdentity().publicKey;
    const b = generateIdentity().publicKey;
    expect(safetyNumber(a, b)).toBe(safetyNumber(b, a));
  });

  it('is 12 groups of 5 digits', () => {
    const groups = safetyNumber(generateIdentity().publicKey, generateIdentity().publicKey).split(' ');
    expect(groups).toHaveLength(12);
    groups.forEach((g) => expect(g).toMatch(/^\d{5}$/));
  });

  it('changes when either identity key changes', () => {
    const a = generateIdentity().publicKey;
    const b = generateIdentity().publicKey;
    const c = generateIdentity().publicKey;
    expect(safetyNumber(a, b)).not.toBe(safetyNumber(a, c));
    expect(safetyNumber(a, b)).not.toBe(safetyNumber(c, b));
  });

  it('verifies a matching QR payload and rejects a substituted key', () => {
    const alice = generateIdentity().publicKey;
    const bob = generateIdentity().publicKey;
    const mallory = generateIdentity().publicKey;

    const payload = safetyQrPayload(alice, bob);
    expect(verifyQrPayload(payload, bob, alice)).toBe(true);
    expect(verifyQrPayload(payload, alice, mallory)).toBe(false);
  });
});

describe('mailboxes', () => {
  it('derives deterministically from the shared secret', () => {
    const secret = randomBytes(32);
    expect(mailboxFor(secret, 20000)).toBe(mailboxFor(secret, 20000));
    expect(mailboxFor(secret, 20000)).toMatch(/^mb_[0-9a-f]{32}$/);
  });

  it('rotates every day and is unlinkable across days', () => {
    const secret = randomBytes(32);
    expect(mailboxFor(secret, 20000)).not.toBe(mailboxFor(secret, 20001));
  });

  it('differs per contact secret', () => {
    expect(mailboxFor(randomBytes(32), 20000)).not.toBe(mailboxFor(randomBytes(32), 20000));
  });

  it('publishes yesterday, today and tomorrow so clock skew cannot lose mail', () => {
    const secret = randomBytes(32);
    const at = new Date('2026-03-15T23:59:58Z');
    const published = currentMailboxes(secret, at);

    expect(published).toHaveLength(3);
    expect(published).toContain(deliveryMailbox(secret, at));
    // A sender whose clock is two seconds fast targets tomorrow's mailbox,
    // which must already be registered.
    const skewed = new Date('2026-03-16T00:00:00Z');
    expect(published).toContain(deliveryMailbox(secret, skewed));
  });

  it('computes the day number in UTC', () => {
    expect(dayNumber(new Date('1970-01-01T00:00:00Z'))).toBe(0);
    expect(dayNumber(new Date('1970-01-02T00:00:00Z'))).toBe(1);
  });
});

describe('registration proof', () => {
  it('produces a proof the server-side verification accepts', () => {
    const identity = generateIdentity();
    const at = new Date('2026-07-29T12:00:00Z');
    const { proofTs, proof } = registrationProof(identity, at);

    expect(proofTs).toBe('2026-07-29T12:00:00Z');
    // Mirrors the Go implementation in server/internal/auth: context prefix
    // concatenated with the RFC3339 timestamp.
    const message = concat(utf8(SIG_CONTEXT.registration), utf8(proofTs));
    expect(verify(identity.publicKey, message, fromBase64(proof))).toBe(true);
  });

  it('does not verify under a different identity key', () => {
    const { proofTs, proof } = registrationProof(generateIdentity());
    const message = concat(utf8(SIG_CONTEXT.registration), utf8(proofTs));
    expect(verify(generateIdentity().publicKey, message, fromBase64(proof))).toBe(false);
  });
});

describe('what an envelope size tells an observer', () => {
  // The claim in the README's comparison table and docs/THREAT_MODEL.md: the
  // server sees a bucket, not a length. The bucket function is tested above;
  // this is about the thing that actually crosses the wire, which is where a
  // change to the content encoding — or somebody dropping the padding for
  // efficiency — would show up.
  //
  // An envelope is a padded payload plus a fixed header: the ephemeral key,
  // the nonce and the tag. That constant is the same for every envelope and
  // reveals nothing, so the observable value is `bucket + overhead` rather
  // than `bucket`.
  const recipient = generateIdentity();

  function envelopeFor(text: string): Uint8Array {
    return sealEnvelope(recipient.publicKey, {
      senderAccountId: '0123456789ABCDEFGHJKMNPQRS',
      senderDeviceId: 'DEVICE0123456789ABCDEFGHJK',
      senderIdentityKey: randomBytes(32),
      // A ratchet body is the ciphertext of the message, so it grows with it.
      message: { header: randomBytes(80), body: randomBytes(text.length + 16) },
    });
  }

  it('gives the same size to messages of very different lengths', () => {
    // Two messages a person would consider completely different, inside one
    // bucket: "ok" and a sentence.
    expect(envelopeFor('ok').length).toBe(
      envelopeFor('hayır, ve nedenini biraz sonra anlatacağım').length,
    );
  });

  it('collapses four hundred lengths into a handful of sizes', () => {
    const sizes = new Set<number>();
    for (let length = 1; length <= 400; length += 1) {
      sizes.add(envelopeFor('x'.repeat(length)).length);
    }
    // The exact count is not the point; that it is tiny is. A regression that
    // removed the padding would make this 400.
    expect(sizes.size).toBeLessThanOrEqual(3);
  });

  it('moves in bucket-sized steps and nothing finer', () => {
    // Every observable size differs from every other by a bucket boundary,
    // so the gap between two sizes is never one byte of message.
    const sizes = [...new Set([1, 100, 300, 900, 2000, 5000].map((n) => envelopeFor('x'.repeat(n)).length))].sort(
      (a, b) => a - b,
    );
    for (let i = 1; i < sizes.length; i++) {
      expect(sizes[i] - sizes[i - 1]).toBeGreaterThanOrEqual(256);
    }
  });

  it('still hides the length within a larger bucket', () => {
    // Crossing into the next bucket is visible — the threat model says
    // padding hides exact length, not order of magnitude — but inside one,
    // nothing is.
    expect(envelopeFor('x'.repeat(1500)).length).toBe(envelopeFor('y'.repeat(2500)).length);
  });

  it('does not vary with who the sender says they are', () => {
    // Account ids are fixed-width today. A future change to a
    // variable-length identifier would leak its length through the envelope,
    // and this is where that would show up.
    const fixed = { senderIdentityKey: randomBytes(32), message: { header: randomBytes(80), body: randomBytes(40) } };
    expect(
      sealEnvelope(recipient.publicKey, { senderAccountId: 'A', senderDeviceId: 'B', ...fixed }).length,
    ).toBe(
      sealEnvelope(recipient.publicKey, {
        senderAccountId: '0123456789ABCDEFGHJKMNPQRS',
        senderDeviceId: 'DEVICE0123456789ABCDEFGHJK',
        ...fixed,
      }).length,
    );
  });
});
