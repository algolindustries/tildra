import { describe, expect, it } from 'vitest';

import {
  CALL_RINGING_TIMEOUT_MS,
  CALL_SIGNAL_MAX_AGE_MS,
  CALL_SIGNAL_MAX_SKEW_MS,
  CallError,
  CallSession,
  CallSignal,
  CallSignalKind,
  MAX_SDP_BYTES,
  advanceCall,
  beginIncomingCall,
  beginOutgoingCall,
  callDurationLabel,
  callHasTimedOut,
  callTrust,
  decodeCallSignal,
  encodeCallSignal,
  filterIceCandidates,
  formatFingerprint,
  iceTransportPolicyFor,
  parseIceCandidate,
  TurnCredential,
  iceConfigurationFor,
  sdpFingerprint,
  signCallSdp,
  verifyCallSdp,
} from '../calling';
import { ContentType, decodeContent, encodeContent, callSignalContent } from '../content';
import { generateSigningKeyPair, randomBytes, toHex } from '../primitives';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A fingerprint in the colon-separated hex form RFC 4572 specifies. */
function hexFingerprint(bytes: number, seed = 1): string {
  const out: string[] = [];
  for (let i = 0; i < bytes; i++) {
    out.push(((i * 7 + seed * 31) % 256).toString(16).padStart(2, '0').toUpperCase());
  }
  return out.join(':');
}

const FP_A = hexFingerprint(32, 1);
const FP_B = hexFingerprint(32, 2);

function sdp(options: { fingerprints?: string[]; media?: string[]; extra?: string[] } = {}): string {
  const fingerprints = options.fingerprints ?? [`sha-256 ${FP_A}`];
  const media = options.media ?? ['m=audio 9 UDP/TLS/RTP/SAVPF 111 103'];

  const lines = [
    'v=0',
    'o=- 4611731400430051336 2 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'a=group:BUNDLE 0',
  ];
  for (const m of media) {
    lines.push(m);
    lines.push('c=IN IP4 0.0.0.0');
    lines.push('a=ice-ufrag:4ZcD');
    lines.push('a=ice-pwd:2u1muCWoOi3uLifh0NuRHlZ7');
    lines.push('a=setup:actpass');
    lines.push('a=rtcp-mux');
  }
  for (const fp of fingerprints) {
    lines.push(`a=fingerprint:${fp}`);
  }
  lines.push(...(options.extra ?? []));
  return lines.join('\r\n') + '\r\n';
}

const CALL_ID = 'call-abc12345';
const ALICE = 'acct-alice';
const BOB = 'acct-bob';
const NOW = 1_770_000_000_000;

// ---------------------------------------------------------------------------
// SDP
// ---------------------------------------------------------------------------

describe('SDP fingerprints', () => {
  it('extracts the fingerprint from a normal offer', () => {
    const fp = sdpFingerprint(sdp());
    expect(fp.hash).toBe('sha-256');
    expect(fp.value).toBe(FP_A);
    expect(formatFingerprint(fp)).toBe(`sha-256 ${FP_A}`);
  });

  it('accepts a session-level and media-level fingerprint that agree', () => {
    const fp = sdpFingerprint(
      sdp({ fingerprints: [`sha-256 ${FP_A}`, `sha-256 ${FP_A}`, `sha-256 ${FP_A}`] }),
    );
    expect(fp.value).toBe(FP_A);
  });

  it('refuses an SDP carrying two different fingerprints', () => {
    // Legal SDP, and exactly how an attacker gets a second DTLS association
    // past a check that only looks at the first line it finds.
    expect(() => sdpFingerprint(sdp({ fingerprints: [`sha-256 ${FP_A}`, `sha-256 ${FP_B}`] }))).toThrow(
      /more than one DTLS fingerprint/,
    );
  });

  it('refuses two fingerprints that differ only by hash function', () => {
    expect(() =>
      sdpFingerprint(sdp({ fingerprints: [`sha-256 ${FP_A}`, `sha-384 ${hexFingerprint(48)}`] })),
    ).toThrow(/more than one DTLS fingerprint/);
  });

  it('refuses SHA-1', () => {
    expect(() => sdpFingerprint(sdp({ fingerprints: [`sha-1 ${hexFingerprint(20)}`] }))).toThrow(
      /SHA-256 or stronger/,
    );
  });

  it('refuses MD5', () => {
    expect(() => sdpFingerprint(sdp({ fingerprints: [`md5 ${hexFingerprint(16)}`] }))).toThrow(
      /SHA-256 or stronger/,
    );
  });

  it('accepts SHA-384 and SHA-512 at their own lengths', () => {
    expect(sdpFingerprint(sdp({ fingerprints: [`sha-384 ${hexFingerprint(48)}`] })).hash).toBe('sha-384');
    expect(sdpFingerprint(sdp({ fingerprints: [`sha-512 ${hexFingerprint(64)}`] })).hash).toBe('sha-512');
  });

  it('refuses a fingerprint whose length does not match its hash', () => {
    expect(() => sdpFingerprint(sdp({ fingerprints: [`sha-256 ${hexFingerprint(20)}`] }))).toThrow(
      /should be 32 bytes/,
    );
    expect(() => sdpFingerprint(sdp({ fingerprints: [`sha-512 ${hexFingerprint(32)}`] }))).toThrow(
      /should be 64 bytes/,
    );
  });

  it('refuses a fingerprint that is not colon-separated hex', () => {
    expect(() => sdpFingerprint(sdp({ fingerprints: ['sha-256 not-a-fingerprint'] }))).toThrow(
      /colon-separated hex/,
    );
    expect(() => sdpFingerprint(sdp({ fingerprints: [`sha-256 ${FP_A.replace(/:/g, '')}`] }))).toThrow(
      /colon-separated hex/,
    );
  });

  it('refuses a malformed fingerprint line', () => {
    expect(() => sdpFingerprint(sdp({ fingerprints: ['sha-256'] }))).toThrow(/malformed a=fingerprint/);
    expect(() => sdpFingerprint(sdp({ fingerprints: [`sha-256 ${FP_A} extra`] }))).toThrow(
      /malformed a=fingerprint/,
    );
  });

  it('refuses an SDP with no fingerprint at all', () => {
    expect(() => sdpFingerprint(sdp({ fingerprints: [] }))).toThrow(/no DTLS fingerprint/);
  });

  it('refuses SDES key exchange', () => {
    expect(() =>
      sdpFingerprint(sdp({ extra: ['a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQ'] })),
    ).toThrow(/SDES/);
  });

  it('refuses a media line that is not DTLS-protected', () => {
    expect(() => sdpFingerprint(sdp({ media: ['m=audio 9 RTP/AVP 111'] }))).toThrow(/not DTLS-protected/);
    expect(() => sdpFingerprint(sdp({ media: ['m=audio 9 RTP/SAVP 111'] }))).toThrow(/not DTLS-protected/);
  });

  it('accepts a DTLS data channel alongside media', () => {
    const fp = sdpFingerprint(
      sdp({
        media: ['m=audio 9 UDP/TLS/RTP/SAVPF 111', 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel'],
      }),
    );
    expect(fp.value).toBe(FP_A);
  });

  it('ignores the transport of a rejected media section', () => {
    // Port 0 means the section is declined; refusing it would break every
    // renegotiation that drops video.
    const fp = sdpFingerprint(
      sdp({ media: ['m=audio 9 UDP/TLS/RTP/SAVPF 111', 'm=video 0 RTP/AVP 96'] }),
    );
    expect(fp.value).toBe(FP_A);
  });

  it('normalizes case in both halves of the fingerprint', () => {
    const fp = sdpFingerprint(sdp({ fingerprints: [`SHA-256 ${FP_A.toLowerCase()}`] }));
    expect(fp.hash).toBe('sha-256');
    expect(fp.value).toBe(FP_A);
  });

  it('parses an SDP that uses bare LF line endings', () => {
    const fp = sdpFingerprint(sdp().replace(/\r\n/g, '\n'));
    expect(fp.value).toBe(FP_A);
  });

  it('refuses an oversized SDP before parsing it', () => {
    expect(() => sdpFingerprint('v=0\r\n' + 'a=x\r\n'.repeat(MAX_SDP_BYTES))).toThrow(/maximum size/);
  });
});

// ---------------------------------------------------------------------------
// Fingerprint binding
// ---------------------------------------------------------------------------

describe('binding the DTLS fingerprint to the identity key', () => {
  const alice = generateSigningKeyPair();

  function offer(overrides: Partial<Parameters<typeof signCallSdp>[1]> = {}): CallSignal {
    return signCallSdp(alice, {
      kind: CallSignalKind.Offer,
      callId: CALL_ID,
      sdp: sdp(),
      fromAccountId: ALICE,
      toAccountId: BOB,
      now: NOW,
      ...overrides,
    });
  }

  const expectation = { callId: CALL_ID, fromAccountId: ALICE, toAccountId: BOB, now: NOW };

  it('verifies an offer the peer actually signed', () => {
    const fp = verifyCallSdp(offer(), alice.publicKey, expectation);
    expect(fp.value).toBe(FP_A);
  });

  it('survives an encode/decode round trip', () => {
    const signal = offer({ video: true });
    const decoded = decodeCallSignal(encodeCallSignal(signal));
    expect(decoded.video).toBe(true);
    expect(decoded.timestamp).toBe(signal.timestamp);
    expect(verifyCallSdp(decoded, alice.publicKey, expectation).value).toBe(FP_A);
  });

  it('rejects an SDP whose fingerprint was swapped under a valid signature', () => {
    // The whole point. A server that re-terminates DTLS has to change this
    // line, and it cannot re-sign it.
    const swapped = { ...offer(), body: sdp({ fingerprints: [`sha-256 ${FP_B}`] }) };
    expect(() => verifyCallSdp(swapped, alice.publicKey, expectation)).toThrow(/not signed by the identity key/);
  });

  it('rejects a fingerprint appended to an otherwise valid SDP', () => {
    const injected = {
      ...offer(),
      body: sdp({ fingerprints: [`sha-256 ${FP_A}`, `sha-256 ${FP_B}`] }),
    };
    expect(() => verifyCallSdp(injected, alice.publicKey, expectation)).toThrow(/more than one DTLS fingerprint/);
  });

  it('rejects a signature by anyone but the peer', () => {
    const mallory = generateSigningKeyPair();
    expect(() => verifyCallSdp(offer(), mallory.publicKey, expectation)).toThrow(CallError);
  });

  it('rejects an offer replayed into a different call', () => {
    const signal = offer();
    expect(() =>
      verifyCallSdp({ ...signal, callId: 'call-other123' }, alice.publicKey, {
        ...expectation,
        callId: 'call-other123',
      }),
    ).toThrow(CallError);
  });

  it('rejects an offer relayed to a third party', () => {
    // Bound to the recipient, so the server cannot ring someone else with an
    // offer Alice made for Bob.
    expect(() =>
      verifyCallSdp(offer(), alice.publicKey, { ...expectation, toAccountId: 'acct-carol' }),
    ).toThrow(CallError);
  });

  it('rejects an offer attributed to a different sender', () => {
    expect(() =>
      verifyCallSdp(offer(), alice.publicKey, { ...expectation, fromAccountId: 'acct-carol' }),
    ).toThrow(CallError);
  });

  it('rejects an offer signature presented as an answer', () => {
    // Role confusion: without the role in the transcript, Alice's offer would
    // verify as her answer to a call Mallory claims she placed.
    const asAnswer = { ...offer(), kind: CallSignalKind.Answer };
    expect(() => verifyCallSdp(asAnswer, alice.publicKey, expectation)).toThrow(CallError);
  });

  it('rejects an answer signature presented as an offer', () => {
    const answer = signCallSdp(alice, {
      kind: CallSignalKind.Answer,
      callId: CALL_ID,
      sdp: sdp(),
      fromAccountId: ALICE,
      toAccountId: BOB,
      now: NOW,
    });
    expect(() => verifyCallSdp({ ...answer, kind: CallSignalKind.Offer }, alice.publicKey, expectation)).toThrow(
      CallError,
    );
  });

  it('rejects a stale offer', () => {
    expect(() =>
      verifyCallSdp(offer(), alice.publicKey, { ...expectation, now: NOW + CALL_SIGNAL_MAX_AGE_MS + 1000 }),
    ).toThrow(/too old/);
  });

  it('accepts an offer inside the freshness window', () => {
    expect(
      verifyCallSdp(offer(), alice.publicKey, { ...expectation, now: NOW + CALL_SIGNAL_MAX_AGE_MS - 1000 }).value,
    ).toBe(FP_A);
  });

  it('rejects an offer dated too far in the future', () => {
    expect(() =>
      verifyCallSdp(offer(), alice.publicKey, { ...expectation, now: NOW - CALL_SIGNAL_MAX_SKEW_MS - 1000 }),
    ).toThrow(/future/);
  });

  it('tolerates a peer whose clock runs a little fast', () => {
    expect(
      verifyCallSdp(offer(), alice.publicKey, { ...expectation, now: NOW - CALL_SIGNAL_MAX_SKEW_MS + 1000 }).value,
    ).toBe(FP_A);
  });

  it('rejects an unsigned offer', () => {
    const { signature, ...unsigned } = offer();
    expect(signature).toBeDefined();
    expect(() => verifyCallSdp(unsigned as CallSignal, alice.publicKey, expectation)).toThrow(/not signed/);
  });

  it('rejects an offer with no timestamp', () => {
    expect(() => verifyCallSdp({ ...offer(), timestamp: undefined }, alice.publicKey, expectation)).toThrow(
      /no timestamp/,
    );
  });

  it('rejects a timestamp moved without re-signing', () => {
    expect(() =>
      verifyCallSdp({ ...offer(), timestamp: NOW + 5000 }, alice.publicKey, { ...expectation, now: NOW + 5000 }),
    ).toThrow(CallError);
  });

  it('rejects a corrupted signature', () => {
    const signal = offer();
    const tampered = Uint8Array.from(signal.signature!);
    tampered[0] ^= 0x01;
    expect(() => verifyCallSdp({ ...signal, signature: tampered }, alice.publicKey, expectation)).toThrow(CallError);
  });

  it('refuses to look for a binding on kinds that do not carry one', () => {
    for (const kind of [CallSignalKind.Candidate, CallSignalKind.Hangup, CallSignalKind.Busy]) {
      expect(() => verifyCallSdp({ ...offer(), kind }, alice.publicKey, expectation)).toThrow(
        /only an offer or an answer/,
      );
    }
  });

  it('fails on every single-field mutation of the transcript', () => {
    // Each field is in the signature for a reason; a test per field would let
    // one be dropped later without anything going red.
    const signal = offer();
    const mutations: [string, () => void][] = [
      ['callId', () => verifyCallSdp({ ...signal, callId: 'call-zzz98765' }, alice.publicKey, { ...expectation, callId: 'call-zzz98765' })],
      ['role', () => verifyCallSdp({ ...signal, kind: CallSignalKind.Answer }, alice.publicKey, expectation)],
      ['from', () => verifyCallSdp(signal, alice.publicKey, { ...expectation, fromAccountId: 'x' })],
      ['to', () => verifyCallSdp(signal, alice.publicKey, { ...expectation, toAccountId: 'x' })],
      ['fingerprint', () => verifyCallSdp({ ...signal, body: sdp({ fingerprints: [`sha-256 ${FP_B}`] }) }, alice.publicKey, expectation)],
      ['timestamp', () => verifyCallSdp({ ...signal, timestamp: NOW + 1000 }, alice.publicKey, { ...expectation, now: NOW + 1000 })],
      ['key', () => verifyCallSdp(signal, generateSigningKeyPair().publicKey, expectation)],
    ];
    for (const [field, run] of mutations) {
      expect(run, `mutating ${field} should not verify`).toThrow(CallError);
    }
  });

  it('does not let two account ids run together in the transcript', () => {
    // Framing rather than delimiters: "ab" + "c" and "a" + "bc" must not hash
    // to the same transcript.
    const signed = signCallSdp(alice, {
      kind: CallSignalKind.Offer,
      callId: CALL_ID,
      sdp: sdp(),
      fromAccountId: 'ab',
      toAccountId: 'c',
      now: NOW,
    });
    expect(() =>
      verifyCallSdp(signed, alice.publicKey, { callId: CALL_ID, fromAccountId: 'a', toAccountId: 'bc', now: NOW }),
    ).toThrow(CallError);
  });

  it('refuses to sign an SDP it would refuse to verify', () => {
    expect(() =>
      signCallSdp(alice, {
        kind: CallSignalKind.Offer,
        callId: CALL_ID,
        sdp: sdp({ fingerprints: [`sha-1 ${hexFingerprint(20)}`] }),
        fromAccountId: ALICE,
        toAccountId: BOB,
      }),
    ).toThrow(/SHA-256 or stronger/);
  });
});

// ---------------------------------------------------------------------------
// Signal encoding
// ---------------------------------------------------------------------------

describe('call signal encoding', () => {
  it('round-trips a candidate with no signature or timestamp', () => {
    const signal: CallSignal = {
      kind: CallSignalKind.Candidate,
      callId: CALL_ID,
      body: 'candidate:1 1 UDP 2130706431 203.0.113.1 54321 typ relay',
    };
    const decoded = decodeCallSignal(encodeCallSignal(signal));
    expect(decoded).toEqual(signal);
    expect(decoded.signature).toBeUndefined();
    expect(decoded.timestamp).toBeUndefined();
  });

  it('round-trips a hangup reason', () => {
    const decoded = decodeCallSignal(
      encodeCallSignal({ kind: CallSignalKind.Hangup, callId: CALL_ID, body: 'declined' }),
    );
    expect(decoded.kind).toBe(CallSignalKind.Hangup);
    expect(decoded.body).toBe('declined');
  });

  it('refuses a signal kind it does not understand', () => {
    const forged = encodeCallSignal({ kind: 99 as CallSignalKind, callId: CALL_ID, body: '' });
    expect(() => decodeCallSignal(forged)).toThrow(/unsupported call signal kind/);
  });

  it('refuses a call id that could be anything at all', () => {
    for (const bad of ['', 'short', 'has spaces here', 'x'.repeat(65), 'call:with:colons']) {
      expect(() => encodeCallSignal({ kind: CallSignalKind.Hangup, callId: bad, body: '' })).toThrow(/call id/);
    }
  });

  it('travels as its own content type and is never mistaken for chat', () => {
    const payload = encodeCallSignal({ kind: CallSignalKind.Hangup, callId: CALL_ID, body: 'bye' });
    const decoded = decodeContent(encodeContent(callSignalContent(payload)));
    expect(decoded.type).toBe(ContentType.CallSignal);
    expect(decoded.text).toBeUndefined();
    expect(decodeCallSignal(decoded.payload!).body).toBe('bye');
  });

  it('rejects a body larger than an SDP is allowed to be', () => {
    const huge = encodeCallSignal({
      kind: CallSignalKind.Hangup,
      callId: CALL_ID,
      body: 'x'.repeat(MAX_SDP_BYTES + 1),
    });
    expect(() => decodeCallSignal(huge)).toThrow(/too large/);
  });

  it('rejects trailing bytes after the signal', () => {
    const encoded = encodeCallSignal({ kind: CallSignalKind.Hangup, callId: CALL_ID, body: 'bye' });
    const extended = new Uint8Array(encoded.length + 1);
    extended.set(encoded);
    expect(() => decodeCallSignal(extended)).toThrow(/trailing bytes/);
  });

  it('preserves a signature through encoding byte for byte', () => {
    const signature = randomBytes(64);
    const decoded = decodeCallSignal(
      encodeCallSignal({ kind: CallSignalKind.Answer, callId: CALL_ID, body: 'x', signature, timestamp: NOW }),
    );
    expect(toHex(decoded.signature!)).toBe(toHex(signature));
  });
});

// ---------------------------------------------------------------------------
// ICE
// ---------------------------------------------------------------------------

describe('ICE candidate policy', () => {
  const host = 'candidate:1 1 UDP 2130706431 192.168.1.42 54321 typ host';
  const srflx = 'candidate:2 1 UDP 1694498815 198.51.100.7 54322 typ srflx raddr 192.168.1.42 rport 54321';
  const prflx = 'candidate:3 1 UDP 1694498814 198.51.100.8 54323 typ prflx';
  const relay = 'candidate:4 1 UDP 41885439 203.0.113.9 54324 typ relay raddr 198.51.100.7 rport 54322';

  it('keeps only relay candidates under the relay policy', () => {
    expect(filterIceCandidates([host, srflx, prflx, relay], 'relay')).toEqual([relay]);
  });

  it('keeps every well-formed candidate under the all policy', () => {
    expect(filterIceCandidates([host, srflx, prflx, relay], 'all')).toHaveLength(4);
  });

  it('drops candidates it cannot classify, rather than passing them through', () => {
    // Fail closed: an unparsed candidate might be a host candidate, and a
    // leaked address cannot be taken back.
    const junk = ['', 'candidate:1 1 UDP 2130706431 192.168.1.42 54321', 'not a candidate', 'candidate:', 'x'.repeat(600)];
    expect(filterIceCandidates(junk, 'all')).toEqual([]);
    expect(filterIceCandidates(junk, 'relay')).toEqual([]);
  });

  it('drops a candidate with an unknown type', () => {
    expect(filterIceCandidates(['candidate:1 1 UDP 2130706431 1.2.3.4 1 typ mystery'], 'all')).toEqual([]);
  });

  it('accepts the a= prefixed form as it appears in an SDP', () => {
    expect(parseIceCandidate(`a=${relay}`)?.type).toBe('relay');
    expect(filterIceCandidates([`a=${host}`], 'relay')).toEqual([]);
    expect(filterIceCandidates([`a=${relay}`], 'relay')).toHaveLength(1);
  });

  it('holds an incoming call to relay-only until it is answered', () => {
    // A call you never picked up must not tell the caller where you are.
    let call = beginIncomingCall({
      callId: CALL_ID,
      peerAccountId: ALICE,
      peerFingerprint: sdpFingerprint(sdp()),
      now: NOW,
    });
    expect(iceTransportPolicyFor(call)).toBe('relay');

    call = advanceCall(call, { type: 'accept' }, NOW + 1000);
    expect(iceTransportPolicyFor(call)).toBe('all');
  });

  it('lets an outgoing call use direct paths from the start', () => {
    // The caller already chose to reveal themselves to this person.
    const call = beginOutgoingCall({ callId: CALL_ID, peerAccountId: BOB, now: NOW });
    expect(iceTransportPolicyFor(call)).toBe('all');
  });
});

// ---------------------------------------------------------------------------
// Call state
// ---------------------------------------------------------------------------

describe('call state machine', () => {
  const fingerprint = sdpFingerprint(sdp());

  function outgoing() {
    return beginOutgoingCall({ callId: CALL_ID, peerAccountId: BOB, now: NOW });
  }
  function incoming() {
    return beginIncomingCall({ callId: CALL_ID, peerAccountId: ALICE, peerFingerprint: fingerprint, now: NOW });
  }

  it('walks an outgoing call from ringing to active', () => {
    let call = outgoing();
    expect(call.phase).toBe('ringing');

    call = advanceCall(call, { type: 'signal', kind: CallSignalKind.Answer, fingerprint }, NOW + 1000);
    expect(call.phase).toBe('connecting');
    expect(call.peerFingerprint?.value).toBe(FP_A);

    call = advanceCall(call, { type: 'connected' }, NOW + 2000);
    expect(call.phase).toBe('active');

    call = advanceCall(call, { type: 'end', reason: 'hangup' }, NOW + 3000);
    expect(call.phase).toBe('ended');
    expect(call.endedReason).toBe('hangup');
  });

  it('walks an incoming call from ringing to active', () => {
    let call = incoming();
    call = advanceCall(call, { type: 'accept' }, NOW + 1000);
    expect(call.phase).toBe('connecting');
    call = advanceCall(call, { type: 'connected' }, NOW + 2000);
    expect(call.phase).toBe('active');
  });

  it('refuses everything from the peer once the call has ended', () => {
    // A late candidate that revives a hung-up call is how a call screen shows
    // "connected" to someone who already left.
    const ended = advanceCall(outgoing(), { type: 'end', reason: 'hangup' }, NOW + 1000);
    for (const kind of [
      CallSignalKind.Offer,
      CallSignalKind.Answer,
      CallSignalKind.Candidate,
      CallSignalKind.Hangup,
      CallSignalKind.Busy,
    ]) {
      expect(() => advanceCall(ended, { type: 'signal', kind }, NOW + 2000)).toThrow(/has ended/);
    }
    expect(() => advanceCall(ended, { type: 'accept' }, NOW + 2000)).toThrow(/has ended/);
    expect(() => advanceCall(ended, { type: 'connected' }, NOW + 2000)).toThrow(/has ended/);
  });

  it('treats hanging up twice as one hangup', () => {
    const once = advanceCall(outgoing(), { type: 'end', reason: 'hangup' }, NOW + 1000);
    const twice = advanceCall(once, { type: 'end', reason: 'failed' }, NOW + 2000);
    expect(twice).toBe(once);
    expect(twice.endedReason).toBe('hangup');
  });

  it('refuses a second answer', () => {
    const connecting = advanceCall(
      outgoing(),
      { type: 'signal', kind: CallSignalKind.Answer, fingerprint },
      NOW + 1000,
    );
    expect(() =>
      advanceCall(connecting, { type: 'signal', kind: CallSignalKind.Answer, fingerprint }, NOW + 2000),
    ).toThrow(/while the call was connecting/);
  });

  it('refuses an answer to a call we never placed', () => {
    expect(() =>
      advanceCall(incoming(), { type: 'signal', kind: CallSignalKind.Answer, fingerprint }, NOW + 1000),
    ).toThrow(/did not place/);
  });

  it('refuses a second offer for a call in progress', () => {
    expect(() => advanceCall(incoming(), { type: 'signal', kind: CallSignalKind.Offer }, NOW + 1000)).toThrow(
      /already in progress/,
    );
  });

  it('refuses to let the caller accept their own call', () => {
    expect(() => advanceCall(outgoing(), { type: 'accept' }, NOW + 1000)).toThrow(/receiving side/);
  });

  it('refuses to accept a call that is no longer ringing', () => {
    const connecting = advanceCall(incoming(), { type: 'accept' }, NOW + 1000);
    expect(() => advanceCall(connecting, { type: 'accept' }, NOW + 2000)).toThrow(/cannot accept/);
  });

  it('refuses to connect a call that is still ringing', () => {
    expect(() => advanceCall(outgoing(), { type: 'connected' }, NOW + 1000)).toThrow(/cannot connect/);
  });

  it('treats a repeated connected event as idempotent', () => {
    let call = advanceCall(incoming(), { type: 'accept' }, NOW + 1000);
    call = advanceCall(call, { type: 'connected' }, NOW + 2000);
    const again = advanceCall(call, { type: 'connected' }, NOW + 3000);
    expect(again).toBe(call);
  });

  it('distinguishes a decline from a hangup', () => {
    const declined = advanceCall(outgoing(), { type: 'signal', kind: CallSignalKind.Hangup }, NOW + 1000);
    expect(declined.endedReason).toBe('declined');

    let active = advanceCall(outgoing(), { type: 'signal', kind: CallSignalKind.Answer, fingerprint }, NOW + 1000);
    active = advanceCall(active, { type: 'connected' }, NOW + 2000);
    const hungUp = advanceCall(active, { type: 'signal', kind: CallSignalKind.Hangup }, NOW + 3000);
    expect(hungUp.endedReason).toBe('hangup');
  });

  it('records a caller giving up as a hangup on the receiving side', () => {
    const gone = advanceCall(incoming(), { type: 'signal', kind: CallSignalKind.Hangup }, NOW + 1000);
    expect(gone.phase).toBe('ended');
    expect(gone.endedReason).toBe('hangup');
  });

  it('ends an outgoing call on busy, and refuses busy on an incoming one', () => {
    const busy = advanceCall(outgoing(), { type: 'signal', kind: CallSignalKind.Busy }, NOW + 1000);
    expect(busy.endedReason).toBe('busy');
    expect(() => advanceCall(incoming(), { type: 'signal', kind: CallSignalKind.Busy }, NOW + 1000)).toThrow(
      /did not place/,
    );
  });

  it('lets candidates flow at every live phase without moving it', () => {
    let call = outgoing();
    for (const phase of ['ringing', 'connecting', 'active'] as const) {
      const before = call.phase;
      call = advanceCall(call, { type: 'signal', kind: CallSignalKind.Candidate }, NOW + 500);
      expect(call.phase).toBe(before);
      expect(before).toBe(phase);
      if (phase === 'ringing') {
        call = advanceCall(call, { type: 'signal', kind: CallSignalKind.Answer, fingerprint }, NOW + 1000);
      } else if (phase === 'connecting') {
        call = advanceCall(call, { type: 'connected' }, NOW + 2000);
      }
    }
  });

  it('times out a call that rings too long, measured from the phase change', () => {
    const call = outgoing();
    expect(callHasTimedOut(call, NOW + CALL_RINGING_TIMEOUT_MS - 1)).toBe(false);
    expect(callHasTimedOut(call, NOW + CALL_RINGING_TIMEOUT_MS)).toBe(true);

    const answered = advanceCall(
      call,
      { type: 'signal', kind: CallSignalKind.Answer, fingerprint },
      NOW + 1000,
    );
    expect(callHasTimedOut(answered, NOW + CALL_RINGING_TIMEOUT_MS * 10)).toBe(false);
  });

  it('refuses a call id that is not a call id', () => {
    expect(() => beginOutgoingCall({ callId: 'no', peerAccountId: BOB })).toThrow(/call id/);
    expect(() =>
      beginIncomingCall({ callId: 'no', peerAccountId: ALICE, peerFingerprint: fingerprint }),
    ).toThrow(/call id/);
  });
});

// ---------------------------------------------------------------------------
// ICE configuration
// ---------------------------------------------------------------------------

describe('building the ICE configuration', () => {
  const RELAY: TurnCredential = {
    urls: ['turn:turn.example:3478?transport=udp', 'turns:turn.example:5349'],
    username: '1770003600:9f2c',
    credential: 'PSBmC0Zp2yhr8xkAvMkE0Xr1QqM=',
    expiresAt: 1_770_003_600,
  };
  const NOW = 1_770_000_000_000;
  const STUN = ['stun:stun.example:3478'];

  it('hands over the relay and STUN once a call is answered', () => {
    const config = iceConfigurationFor('all', RELAY, { stunUrls: STUN, now: NOW });
    expect(config.iceTransportPolicy).toBe('all');
    expect(config.relayAvailable).toBe(true);
    expect(config.iceServers[0].urls).toEqual(RELAY.urls);
    expect(config.iceServers[0].username).toBe(RELAY.username);
    expect(config.iceServers[1].urls).toEqual(STUN);
  });

  it('never offers STUN under a relay-only policy', () => {
    // A STUN binding request is itself a disclosure of the device's address,
    // and a reflexive candidate is the address. Neither belongs in a phase
    // whose whole purpose is not revealing where the user is.
    const config = iceConfigurationFor('relay', RELAY, { stunUrls: STUN, now: NOW });
    expect(config.iceTransportPolicy).toBe('relay');
    const urls = config.iceServers.flatMap((s) => s.urls);
    expect(urls).toEqual(RELAY.urls);
    expect(urls.some((u) => u.startsWith('stun'))).toBe(false);
  });

  it('does not quietly downgrade to direct paths when there is no relay', () => {
    // The failure this exists to prevent: no TURN configured, so the code
    // "helpfully" falls back and the ringing phase leaks an address.
    const config = iceConfigurationFor('relay', null, { stunUrls: STUN, now: NOW });
    expect(config.iceTransportPolicy).toBe('relay');
    expect(config.iceServers).toEqual([]);
    expect(config.relayAvailable).toBe(false);
  });

  it('reports a missing relay rather than hiding it', () => {
    // Gathering nothing is safe but is not a working call, and the caller has
    // to be able to tell those apart.
    expect(iceConfigurationFor('all', null, { now: NOW }).relayAvailable).toBe(false);
    expect(iceConfigurationFor('all', null, { now: NOW }).iceServers).toEqual([]);
  });

  it('treats an expired credential as no credential', () => {
    const expired = { ...RELAY, expiresAt: Math.floor(NOW / 1000) - 1 };
    expect(iceConfigurationFor('relay', expired, { now: NOW }).relayAvailable).toBe(false);
    expect(iceConfigurationFor('all', expired, { now: NOW }).iceServers).toEqual([]);

    const barelyValid = { ...RELAY, expiresAt: Math.floor(NOW / 1000) + 1 };
    expect(iceConfigurationFor('relay', barelyValid, { now: NOW }).relayAvailable).toBe(true);
  });

  it('ignores a relay entry that is missing its credential', () => {
    for (const broken of [
      { ...RELAY, username: '' },
      { ...RELAY, credential: '' },
      { ...RELAY, urls: [] },
      { ...RELAY, expiresAt: Number.NaN },
    ]) {
      expect(iceConfigurationFor('all', broken, { now: NOW }).relayAvailable, JSON.stringify(broken)).toBe(
        false,
      );
    }
  });

  it('drops a relay URL that is not a relay URL', () => {
    // The server hands these over; a scheme that is not turn: would either be
    // ignored by the ICE agent or be something it should not be dialling.
    const mixed = { ...RELAY, urls: ['http://evil.example', 'turn:turn.example:3478'] };
    const config = iceConfigurationFor('all', mixed, { now: NOW });
    expect(config.iceServers[0].urls).toEqual(['turn:turn.example:3478']);
  });

  it('drops a STUN entry that is not a STUN URL', () => {
    const config = iceConfigurationFor('all', RELAY, {
      stunUrls: ['stun:ok.example:3478', 'https://not-stun.example'],
      now: NOW,
    });
    expect(config.iceServers[1].urls).toEqual(['stun:ok.example:3478']);
  });

  it('matches the policy the call state asks for', () => {
    // The two halves have to agree, or the candidate filter and the ICE agent
    // enforce different rules.
    const incoming = beginIncomingCall({
      callId: CALL_ID,
      peerAccountId: ALICE,
      peerFingerprint: sdpFingerprint(sdp()),
      now: NOW,
    });
    expect(iceConfigurationFor(iceTransportPolicyFor(incoming), RELAY, { now: NOW }).iceTransportPolicy).toBe(
      'relay',
    );

    const answered = advanceCall(incoming, { type: 'accept' }, NOW + 1000);
    expect(iceConfigurationFor(iceTransportPolicyFor(answered), RELAY, { now: NOW }).iceTransportPolicy).toBe(
      'all',
    );
  });
});

// ---------------------------------------------------------------------------
// What the call screen shows
// ---------------------------------------------------------------------------

describe('call trust', () => {
  it('reports a verified contact as verified', () => {
    expect(callTrust({ verified: true, identityChanged: false })).toBe('verified');
  });

  it('reports an unverified contact as unverified', () => {
    expect(callTrust({ verified: false, identityChanged: false })).toBe('unverified');
  });

  it('lets a changed key outrank a previous verification', () => {
    // The thing that was verified is not the thing on the other end now, and
    // a call screen that still says "verified" is actively misleading at the
    // exact moment it matters most.
    expect(callTrust({ verified: true, identityChanged: true })).toBe('changed');
  });

  it('treats somebody we have no conversation with as unverified', () => {
    expect(callTrust(null)).toBe('unverified');
    expect(callTrust(undefined)).toBe('unverified');
  });
});

describe('call duration', () => {
  const active = (phaseAt: number): CallSession => ({
    ...beginOutgoingCall({ callId: CALL_ID, peerAccountId: BOB, now: NOW }),
    phase: 'active',
    phaseAt,
  });

  it('counts from when the media connected, not from when it started ringing', () => {
    // A call log that counts ringing as talk time is wrong in the direction
    // that matters to whoever reads it later.
    const call = active(NOW + 30_000);
    expect(callDurationLabel(call, NOW + 30_000 + 5_000)).toBe('0:05');
  });

  it('formats minutes and seconds', () => {
    expect(callDurationLabel(active(NOW), NOW)).toBe('0:00');
    expect(callDurationLabel(active(NOW), NOW + 9_000)).toBe('0:09');
    expect(callDurationLabel(active(NOW), NOW + 61_000)).toBe('1:01');
    expect(callDurationLabel(active(NOW), NOW + 599_000)).toBe('9:59');
  });

  it('grows an hours field rather than showing 90 minutes', () => {
    expect(callDurationLabel(active(NOW), NOW + 3_600_000)).toBe('1:00:00');
    expect(callDurationLabel(active(NOW), NOW + 3_723_000)).toBe('1:02:03');
  });

  it('never shows a negative duration when the clock moves backwards', () => {
    expect(callDurationLabel(active(NOW), NOW - 5_000)).toBe('0:00');
  });

  it('shows nothing for a call that is not up yet', () => {
    const ringing = beginOutgoingCall({ callId: CALL_ID, peerAccountId: BOB, now: NOW });
    expect(callDurationLabel(ringing, NOW + 10_000)).toBe('');
  });
});
