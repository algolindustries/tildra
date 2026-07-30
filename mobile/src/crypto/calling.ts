/**
 * Call signalling, and binding the media path to the identity keys.
 *
 * WebRTC protects media with DTLS-SRTP. The DTLS handshake authenticates with a
 * self-signed certificate that neither side has ever seen before, so on its own
 * it proves nothing: it says the two endpoints agree on a key, not who they
 * are. What turns that into a call with a specific person is the SDP
 * `a=fingerprint` line — and only if the fingerprint arrives over a channel the
 * peer's identity key vouches for. Otherwise the server can offer its own
 * certificate to each side, terminate both DTLS sessions, and listen.
 *
 * So every offer and answer carries an Ed25519 signature by the sender's
 * identity key over the fingerprint, the call id, both account ids, and a
 * timestamp. The verifier does not trust the signed value: it parses the
 * fingerprint out of the SDP it is about to hand to the peer connection, and
 * checks the signature over *that*. A signature over a fingerprint that is not
 * the one being used is decoration, and this is the shape that makes it
 * impossible to write that bug — there is no separate "claimed fingerprint"
 * field to forget to compare.
 *
 * Signalling itself rides the pairwise Double Ratchet like any other message,
 * so this signature is a second, explicit binding rather than the only one.
 * That redundancy is deliberate: a signal that is ever forwarded, replayed, or
 * carried over a future transport is still bound to one call between two
 * accounts at one moment.
 *
 * **There is no spoken call verification code, on purpose.** ZRTP-style short
 * authentication strings exist because ZRTP has no long-term identity to sign
 * with. Tildra does. An attacker who substitutes the DTLS fingerprint cannot
 * produce the signature, and is rejected without asking the user anything; an
 * attacker who substitutes the *identity key* is what the 60-digit safety
 * number in `safety.ts` is for, and a short code read out during a call would
 * be grindable — the attacker picks both forged fingerprints offline and only
 * needs a collision, which is birthday-cheap at any length people will actually
 * say out loud. A code that looks like a check but is not one is worse than no
 * code. The call screen shows the peer's verification state instead.
 */

import {
  KeyPair,
  concat,
  fromUtf8,
  readU32,
  sign,
  u32,
  utf8,
  verify,
} from './primitives';
import { frame, unframe } from './wire';

export class CallError extends Error {}

const BINDING_CONTEXT = 'tildra-call-fingerprint-v1:';

/**
 * How long a signed offer or answer stays valid.
 *
 * Without this a captured offer can be replayed to make a phone ring later, or
 * a stale answer can be injected into a call the user has since placed to the
 * same person. A ringing call that is two minutes old is dead anyway, so the
 * bound costs nothing real.
 */
export const CALL_SIGNAL_MAX_AGE_MS = 120_000;

/** Tolerance for a peer whose clock runs fast. */
export const CALL_SIGNAL_MAX_SKEW_MS = 60_000;

/** How long the caller rings before giving up. */
export const CALL_RINGING_TIMEOUT_MS = 45_000;

/**
 * Cap on an SDP body. A real offer with every codec is a few kilobytes; this is
 * generous enough not to matter and small enough that a peer cannot make the
 * parser chew through megabytes.
 */
export const MAX_SDP_BYTES = 16 * 1024;
export const MAX_CANDIDATE_LENGTH = 512;
export const MAX_CALL_ID_LENGTH = 64;

/**
 * Hash functions accepted in a fingerprint.
 *
 * SHA-1 and MD5 are still legal in RFC 4572 and still emitted by old stacks.
 * Accepting them would let an attacker who can find a certificate collision
 * present a different certificate under the same signed fingerprint, which is
 * exactly the substitution the signature exists to prevent. There is no
 * interoperability worth that.
 */
const FINGERPRINT_HASHES: Record<string, number> = {
  'sha-256': 32,
  'sha-384': 48,
  'sha-512': 64,
};

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

export enum CallSignalKind {
  Offer = 0,
  Answer = 1,
  Candidate = 2,
  /** The call is over: hung up, declined, or failed. */
  Hangup = 3,
  /** The callee is already in a call. Distinct from a decline. */
  Busy = 4,
}

export interface CallSignal {
  kind: CallSignalKind;
  callId: string;
  /** Offer and Answer: the SDP. Candidate: one candidate line. Hangup: reason. */
  body: string;
  /** Offer and Answer only: over the fingerprint binding transcript. */
  signature?: Uint8Array;
  /** Milliseconds. Offer and Answer only. */
  timestamp?: number;
  /** Offer only: whether the caller is asking for video. */
  video?: boolean;
}

export function encodeCallSignal(signal: CallSignal): Uint8Array {
  assertCallId(signal.callId);
  return frame(
    u32(signal.kind),
    utf8(signal.callId),
    utf8(signal.body),
    signal.signature ?? new Uint8Array(0),
    // Seconds, so the field is a u32 past the year 2100 rather than needing a
    // 64-bit encoding for a value that is only used for a two-minute window.
    u32(Math.floor((signal.timestamp ?? 0) / 1000)),
    u32(signal.video ? 1 : 0),
  );
}

export function decodeCallSignal(data: Uint8Array): CallSignal {
  const [kindBytes, callIdBytes, bodyBytes, signature, tsBytes, videoBytes] = unframe(data, 6);

  const kind = readU32(kindBytes, 0);
  if (!(kind in CallSignalKind) || typeof CallSignalKind[kind] !== 'string') {
    // Same rule as content types: a signal we do not understand is refused,
    // never guessed at. Guessing is how a candidate becomes an offer.
    throw new CallError(`unsupported call signal kind ${kind}`);
  }

  const callId = fromUtf8(callIdBytes);
  assertCallId(callId);

  const body = fromUtf8(bodyBytes);
  if (body.length > MAX_SDP_BYTES) {
    throw new CallError('call signal body is too large');
  }

  const signal: CallSignal = { kind, callId, body };
  if (signature.length > 0) signal.signature = signature;

  const ts = readU32(tsBytes, 0);
  if (ts > 0) signal.timestamp = ts * 1000;
  if (readU32(videoBytes, 0) === 1) signal.video = true;

  return signal;
}

/**
 * Call ids end up inside a signature transcript and inside map keys. The
 * transcript is length-prefixed so a delimiter could not shift a field even if
 * one got through, but a hostile id is still not something to carry around —
 * refusing here means every layer downstream sees something boring.
 */
function assertCallId(callId: string): void {
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(callId)) {
    throw new CallError('call id must be 8-64 characters of [A-Za-z0-9_-]');
  }
}

/**
 * Force a random string into the call-id alphabet.
 *
 * The manager's id source is base64, which carries `+`, `/` and `=`. Rather
 * than give the manager a second random source to keep deterministic in tests,
 * strip what does not belong and insist on what is left being long enough.
 */
export function toCallId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9_-]/g, '');
  if (cleaned.length < 8) {
    throw new CallError('not enough usable characters for a call id');
  }
  return cleaned.slice(0, MAX_CALL_ID_LENGTH);
}

// ---------------------------------------------------------------------------
// SDP
// ---------------------------------------------------------------------------

export interface SdpFingerprint {
  /** Lowercase, e.g. `sha-256`. */
  hash: string;
  /** Uppercase colon-separated hex, as it appears on the wire. */
  value: string;
}

export function formatFingerprint(fp: SdpFingerprint): string {
  return `${fp.hash} ${fp.value}`;
}

/**
 * Pull the one DTLS fingerprint out of an SDP, refusing anything that would
 * make "the one fingerprint" a lie.
 *
 * An SDP may repeat `a=fingerprint` at the session level and per media
 * section, and they are allowed to differ — a legal SDP can run each m-line
 * over a separate DTLS association with its own certificate. Tildra does not
 * do that, and accepting it here would mean signing one fingerprint while the
 * audio actually flowed under another. So: at least one fingerprint, and every
 * one of them identical, or the SDP is rejected.
 */
export function sdpFingerprint(sdp: string): SdpFingerprint {
  if (sdp.length > MAX_SDP_BYTES) {
    throw new CallError('SDP exceeds the maximum size');
  }

  const lines = sdp.split(/\r\n|\r|\n/);
  const fingerprints: SdpFingerprint[] = [];

  for (const raw of lines) {
    const line = raw.trim();

    // SDES carries the media key in the SDP itself. If we ever see one we are
    // not doing DTLS-SRTP, and no amount of fingerprint checking is relevant.
    if (line.startsWith('a=crypto:')) {
      throw new CallError('SDP offers SDES key exchange; only DTLS-SRTP is accepted');
    }

    if (line.startsWith('m=')) {
      assertDtlsMediaLine(line);
      continue;
    }

    if (!line.startsWith('a=fingerprint:')) continue;
    fingerprints.push(parseFingerprint(line.slice('a=fingerprint:'.length).trim()));
  }

  if (fingerprints.length === 0) {
    throw new CallError('SDP carries no DTLS fingerprint');
  }

  const first = fingerprints[0];
  for (const fp of fingerprints) {
    if (fp.hash !== first.hash || fp.value !== first.value) {
      throw new CallError('SDP carries more than one DTLS fingerprint');
    }
  }
  return first;
}

function parseFingerprint(value: string): SdpFingerprint {
  const parts = value.split(/\s+/);
  if (parts.length !== 2) {
    throw new CallError('malformed a=fingerprint line');
  }

  const hash = parts[0].toLowerCase();
  const expectedBytes = FINGERPRINT_HASHES[hash];
  if (!expectedBytes) {
    throw new CallError(`refusing fingerprint hash ${hash}; use SHA-256 or stronger`);
  }

  const hex = parts[1].toUpperCase();
  if (!/^[0-9A-F]{2}(:[0-9A-F]{2})*$/.test(hex)) {
    throw new CallError('fingerprint is not colon-separated hex');
  }
  const byteCount = (hex.length + 1) / 3;
  if (byteCount !== expectedBytes) {
    throw new CallError(`${hash} fingerprint should be ${expectedBytes} bytes, got ${byteCount}`);
  }

  return { hash, value: hex };
}

/**
 * A media line whose transport is not DTLS-based cannot be protected by a
 * fingerprint at all — `RTP/AVP` is plaintext RTP and `RTP/SAVP` is SDES.
 */
function assertDtlsMediaLine(line: string): void {
  const parts = line.slice('m='.length).split(/\s+/);
  if (parts.length < 3) {
    throw new CallError('malformed m= line');
  }
  // A rejected media section (port 0) is not carrying anything, so its
  // transport does not matter and refusing it would break renegotiation.
  if (parts[1] === '0') return;

  const proto = parts[2].toUpperCase();
  if (!/(^|\/)(TLS|DTLS)(\/|$)/.test(proto)) {
    throw new CallError(`media transport ${parts[2]} is not DTLS-protected`);
  }
}

// ---------------------------------------------------------------------------
// Fingerprint binding
// ---------------------------------------------------------------------------

export type CallRole = 'caller' | 'callee';

export interface CallBinding {
  callId: string;
  role: CallRole;
  fromAccountId: string;
  toAccountId: string;
  fingerprint: SdpFingerprint;
  /** Milliseconds. */
  timestamp: number;
}

/**
 * The signed transcript.
 *
 * Length-prefixed rather than colon-joined: with delimiters, an account id
 * containing the delimiter could shift the boundary between two fields and make
 * one signature verify for a different call. Framing makes that impossible by
 * construction instead of by validating every input that reaches it.
 */
function bindingTranscript(binding: CallBinding): Uint8Array {
  return concat(
    utf8(BINDING_CONTEXT),
    frame(
      utf8(binding.callId),
      utf8(binding.role),
      utf8(binding.fromAccountId),
      utf8(binding.toAccountId),
      utf8(formatFingerprint(binding.fingerprint)),
      u32(Math.floor(binding.timestamp / 1000)),
    ),
  );
}

/** Sign the fingerprint of an SDP we are about to send. */
export function signCallSdp(
  identity: KeyPair,
  params: {
    kind: CallSignalKind.Offer | CallSignalKind.Answer;
    callId: string;
    sdp: string;
    fromAccountId: string;
    toAccountId: string;
    video?: boolean;
    now?: number;
  },
): CallSignal {
  assertCallId(params.callId);

  // Signing the fingerprint parsed back out of the SDP, rather than one held
  // separately, is what keeps the signature and the media in step.
  const fingerprint = sdpFingerprint(params.sdp);
  const timestamp = params.now ?? Date.now();
  const role: CallRole = params.kind === CallSignalKind.Offer ? 'caller' : 'callee';

  const signature = sign(
    identity.secretKey,
    bindingTranscript({
      callId: params.callId,
      role,
      fromAccountId: params.fromAccountId,
      toAccountId: params.toAccountId,
      fingerprint,
      timestamp,
    }),
  );

  const signal: CallSignal = {
    kind: params.kind,
    callId: params.callId,
    body: params.sdp,
    signature,
    // Seconds on the wire, so the local copy is truncated the same way the
    // verifier will see it. Otherwise a signature made at .500 verifies
    // against a transcript rebuilt at .000.
    timestamp: Math.floor(timestamp / 1000) * 1000,
  };
  if (params.video) signal.video = true;
  return signal;
}

/**
 * Verify a received offer or answer and return the fingerprint the media is
 * pinned to.
 *
 * `peerIdentityKey` must be the identity key of the conversation the signal
 * arrived on — not one carried in the signal, which would be circular. The
 * caller reads it from the session.
 */
export function verifyCallSdp(
  signal: CallSignal,
  peerIdentityKey: Uint8Array,
  expect: {
    callId: string;
    fromAccountId: string;
    toAccountId: string;
    now?: number;
  },
): SdpFingerprint {
  if (signal.kind !== CallSignalKind.Offer && signal.kind !== CallSignalKind.Answer) {
    throw new CallError('only an offer or an answer carries a fingerprint binding');
  }
  if (!signal.signature) {
    throw new CallError('call signal is not signed');
  }
  if (signal.callId !== expect.callId) {
    throw new CallError('call signal is for a different call');
  }
  if (!signal.timestamp) {
    throw new CallError('call signal has no timestamp');
  }

  const now = expect.now ?? Date.now();
  if (now - signal.timestamp > CALL_SIGNAL_MAX_AGE_MS) {
    throw new CallError('call signal is too old; refusing a possible replay');
  }
  if (signal.timestamp - now > CALL_SIGNAL_MAX_SKEW_MS) {
    throw new CallError('call signal is dated in the future');
  }

  const fingerprint = sdpFingerprint(signal.body);
  const role: CallRole = signal.kind === CallSignalKind.Offer ? 'caller' : 'callee';

  const transcript = bindingTranscript({
    callId: expect.callId,
    role,
    fromAccountId: expect.fromAccountId,
    toAccountId: expect.toAccountId,
    fingerprint,
    timestamp: signal.timestamp,
  });

  if (!verify(peerIdentityKey, transcript, signal.signature)) {
    throw new CallError(
      'the DTLS fingerprint is not signed by the identity key of the person being called',
    );
  }
  return fingerprint;
}

// ---------------------------------------------------------------------------
// ICE
// ---------------------------------------------------------------------------

export type IceTransportPolicy = 'relay' | 'all';

/**
 * Whether a call may use direct paths yet.
 *
 * A host or server-reflexive candidate is the device's IP address. Sending
 * those while the phone is still ringing hands the caller's network location to
 * anyone who can make it ring, including someone who only wanted to find out
 * where you are and hangs up before you answer. Relay-only until the call is
 * accepted means an unanswered call reveals nothing but the TURN server, at the
 * cost of routing media through it for calls that are answered fast.
 */
export function iceTransportPolicyFor(call: CallSession): IceTransportPolicy {
  if (call.direction === 'incoming' && call.phase === 'ringing') return 'relay';
  return 'all';
}

export interface IceCandidateFields {
  candidate: string;
  type: string;
}

/**
 * Keep the candidates a policy permits, and drop anything that does not parse.
 *
 * Failing closed matters here: a candidate we cannot classify might be a host
 * candidate, and dropping a usable path is a slower call while keeping one is
 * an address leak.
 */
export function filterIceCandidates(
  candidates: string[],
  policy: IceTransportPolicy,
): string[] {
  const out: string[] = [];
  for (const candidate of candidates) {
    const parsed = parseIceCandidate(candidate);
    if (!parsed) continue;
    if (policy === 'relay' && parsed.type !== 'relay') continue;
    out.push(candidate);
  }
  return out;
}

export function parseIceCandidate(candidate: string): IceCandidateFields | null {
  if (candidate.length === 0 || candidate.length > MAX_CANDIDATE_LENGTH) return null;

  // Both `a=candidate:...` (as it appears in an SDP) and `candidate:...` (as
  // RTCIceCandidate hands it over) are seen in the wild.
  let value = candidate.trim();
  if (value.startsWith('a=')) value = value.slice(2);
  if (!value.startsWith('candidate:')) return null;

  const parts = value.slice('candidate:'.length).split(/\s+/);
  // foundation component transport priority ip port "typ" type
  if (parts.length < 8 || parts[6] !== 'typ') return null;

  const type = parts[7];
  if (!['host', 'srflx', 'prflx', 'relay'].includes(type)) return null;

  return { candidate, type };
}

// ---------------------------------------------------------------------------
// Call state
// ---------------------------------------------------------------------------

export type CallDirection = 'outgoing' | 'incoming';
export type CallPhase = 'ringing' | 'connecting' | 'active' | 'ended';
export type CallEndReason =
  | 'hangup'
  | 'declined'
  | 'busy'
  | 'unanswered'
  | 'failed';

export interface CallSession {
  callId: string;
  peerAccountId: string;
  /**
   * The peer device the call settled on.
   *
   * An outgoing call rings every device the account has, so this is unset
   * until one of them answers; from then on it is the only device whose
   * signals count. An incoming call knows it from the offer.
   */
  peerDeviceId?: string;
  direction: CallDirection;
  phase: CallPhase;
  video: boolean;
  /** The peer fingerprint the media is pinned to, once one has been verified. */
  peerFingerprint?: SdpFingerprint;
  endedReason?: CallEndReason;
  startedAt: number;
  /** When the phase last changed — the ringing timeout is measured from this. */
  phaseAt: number;
}

export type CallEvent =
  /** The callee picked up. */
  | { type: 'accept' }
  /** ICE and DTLS are up; media is flowing. */
  | { type: 'connected' }
  /** This side is ending the call. */
  | { type: 'end'; reason: CallEndReason }
  /** Something arrived from the peer. Authenticity is checked before this. */
  | {
      type: 'signal';
      kind: CallSignalKind;
      fingerprint?: SdpFingerprint;
      /** Which of the peer's devices sent it. */
      deviceId?: string;
    };

export function beginOutgoingCall(params: {
  callId: string;
  peerAccountId: string;
  video?: boolean;
  now?: number;
}): CallSession {
  assertCallId(params.callId);
  const now = params.now ?? Date.now();
  return {
    callId: params.callId,
    peerAccountId: params.peerAccountId,
    direction: 'outgoing',
    phase: 'ringing',
    video: params.video ?? false,
    startedAt: now,
    phaseAt: now,
  };
}

export function beginIncomingCall(params: {
  callId: string;
  peerAccountId: string;
  peerDeviceId?: string;
  peerFingerprint: SdpFingerprint;
  video?: boolean;
  now?: number;
}): CallSession {
  assertCallId(params.callId);
  const now = params.now ?? Date.now();
  return {
    callId: params.callId,
    peerAccountId: params.peerAccountId,
    peerDeviceId: params.peerDeviceId,
    direction: 'incoming',
    phase: 'ringing',
    video: params.video ?? false,
    peerFingerprint: params.peerFingerprint,
    startedAt: now,
    phaseAt: now,
  };
}

/**
 * The legal transitions, and nothing else.
 *
 * The rule worth stating plainly: **nothing from the peer is accepted once a
 * call has ended.** A late candidate that reopens a hung-up call is how a call
 * screen ends up showing "connected" to someone who thinks they left, and the
 * only way to not have that bug is to make it a transition error rather than
 * something each handler remembers to check.
 *
 * A local `end` is idempotent, because a person double-tapping the hang-up
 * button is not an error.
 */
export function advanceCall(call: CallSession, event: CallEvent, now?: number): CallSession {
  const at = now ?? Date.now();

  if (event.type === 'end') {
    if (call.phase === 'ended') return call;
    return { ...call, phase: 'ended', endedReason: event.reason, phaseAt: at };
  }

  if (call.phase === 'ended') {
    throw new CallError(`call ${call.callId} has ended; refusing ${describe(event)}`);
  }

  switch (event.type) {
    case 'accept':
      if (call.direction !== 'incoming') {
        throw new CallError('only the receiving side can accept a call');
      }
      if (call.phase !== 'ringing') {
        throw new CallError(`cannot accept a call that is ${call.phase}`);
      }
      return { ...call, phase: 'connecting', phaseAt: at };

    case 'connected':
      if (call.phase === 'active') return call;
      if (call.phase !== 'connecting') {
        throw new CallError(`cannot connect a call that is ${call.phase}`);
      }
      return { ...call, phase: 'active', phaseAt: at };

    case 'signal':
      return applySignal(call, event, at);
  }
}

function applySignal(
  call: CallSession,
  event: Extract<CallEvent, { type: 'signal' }>,
  at: number,
): CallSession {
  switch (event.kind) {
    case CallSignalKind.Offer:
      // The incoming call was created from the first offer. A second one is
      // either a duplicate or an attempt to swap the fingerprint mid-call.
      throw new CallError('an offer for a call that is already in progress');

    case CallSignalKind.Answer:
      if (call.direction !== 'outgoing') {
        throw new CallError('an answer arrived for a call we did not place');
      }
      if (call.phase !== 'ringing') {
        throw new CallError(`an answer arrived while the call was ${call.phase}`);
      }
      // The device that answered is the device the call is with, from here on.
      return {
        ...call,
        phase: 'connecting',
        peerFingerprint: event.fingerprint ?? call.peerFingerprint,
        peerDeviceId: event.deviceId ?? call.peerDeviceId,
        phaseAt: at,
      };

    case CallSignalKind.Candidate:
      // Candidates flow throughout, including after connect for an ICE
      // restart. The phase does not move.
      return call;

    case CallSignalKind.Hangup:
      // Before the callee picks up, a hangup from them is a decline; after, it
      // is an ordinary end. The distinction is what the call log shows.
      return {
        ...call,
        phase: 'ended',
        endedReason: call.direction === 'outgoing' && call.phase === 'ringing' ? 'declined' : 'hangup',
        phaseAt: at,
      };

    case CallSignalKind.Busy:
      if (call.direction !== 'outgoing') {
        throw new CallError('a busy signal arrived for a call we did not place');
      }
      return { ...call, phase: 'ended', endedReason: 'busy', phaseAt: at };
  }
}

/** Whether a call has rung long enough that either side should give up. */
export function callHasTimedOut(call: CallSession, now: number): boolean {
  return call.phase === 'ringing' && now - call.phaseAt >= CALL_RINGING_TIMEOUT_MS;
}

function describe(event: CallEvent): string {
  if (event.type === 'signal') return `a ${CallSignalKind[event.kind].toLowerCase()} signal`;
  return `a ${event.type} event`;
}
