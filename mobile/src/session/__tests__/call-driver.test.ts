import { describe, expect, it } from 'vitest';

import {
  CallDriver,
  CallDriverDeps,
  CallDriverError,
  CallSignalling,
  PeerConnection,
  PeerConnectionHandlers,
} from '../call-driver';
import { SessionManager } from '../manager';
import {
  CallEndReason,
  CallSession,
  IceConfiguration,
  IceTransportPolicy,
  beginIncomingCall,
  beginOutgoingCall,
  sdpFingerprint,
} from '../../crypto/calling';

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

function sdp(seed = 1): string {
  const bytes: string[] = [];
  for (let i = 0; i < 32; i++) {
    bytes.push(((i * 13 + seed * 29) % 256).toString(16).padStart(2, '0').toUpperCase());
  }
  return [
    'v=0',
    'o=- 1 2 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'm=audio 9 UDP/TLS/RTP/SAVPF 111',
    `a=fingerprint:sha-256 ${bytes.join(':')}`,
    '',
  ].join('\r\n');
}

const HOST = 'candidate:1 1 UDP 2130706431 192.168.1.42 54321 typ host';
const RELAY = 'candidate:4 1 UDP 41885439 203.0.113.9 54324 typ relay';
const ALICE = 'acct-alice';
const BOB = 'acct-bob';
const CALL_ID = 'call-abcd1234';
const NOW = 1_770_000_000_000;

function relayConfig(policy: IceTransportPolicy, relayAvailable = true): IceConfiguration {
  return {
    iceServers: relayAvailable ? [{ urls: ['turn:turn.test:3478'], username: 'u', credential: 'c' }] : [],
    iceTransportPolicy: policy,
    relayAvailable,
  };
}

/** Records every operation, in order, so ordering bugs are visible. */
class FakePeer implements PeerConnection {
  readonly ops: string[] = [];
  readonly addedCandidates: string[] = [];
  configs: IceConfiguration[] = [];
  closes = 0;
  handlers!: PeerConnectionHandlers;
  failAddCandidate = false;

  async createOffer(options: { video: boolean; iceRestart?: boolean }): Promise<string> {
    this.ops.push(`createOffer(video=${options.video}${options.iceRestart ? ',restart' : ''})`);
    return sdp(1);
  }
  async createAnswer(): Promise<string> {
    this.ops.push('createAnswer');
    return sdp(2);
  }
  async setLocalDescription(type: 'offer' | 'answer'): Promise<void> {
    this.ops.push(`setLocal(${type})`);
  }
  async setRemoteDescription(type: 'offer' | 'answer'): Promise<void> {
    this.ops.push(`setRemote(${type})`);
  }
  async addIceCandidate(candidate: string): Promise<void> {
    if (this.failAddCandidate) throw new Error('no remote description');
    this.ops.push('addIceCandidate');
    this.addedCandidates.push(candidate);
  }
  async setConfiguration(config: IceConfiguration): Promise<void> {
    this.ops.push(`setConfiguration(${config.iceTransportPolicy})`);
    this.configs.push(config);
  }
  close(): void {
    this.ops.push('close');
    this.closes += 1;
  }
}

/** A stand-in for SessionManager's call surface. */
class FakeSignalling {
  sent: string[] = [];
  ended: { callId: string; reason?: CallEndReason }[] = [];
  connectedCalls: string[] = [];
  configRequests: (CallSession | IceTransportPolicy)[] = [];
  relayAvailable = true;
  /** Set by tests to make the policy of a live call visible to sendCallCandidate. */
  session: CallSession;

  constructor(session: CallSession) {
    this.session = session;
  }

  async placeCall(_accountId: string, params: { sdp: string; video?: boolean }): Promise<CallSession> {
    this.session = { ...this.session, video: params.video ?? false };
    return this.session;
  }
  async answerCall(_callId: string, _sdp: string): Promise<CallSession> {
    this.session = { ...this.session, phase: 'connecting' };
    return this.session;
  }
  async sendCallCandidate(_callId: string, candidate: string): Promise<boolean> {
    // Mirrors the manager: relay-only withholds anything that is not a relay.
    if (this.session.direction === 'incoming' && this.session.phase === 'ringing') {
      if (!candidate.includes('typ relay')) return false;
    }
    this.sent.push(candidate);
    return true;
  }
  reoffers: string[] = [];
  reanswers: string[] = [];

  async renegotiateCall(_callId: string, sdp: string): Promise<void> {
    this.reoffers.push(sdp);
  }
  async answerRenegotiation(_callId: string, sdp: string): Promise<void> {
    this.reanswers.push(sdp);
  }
  markCallConnected(callId: string): CallSession {
    this.connectedCalls.push(callId);
    this.session = { ...this.session, phase: 'active' };
    return this.session;
  }
  async endCall(callId: string, reason?: CallEndReason): Promise<void> {
    this.ended.push({ callId, reason });
    this.session = { ...this.session, phase: 'ended', endedReason: reason };
  }
  async iceConfiguration(target: CallSession | IceTransportPolicy): Promise<IceConfiguration> {
    this.configRequests.push(target);
    const policy: IceTransportPolicy =
      typeof target === 'string'
        ? target
        : target.direction === 'incoming' && target.phase === 'ringing'
          ? 'relay'
          : 'all';
    return relayConfig(policy, this.relayAvailable);
  }
}

interface Rig {
  deps: CallDriverDeps;
  peer: FakePeer;
  signalling: FakeSignalling;
  errors: Error[];
}

function rig(session: CallSession): Rig {
  const peer = new FakePeer();
  const signalling = new FakeSignalling(session);
  const errors: Error[] = [];
  return {
    peer,
    signalling,
    errors,
    deps: {
      signalling,
      onError: (err) => errors.push(err),
      async createPeerConnection(_config, handlers) {
        peer.handlers = handlers;
        return peer;
      },
    },
  };
}

function outgoing(): CallSession {
  return beginOutgoingCall({ callId: CALL_ID, peerAccountId: BOB, now: NOW });
}
function incoming(): CallSession {
  return beginIncomingCall({
    callId: CALL_ID,
    peerAccountId: ALICE,
    peerFingerprint: sdpFingerprint(sdp(1)),
    now: NOW,
  });
}

// ---------------------------------------------------------------------------
// Placing
// ---------------------------------------------------------------------------

describe('placing a call', () => {
  it('creates the offer before there is a call, in the right order', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB, { video: true });

    expect(r.peer.ops).toEqual(['createOffer(video=true)', 'setLocal(offer)']);
    expect(driver.call.callId).toBe(CALL_ID);
    expect(r.signalling.configRequests[0]).toBe('all');
  });

  it('does not drop candidates gathered before the call has an id', async () => {
    // The peer connection starts producing candidates the moment the local
    // description is set, which is before placeCall has returned. Dropping
    // those loses exactly the fastest ones — the local candidates that would
    // have given a direct path.
    const peer = new FakePeer();
    const signalling = new FakeSignalling(outgoing());
    const errors: Error[] = [];

    const deps: CallDriverDeps = {
      signalling,
      onError: (err) => errors.push(err),
      async createPeerConnection(_config, handlers) {
        peer.handlers = handlers;
        // Gather immediately, the way a real stack does.
        handlers.onLocalCandidate(HOST);
        handlers.onLocalCandidate(RELAY);
        return peer;
      },
    };

    await CallDriver.place(deps, BOB);
    expect(signalling.sent).toEqual([HOST, RELAY]);
    expect(errors).toEqual([]);
  });

  it('closes the connection when the call cannot be placed', async () => {
    // A peer connection left open after a failed start is a live microphone
    // nobody is watching.
    const r = rig(outgoing());
    r.signalling.placeCall = async () => {
      throw new Error('no devices');
    };

    await expect(CallDriver.place(r.deps, BOB)).rejects.toThrow(/no devices/);
    expect(r.peer.closes).toBe(1);
  });

  it('reports a missing relay without refusing to place the call', async () => {
    // Direct paths still work; the caller needs to know the relay fallback is
    // not there.
    const r = rig(outgoing());
    r.signalling.relayAvailable = false;
    const driver = await CallDriver.place(r.deps, BOB);
    expect(driver.relayAvailable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

describe('receiving a call', () => {
  it('installs the offer and starts relay-only', async () => {
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));

    expect(r.peer.ops).toEqual(['setRemote(offer)']);
    expect(driver.call.direction).toBe('incoming');
    const requested = r.signalling.configRequests[0];
    expect(typeof requested).not.toBe('string');
  });

  it('widens the address policy only when the user accepts', async () => {
    // The rule that makes an unanswered call unable to reveal where you are.
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));

    // While ringing, the manager withholds a host candidate.
    r.peer.handlers.onLocalCandidate(HOST);
    r.peer.handlers.onLocalCandidate(RELAY);
    await Promise.resolve();
    expect(r.signalling.sent).toEqual([RELAY]);

    await driver.accept();
    expect(r.peer.ops).toEqual([
      'setRemote(offer)',
      'createAnswer',
      'setLocal(answer)',
      'setConfiguration(all)',
      // The widened policy only takes effect through an ICE restart, and an
      // ICE restart is a new offer.
      'createOffer(video=false,restart)',
      'setLocal(offer)',
    ]);
    expect(r.peer.configs.at(-1)?.iceTransportPolicy).toBe('all');

    r.peer.handlers.onLocalCandidate(HOST);
    await Promise.resolve();
    expect(r.signalling.sent).toEqual([RELAY, HOST]);
  });

  it('answers before reconfiguring, so the peer is not left waiting', async () => {
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));
    await driver.accept();

    const answerAt = r.peer.ops.indexOf('setLocal(answer)');
    const reconfigureAt = r.peer.ops.indexOf('setConfiguration(all)');
    expect(answerAt).toBeGreaterThanOrEqual(0);
    expect(reconfigureAt).toBeGreaterThan(answerAt);
  });
});

// ---------------------------------------------------------------------------
// Candidate ordering
// ---------------------------------------------------------------------------

describe('remote candidates that arrive early', () => {
  it('buffers them until there is a description to attach them to', async () => {
    // Signalling is a race: the peer sends its answer and starts gathering,
    // and nothing keeps those in order across a network. Adding a candidate
    // too early is rejected, and the call quietly ends up on the relay.
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);

    r.peer.failAddCandidate = true;
    await driver.addRemoteCandidate(HOST);
    await driver.addRemoteCandidate(RELAY);
    expect(r.peer.addedCandidates).toEqual([]);

    r.peer.failAddCandidate = false;
    await driver.acceptAnswer({ ...outgoing(), phase: 'connecting' }, sdp(2));

    expect(r.peer.addedCandidates).toEqual([HOST, RELAY]);
    expect(r.peer.ops.indexOf('setRemote(answer)')).toBeLessThan(
      r.peer.ops.indexOf('addIceCandidate'),
    );
  });

  it('adds a candidate straight away once the description is in', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    await driver.acceptAnswer({ ...outgoing(), phase: 'connecting' }, sdp(2));

    await driver.addRemoteCandidate(RELAY);
    expect(r.peer.addedCandidates).toEqual([RELAY]);
  });

  it('does not buffer for an incoming call, whose description arrives first', async () => {
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));
    await driver.addRemoteCandidate(RELAY);
    expect(r.peer.addedCandidates).toEqual([RELAY]);
  });

  it('drops a candidate that arrives after the call is over', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    await driver.hangUp();

    await driver.addRemoteCandidate(RELAY);
    expect(r.peer.addedCandidates).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Ending
// ---------------------------------------------------------------------------

describe('ending a call', () => {
  it('stops the media before telling the peer', async () => {
    // A hangup that fails to send must still stop the microphone.
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    r.signalling.endCall = async () => {
      throw new Error('offline');
    };

    await expect(driver.hangUp()).rejects.toThrow(/offline/);
    expect(r.peer.closes).toBe(1);
  });

  it('closes exactly once however many times it is asked', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);

    await driver.hangUp();
    await driver.hangUp('failed');
    await driver.hangUp();

    expect(r.peer.closes).toBe(1);
    expect(r.signalling.ended).toEqual([{ callId: CALL_ID, reason: 'hangup' }]);
  });

  it('refuses to accept a call that is already over', async () => {
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));
    await driver.hangUp('declined');
    await expect(driver.accept()).rejects.toThrow(CallDriverError);
  });

  it('ends the call when the connection fails', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);

    r.peer.handlers.onFailed('ice failed');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(r.signalling.ended).toEqual([{ callId: CALL_ID, reason: 'failed' }]);
    expect(r.peer.closes).toBe(1);
    expect(r.errors.map((e) => e.message).join()).toMatch(/ice failed/);
    expect(driver.call.callId).toBe(CALL_ID);
  });

  it('ignores a connection event after hanging up', async () => {
    // Otherwise a late "connected" marks a call active that the user has left.
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    await driver.hangUp();

    r.peer.handlers.onConnected();
    r.peer.handlers.onLocalCandidate(RELAY);
    await Promise.resolve();

    expect(r.signalling.connectedCalls).toEqual([]);
    expect(r.signalling.sent).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Connecting
// ---------------------------------------------------------------------------

describe('connecting', () => {
  it('marks the call active when the media comes up', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    await driver.acceptAnswer({ ...outgoing(), phase: 'connecting' }, sdp(2));

    r.peer.handlers.onConnected();
    expect(r.signalling.connectedCalls).toEqual([CALL_ID]);
    expect(driver.call.phase).toBe('active');
  });

  it('does not lose a connection that came up during setup', async () => {
    const peer = new FakePeer();
    const signalling = new FakeSignalling(outgoing());
    const deps: CallDriverDeps = {
      signalling,
      async createPeerConnection(_config, handlers) {
        peer.handlers = handlers;
        handlers.onConnected();
        return peer;
      },
    };

    await CallDriver.place(deps, BOB);
    expect(signalling.connectedCalls).toEqual([CALL_ID]);
  });

  it('treats a setup that connected and then failed as failed', async () => {
    const peer = new FakePeer();
    const signalling = new FakeSignalling(outgoing());
    const errors: Error[] = [];
    const deps: CallDriverDeps = {
      signalling,
      onError: (err) => errors.push(err),
      async createPeerConnection(_config, handlers) {
        peer.handlers = handlers;
        handlers.onConnected();
        handlers.onFailed('dtls failed');
        return peer;
      },
    };

    await CallDriver.place(deps, BOB);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(signalling.ended.at(-1)?.reason).toBe('failed');
    expect(peer.closes).toBe(1);
  });

  it('reports a signalling failure rather than throwing at the media stack', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    r.signalling.sendCallCandidate = async () => {
      throw new Error('socket closed');
    };

    r.peer.handlers.onLocalCandidate(RELAY);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(r.errors.map((e) => e.message).join()).toMatch(/socket closed/);
    expect(driver.call.phase).not.toBe('ended');
  });
});

// ---------------------------------------------------------------------------
// The interface and the real class
// ---------------------------------------------------------------------------

describe('the signalling interface', () => {
  it('is satisfied by the real SessionManager', () => {
    // Compile-time, not runtime: the value is never called. Without this the
    // fake could drift from the class it stands in for, and every test above
    // would keep passing while nothing real matched.
    const check = (manager: SessionManager): CallSignalling => manager;
    expect(typeof check).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// Renegotiation
// ---------------------------------------------------------------------------

describe('renegotiating', () => {
  it('re-offers with an ICE restart when the policy widens on answer', async () => {
    // Without this the answered call stays on the relay for its whole life
    // with nothing indicating anything is wrong.
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));
    await driver.accept();

    expect(r.signalling.reoffers).toHaveLength(1);
    expect(r.peer.ops.indexOf('setConfiguration(all)')).toBeLessThan(
      r.peer.ops.indexOf('createOffer(video=false,restart)'),
    );
  });

  it('does not tear the call down when the re-offer cannot be sent', async () => {
    // A call up and talking over the relay is worse than one on a direct path
    // and much better than one torn down for failing to improve.
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));
    r.signalling.renegotiateCall = async () => {
      throw new Error('socket closed');
    };

    await driver.accept();
    expect(r.errors.map((e) => e.message).join()).toMatch(/socket closed/);
    expect(r.signalling.ended).toEqual([]);
  });

  it('answers a re-offer from the peer', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    await driver.acceptAnswer({ ...outgoing(), phase: 'connecting' }, sdp(2));

    await driver.acceptRenegotiation({ ...outgoing(), phase: 'active' }, sdp(2));

    expect(r.signalling.reanswers).toHaveLength(1);
    const ops = r.peer.ops.join(',');
    expect(ops).toContain('setRemote(offer),createAnswer,setLocal(answer)');
  });

  it('installs the answer to its own re-offer', async () => {
    const r = rig(incoming());
    const driver = await CallDriver.receive(r.deps, incoming(), sdp(1));
    await driver.accept();

    await driver.acceptRenegotiationAnswer({ ...incoming(), phase: 'active' }, sdp(2));
    expect(r.peer.ops.at(-1)).toBe('setRemote(answer)');
  });

  it('refuses to renegotiate a call that is over', async () => {
    const r = rig(outgoing());
    const driver = await CallDriver.place(r.deps, BOB);
    await driver.hangUp();

    await expect(driver.renegotiate()).rejects.toThrow(CallDriverError);
    await expect(driver.acceptRenegotiation(outgoing(), sdp(2))).rejects.toThrow(CallDriverError);
  });
});
