import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { IceConfiguration, PeerConnectionHandlers } from '../call-driver';

/**
 * The real media adapter, against a double of `react-native-webrtc`.
 *
 * **What this cannot tell you.** No media flows here, no device is involved,
 * and the library is not exercised — if `react-native-webrtc` behaves
 * differently from the fake below, these tests pass and a call still fails.
 * The header of `webrtc-peer.ts` said this file "cannot run in the test
 * suite", and that was true of the media and false of the logic.
 *
 * **What it does tell you.** The adapter is thin, but it is not empty: it
 * decides when to re-gather candidates, what counts as a candidate, which
 * connection states end a call, and in what order a call is torn down. Each
 * of those is a rule with a wrong answer that a phone would show as something
 * vague — a call stuck on the relay, a call that drops on a tunnel change, a
 * microphone still live after hanging up. Those are the rules pinned here.
 *
 * The fake is written against the same shapes the adapter calls, so a
 * signature change in the library shows up as a typecheck failure in
 * `webrtc-peer.ts` rather than a silently diverging double.
 */

const rtc = vi.hoisted(() => {
  class FakeTrack {
    enabled = true;
    stopped = false;
    constructor(
      readonly kind: 'audio' | 'video',
      private readonly log: string[],
    ) {}
    stop(): void {
      this.stopped = true;
      this.log.push(`stop:${this.kind}`);
    }
  }

  class FakeStream {
    readonly tracks: FakeTrack[];
    constructor(kinds: ('audio' | 'video')[], log: string[]) {
      this.tracks = kinds.map((kind) => new FakeTrack(kind, log));
    }
    getTracks(): FakeTrack[] {
      return this.tracks;
    }
    getAudioTracks(): FakeTrack[] {
      return this.tracks.filter((t) => t.kind === 'audio');
    }
    getVideoTracks(): FakeTrack[] {
      return this.tracks.filter((t) => t.kind === 'video');
    }
  }

  interface Description {
    type: string;
    sdp: string;
  }

  class FakePeerConnection {
    static last: FakePeerConnection | null = null;

    connectionState = 'new';
    onicecandidate: ((event: { candidate: unknown }) => void) | null = null;
    ontrack: ((event: { streams: unknown[] }) => void) | null = null;
    onconnectionstatechange: (() => void) | null = null;

    readonly addedTracks: { track: FakeTrack; stream: FakeStream }[] = [];
    readonly configurations: unknown[] = [];
    readonly offerOptions: Record<string, unknown>[] = [];
    readonly localDescriptions: Description[] = [];
    readonly remoteDescriptions: Description[] = [];
    readonly candidates: unknown[] = [];
    restartIceCalls = 0;
    closed = 0;
    /** How many tracks had been added by the time an SDP was first built. */
    tracksWhenSdpBuilt: number | null = null;

    constructor(
      readonly initialConfig: unknown,
      private readonly log: string[],
    ) {
      FakePeerConnection.last = this;
    }

    addTrack(track: FakeTrack, stream: FakeStream): void {
      this.addedTracks.push({ track, stream });
      this.log.push(`addTrack:${track.kind}`);
    }

    private noteSdpBuilt(): void {
      if (this.tracksWhenSdpBuilt === null) this.tracksWhenSdpBuilt = this.addedTracks.length;
    }

    async createOffer(options: Record<string, unknown>): Promise<Description> {
      this.noteSdpBuilt();
      this.offerOptions.push(options);
      this.log.push('createOffer');
      return { type: 'offer', sdp: `offer-sdp-${this.offerOptions.length}` };
    }

    async createAnswer(): Promise<Description> {
      this.noteSdpBuilt();
      this.log.push('createAnswer');
      return { type: 'answer', sdp: 'answer-sdp' };
    }

    async setLocalDescription(description: Description): Promise<void> {
      this.localDescriptions.push(description);
    }

    async setRemoteDescription(description: Description): Promise<void> {
      this.remoteDescriptions.push(description);
    }

    async addIceCandidate(candidate: unknown): Promise<void> {
      this.candidates.push(candidate);
    }

    setConfiguration(config: unknown): void {
      this.configurations.push(config);
      this.log.push('setConfiguration');
    }

    restartIce(): void {
      this.restartIceCalls += 1;
      this.log.push('restartIce');
    }

    close(): void {
      this.closed += 1;
      this.log.push('pc.close');
    }
  }

  const state = {
    log: [] as string[],
    getUserMedia: [] as { audio: unknown; video: unknown }[],
    stream: null as FakeStream | null,
  };

  return { FakeTrack, FakeStream, FakePeerConnection, state };
});

vi.mock('react-native-webrtc', () => ({
  MediaStream: rtc.FakeStream,
  RTCPeerConnection: class {
    constructor(config: unknown) {
      return new rtc.FakePeerConnection(config, rtc.state.log) as never;
    }
  },
  RTCSessionDescription: class {
    constructor(init: { type: string; sdp: string }) {
      return { ...init } as never;
    }
  },
  RTCIceCandidate: class {
    constructor(init: Record<string, unknown>) {
      return { ...init } as never;
    }
  },
  mediaDevices: {
    async getUserMedia(constraints: { audio: unknown; video: unknown }) {
      rtc.state.getUserMedia.push(constraints);
      const kinds: ('audio' | 'video')[] = constraints.video ? ['audio', 'video'] : ['audio'];
      rtc.state.stream = new rtc.FakeStream(kinds, rtc.state.log);
      return rtc.state.stream;
    },
  },
}));

const { createWebRtcPeer } = await import('../webrtc-peer');

const RELAY_ONLY: IceConfiguration = {
  iceServers: [{ urls: ['turn:relay.example:3478'], username: 'u', credential: 'p' }],
  iceTransportPolicy: 'relay',
  relayAvailable: true,
};

const DIRECT: IceConfiguration = {
  iceServers: [{ urls: ['stun:stun.example:3478'] }],
  iceTransportPolicy: 'all',
  relayAvailable: false,
};

function recordingHandlers(): PeerConnectionHandlers & {
  candidates: string[];
  connected: number;
  failures: string[];
} {
  const seen = {
    candidates: [] as string[],
    connected: 0,
    failures: [] as string[],
    onLocalCandidate(candidate: string) {
      seen.candidates.push(candidate);
    },
    onConnected() {
      seen.connected += 1;
    },
    onFailed(reason: string) {
      seen.failures.push(reason);
    },
  };
  return seen;
}

async function makePeer(options: { video?: boolean; config?: IceConfiguration } = {}) {
  const handlers = recordingHandlers();
  const streams: unknown[] = [];
  const peer = await createWebRtcPeer({
    config: options.config ?? RELAY_ONLY,
    handlers,
    video: options.video ?? false,
    onRemoteStream: (stream) => streams.push(stream),
  });
  const pc = rtc.FakePeerConnection.last!;
  return { peer, pc, handlers, streams };
}

beforeEach(() => {
  rtc.state.log.length = 0;
  rtc.state.getUserMedia.length = 0;
  rtc.state.stream = null;
  rtc.FakePeerConnection.last = null;
});

describe('setting the call up', () => {
  it('hands the connection the configuration it was given', async () => {
    const { pc } = await makePeer({ config: RELAY_ONLY });
    expect(pc.initialConfig).toEqual({
      iceServers: RELAY_ONLY.iceServers,
      iceTransportPolicy: 'relay',
    });
  });

  it('adds the tracks before any SDP is built', async () => {
    // An offer built with no media sections has no fingerprint to bind and no
    // media to carry, and the call connects silently to nothing. The ordering
    // is the whole reason getUserMedia is awaited in the constructor rather
    // than alongside the first offer.
    const { peer, pc } = await makePeer({ video: true });
    expect(pc.tracksWhenSdpBuilt).toBeNull();

    await peer.createOffer({ video: true });
    expect(pc.tracksWhenSdpBuilt).toBe(2);
    expect(rtc.state.log.indexOf('createOffer')).toBeGreaterThan(
      rtc.state.log.lastIndexOf('addTrack:video'),
    );
  });

  it('asks for the camera only for a video call', async () => {
    await makePeer({ video: false });
    expect(rtc.state.getUserMedia).toEqual([{ audio: true, video: false }]);
    expect(rtc.state.stream!.getVideoTracks()).toHaveLength(0);

    rtc.state.getUserMedia.length = 0;
    await makePeer({ video: true });
    expect(rtc.state.getUserMedia).toEqual([{ audio: true, video: { facingMode: 'user' } }]);
    expect(rtc.state.stream!.getVideoTracks()).toHaveLength(1);
  });

  it('exposes the local stream and has no remote stream yet', async () => {
    const { peer } = await makePeer();
    expect(peer.localStream).toBe(rtc.state.stream);
    expect(peer.remoteStream).toBeNull();
  });
});

describe('what reaches the signalling layer', () => {
  it('forwards a candidate', async () => {
    const { pc, handlers } = await makePeer();
    pc.onicecandidate!({ candidate: { candidate: 'candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host' } });
    expect(handlers.candidates).toEqual([
      'candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host',
    ]);
  });

  it('does not forward the end-of-gathering marker', async () => {
    // A null candidate means gathering finished. Sent as a candidate it is a
    // signalling message the peer cannot parse, and on the receiving side it
    // is an error on a call that is otherwise fine.
    const { pc, handlers } = await makePeer();
    pc.onicecandidate!({ candidate: null });
    pc.onicecandidate!({ candidate: { candidate: '' } });
    expect(handlers.candidates).toEqual([]);
  });

  it('reports a remote stream once, and ignores an event carrying none', async () => {
    const { peer, pc, streams } = await makePeer();
    pc.ontrack!({ streams: [] });
    expect(peer.remoteStream).toBeNull();
    expect(streams).toEqual([]);

    const remote = { id: 'remote' };
    pc.ontrack!({ streams: [remote] });
    expect(peer.remoteStream).toBe(remote);
    expect(streams).toEqual([remote]);
  });
});

describe('which connection states end a call', () => {
  it('reports connected and failed', async () => {
    const { pc, handlers } = await makePeer();
    pc.connectionState = 'connected';
    pc.onconnectionstatechange!();
    expect(handlers.connected).toBe(1);

    pc.connectionState = 'failed';
    pc.onconnectionstatechange!();
    expect(handlers.failures).toEqual(['the connection failed']);
  });

  it('treats disconnected as recoverable', async () => {
    // ICE recovers from `disconnected` on its own more often than not. Ending
    // the call on it would drop every call that crosses a tunnel change, and
    // the user would read that as Tildra being unreliable on a train.
    const { pc, handlers } = await makePeer();
    for (const state of ['connecting', 'disconnected', 'new', 'closed']) {
      pc.connectionState = state;
      pc.onconnectionstatechange!();
    }
    expect(handlers.connected).toBe(0);
    expect(handlers.failures).toEqual([]);
  });

  it('says nothing after the call is closed', async () => {
    // The library fires a state change while tearing down. A `failed` arriving
    // after close would end a call that has already ended — visible as the
    // next call being killed by the previous one's teardown.
    const { peer, pc, handlers } = await makePeer();
    peer.close();
    pc.connectionState = 'failed';
    pc.onconnectionstatechange!();
    pc.connectionState = 'connected';
    pc.onconnectionstatechange!();
    expect(handlers.failures).toEqual([]);
    expect(handlers.connected).toBe(0);
  });
});

describe('widening the address policy', () => {
  it('re-gathers when relay-only opens up to direct paths', async () => {
    // This is the hazard `docs/STATUS.md` flags: setConfiguration alone does
    // not go back for the host candidates skipped while relay-only, so an
    // answered call sits on the relay forever with nothing indicating
    // anything is wrong.
    const { peer, pc } = await makePeer({ config: RELAY_ONLY });
    await peer.setConfiguration(DIRECT);

    expect(pc.configurations).toEqual([
      { iceServers: DIRECT.iceServers, iceTransportPolicy: 'all' },
    ]);
    expect(pc.restartIceCalls).toBe(1);
    expect(rtc.state.log.indexOf('setConfiguration')).toBeLessThan(
      rtc.state.log.indexOf('restartIce'),
    );
  });

  it('does not re-gather when the policy did not widen', async () => {
    // A restart the agent did not need costs a round of gathering and a fresh
    // set of credentials mid-call.
    const cases: [IceConfiguration, IceConfiguration][] = [
      [RELAY_ONLY, RELAY_ONLY],
      [DIRECT, DIRECT],
      [DIRECT, RELAY_ONLY],
    ];
    for (const [from, to] of cases) {
      rtc.state.log.length = 0;
      const { peer, pc } = await makePeer({ config: from });
      await peer.setConfiguration(to);
      expect(pc.restartIceCalls, `${from.iceTransportPolicy} -> ${to.iceTransportPolicy}`).toBe(0);
    }
  });

  it('widens once, not on every later call', async () => {
    const { peer, pc } = await makePeer({ config: RELAY_ONLY });
    await peer.setConfiguration(DIRECT);
    await peer.setConfiguration(DIRECT);
    expect(pc.restartIceCalls).toBe(1);
  });

  it('re-gathers again if the policy narrows and widens a second time', async () => {
    const { peer, pc } = await makePeer({ config: RELAY_ONLY });
    await peer.setConfiguration(DIRECT);
    await peer.setConfiguration(RELAY_ONLY);
    await peer.setConfiguration(DIRECT);
    expect(pc.restartIceCalls).toBe(2);
  });
});

describe('the descriptions it builds', () => {
  it('passes the ice restart flag through to the offer', async () => {
    const { peer, pc } = await makePeer();
    await peer.createOffer({ video: false });
    await peer.createOffer({ video: true, iceRestart: true });
    expect(pc.offerOptions).toEqual([
      { offerToReceiveAudio: true, offerToReceiveVideo: false, iceRestart: false },
      { offerToReceiveAudio: true, offerToReceiveVideo: true, iceRestart: true },
    ]);
  });

  it('returns the SDP rather than the description object', async () => {
    const { peer } = await makePeer();
    expect(await peer.createOffer({ video: false })).toBe('offer-sdp-1');
    expect(await peer.createAnswer()).toBe('answer-sdp');
  });

  it('sets descriptions with the type it was told', async () => {
    const { peer, pc } = await makePeer();
    await peer.setLocalDescription('offer', 'local-sdp');
    await peer.setRemoteDescription('answer', 'remote-sdp');
    expect(pc.localDescriptions).toEqual([{ type: 'offer', sdp: 'local-sdp' }]);
    expect(pc.remoteDescriptions).toEqual([{ type: 'answer', sdp: 'remote-sdp' }]);
  });

  it('applies a remote candidate to the bundled transport', async () => {
    // sdpMid '0' and index 0 assume every call is BUNDLE-ed onto one
    // transport, which is what the offers built here negotiate. Pinned
    // because a call that stops bundling would make these the wrong answer
    // silently — the candidate would be applied to a transport that is not
    // carrying the media.
    const { peer, pc } = await makePeer();
    await peer.addIceCandidate('candidate:2 1 udp 1 1.2.3.4 5 typ srflx');
    expect(pc.candidates).toEqual([
      { candidate: 'candidate:2 1 udp 1 1.2.3.4 5 typ srflx', sdpMid: '0', sdpMLineIndex: 0 },
    ]);
  });
});

describe('mute and camera', () => {
  it('mutes only the microphone', async () => {
    const { peer } = await makePeer({ video: true });
    peer.setMuted(true);
    expect(rtc.state.stream!.getAudioTracks().every((t) => !t.enabled)).toBe(true);
    expect(rtc.state.stream!.getVideoTracks().every((t) => t.enabled)).toBe(true);

    peer.setMuted(false);
    expect(rtc.state.stream!.getAudioTracks().every((t) => t.enabled)).toBe(true);
  });

  it('turns the camera off without muting', async () => {
    const { peer } = await makePeer({ video: true });
    peer.setCameraEnabled(false);
    expect(rtc.state.stream!.getVideoTracks().every((t) => !t.enabled)).toBe(true);
    expect(rtc.state.stream!.getAudioTracks().every((t) => t.enabled)).toBe(true);
  });

  it('does nothing rather than throwing when there is no camera', async () => {
    const { peer } = await makePeer({ video: false });
    expect(() => peer.setCameraEnabled(true)).not.toThrow();
  });
});

describe('hanging up', () => {
  it('stops the tracks before closing the connection', async () => {
    // Closing the peer connection does not release the camera or the
    // microphone on either platform. A call that ends with the microphone
    // still live is the worst bug this file could have, and the order is the
    // only thing preventing it.
    const { peer } = await makePeer({ video: true });
    peer.close();

    const closedAt = rtc.state.log.indexOf('pc.close');
    expect(closedAt).toBeGreaterThan(-1);
    expect(rtc.state.log.indexOf('stop:audio')).toBeLessThan(closedAt);
    expect(rtc.state.log.indexOf('stop:video')).toBeLessThan(closedAt);
    expect(rtc.state.stream!.getTracks().every((t) => t.stopped)).toBe(true);
  });

  it('is safe to call twice', async () => {
    const { peer, pc } = await makePeer();
    peer.close();
    peer.close();
    expect(pc.closed).toBe(1);
  });
});
