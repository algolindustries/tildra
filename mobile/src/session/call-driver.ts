/**
 * Driving one call: the sequence of peer-connection operations, and the
 * ordering hazards that come with them.
 *
 * Everything security-relevant about a call already happened before this file
 * runs — the fingerprint is bound to the identity key in `crypto/calling.ts`
 * and checked by `SessionManager` before a phone rings. What is left is
 * ordering, and ordering is where WebRTC code goes wrong quietly:
 *
 * - **A remote ICE candidate can arrive before the description it belongs
 *   to.** Signalling is a race: the peer sends its offer and then starts
 *   gathering, and nothing keeps those two in order across a network. A
 *   candidate added before `setRemoteDescription` is rejected, and the usual
 *   result is a call that connects over the relay when a direct path existed,
 *   or does not connect at all. So they are buffered and flushed.
 * - **Local candidates are gathered before the call has an id.** The peer
 *   connection starts producing them the moment the local description is set,
 *   which is before `placeCall` has returned. Dropping those is the same bug
 *   from the other side.
 * - **The address policy changes mid-call.** An incoming call gathers
 *   relay-only while it rings and direct paths once it is answered. That is
 *   not a preference; it is the reason an unanswered call cannot be used to
 *   find out where someone is, and it has to be applied to the live peer
 *   connection at the moment the user accepts.
 *
 * The peer connection is an interface rather than `RTCPeerConnection` so this
 * logic can be tested. A media stack cannot run headlessly; this can.
 */

import {
  CallEndReason,
  CallSession,
  IceConfiguration,
  IceTransportPolicy,
} from '../crypto/calling';

// Re-exported so an adapter implementing `PeerConnection` has one import.
export type { IceConfiguration } from '../crypto/calling';

export class CallDriverError extends Error {}

/** The part of a peer connection this driver uses. */
export interface PeerConnection {
  createOffer(options: { video: boolean }): Promise<string>;
  createAnswer(): Promise<string>;
  setLocalDescription(type: 'offer' | 'answer', sdp: string): Promise<void>;
  setRemoteDescription(type: 'offer' | 'answer', sdp: string): Promise<void>;
  addIceCandidate(candidate: string): Promise<void>;
  /**
   * Apply a new ICE configuration to a live connection.
   *
   * The implementation **must re-gather** — an ICE restart — when the policy
   * widens from `relay` to `all`. `RTCPeerConnection.setConfiguration` on its
   * own changes the policy for future gathering and does not go back for the
   * host candidates it skipped while relay-only, so an answered call would
   * stay on the relay forever with no sign anything was wrong.
   */
  setConfiguration(config: IceConfiguration): Promise<void>;
  close(): void;
}

export interface PeerConnectionHandlers {
  onLocalCandidate: (candidate: string) => void;
  onConnected: () => void;
  onFailed: (reason: string) => void;
}

/**
 * What the driver needs from the session layer.
 *
 * `SessionManager` satisfies this structurally, and `call-driver.test.ts`
 * asserts that at compile time — an interface that drifts from the class it
 * describes is a double that tests something nothing runs.
 */
export interface CallSignalling {
  placeCall(accountId: string, params: { sdp: string; video?: boolean }): Promise<CallSession>;
  answerCall(callId: string, sdp: string): Promise<CallSession>;
  sendCallCandidate(callId: string, candidate: string): Promise<boolean>;
  markCallConnected(callId: string): CallSession;
  endCall(callId: string, reason?: CallEndReason): Promise<void>;
  iceConfiguration(target: CallSession | IceTransportPolicy): Promise<IceConfiguration>;
}

export interface CallDriverDeps {
  signalling: CallSignalling;
  createPeerConnection(
    config: IceConfiguration,
    handlers: PeerConnectionHandlers,
  ): Promise<PeerConnection>;
  onError?: (error: Error) => void;
}

export class CallDriver {
  private readonly deps: CallDriverDeps;
  private readonly pc: PeerConnection;
  private session: CallSession;

  /** Remote candidates that arrived before there was a description to attach them to. */
  private pendingRemote: string[] = [];
  private remoteDescriptionSet = false;

  private closed = false;

  private constructor(deps: CallDriverDeps, pc: PeerConnection, session: CallSession) {
    this.deps = deps;
    this.pc = pc;
    this.session = session;
  }

  get call(): CallSession {
    return this.session;
  }

  /** Whether the relay is reachable — false means a relay-only phase gathers nothing. */
  relayAvailable = true;

  /**
   * What the peer connection reports, bound to this call.
   *
   * Public because the setup buffer replays into it once the driver exists;
   * nothing else should call these.
   */
  handlers(): PeerConnectionHandlers {
    return {
      onLocalCandidate: (candidate) => {
        if (this.closed) return;
        void this.sendLocal(candidate);
      },
      onConnected: () => {
        if (this.closed) return;
        try {
          this.session = this.deps.signalling.markCallConnected(this.session.callId);
        } catch (err) {
          this.deps.onError?.(err instanceof Error ? err : new Error(String(err)));
        }
      },
      onFailed: (reason) => {
        if (this.closed) return;
        this.deps.onError?.(new CallDriverError(`the call failed: ${reason}`));
        void this.hangUp('failed');
      },
    };
  }

  // -------------------------------------------------------------------------
  // Starting
  // -------------------------------------------------------------------------

  /**
   * Place a call.
   *
   * The peer connection has to exist before there is a call, because the offer
   * comes out of it. An outgoing call is never relay-only — the caller already
   * chose to reveal themselves to this person — so its policy is known without
   * a session to ask about.
   */
  static async place(
    deps: CallDriverDeps,
    accountId: string,
    params: { video?: boolean } = {},
  ): Promise<CallDriver> {
    const config = await deps.signalling.iceConfiguration('all');
    const setup = new Setup();
    const pc = await deps.createPeerConnection(config, setup.handlers());

    try {
      const sdp = await pc.createOffer({ video: params.video ?? false });
      await pc.setLocalDescription('offer', sdp);
      // Gathering starts here, before placeCall has returned a call id. Those
      // candidates are held by `setup` rather than dropped.
      const session = await deps.signalling.placeCall(accountId, { sdp, video: params.video });

      const driver = new CallDriver(deps, pc, session);
      driver.relayAvailable = config.relayAvailable;
      setup.handOver(driver);
      return driver;
    } catch (err) {
      // A peer connection left open after a failed start is a live microphone
      // nobody is watching.
      pc.close();
      throw err;
    }
  }

  /**
   * Take an incoming call that `SessionManager` has already verified.
   *
   * The offer's fingerprint was checked against the caller's identity key
   * before this was reached — an offer that failed that check never gets here,
   * and never rings.
   */
  static async receive(
    deps: CallDriverDeps,
    session: CallSession,
    offerSdp: string,
  ): Promise<CallDriver> {
    const config = await deps.signalling.iceConfiguration(session);
    const setup = new Setup();
    const pc = await deps.createPeerConnection(config, setup.handlers());

    try {
      const driver = new CallDriver(deps, pc, session);
      driver.relayAvailable = config.relayAvailable;
      await pc.setRemoteDescription('offer', offerSdp);
      driver.remoteDescriptionSet = true;
      await driver.flushRemote();
      setup.handOver(driver);
      return driver;
    } catch (err) {
      pc.close();
      throw err;
    }
  }

  // -------------------------------------------------------------------------
  // Progress
  // -------------------------------------------------------------------------

  /**
   * Pick up.
   *
   * The configuration is replaced before the answer goes out. Until this
   * moment the connection was relay-only so that a call the user never
   * answered could not reveal where they are; from here direct paths are
   * allowed, because the user has chosen to talk to this person.
   */
  async accept(): Promise<CallSession> {
    this.assertOpen();

    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription('answer', answer);

    this.session = await this.deps.signalling.answerCall(this.session.callId, answer);

    const config = await this.deps.signalling.iceConfiguration(this.session);
    this.relayAvailable = config.relayAvailable;
    await this.pc.setConfiguration(config);

    return this.session;
  }

  /** The peer picked up; their SDP is theirs to install. */
  async acceptAnswer(session: CallSession, answerSdp: string): Promise<void> {
    this.assertOpen();
    this.session = session;

    await this.pc.setRemoteDescription('answer', answerSdp);
    this.remoteDescriptionSet = true;
    await this.flushRemote();
  }

  /**
   * A candidate from the peer.
   *
   * Buffered until there is a remote description. This is the ordering hazard
   * that costs a direct path when it is got wrong, and it is silent: the call
   * still connects, over the relay, a little slower.
   */
  async addRemoteCandidate(candidate: string): Promise<void> {
    if (this.closed) return;
    if (!this.remoteDescriptionSet) {
      this.pendingRemote.push(candidate);
      return;
    }
    await this.pc.addIceCandidate(candidate);
  }

  async hangUp(reason: CallEndReason = 'hangup'): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    // Closed first: whatever happens to the signalling message, the media
    // stops. A hangup that failed to send must not leave a call running.
    this.pc.close();
    await this.deps.signalling.endCall(this.session.callId, reason);
  }

  // -------------------------------------------------------------------------
  // Callbacks from the peer connection
  // -------------------------------------------------------------------------

  private async sendLocal(candidate: string): Promise<void> {
    try {
      // The manager applies the address policy: a candidate the policy
      // withholds returns false and is not an error.
      await this.deps.signalling.sendCallCandidate(this.session.callId, candidate);
    } catch (err) {
      this.deps.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
  }

  // -------------------------------------------------------------------------
  // Buffers
  // -------------------------------------------------------------------------

  private async flushRemote(): Promise<void> {
    const queued = this.pendingRemote;
    this.pendingRemote = [];
    for (const candidate of queued) {
      if (this.closed) return;
      await this.pc.addIceCandidate(candidate);
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new CallDriverError(`call ${this.session.callId} is already over`);
    }
  }
}

/**
 * Holds what the peer connection reports before the driver exists.
 *
 * There is an unavoidable gap: the connection must be built before there is a
 * call to attach it to, and it starts talking immediately. Handlers that
 * checked `driver?.` and did nothing when it was null would drop exactly the
 * candidates gathered fastest — the local ones, on the fast network, which are
 * the ones that would have given a direct path.
 */
class Setup {
  private candidates: string[] = [];
  private connected = false;
  private failure: string | null = null;
  private sink: PeerConnectionHandlers | null = null;

  handlers(): PeerConnectionHandlers {
    return {
      onLocalCandidate: (candidate) => {
        if (this.sink) this.sink.onLocalCandidate(candidate);
        else this.candidates.push(candidate);
      },
      onConnected: () => {
        if (this.sink) this.sink.onConnected();
        else this.connected = true;
      },
      onFailed: (reason) => {
        if (this.sink) this.sink.onFailed(reason);
        else this.failure = reason;
      },
    };
  }

  handOver(driver: CallDriver): void {
    const sink = driver.handlers();
    this.sink = sink;

    const queued = this.candidates;
    this.candidates = [];
    for (const candidate of queued) sink.onLocalCandidate(candidate);

    // Order matters: a connection that came up and then failed during setup
    // is a failed call, not a connected one.
    if (this.connected) sink.onConnected();
    if (this.failure !== null) sink.onFailed(this.failure);
  }
}
