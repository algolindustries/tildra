/**
 * The real media stack behind `CallDriver`'s `PeerConnection` interface.
 *
 * Everything in this file needs a device. It cannot run in the test suite,
 * which is exactly why the ordering and policy logic lives in
 * `call-driver.ts` behind an interface and is tested against a fake — this
 * file is deliberately as thin as it can be, because nothing in it is checked
 * by anything but a person holding a phone.
 *
 * Three things here are not boilerplate and are the reason it is not thinner.
 */

import {
  MediaStream,
  RTCIceCandidate,
  RTCPeerConnection,
  RTCSessionDescription,
  mediaDevices,
} from 'react-native-webrtc';

import { IceConfiguration, PeerConnection, PeerConnectionHandlers } from './call-driver';

export interface WebRtcPeer extends PeerConnection {
  /** The camera and microphone this device is sending. */
  readonly localStream: MediaStream | null;
  /** What the peer is sending, once any of it arrives. */
  readonly remoteStream: MediaStream | null;
  setMuted(muted: boolean): void;
  setCameraEnabled(enabled: boolean): void;
}

export interface WebRtcPeerOptions {
  config: IceConfiguration;
  handlers: PeerConnectionHandlers;
  video: boolean;
  onRemoteStream?: (stream: MediaStream) => void;
}

export async function createWebRtcPeer(options: WebRtcPeerOptions): Promise<WebRtcPeer> {
  const { config, handlers, video } = options;

  const pc = new RTCPeerConnection({
    iceServers: config.iceServers,
    iceTransportPolicy: config.iceTransportPolicy,
  });

  // Tracks are added before any offer or answer is created. An SDP built
  // without them has no media sections, so the fingerprint check downstream
  // would be verifying a description that carries no media — and the call
  // would connect silently to nothing.
  const localStream = await mediaDevices.getUserMedia({
    audio: true,
    video: video ? { facingMode: 'user' } : false,
  });
  for (const track of localStream.getTracks()) {
    pc.addTrack(track, localStream);
  }

  let remoteStream: MediaStream | null = null;
  let currentPolicy = config.iceTransportPolicy;
  let closed = false;

  // The library's typings describe these as `on*` properties with a loosely
  // typed event, so the shapes are narrowed here rather than asserted at each
  // use.
  pc.onicecandidate = ((event: { candidate: RTCIceCandidate | null }) => {
    // A null candidate is the end-of-gathering marker, not a candidate.
    if (!event.candidate?.candidate) return;
    handlers.onLocalCandidate(event.candidate.candidate);
  }) as never;

  pc.ontrack = ((event: { streams: MediaStream[] }) => {
    const [stream] = event.streams;
    if (!stream) return;
    remoteStream = stream;
    options.onRemoteStream?.(stream);
  }) as never;

  pc.onconnectionstatechange = (() => {
    if (closed) return;
    switch (pc.connectionState) {
      case 'connected':
        handlers.onConnected();
        return;
      case 'failed':
        handlers.onFailed('the connection failed');
        return;
      case 'disconnected':
        // Not a failure: ICE recovers from this on its own more often than
        // not, and ending a call on every tunnel change would make Tildra
        // unusable on a train.
        return;
      default:
        return;
    }
  }) as never;

  return {
    get localStream() {
      return localStream;
    },
    get remoteStream() {
      return remoteStream;
    },

    async createOffer(offerOptions: { video: boolean }): Promise<string> {
      const offer = await pc.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: offerOptions.video,
      });
      return offer.sdp;
    },

    async createAnswer(): Promise<string> {
      const answer = await pc.createAnswer();
      return answer.sdp;
    },

    async setLocalDescription(type: 'offer' | 'answer', sdp: string): Promise<void> {
      await pc.setLocalDescription(new RTCSessionDescription({ type, sdp }));
    },

    async setRemoteDescription(type: 'offer' | 'answer', sdp: string): Promise<void> {
      await pc.setRemoteDescription(new RTCSessionDescription({ type, sdp }));
    },

    async addIceCandidate(candidate: string): Promise<void> {
      await pc.addIceCandidate(new RTCIceCandidate({ candidate, sdpMid: '0', sdpMLineIndex: 0 }));
    },

    async setConfiguration(next: IceConfiguration): Promise<void> {
      pc.setConfiguration({
        iceServers: next.iceServers,
        iceTransportPolicy: next.iceTransportPolicy,
      });

      // Widening from relay-only to direct paths does not go back for the
      // candidates that were skipped, so the transport policy alone would
      // leave an answered call on the relay forever. restartIce() asks the
      // agent to gather again.
      //
      // INCOMPLETE, and worth knowing: an ICE restart changes the ufrag and
      // pwd, which strictly needs a fresh offer/answer, and `CallDriver` does
      // not model renegotiation. Until it does, what actually holds the
      // address policy is the send and receive filters in `SessionManager`,
      // not the agent. See docs/STATUS.md.
      if (currentPolicy === 'relay' && next.iceTransportPolicy === 'all') {
        pc.restartIce();
      }
      currentPolicy = next.iceTransportPolicy;
    },

    setMuted(muted: boolean): void {
      for (const track of localStream.getAudioTracks()) track.enabled = !muted;
    },

    setCameraEnabled(enabled: boolean): void {
      for (const track of localStream.getVideoTracks()) track.enabled = enabled;
    },

    close(): void {
      if (closed) return;
      closed = true;
      // Tracks first. Closing the peer connection does not release the
      // camera or the microphone on either platform, and a call that ends
      // with the microphone still live is the worst bug this file could
      // have.
      for (const track of localStream.getTracks()) track.stop();
      pc.close();
    },
  };
}
