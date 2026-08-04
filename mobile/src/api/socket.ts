/**
 * Real-time delivery socket.
 *
 * The token travels as a WebSocket subprotocol rather than a header because
 * React Native's WebSocket cannot set headers on the upgrade request. The
 * server reads it from `Sec-WebSocket-Protocol`.
 */

import { fromBase64 } from '../crypto/primitives';
import { assertUsableServerUrl } from '../crypto/scan';

export interface IncomingEnvelope {
  id: string;
  mailbox: string;
  ciphertext: Uint8Array;
  serverTs: string;
}

export interface SocketHandlers {
  onEnvelope: (envelope: IncomingEnvelope) => void | Promise<void>;
  onStateChange?: (state: SocketState) => void;
  onError?: (error: Error) => void;
}

export type SocketState = 'connecting' | 'open' | 'closed' | 'reconnecting';

/**
 * An error frame from the server, carrying words the server chose.
 *
 * A distinct type because the destination has to know. Everything reported
 * through `onError` ends up in a banner the app titles, and a plain `Error`
 * gets its message rendered as-is — which for this one is the server writing
 * under our heading. `describeError` attributes it instead. See `serverText`.
 */
export class ServerFrameError extends Error {}

/** Backoff schedule in ms. Caps at 30s — a phone that has been in a tunnel for
 *  an hour should reconnect promptly when it comes out, not sulk. */
const BACKOFF_MS = [0, 1_000, 2_000, 5_000, 10_000, 20_000, 30_000];

export class TildraSocket {
  private ws: WebSocket | null = null;
  private state: SocketState = 'closed';
  private attempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private closedByUs = false;
  /**
   * Envelopes handled successfully whose ack has not reached the server.
   *
   * Held until the send is on the wire, not until it is attempted: a socket
   * that dies between handling an envelope and acking it used to drop the
   * record, so the reconnect had nothing to replay and the server redelivered
   * a message the client had already stored.
   */
  private readonly pendingAcks = new Map<string, Set<string>>();
  /** Mailboxes added since connect, replayed after a reconnect. */
  private readonly subscribed = new Set<string>();
  /** Tail of the envelope-processing chain; see onmessage. */
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly handlers: SocketHandlers,
  ) {
    // The socket derives ws:// from http:// and wss:// from https://, so an
    // unchecked base URL here is the same hole as an unchecked one in the
    // client — and it is the connection that carries every delivered envelope.
    assertUsableServerUrl(baseUrl, 'the server address');
  }

  connect(): void {
    this.closedByUs = false;
    this.open();
  }

  private open(): void {
    this.setState(this.attempt === 0 ? 'connecting' : 'reconnecting');

    if (typeof WebSocket === 'undefined') {
      // React Native always provides one. Node only does from v22 — worth
      // saying out loud, because the alternative is a bare ReferenceError
      // from inside a reconnect timer.
      throw new Error('Tildra: no WebSocket implementation available (Node 22+ or React Native required)');
    }

    const url = `${this.baseUrl.replace(/^http/, 'ws').replace(/\/+$/, '')}/v1/ws`;
    // Two subprotocols: the version the server negotiates, and the credential
    // it reads but does not select.
    const ws = new WebSocket(url, ['tildra.v1', `bearer.${this.token}`]);
    this.ws = ws;

    ws.onopen = () => {
      this.attempt = 0;
      this.setState('open');
      if (this.subscribed.size > 0) {
        ws.send(JSON.stringify({ type: 'subscribe', mailboxes: [...this.subscribed] }));
      }
      // Re-ack anything whose ack did not make it out before the previous
      // socket died. Cleared only on a send that succeeded, so a second death
      // mid-replay leaves the record for the socket after it.
      for (const [mailbox, ids] of this.pendingAcks) {
        if (this.sendAck(mailbox, [...ids])) this.pendingAcks.delete(mailbox);
      }
    };

    ws.onmessage = (event: WebSocketMessageEvent) => {
      // A socket the caller has closed, or one a reconnect has already
      // replaced, must not keep delivering. `close()` returns before the
      // WebSocket finishes closing, so an envelope already in flight would
      // otherwise advance a ratchet, write session state and surface as a
      // message in an app that has torn that session down — after a logout,
      // say. A stale socket delivering into the session that replaced it is
      // the same hazard from the other direction.
      //
      // Dropping it loses nothing. The ack is sent only after the handler
      // succeeds, so an envelope that was never handled is still queued on
      // the server and arrives again on the next connect.
      if (this.closedByUs || this.ws !== ws) return;

      // Serialized, not fired in parallel. Each envelope advances a ratchet
      // and writes the result back, so two handlers running concurrently read
      // the same state and one of them overwrites the other — the message is
      // lost and the session can end up wedged. Ordering also matters on its
      // own: the ratchet expects the chain in sequence.
      this.queue = this.queue.then(() => this.handleMessage(event.data)).catch((err) => {
        this.handlers.onError?.(err instanceof Error ? err : new Error(String(err)));
      });
    };

    ws.onerror = () => {
      // A socket we closed on purpose still fires this, and reporting it would
      // surface a spurious error every time the user logs out or the app is
      // backgrounded.
      if (this.closedByUs) return;
      // The error event carries nothing useful in React Native; onclose
      // follows immediately and carries the reason.
      this.handlers.onError?.(new Error('Tildra: socket error'));
    };

    ws.onclose = () => {
      this.ws = null;
      if (this.closedByUs) {
        this.setState('closed');
        return;
      }
      this.scheduleReconnect();
    };
  }

  private async handleMessage(data: unknown): Promise<void> {
    if (typeof data !== 'string') return;

    let frame: { type?: string; envelope?: { id: string; mailbox: string; ciphertext: string; serverTs: string }; error?: string };
    try {
      frame = JSON.parse(data);
    } catch {
      this.handlers.onError?.(new Error('Tildra: malformed frame from server'));
      return;
    }

    if (frame.type === 'error') {
      this.handlers.onError?.(new ServerFrameError(frame.error ?? 'server error'));
      return;
    }
    if (frame.type !== 'message' || !frame.envelope) return;

    const envelope: IncomingEnvelope = {
      id: frame.envelope.id,
      mailbox: frame.envelope.mailbox,
      ciphertext: fromBase64(frame.envelope.ciphertext),
      serverTs: frame.envelope.serverTs,
    };

    try {
      await this.handlers.onEnvelope(envelope);
    } catch (err) {
      // Delivery failed locally — leave it unacked so the server redelivers
      // on the next connect. Acking here would lose the message permanently,
      // which is also why nothing is recorded as pending until the handler
      // has returned: a pending ack replayed on reconnect would ack an
      // envelope whose handler was still running, or had since failed.
      this.handlers.onError?.(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    this.ack(envelope);
  }

  private track(envelope: IncomingEnvelope): void {
    let set = this.pendingAcks.get(envelope.mailbox);
    if (!set) {
      set = new Set();
      this.pendingAcks.set(envelope.mailbox, set);
    }
    set.add(envelope.id);
  }

  private untrack(envelope: IncomingEnvelope): void {
    const set = this.pendingAcks.get(envelope.mailbox);
    set?.delete(envelope.id);
    if (set && set.size === 0) this.pendingAcks.delete(envelope.mailbox);
  }

  /**
   * Start listening on mailboxes created after this socket opened.
   *
   * Every new conversation derives a new mailbox. Without this the socket
   * keeps serving the addresses it knew at connect time, and messages from
   * anyone met since would sit in the queue until the next reconnect.
   *
   * Remembered so a reconnect re-subscribes; the server also re-reads the
   * stored list on connect, so this is belt and braces.
   */
  subscribe(mailboxes: string[]): void {
    for (const mailbox of mailboxes) this.subscribed.add(mailbox);
    if (this.ws?.readyState !== 1) return;
    this.ws.send(JSON.stringify({ type: 'subscribe', mailboxes }));
  }

  /** Tell the server the envelope is safely stored, so it can destroy it. */
  private ack(envelope: IncomingEnvelope): void {
    this.track(envelope);
    if (this.sendAck(envelope.mailbox, [envelope.id])) this.untrack(envelope);
  }

  /** Reports whether the frame actually went out, which `ack` depends on. */
  private sendAck(mailbox: string, ids: string[]): boolean {
    if (!ids.length || this.ws?.readyState !== 1) return false;
    this.ws.send(JSON.stringify({ type: 'ack', mailbox, ids }));
    return true;
  }

  private scheduleReconnect(): void {
    this.setState('reconnecting');
    const delay = BACKOFF_MS[Math.min(this.attempt, BACKOFF_MS.length - 1)];
    this.attempt += 1;
    this.reconnectTimer = setTimeout(() => this.open(), delay);
  }

  private setState(state: SocketState): void {
    if (this.state === state) return;
    this.state = state;
    this.handlers.onStateChange?.(state);
  }

  get currentState(): SocketState {
    return this.state;
  }

  close(): void {
    this.closedByUs = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
    this.setState('closed');
  }
}
