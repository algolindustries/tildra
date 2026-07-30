import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { TildraSocket, type SocketState } from '../socket';
import type { IncomingEnvelope } from '../socket';
import { toBase64, utf8 } from '../../crypto/primitives';

/**
 * The socket's lifecycle, against a fake WebSocket.
 *
 * `integration.test.ts` drives this class against the real server and proves
 * the happy path carries traffic. What it cannot do is put the socket in the
 * states that only happen when something goes wrong — closed mid-delivery,
 * replaced by a reconnect, handed a frame that does not parse — because those
 * are races, and a test that has to win a race to be meaningful is a test that
 * quietly stops meaning anything on a slow machine. Everything here is exact.
 *
 * `WebSocket` is read off the global, so substituting one is all it takes.
 */

interface Sent {
  type: string;
  mailbox?: string;
  ids?: string[];
  mailboxes?: string[];
}

class FakeWebSocket {
  static open: FakeWebSocket[] = [];

  readyState = 0;
  readonly sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  closeCalls = 0;

  constructor(
    readonly url: string,
    readonly protocols: string[],
  ) {
    FakeWebSocket.open.push(this);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.closeCalls += 1;
    this.readyState = 3;
  }

  // --- driving it from a test ---

  accept(): void {
    this.readyState = 1;
    this.onopen?.();
  }

  deliver(envelope: { id: string; mailbox: string; text: string }): void {
    this.onmessage?.({
      data: JSON.stringify({
        type: 'message',
        envelope: {
          id: envelope.id,
          mailbox: envelope.mailbox,
          ciphertext: toBase64(utf8(envelope.text)),
          serverTs: '2026-07-30T00:00:00Z',
        },
      }),
    });
  }

  raw(data: unknown): void {
    this.onmessage?.({ data });
  }

  /** A real WebSocket fires onclose once; the fake refuses to pretend twice. */
  drop(): void {
    if (this.readyState === 3) throw new Error('this socket has already closed');
    this.readyState = 3;
    this.onclose?.();
  }

  frames(): Sent[] {
    return this.sent.map((s) => JSON.parse(s) as Sent);
  }
}

const TOKEN = 'tok';

function connectSocket(
  handlers: {
    onEnvelope?: (e: IncomingEnvelope) => Promise<void> | void;
    onError?: (e: Error) => void;
  } = {},
) {
  const received: IncomingEnvelope[] = [];
  const errors: Error[] = [];
  const states: SocketState[] = [];
  const socket = new TildraSocket('http://server.test', TOKEN, {
    onEnvelope: async (envelope) => {
      received.push(envelope);
      await handlers.onEnvelope?.(envelope);
    },
    onError: (error) => {
      errors.push(error);
      handlers.onError?.(error);
    },
    onStateChange: (state) => states.push(state),
  });
  socket.connect();
  return { socket, received, errors, states, ws: () => FakeWebSocket.open.at(-1)! };
}

/** The socket serialises delivery through a promise chain; let it drain. */
async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
}

beforeEach(() => {
  FakeWebSocket.open = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('connecting', () => {
  it('carries the version and the credential as subprotocols', () => {
    const { ws } = connectSocket();
    expect(ws().url).toBe('ws://server.test/v1/ws');
    expect(ws().protocols).toEqual(['tildra.v1', `bearer.${TOKEN}`]);
  });

  it('reports connecting then open', () => {
    const { states, ws } = connectSocket();
    expect(states).toEqual(['connecting']);
    ws().accept();
    expect(states).toEqual(['connecting', 'open']);
  });
});

describe('delivery', () => {
  it('hands over an envelope and acks it', async () => {
    const { received, ws } = connectSocket();
    ws().accept();
    ws().deliver({ id: 'e1', mailbox: 'mb_a', text: 'merhaba' });
    await settle();

    expect(received.map((e) => e.id)).toEqual(['e1']);
    expect(ws().frames()).toEqual([{ type: 'ack', mailbox: 'mb_a', ids: ['e1'] }]);
  });

  it('leaves an envelope unacked when the handler throws', async () => {
    // Acking here would destroy the message on the server while the client
    // failed to store it. Unacked means it comes back on the next connect.
    const { errors, ws } = connectSocket({
      onEnvelope: () => {
        throw new Error('vault locked');
      },
    });
    ws().accept();
    ws().deliver({ id: 'e1', mailbox: 'mb_a', text: 'merhaba' });
    await settle();

    expect(ws().frames()).toEqual([]);
    expect(errors.map((e) => e.message)).toEqual(['vault locked']);
  });

  it('processes envelopes one at a time', async () => {
    // Two handlers running at once read the same ratchet state and one
    // overwrites the other, which loses a message and can wedge the session.
    const order: string[] = [];
    let releaseFirst: (() => void) | undefined;
    const { ws } = connectSocket({
      onEnvelope: (envelope) => {
        order.push(`start:${envelope.id}`);
        if (envelope.id === 'e1') {
          return new Promise<void>((resolve) => {
            releaseFirst = () => {
              order.push('end:e1');
              resolve();
            };
          });
        }
        order.push(`end:${envelope.id}`);
        return undefined;
      },
    });
    ws().accept();
    ws().deliver({ id: 'e1', mailbox: 'mb_a', text: 'bir' });
    ws().deliver({ id: 'e2', mailbox: 'mb_a', text: 'iki' });
    await settle();

    expect(order).toEqual(['start:e1']);
    releaseFirst!();
    await settle();
    expect(order).toEqual(['start:e1', 'end:e1', 'start:e2', 'end:e2']);
  });

  it('reports a frame that does not parse rather than throwing', async () => {
    const { errors, ws } = connectSocket();
    ws().accept();
    ws().raw('{not json');
    await settle();
    expect(errors.map((e) => e.message)).toEqual(['Tildra: malformed frame from server']);
  });

  it('reports an error frame from the server', async () => {
    const { errors, ws } = connectSocket();
    ws().accept();
    ws().raw(JSON.stringify({ type: 'error', error: 'unknown mailbox' }));
    await settle();
    expect(errors.map((e) => e.message)).toEqual(['unknown mailbox']);
  });

  it('ignores frames that are neither', async () => {
    const { received, errors, ws } = connectSocket();
    ws().accept();
    ws().raw(JSON.stringify({ type: 'pong' }));
    ws().raw(JSON.stringify({ type: 'message' }));
    ws().raw(123);
    await settle();
    expect(received).toEqual([]);
    expect(errors).toEqual([]);
  });
});

describe('a socket that is no longer the live one', () => {
  it('ignores an envelope that arrives after close', async () => {
    // `close()` returns before the WebSocket has finished closing. Without a
    // guard the envelope in flight advances a ratchet and surfaces as a
    // message in an app that has just torn the session down — after a logout,
    // for instance.
    const { received, socket, ws } = connectSocket();
    const live = ws();
    live.accept();
    socket.close();
    live.deliver({ id: 'e1', mailbox: 'mb_a', text: 'too late' });
    await settle();

    expect(received).toEqual([]);
    expect(live.frames()).toEqual([]);
  });

  it('ignores an envelope from the socket a reconnect replaced', async () => {
    vi.useFakeTimers();
    const { received, ws } = connectSocket();
    const first = ws();
    first.accept();
    first.drop();

    await vi.advanceTimersByTimeAsync(0);
    const second = ws();
    expect(second).not.toBe(first);
    second.accept();

    first.deliver({ id: 'stale', mailbox: 'mb_a', text: 'from the dead' });
    second.deliver({ id: 'fresh', mailbox: 'mb_a', text: 'live' });
    await settle();

    expect(received.map((e) => e.id)).toEqual(['fresh']);
  });

  it('does not report an error for a socket we closed', () => {
    // Every logout fires onerror. Surfacing it would put a warning in front of
    // the user for something they asked for.
    const { errors, socket, ws } = connectSocket();
    const live = ws();
    live.accept();
    socket.close();
    live.onerror?.();
    expect(errors).toEqual([]);
  });

  it('does report an error for a socket that failed on its own', () => {
    const { errors, ws } = connectSocket();
    ws().accept();
    ws().onerror?.();
    expect(errors.map((e) => e.message)).toEqual(['Tildra: socket error']);
  });
});

describe('reconnecting', () => {
  it('comes back after a drop and does not after a close', async () => {
    vi.useFakeTimers();
    const { socket, states, ws } = connectSocket();
    ws().accept();
    ws().drop();
    expect(states).toEqual(['connecting', 'open', 'reconnecting']);

    await vi.advanceTimersByTimeAsync(0);
    expect(FakeWebSocket.open).toHaveLength(2);
    ws().accept();

    socket.close();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.open).toHaveLength(2);
    expect(socket.currentState).toBe('closed');
  });

  it('cancels a reconnect that was already scheduled', async () => {
    // Closing during the backoff wait, which is when a user is most likely to
    // do it: the socket is down, the app looks stuck, they log out. Without
    // the timer being cancelled the reconnect fires afterwards and opens a
    // socket for a session that is over.
    vi.useFakeTimers();
    const { socket, ws } = connectSocket();
    ws().accept();
    ws().drop();

    // The first retry is immediate; the wait only exists from the second.
    await vi.advanceTimersByTimeAsync(0);
    expect(FakeWebSocket.open).toHaveLength(2);
    ws().drop();
    expect(socket.currentState).toBe('reconnecting');

    socket.close();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.open).toHaveLength(2);
    expect(socket.currentState).toBe('closed');
  });

  it('backs off, and starts over once a connection sticks', async () => {
    // A phone out of signal must not hammer the server, and one coming out of
    // a tunnel must not sulk for thirty seconds because of what happened
    // before it went in.
    vi.useFakeTimers();
    const { ws } = connectSocket();
    ws().accept();

    ws().drop();
    await vi.advanceTimersByTimeAsync(0);
    expect(FakeWebSocket.open).toHaveLength(2);

    ws().drop();
    await vi.advanceTimersByTimeAsync(999);
    expect(FakeWebSocket.open).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(FakeWebSocket.open).toHaveLength(3);

    // A socket that opens resets the schedule.
    ws().accept();
    ws().drop();
    await vi.advanceTimersByTimeAsync(0);
    expect(FakeWebSocket.open).toHaveLength(4);
  });

  it('re-acks what was in flight when the socket died', async () => {
    // The envelope was handled and the ack never left. Without this the
    // server redelivers it forever.
    vi.useFakeTimers();
    let block: (() => void) | undefined;
    const { ws } = connectSocket({
      onEnvelope: () => new Promise<void>((resolve) => (block = resolve)),
    });
    const first = ws();
    first.accept();
    first.deliver({ id: 'e1', mailbox: 'mb_a', text: 'merhaba' });
    await settle();

    first.drop();
    block!();
    await settle();
    expect(first.frames()).toEqual([]);

    await vi.advanceTimersByTimeAsync(0);
    const second = ws();
    second.accept();
    expect(second.frames()).toContainEqual({ type: 'ack', mailbox: 'mb_a', ids: ['e1'] });
  });
});

describe('subscribing', () => {
  it('sends straight away when the socket is open', () => {
    const { socket, ws } = connectSocket();
    ws().accept();
    socket.subscribe(['mb_a', 'mb_b']);
    expect(ws().frames()).toEqual([{ type: 'subscribe', mailboxes: ['mb_a', 'mb_b'] }]);
  });

  it('replays on open what was asked for before it', () => {
    // Every new conversation derives a mailbox, and the manager hands them
    // over as sessions appear — which is often before the socket is up.
    const { socket, ws } = connectSocket();
    socket.subscribe(['mb_early']);
    expect(ws().frames()).toEqual([]);

    ws().accept();
    expect(ws().frames()).toEqual([{ type: 'subscribe', mailboxes: ['mb_early'] }]);
  });

  it('replays the whole set after a reconnect, not just the new ones', async () => {
    vi.useFakeTimers();
    const { socket, ws } = connectSocket();
    ws().accept();
    socket.subscribe(['mb_a']);
    ws().drop();

    await vi.advanceTimersByTimeAsync(0);
    socket.subscribe(['mb_b']);
    ws().accept();

    const subscribes = ws()
      .frames()
      .filter((f) => f.type === 'subscribe');
    expect(subscribes).toHaveLength(1);
    expect(subscribes[0].mailboxes!.sort()).toEqual(['mb_a', 'mb_b']);
  });
});
