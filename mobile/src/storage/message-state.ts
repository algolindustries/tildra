/**
 * How far a message got.
 *
 * Separate from `db.ts` because this is the one part of the message model that
 * code with no database needs at runtime: the session layer compares states,
 * and the in-memory test double has to apply the same monotonic rule the SQLite
 * `UPDATE` does. Importing it from `db.ts` would pull `expo-sqlite`, and
 * through it React Native's Flow-typed entry point, into every one of those
 * callers — which is a parse failure under vitest, not a slow import.
 */

/**
 * `delivered` is also the state an *incoming* message is stored in: it reached
 * this device, which is the only thing there is to say about it.
 */
export type MessageState = 'pending' | 'sent' | 'delivered' | 'read' | 'failed';

/**
 * The order receipts may move a message along.
 *
 * `failed` sits below `pending` so that nothing a peer claims can ever produce
 * it — it is this device's own observation that nothing went out, applied by
 * the send path with `setMessageState` rather than by `advanceMessageState`.
 */
export const MESSAGE_STATE_ORDER: Record<MessageState, number> = {
  failed: -1,
  pending: 0,
  sent: 1,
  delivered: 2,
  read: 3,
};
