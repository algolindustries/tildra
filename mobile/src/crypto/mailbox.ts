/**
 * Rotating mailbox identifiers — docs/PROTOCOL.md §5.
 *
 * A mailbox is where the server drops an envelope. It must be stable enough
 * that a sender who learned it yesterday can still deliver today, and rotate
 * fast enough that the server cannot use it as a long-lived account handle.
 * A day is the compromise.
 */

import { INFO, kdf, toHex, utf8, concat } from './primitives';

export const MAILBOX_ID_LENGTH = 32; // hex chars, from 16 bytes
const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** Days since the Unix epoch, UTC. Both sides must agree without coordinating. */
export function dayNumber(at: Date = new Date()): number {
  return Math.floor(at.getTime() / MS_PER_DAY);
}

/**
 * Derive the mailbox for one day from the secret shared with a contact.
 *
 * The secret comes out of the session, so only people you have a session with
 * can compute your mailbox — the server cannot enumerate them, and neither can
 * a stranger.
 */
export function mailboxFor(sharedMailboxSecret: Uint8Array, day: number): string {
  const info = `${INFO.mailbox}:${day}`;
  return `mb_${toHex(kdf(sharedMailboxSecret, undefined, info, 16))}`;
}

/**
 * The mailboxes to publish right now: yesterday, today and tomorrow.
 *
 * Three, not one, because clocks drift and a message sent at 23:59:58 must not
 * land in a mailbox nobody is listening to. The server holds each for 48h.
 */
export function currentMailboxes(sharedMailboxSecret: Uint8Array, at: Date = new Date()): string[] {
  const today = dayNumber(at);
  return [today - 1, today, today + 1].map((d) => mailboxFor(sharedMailboxSecret, d));
}

/**
 * The mailbox to send to. Uses today's, which the recipient is guaranteed to
 * be watching if they have been online in the last day.
 */
export function deliveryMailbox(sharedMailboxSecret: Uint8Array, at: Date = new Date()): string {
  return mailboxFor(sharedMailboxSecret, dayNumber(at));
}

/**
 * Derive the mailbox secret for one side of a session.
 *
 * Both parties can compute both directions from the same session secret: the
 * sender needs the recipient's mailbox to deliver, and the recipient needs its
 * own to register. `owner` names whose mailbox is being derived.
 *
 * Separate from the message keys so that learning a mailbox secret — which the
 * sender necessarily knows — reveals nothing about message content.
 */
export function deriveMailboxSecret(
  sessionSecret: Uint8Array,
  ownerAccountId: string,
  ownerDeviceId: string,
): Uint8Array {
  return kdf(
    concat(sessionSecret, utf8(`${ownerAccountId}/${ownerDeviceId}`)),
    undefined,
    INFO.mailbox,
    32,
  );
}

/**
 * The mailbox a device listens on for first contact.
 *
 * There is a bootstrapping problem that no amount of key rotation solves: to
 * deliver the first message, the sender needs a mailbox the recipient is
 * already watching — but a per-session mailbox is derived from a secret the
 * recipient cannot compute until that first message arrives.
 *
 * So a device also publishes one stable inbox derived from its identity key.
 * Anyone holding that public key can compute it, which includes the server,
 * so the server can tell that *someone* opened a conversation with this device
 * and when. It cannot tell who, and it learns nothing further: from the reply
 * onwards the conversation moves to per-session mailboxes that rotate daily
 * and are unlinkable both across days and across contacts.
 *
 * This is documented as a known limitation in docs/THREAT_MODEL.md rather than
 * papered over — first-contact timing is real metadata, and closing it needs
 * something closer to a mixnet than to a key derivation.
 */
export function contactInbox(identityKey: Uint8Array): string {
  return `mb_${toHex(kdf(identityKey, undefined, INFO.contactInbox, 16))}`;
}
