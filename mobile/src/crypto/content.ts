/**
 * Plaintext content types.
 *
 * The bytes inside a pairwise Double Ratchet message are not always chat text.
 * Sender-key distribution for groups travels the same way, because it has to
 * be confidential to each member individually — that is what makes the group
 * layer work.
 *
 * Typing the payload explicitly rather than sniffing it means a control
 * message can never be rendered as a chat bubble, and text can never be
 * mistaken for a key.
 */

import { readU32, u32, utf8, fromUtf8 } from './primitives';
import { frame, unframe } from './wire';

export enum ContentType {
  Text = 0,
  SenderKeyDistribution = 1,
  /** Tells members to discard a group's sender keys and expect new ones. */
  GroupRotation = 2,
}

export interface Content {
  type: ContentType;
  /** Present for Text. */
  text?: string;
  /** Present for SenderKeyDistribution and GroupRotation. */
  groupId?: string;
  /** Present for SenderKeyDistribution: the encoded distribution blob. */
  payload?: Uint8Array;
}

export class ContentError extends Error {}

export function encodeContent(content: Content): Uint8Array {
  return frame(
    u32(content.type),
    utf8(content.groupId ?? ''),
    content.type === ContentType.Text ? utf8(content.text ?? '') : (content.payload ?? new Uint8Array(0)),
  );
}

export function decodeContent(data: Uint8Array): Content {
  const [typeBytes, groupIdBytes, payload] = unframe(data, 3);
  const type = readU32(typeBytes, 0);
  const groupId = fromUtf8(groupIdBytes);

  switch (type) {
    case ContentType.Text:
      return { type, text: fromUtf8(payload) };
    case ContentType.SenderKeyDistribution:
      if (!groupId) throw new ContentError('sender key distribution without a group id');
      return { type, groupId, payload };
    case ContentType.GroupRotation:
      if (!groupId) throw new ContentError('group rotation without a group id');
      return { type, groupId };
    default:
      // A newer client sending a type we do not understand must not be
      // rendered as anything. Refusing is the only safe reading.
      throw new ContentError(`unsupported content type ${type}`);
  }
}

export function textContent(text: string): Content {
  return { type: ContentType.Text, text };
}

export function senderKeyContent(groupId: string, payload: Uint8Array): Content {
  return { type: ContentType.SenderKeyDistribution, groupId, payload };
}

export function rotationContent(groupId: string): Content {
  return { type: ContentType.GroupRotation, groupId };
}
