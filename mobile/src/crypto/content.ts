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
  /** Who I am: display name and picture, sent to people I talk to. */
  Profile = 3,
  /** A file: caption plus the reference needed to fetch and decrypt it. */
  Attachment = 4,
  /**
   * A tree head this device has verified, passed to a contact so the two can
   * check they are being shown the same log. Costs one small message and is
   * the only thing that catches a server running a split view.
   */
  TransparencyGossip = 5,
  /**
   * Call setup: an offer, an answer, an ICE candidate, or a hangup. Rides the
   * pairwise ratchet like everything else, so the server sees that two people
   * exchanged some small messages and not that a call happened.
   */
  CallSignal = 6,
}

export interface Content {
  type: ContentType;
  /** Present for Text. */
  text?: string;
  /** Present for SenderKeyDistribution and GroupRotation. */
  groupId?: string;
  /** Present for SenderKeyDistribution and Profile: the encoded blob. */
  payload?: Uint8Array;
}

/**
 * A user's public-facing self.
 *
 * Tildra is not an anonymous messenger — people you talk to should see who you
 * are. What makes that compatible with the threat model is *where* it lives:
 * a profile is sent to your contacts over their pairwise session, encrypted
 * exactly like a message. The server stores no name and no picture, and cannot
 * enumerate who anyone is. Your account is still a key; the name is something
 * you hand to specific people.
 */
export interface Profile {
  displayName: string;
  /** Encoded image bytes (JPEG or PNG), already resized by the caller. */
  avatar?: Uint8Array;
  about?: string;
  /** Milliseconds. Lets a receiver ignore an out-of-order older profile. */
  updatedAt: number;
}

/**
 * Cap on the avatar. Anything larger is the caller's job to downscale — this
 * is a hard refusal rather than a silent crop, because a profile that is
 * quietly truncated becomes an image that fails to decode on the far side.
 */
export const MAX_AVATAR_BYTES = 96 * 1024;
export const MAX_DISPLAY_NAME_LENGTH = 48;
export const MAX_ABOUT_LENGTH = 140;

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
    case ContentType.Profile:
      return { type, payload };
    case ContentType.Attachment:
      // The caption rides in `text` so a client that renders the message has
      // something to show even before the blob is fetched.
      return { type, text: groupId, payload };
    case ContentType.TransparencyGossip:
      return { type, payload };
    case ContentType.CallSignal:
      return { type, payload };
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

/**
 * A file message.
 *
 * The caption reuses the group-id slot in the frame, which is otherwise unused
 * for this type — the wire format stays three fields wide rather than growing
 * a fourth that is empty for every other content type.
 */
export function attachmentContent(reference: Uint8Array, caption: string): Content {
  return { type: ContentType.Attachment, groupId: caption, payload: reference };
}

export function gossipContent(treeHead: Uint8Array): Content {
  return { type: ContentType.TransparencyGossip, payload: treeHead };
}

export function callSignalContent(signal: Uint8Array): Content {
  return { type: ContentType.CallSignal, payload: signal };
}

export function profileContent(profile: Profile): Content {
  return { type: ContentType.Profile, payload: encodeProfile(profile) };
}

export function encodeProfile(profile: Profile): Uint8Array {
  const displayName = profile.displayName.trim();
  if (!displayName) throw new ContentError('profile display name is empty');
  if (displayName.length > MAX_DISPLAY_NAME_LENGTH) {
    throw new ContentError(`display name exceeds ${MAX_DISPLAY_NAME_LENGTH} characters`);
  }
  if ((profile.about ?? '').length > MAX_ABOUT_LENGTH) {
    throw new ContentError(`about exceeds ${MAX_ABOUT_LENGTH} characters`);
  }
  if (profile.avatar && profile.avatar.length > MAX_AVATAR_BYTES) {
    throw new ContentError(`avatar exceeds ${MAX_AVATAR_BYTES} bytes; downscale it first`);
  }

  return frame(
    utf8(displayName),
    utf8(profile.about ?? ''),
    u32(Math.floor(profile.updatedAt / 1000)),
    profile.avatar ?? new Uint8Array(0),
  );
}

export function decodeProfile(data: Uint8Array): Profile {
  const [displayName, about, updatedAt, avatar] = unframe(data, 4);

  // The sender controls these bytes, so they are bounded on the way in too.
  // A peer that sends a megabyte of "name" should be rejected, not rendered.
  const name = fromUtf8(displayName);
  if (name.length > MAX_DISPLAY_NAME_LENGTH) {
    throw new ContentError('received display name is too long');
  }
  if (avatar.length > MAX_AVATAR_BYTES) {
    throw new ContentError('received avatar is too large');
  }

  return {
    displayName: sanitize(name) || 'Unnamed',
    about: sanitize(fromUtf8(about)) || undefined,
    avatar: avatar.length > 0 ? avatar : undefined,
    updatedAt: readU32(updatedAt, 0) * 1000,
  };
}

/**
 * Strip control characters and collapse whitespace.
 *
 * A display name is rendered next to messages from someone you may not know
 * well. Newlines and bidirectional overrides in that position are a spoofing
 * tool, not a formatting preference.
 *
 * Exported because a group's name is the same kind of text from the same kind
 * of sender, and the reason that one went unsanitised is that this rule lived
 * here and nowhere it could be reached from.
 */
export function sanitizeDisplayText(value: string): string {
  return (
    value
      // C0 and C1 control characters become a space, not nothing: a newline
      // separated two words, and deleting it would run them together into a
      // different name than the one that was sent.
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
      // Every Unicode format character, rather than a hand-written list of
      // them. These let a name render as something other than what it is,
      // which next to a stranger's messages is impersonation rather than
      // styling — and the list this replaces had holes: U+061C, the Arabic
      // letter mark, which is a bidi control; U+2060 word joiner; U+FFF9-FFFB;
      // and the whole U+E0000 tag block, which is the standard way to carry
      // hidden text inside a name. `Ali<U+2060>ce` renders as `Alice`, which
      // is the impersonation this exists to stop.
      //
      // Cf includes U+200D, so an emoji joined sequence in a name decomposes
      // into its parts. That was already true of the list this replaces.
      .replace(/\p{Cf}/gu, '')
      .replace(/\s+/g, ' ')
      .trim()
  );
}

const sanitize = sanitizeDisplayText;
