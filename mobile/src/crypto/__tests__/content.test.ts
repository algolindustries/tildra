import { describe, expect, it } from 'vitest';

import {
  ContentError,
  ContentType,
  MAX_AVATAR_BYTES,
  MAX_DISPLAY_NAME_LENGTH,
  decodeContent,
  decodeProfile,
  encodeContent,
  encodeProfile,
  profileContent,
  rotationContent,
  senderKeyContent,
  textContent,
} from '../content';
import { equal, randomBytes, utf8 } from '../primitives';
import { groupConversationKey, groupIdFromConversationKey } from '../../session/manager';

describe('content typing', () => {
  it('round-trips text', () => {
    const decoded = decodeContent(encodeContent(textContent('merhaba dünya')));
    expect(decoded.type).toBe(ContentType.Text);
    expect(decoded.text).toBe('merhaba dünya');
  });

  it('round-trips a sender key distribution', () => {
    const payload = randomBytes(120);
    const decoded = decodeContent(encodeContent(senderKeyContent('grp-1', payload)));
    expect(decoded.type).toBe(ContentType.SenderKeyDistribution);
    expect(decoded.groupId).toBe('grp-1');
    expect(equal(decoded.payload!, payload)).toBe(true);
  });

  it('round-trips a group rotation', () => {
    const decoded = decodeContent(encodeContent(rotationContent('grp-2')));
    expect(decoded.type).toBe(ContentType.GroupRotation);
    expect(decoded.groupId).toBe('grp-2');
  });

  it('refuses a content type it does not understand', () => {
    // A newer client must not have its control messages rendered as chat.
    const forged = encodeContent({ type: 99 as ContentType, text: 'pretend chat' });
    expect(() => decodeContent(forged)).toThrow(/unsupported content type/);
  });

  it('refuses a sender key distribution with no group', () => {
    const forged = encodeContent({
      type: ContentType.SenderKeyDistribution,
      payload: randomBytes(10),
    });
    expect(() => decodeContent(forged)).toThrow(ContentError);
  });

  it('does not confuse text for a control message', () => {
    // Text that happens to look like a distribution blob must still decode as
    // text, because the type is carried explicitly and never inferred.
    const decoded = decodeContent(encodeContent(textContent('grp-1')));
    expect(decoded.type).toBe(ContentType.Text);
    expect(decoded.text).toBe('grp-1');
  });
});

describe('profiles', () => {
  const at = new Date('2026-05-01T10:00:00Z').getTime();

  it('round-trips a full profile', () => {
    const avatar = randomBytes(4096);
    const decoded = decodeProfile(
      encodeProfile({ displayName: 'Ayşe Kaya', about: 'İstanbul', avatar, updatedAt: at }),
    );

    expect(decoded.displayName).toBe('Ayşe Kaya');
    expect(decoded.about).toBe('İstanbul');
    expect(equal(decoded.avatar!, avatar)).toBe(true);
    expect(decoded.updatedAt).toBe(at);
  });

  it('round-trips a profile with no picture or about', () => {
    const decoded = decodeProfile(encodeProfile({ displayName: 'Just a name', updatedAt: at }));
    expect(decoded.displayName).toBe('Just a name');
    expect(decoded.avatar).toBeUndefined();
    expect(decoded.about).toBeUndefined();
  });

  it('travels inside a typed content message', () => {
    const decoded = decodeContent(
      encodeContent(profileContent({ displayName: 'Barış', updatedAt: at })),
    );
    expect(decoded.type).toBe(ContentType.Profile);
    expect(decodeProfile(decoded.payload!).displayName).toBe('Barış');
  });

  it('refuses an empty display name', () => {
    expect(() => encodeProfile({ displayName: '   ', updatedAt: at })).toThrow(ContentError);
  });

  it('refuses an oversized name, about, or avatar', () => {
    expect(() => encodeProfile({ displayName: 'x'.repeat(200), updatedAt: at })).toThrow(/display name/);
    expect(() =>
      encodeProfile({ displayName: 'ok', about: 'y'.repeat(500), updatedAt: at }),
    ).toThrow(/about/);
    expect(() =>
      encodeProfile({ displayName: 'ok', avatar: randomBytes(MAX_AVATAR_BYTES + 1), updatedAt: at }),
    ).toThrow(/avatar/);
  });

  it('strips control characters and bidi overrides from a received name', () => {
    // A name rendered next to someone's messages is an impersonation surface.
    // A right-to-left override can make "evil‮txt.exe" display as
    // something else entirely, and newlines can fake a second sender.
    const hostile = encodeProfile({
      displayName: 'Ayse‮​evil\nname',
      updatedAt: at,
    });
    const decoded = decodeProfile(hostile);

    expect(decoded.displayName).not.toMatch(/[‪-‮]/);
    expect(decoded.displayName).not.toMatch(/[​-‏]/);
    expect(decoded.displayName).not.toContain('\n');
    expect(decoded.displayName).toBe('Ayseevil name');
  });

  it('strips every format character, not the ones somebody remembered', () => {
    // The rule was a hand-written list of ranges and it had holes. Each of
    // these is invisible or reorders what is displayed, and each one lets a
    // name render as somebody else's — which is the whole point of sanitising
    // it. The test above passes against the version with the holes.
    for (const [label, hidden] of [
      ['word joiner U+2060', '⁠'],
      ['Arabic letter mark U+061C', '؜'],
      ['soft hyphen U+00AD', '­'],
      ['invisible separator U+2063', '⁣'],
      ['interlinear annotation U+FFF9', '￹'],
      ['tag character U+E0061', '\u{E0061}'],
      ['Mongolian vowel separator U+180E', '᠎'],
    ] as const) {
      const decoded = decodeProfile(
        encodeProfile({ displayName: `Ali${hidden}ce`, updatedAt: at }),
      );
      expect(decoded.displayName, label).toBe('Alice');
    }
  });

  it('falls back rather than rendering an empty name', () => {
    // A name that is entirely control characters sanitizes to nothing, and a
    // blank row in the chat list is worse than a placeholder.
    const blank = encodeProfile({ displayName: '​​x', updatedAt: at });
    expect(decodeProfile(blank).displayName).toBe('x');
  });

  it('rejects a name longer than the limit on the way in', () => {
    // encodeProfile enforces this for our own profile; decodeProfile has to
    // enforce it again because the bytes came from someone else.
    const oversized = encodeProfile({
      displayName: 'x'.repeat(MAX_DISPLAY_NAME_LENGTH),
      updatedAt: at,
    });
    expect(() => decodeProfile(oversized)).not.toThrow();

    const handCrafted = encodeContent({
      type: ContentType.Profile,
      payload: utf8('not a valid profile frame'),
    });
    expect(() => decodeProfile(decodeContent(handCrafted).payload!)).toThrow();
  });

  it('keeps second precision on the timestamp', () => {
    const decoded = decodeProfile(
      encodeProfile({ displayName: 'x', updatedAt: at + 999 }),
    );
    expect(decoded.updatedAt).toBe(at);
  });
});

describe('group conversation keys', () => {
  it('round-trips a group id', () => {
    expect(groupIdFromConversationKey(groupConversationKey('grp-1'))).toBe('grp-1');
    expect(groupIdFromConversationKey(groupConversationKey('a:b:c'))).toBe('a:b:c');
  });

  it('says a person is not a group', () => {
    // Account ids are Crockford base32, so they can never carry the prefix —
    // but the check is on the prefix, not on that assumption.
    expect(groupIdFromConversationKey('01H8XGJWBWBAQ4TT1TT1TT1TT1')).toBeNull();
    expect(groupIdFromConversationKey('')).toBeNull();
    expect(groupIdFromConversationKey('groupish:1')).toBeNull();
  });

  it('refuses a prefix with nothing after it', () => {
    // Otherwise an empty group id would look like a valid group and every
    // message for it would go nowhere.
    expect(groupIdFromConversationKey('group:')).toBeNull();
  });
});
