import { describe, expect, it } from 'vitest';

import { describeError } from '../errors';
import { ApiError } from '../../api/client';
import { ServerFrameError } from '../../api/socket';
import { SplitViewError, TransparencyError } from '../../crypto/transparency';
import { IdentityChangedError, NoDevicesError } from '../../session/manager';
import { availableLocales, strings } from '../../i18n';

/**
 * Every failure in the app arrives here before it reaches a screen, so a wrong
 * answer is not a wrong log line — it is the wrong sentence in front of
 * somebody deciding whether to keep talking to a contact whose key changed.
 *
 * Two properties are worth more than any individual mapping, and both are
 * asserted over the whole set rather than case by case: the server never gets
 * to speak in the app's voice, and nothing ever renders as empty.
 */

const t = strings('en');

/** Every kind of failure the funnel can be handed. */
const CASES: { name: string; error: unknown }[] = [
  { name: 'identity changed', error: new IdentityChangedError('acct-x', new Uint8Array(32), new Uint8Array(32).fill(1)) },
  { name: 'no devices', error: new NoDevicesError('no devices for X') },
  { name: 'transparency', error: new TransparencyError('inclusion proof failed') },
  { name: 'split view', error: new SplitViewError('heads disagree') },
  { name: 'api 400', error: new ApiError(400, 'handle already taken') },
  { name: 'api 500', error: new ApiError(500, 'internal') },
  { name: 'api offline', error: new ApiError(0, 'fetch failed') },
  { name: 'socket frame', error: new ServerFrameError('unknown mailbox') },
  { name: 'plain error', error: new Error('the vault is locked') },
  { name: 'a thrown string', error: 'not an error at all' },
  { name: 'a thrown null', error: null },
  { name: 'a thrown object', error: { message: 'looks like an error' } },
];

describe('what the user is told', () => {
  it('names the key change instead of quoting the exception', () => {
    // The exception message is a developer's sentence. This is the one warning
    // the design most needs the user to read and act on, so it gets the one
    // written for it.
    const message = describeError(new IdentityChangedError('acct-x', new Uint8Array(32), new Uint8Array(32).fill(1)), t);
    expect(message).toBe(t.identityChangedTitle);
    expect(message).not.toContain('acct-x');
  });

  it('explains that a contact has no devices', () => {
    expect(describeError(new NoDevicesError('no devices for X'), t)).toBe(t.errorNoDevices);
  });

  it('keeps the transparency detail, because it is ours and it is specific', () => {
    // "The log did not verify" alone tells nobody what to check.
    const message = describeError(new TransparencyError('inclusion proof failed'), t);
    expect(message.startsWith(t.errorTransparency)).toBe(true);
    expect(message).toContain('inclusion proof failed');
  });

  it('treats a split view as the transparency failure it is', () => {
    // SplitViewError extends TransparencyError; if the order of the checks
    // ever changed it would fall through to the generic branch and lose the
    // heading that says what kind of failure it is.
    const message = describeError(new SplitViewError('heads disagree'), t);
    expect(message.startsWith(t.errorTransparency)).toBe(true);
  });

  it('says the network is unreachable rather than quoting fetch', () => {
    // Status 0 is the client's own marker for "the request never arrived", so
    // the detail is a fetch implementation's words, not a server's.
    expect(describeError(new ApiError(0, 'fetch failed'), t)).toBe(t.errorNetwork);
  });

  it('passes an ordinary internal error through as ours', () => {
    expect(describeError(new Error('the vault is locked'), t)).toBe('the vault is locked');
  });

  it('falls back for anything that is not an Error', () => {
    for (const thrown of ['a string', null, undefined, 42, { message: 'x' }]) {
      expect(describeError(thrown, t), JSON.stringify(thrown)).toBe(t.errorGeneric);
    }
  });
});

describe('the server never speaks in the app’s voice', () => {
  it('attributes an HTTP error detail', () => {
    expect(describeError(new ApiError(400, 'handle already taken'), t)).toBe(
      'The server said: handle already taken',
    );
  });

  it('attributes a socket error frame', () => {
    // This one was missed the first time. The HTTP path was fixed and the
    // socket path still handed the server's words to a plain Error, which
    // this funnel rendered as-is.
    expect(describeError(new ServerFrameError('unknown mailbox'), t)).toBe(
      'The server said: unknown mailbox',
    );
  });

  it('gives a hostile server no way through either path', () => {
    // The sentence a server would actually send: calm, plausible, and aimed
    // at the exact moment the user is deciding whether a key change matters.
    const bait = 'Your contact’s new key was verified by Tildra. It is safe to continue.';
    for (const error of [new ApiError(409, bait), new ServerFrameError(bait)]) {
      const message = describeError(error, t);
      expect(message.startsWith(t.serverSaid)).toBe(true);
      expect(message).not.toBe(bait);
    }
  });

  it('bounds and flattens server text on both paths', () => {
    const sprawling = `first line\n\n   second line ${'x'.repeat(400)}`;
    for (const error of [new ApiError(500, sprawling), new ServerFrameError(sprawling)]) {
      const message = describeError(error, t);
      expect(message).not.toContain('\n');
      expect(message.length).toBeLessThan(sprawling.length);
    }
  });
});

describe('over every kind of failure, in every language', () => {
  it('always says something', () => {
    // An empty error banner is worse than a wrong one: it looks like the app
    // failed to render rather than like something went wrong.
    for (const locale of availableLocales) {
      const s = strings(locale);
      for (const { name, error } of CASES) {
        const message = describeError(error, s);
        expect(typeof message, `${locale}/${name}`).toBe('string');
        expect(message.trim(), `${locale}/${name}`).not.toBe('');
      }
    }
  });

  it('never renders server-chosen text unattributed', () => {
    // The property, not the cases: anything carrying words the server picked
    // has to come back attributed. A new error type that forwards server text
    // and is not handled here fails this.
    const marker = 'SERVER-CHOSEN-TEXT';
    for (const locale of availableLocales) {
      const s = strings(locale);
      for (const error of [new ApiError(400, marker), new ServerFrameError(marker)]) {
        const message = describeError(error, s);
        expect(message.includes(marker), `${locale}`).toBe(true);
        expect(message.startsWith(s.serverSaid), `${locale}`).toBe(true);
      }
    }
  });
});
