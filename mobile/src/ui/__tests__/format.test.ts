import { describe, expect, it } from 'vitest';

import {
  buildRows,
  dayLabel,
  formatAccountId,
  messageTime,
  parseContactInput,
  previewText,
  relativeTime,
  safetyNumberRows,
  MAX_SERVER_TEXT,
  serverText,
} from '../format';
import { avatarColor, initials } from '../theme';
import { availableLocales, resolveLocale, strings } from '../../i18n';
import { Message } from '../../storage/db';

const s = strings('en');

function message(overrides: Partial<Message> = {}): Message {
  return {
    id: Math.random().toString(36).slice(2),
    conversationId: 'c1',
    text: 'hello',
    outgoing: false,
    createdAt: Date.now(),
    state: 'delivered',
    ...overrides,
  };
}

describe('i18n', () => {
  it('ships the same keys in every locale', () => {
    const reference = Object.keys(strings('en')).sort();
    for (const locale of availableLocales) {
      expect(Object.keys(strings(locale)).sort()).toEqual(reference);
    }
  });

  it('has no empty strings in any locale', () => {
    for (const locale of availableLocales) {
      for (const [key, value] of Object.entries(strings(locale))) {
        expect(value.trim(), `${locale}.${key} is empty`).not.toBe('');
      }
    }
  });

  it('resolves platform locale tags', () => {
    expect(resolveLocale('tr-TR')).toBe('tr');
    expect(resolveLocale('tr')).toBe('tr');
    expect(resolveLocale('en_GB')).toBe('en');
    expect(resolveLocale('de-DE')).toBe('en');
    expect(resolveLocale(undefined)).toBe('en');
    expect(resolveLocale('')).toBe('en');
  });

  it('explains what to do in the identity-change warning', () => {
    // The wording is load-bearing: a warning that does not say what to do gets
    // dismissed, and this is the one warning that must not be.
    for (const locale of availableLocales) {
      const t = strings(locale);
      expect(t.identityChangedBody.length).toBeGreaterThan(80);
      expect(t.identityChangedAction.trim()).not.toBe('');
    }
  });
});

describe('day boundaries', () => {
  const now = new Date('2026-03-15T12:00:00').getTime();

  it('labels today and yesterday by calendar day, not by 24 hours', () => {
    // 23:50 the previous evening is "yesterday" even though it is under 24h.
    const lateYesterday = new Date('2026-03-14T23:50:00').getTime();
    expect(dayLabel(lateYesterday, s, new Date('2026-03-15T00:10:00').getTime())).toBe('Yesterday');

    expect(dayLabel(new Date('2026-03-15T08:00:00').getTime(), s, now)).toBe('Today');
  });

  it('falls back to a date for older messages', () => {
    const label = dayLabel(new Date('2026-01-02T10:00:00').getTime(), s, now);
    expect(label).not.toBe('Today');
    expect(label).not.toBe('Yesterday');
    expect(label).toMatch(/Jan/);
  });

  it('includes the year for messages from another year', () => {
    expect(dayLabel(new Date('2024-06-01T10:00:00').getTime(), s, now)).toMatch(/2024/);
  });

  it('formats clock time in 24 hours', () => {
    expect(messageTime(new Date('2026-03-15T09:05:00').getTime())).toBe('09:05');
    expect(messageTime(new Date('2026-03-15T21:30:00').getTime())).toBe('21:30');
  });

  it('shows a weekday for messages within the last week', () => {
    const threeDaysAgo = new Date('2026-03-12T10:00:00').getTime();
    expect(relativeTime(threeDaysAgo, s, now)).toMatch(/^[A-Z][a-z]{2}$/);
  });

  it('shows the time for today in the chat list', () => {
    expect(relativeTime(new Date('2026-03-15T08:15:00').getTime(), s, now)).toBe('08:15');
  });
});

describe('message rows', () => {
  const now = new Date('2026-03-15T12:00:00').getTime();

  it('inserts one day separator per day', () => {
    const rows = buildRows(
      [
        message({ createdAt: new Date('2026-03-14T10:00:00').getTime() }),
        message({ createdAt: new Date('2026-03-14T11:00:00').getTime() }),
        message({ createdAt: new Date('2026-03-15T09:00:00').getTime() }),
      ],
      s,
      now,
    );
    expect(rows.filter((r) => r.kind === 'day')).toHaveLength(2);
    expect(rows[0].kind).toBe('day');
  });

  it('marks only the last message in a run from the same sender', () => {
    const rows = buildRows(
      [
        message({ outgoing: true, createdAt: now - 3000 }),
        message({ outgoing: true, createdAt: now - 2000 }),
        message({ outgoing: false, createdAt: now - 1000 }),
      ],
      s,
      now,
    );
    const tails = rows.filter((r) => r.kind === 'message').map((r) => r.kind === 'message' && r.showTail);
    expect(tails).toEqual([false, true, true]);
  });

  it('gives every row a unique key', () => {
    const rows = buildRows(
      [
        message({ createdAt: new Date('2026-03-14T10:00:00').getTime() }),
        message({ createdAt: new Date('2026-03-15T10:00:00').getTime() }),
      ],
      s,
      now,
    );
    expect(new Set(rows.map((r) => r.key)).size).toBe(rows.length);
  });

  it('returns nothing for an empty conversation', () => {
    expect(buildRows([], s, now)).toEqual([]);
  });
});

describe('previews', () => {
  it('collapses whitespace and newlines onto one line', () => {
    expect(previewText(message({ text: 'line one\n\nline   two' }))).toBe('line one line two');
  });

  it('truncates with an ellipsis and no dangling space', () => {
    const preview = previewText(message({ text: 'a '.repeat(100) }), 20);
    expect(preview.length).toBeLessThanOrEqual(20);
    expect(preview.endsWith('…')).toBe(true);
    expect(preview).not.toMatch(/ …$/);
  });

  it('handles an empty conversation', () => {
    expect(previewText(undefined)).toBe('');
  });
});

describe('safety numbers', () => {
  it('lays 12 groups out in three rows of four', () => {
    const rows = safetyNumberRows('11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 12121 34343');
    expect(rows).toHaveLength(3);
    rows.forEach((row) => expect(row).toHaveLength(4));
  });

  it('does not drop groups when the count is uneven', () => {
    const rows = safetyNumberRows('11111 22222 33333');
    expect(rows.flat()).toHaveLength(3);
  });
});

describe('account identifiers', () => {
  it('groups an account ID for reading aloud', () => {
    expect(formatAccountId('0123456789ABCDEFGHJKMNPQRS')).toBe('012345-6789AB-CDEFGH-JKMNPQ-RS');
  });

  it('recognises a handle written with an @', () => {
    expect(parseContactInput('@Ayse')).toEqual({ kind: 'handle', value: 'ayse' });
  });

  it('recognises an account ID, including one typed with separators', () => {
    expect(parseContactInput('0123456789ABCDEFGHJKMNPQRS')).toEqual({
      kind: 'accountId',
      value: '0123456789ABCDEFGHJKMNPQRS',
    });
    expect(parseContactInput('012345-6789AB-CDEFGH-JKMNPQ-RS')).toEqual({
      kind: 'accountId',
      value: '0123456789ABCDEFGHJKMNPQRS',
    });
    expect(parseContactInput('  0123456789abcdefghjkmnpqrs  ')).toEqual({
      kind: 'accountId',
      value: '0123456789ABCDEFGHJKMNPQRS',
    });
  });

  it('treats ambiguous input as a handle', () => {
    // Wrong length, so it cannot be an account ID. Treating it as a handle
    // gives a "no such handle" the user can act on, rather than a lookup that
    // cannot possibly succeed.
    expect(parseContactInput('0123456789').kind).toBe('handle');
  });
});

describe('avatars', () => {
  it('gives the same account the same colour every time', () => {
    expect(avatarColor('ABC123')).toBe(avatarColor('ABC123'));
  });

  it('spreads different accounts across the palette', () => {
    const colors = new Set(
      Array.from({ length: 40 }, (_, i) => avatarColor(`ACCOUNT${i}XYZ`)),
    );
    expect(colors.size).toBeGreaterThan(3);
  });

  it('derives initials from handles and account IDs', () => {
    expect(initials('@ayse')).toBe('AY');
    expect(initials('ayse_kaya')).toBe('AK');
    expect(initials('Ayse Kaya')).toBe('AK');
    expect(initials('0123456789ABCDEF')).toBe('01');
    expect(initials('')).toBe('?');
    expect(initials('   ')).toBe('?');
  });
});

describe('text the server chose', () => {
  const t = strings('en');
  const said = 'The server said: ';

  it('attributes it rather than letting it speak as the app', () => {
    // The banner around this is titled by the app. Without the attribution the
    // body reads as something Tildra is telling you, and the server picks the
    // words - at exactly the moment the design needs the user to trust what
    // the app says about a key change.
    expect(serverText('mailbox not found', t)).toBe(`${said}mailbox not found`);
  });

  it('flattens anything that could lay out a second interface', () => {
    // A newline plus indentation renders as its own line in a Banner, so a
    // server can append what looks like the app's own reassurance underneath
    // the app's own error.
    const hostile = 'rate limited\n\n  Verified by Tildra, safe to continue';
    expect(serverText(hostile, t)).toBe(
      `${said}rate limited Verified by Tildra, safe to continue`,
    );
  });

  it('strips characters that reorder or hide what is displayed', () => {
    // U+202E reverses the run after it, so what is stored and what is read are
    // different sentences. U+200B and U+FEFF are invisible, U+00A0 is a space
    // that does not collapse, U+0007 is a control character no diagnostic
    // needs, and U+2028 is a line separator.
    const cases: [string, string][] = [
      ['‮elbatpecca si egnahc yek', 'elbatpecca si egnahc yek'],
      ['a​b', 'a b'],
      ['a  b', 'a b'],
      ['bell', 'bel l'],
      ['a b', 'a b'],
      ['a﻿b', 'a b'],
      ['  spaced \t\r\n  out  ', 'spaced out'],
    ];
    for (const [input, want] of cases) {
      expect(serverText(input, t), JSON.stringify(input)).toBe(`${said}${want}`);
    }
  });

  it('bounds it so the app keeps the screen', () => {
    const out = serverText('x'.repeat(500), t);
    expect(out.startsWith(said)).toBe(true);
    expect(out.length).toBe(said.length + MAX_SERVER_TEXT);
    expect(out.endsWith('…')).toBe(true);
  });

  it('keeps a message that is exactly at the bound intact', () => {
    const exact = 'y'.repeat(MAX_SERVER_TEXT);
    expect(serverText(exact, t)).toBe(`${said}${exact}`);
    expect(serverText(exact, t).endsWith('…')).toBe(false);
  });

  it('falls back to the generic message when nothing usable is left', () => {
    // A bare attribution with nothing after it reads as a broken app rather
    // than as a server that sent noise.
    for (const empty of ['', '   ', '\n\t', '​​', '‮', ' ']) {
      expect(serverText(empty, t), JSON.stringify(empty)).toBe(t.errorGeneric);
    }
  });

  it('leaves ordinary text alone, in either language', () => {
    expect(serverText('handle already taken', t)).toBe(`${said}handle already taken`);
    expect(serverText('kullanıcı adı alınmış', strings('tr'))).toBe(
      'Sunucu şunu bildirdi: kullanıcı adı alınmış',
    );
  });
});
