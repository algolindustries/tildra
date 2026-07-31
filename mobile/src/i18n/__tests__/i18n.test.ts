import { describe, expect, it } from 'vitest';

import { Locale, Strings, availableLocales, isSupportedLocale, resolveLocale, strings } from '..';

/**
 * The locale layer.
 *
 * Most of this file is two string tables, and TypeScript already guarantees
 * they hold the same keys — `const tr: Strings` will not compile otherwise. So
 * the tests here are about the three things the compiler cannot see: whether
 * the type guard tells the truth, whether a table is complete rather than
 * merely present, and whether the Turkish one was actually translated.
 *
 * `format.test.ts` and `errors.test.ts` already drive `strings` and
 * `availableLocales` from the outside. What neither touches is
 * `isSupportedLocale`, which is where the bug was.
 */

/**
 * Everything a plain object inherits. The guard used to answer true for all of
 * it, so this is checked exhaustively rather than with the two or three names
 * anyone would think to write down.
 */
const INHERITED = Object.getOwnPropertyNames(Object.prototype);

describe('the supported-locale guard', () => {
  it('accepts exactly the locales that ship', () => {
    for (const locale of availableLocales) expect(isSupportedLocale(locale)).toBe(true);
  });

  it('rejects a language we do not ship', () => {
    expect(isSupportedLocale('de')).toBe(false);
    expect(isSupportedLocale('')).toBe(false);
  });

  it('rejects every property a plain object inherits', () => {
    // `value in LOCALES` walks the prototype chain, so 'constructor',
    // 'toString', 'hasOwnProperty' and '__proto__' all passed. This is a type
    // guard, so TypeScript then treated them as a Locale, and `strings` handed
    // back a function or Object.prototype — every label in the app rendering as
    // undefined, with nothing raised anywhere.
    expect(INHERITED.length).toBeGreaterThan(5);
    for (const name of INHERITED) {
      expect(isSupportedLocale(name), `${name} is not a locale`).toBe(false);
    }
  });
});

describe('resolving a platform tag', () => {
  it('takes the language out of a region tag, in either separator', () => {
    expect(resolveLocale('tr-TR')).toBe('tr');
    expect(resolveLocale('en_GB')).toBe('en');
  });

  it('is case-insensitive, because platforms disagree about case', () => {
    expect(resolveLocale('TR-tr')).toBe('tr');
    expect(resolveLocale('EN')).toBe('en');
  });

  it('falls back to English rather than showing raw keys', () => {
    expect(resolveLocale('de-DE')).toBe('en');
    expect(resolveLocale(undefined)).toBe('en');
    expect(resolveLocale(null)).toBe('en');
    expect(resolveLocale('')).toBe('en');
  });

  it('never returns something strings() cannot serve', () => {
    // The property that matters, over every tag shape that has ever looked
    // plausible plus the ones that broke the guard. A resolve that returns a
    // value with no table is not an error the user sees — it is an interface
    // full of undefined.
    const tags = [
      ...INHERITED,
      ...INHERITED.map((name) => `${name}-US`),
      'tr-TR',
      'en_GB',
      'de',
      'zh-Hant-TW',
      '-tr',
      '_',
      '   ',
      'en-',
      '__proto__',
      'constructor-tr',
    ];

    for (const tag of tags) {
      const resolved = resolveLocale(tag);
      expect(availableLocales).toContain(resolved);
      expect(typeof strings(resolved).appName, `tag ${tag}`).toBe('string');
    }
  });
});

describe('the tables themselves', () => {
  const keys = Object.keys(strings('en')) as Array<keyof Strings>;

  it('ships at least the two locales the type names', () => {
    expect(new Set(availableLocales)).toEqual(new Set<Locale>(['en', 'tr']));
  });

  it('has a non-empty string for every key, in every locale', () => {
    // Presence is the compiler's job. Emptiness is not: `welcomeTitle: ''`
    // typechecks and renders a blank screen.
    expect(keys.length).toBeGreaterThan(100);
    for (const locale of availableLocales) {
      const table = strings(locale);
      for (const key of keys) {
        expect(typeof table[key], `${locale}.${key}`).toBe('string');
        expect(table[key].trim(), `${locale}.${key}`).not.toBe('');
      }
    }
  });

  it('was translated rather than copied', () => {
    // A new key added to both tables with the English text pasted into the
    // Turkish one typechecks and reads as finished work. The brand name is the
    // only string that is deliberately the same in both.
    const shared = keys.filter((key) => strings('en')[key] === strings('tr')[key]);

    expect(shared).toEqual(['appName']);
  });

  it('always hands back a table, even for a locale that does not exist', () => {
    // Dead code in a compiling program, and deliberately kept: the guard above
    // was wrong once and the compiler believed it. English is a worse answer
    // than the user's language and a much better one than a blank app.
    const table = strings('constructor' as Locale);

    expect(table).toBe(strings('en'));
  });
});
