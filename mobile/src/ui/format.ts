/**
 * Formatting for the interface.
 *
 * Pure functions, no React, no Expo — so the parts most likely to be wrong
 * (date boundaries, grouping, truncation of user text) are testable.
 */

import { Strings } from '../i18n';
import { Message } from '../storage/db';

/** Clock time for a message bubble. */
export function messageTime(timestamp: number, locale: string = 'en'): string {
  return new Date(timestamp).toLocaleTimeString(locale, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

/**
 * Label for a day separator.
 *
 * Compares calendar days rather than subtracting 24 hours: a message sent at
 * 23:50 is "yesterday" at 00:10, not "today".
 */
export function dayLabel(timestamp: number, s: Strings, now: number = Date.now(), locale = 'en'): string {
  const day = startOfDay(timestamp);
  const today = startOfDay(now);
  const oneDay = 24 * 60 * 60 * 1000;

  if (day === today) return s.today;
  if (day === today - oneDay) return s.yesterday;

  const date = new Date(timestamp);
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  return date.toLocaleDateString(locale, {
    day: 'numeric',
    month: 'short',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
}

function startOfDay(timestamp: number): number {
  const d = new Date(timestamp);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/** Relative timestamp for the chat list. */
export function relativeTime(timestamp: number, s: Strings, now: number = Date.now(), locale = 'en'): string {
  const day = startOfDay(timestamp);
  const today = startOfDay(now);
  const oneDay = 24 * 60 * 60 * 1000;

  if (day === today) return messageTime(timestamp, locale);
  if (day === today - oneDay) return s.yesterday;
  if (today - day < 7 * oneDay) {
    return new Date(timestamp).toLocaleDateString(locale, { weekday: 'short' });
  }
  return new Date(timestamp).toLocaleDateString(locale, { day: 'numeric', month: 'numeric' });
}

export type Row =
  | { kind: 'day'; key: string; label: string }
  | { kind: 'message'; key: string; message: Message; showTail: boolean };

/**
 * Turn a flat message list into rows with day separators.
 *
 * `showTail` marks the last message in a run from the same sender, so only
 * that bubble gets the pointed corner — a small thing that makes a long
 * conversation much easier to scan.
 */
export function buildRows(messages: Message[], s: Strings, now = Date.now(), locale = 'en'): Row[] {
  const rows: Row[] = [];
  let lastDay: number | null = null;

  messages.forEach((message, index) => {
    const day = new Date(message.createdAt).setHours(0, 0, 0, 0);
    if (day !== lastDay) {
      rows.push({ kind: 'day', key: `day-${day}`, label: dayLabel(message.createdAt, s, now, locale) });
      lastDay = day;
    }
    const next = messages[index + 1];
    const showTail =
      !next ||
      next.outgoing !== message.outgoing ||
      new Date(next.createdAt).setHours(0, 0, 0, 0) !== day;
    rows.push({ kind: 'message', key: message.id, message, showTail });
  });

  return rows;
}

/** Preview line for the chat list. */
export function previewText(message: Message | undefined, maxLength = 80): string {
  if (!message) return '';
  const collapsed = message.text.replace(/\s+/g, ' ').trim();
  if (collapsed.length <= maxLength) return collapsed;
  return `${collapsed.slice(0, maxLength - 1).trimEnd()}…`;
}

/**
 * Group a safety number into readable chunks.
 *
 * Two people read these aloud to each other. Twelve groups of five in three
 * rows of four is the layout that survives that best.
 */
export function safetyNumberRows(safetyNumber: string): string[][] {
  const groups = safetyNumber.split(/\s+/).filter(Boolean);
  const rows: string[][] = [];
  for (let i = 0; i < groups.length; i += 4) rows.push(groups.slice(i, i + 4));
  return rows;
}

/** Display form of an account ID: grouped so it can be read aloud. */
export function formatAccountId(accountId: string): string {
  return accountId.replace(/(.{6})(?=.)/g, '$1-');
}

/**
 * Distinguish a handle from an account ID in whatever the user typed.
 *
 * Handles are lowercase and short; account IDs are 26 characters of Crockford
 * base32. Guessing wrong sends the user to a lookup that cannot succeed, so
 * this errs toward treating ambiguous input as a handle — the recoverable case.
 */
export function parseContactInput(input: string): { kind: 'handle' | 'accountId'; value: string } {
  const trimmed = input.trim();
  if (trimmed.startsWith('@')) {
    return { kind: 'handle', value: trimmed.slice(1).toLowerCase() };
  }
  const compact = trimmed.replace(/[\s-]/g, '').toUpperCase();
  if (/^[0-9A-HJKMNP-TV-Z]{26}$/.test(compact)) {
    return { kind: 'accountId', value: compact };
  }
  return { kind: 'handle', value: trimmed.toLowerCase() };
}
