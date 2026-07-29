/**
 * Visual language.
 *
 * Dark by default, because a messaging app is used in bed at 1am more than
 * anywhere else. Colour is used sparingly and means something: accent for
 * your own messages, danger for the one screen that must stop the user.
 */

export const palette = {
  // Backgrounds, darkest to lightest.
  bg: '#0B0D10',
  surface: '#14171C',
  surfaceRaised: '#1C2027',
  border: '#262B33',

  text: '#E8EBEF',
  textMuted: '#8A929E',
  textFaint: '#5A626E',

  // The accent is a desaturated teal — legible on dark, distinguishable for
  // the most common forms of colour blindness, and not the blue every other
  // messenger uses.
  accent: '#3DD6C0',
  accentDim: '#1E6B61',
  onAccent: '#06120F',

  danger: '#FF6B6B',
  dangerDim: '#4A1F1F',
  warning: '#FFB454',
  success: '#5FD97A',
} as const;

export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 24,
  xxl: 32,
} as const;

export const radius = {
  sm: 8,
  md: 12,
  lg: 18,
  pill: 999,
} as const;

export const typography = {
  title: { fontSize: 28, fontWeight: '700' as const, letterSpacing: -0.5 },
  heading: { fontSize: 20, fontWeight: '600' as const },
  body: { fontSize: 16, fontWeight: '400' as const },
  bodyStrong: { fontSize: 16, fontWeight: '600' as const },
  small: { fontSize: 13, fontWeight: '400' as const },
  tiny: { fontSize: 11, fontWeight: '500' as const, letterSpacing: 0.3 },
  // Safety numbers are compared digit by digit by two people reading aloud.
  // Monospace and generous tracking are functional here, not decorative.
  mono: { fontSize: 18, fontFamily: 'Courier', letterSpacing: 1.5 },
} as const;

/**
 * A stable colour per account, for avatars.
 *
 * Derived from the account ID so the same contact is the same colour on every
 * device, without storing anything.
 */
export function avatarColor(accountId: string): string {
  const colors = ['#3DD6C0', '#7C9CF5', '#F5A97C', '#C79CF5', '#F57C9C', '#9CF5B4', '#F5D97C'];
  let sum = 0;
  for (let i = 0; i < accountId.length; i++) sum = (sum + accountId.charCodeAt(i) * (i + 1)) % 9973;
  return colors[sum % colors.length];
}

/** Up to two initials for an avatar, from a handle or an account ID. */
export function initials(name: string): string {
  const cleaned = name.replace(/^@/, '').trim();
  if (!cleaned) return '?';
  const words = cleaned.split(/[\s_-]+/).filter(Boolean);
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return cleaned.slice(0, 2).toUpperCase();
}
