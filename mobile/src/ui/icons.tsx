/**
 * The icon set.
 *
 * These were emoji until they were not. `☎` renders as a red rotary telephone
 * on iOS, `🎙` as a full-colour studio microphone, and both sat in a header
 * built entirely from one teal accent — so the two loudest things on the screen
 * were the two the design never chose. `▣` was worse: a video call button that
 * is simply a filled square says nothing at all.
 *
 * Emoji are also not ours to draw. They change with the platform, they carry
 * the vendor's palette rather than the app's, and they do not dim when a button
 * is disabled, so `blocked` styling silently did nothing to them.
 *
 * Everything here is one 24-unit grid, 2-unit strokes, round caps and joins,
 * and takes its colour from the caller. `react-native-svg` is already a
 * dependency — `react-native-qrcode-svg` pulls it in — so this costs no bundle
 * we were not already paying for.
 */

import React from 'react';
import Svg, { Circle, Path, Polyline, Rect } from 'react-native-svg';

import { palette } from './theme';

export interface IconProps {
  size?: number;
  color?: string;
}

const DEFAULT_SIZE = 22;

function Icon({
  size = DEFAULT_SIZE,
  color = palette.accent,
  children,
}: IconProps & { children: React.ReactNode }) {
  return (
    <Svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {children}
    </Svg>
  );
}

/** Audio call. A handset, not the emoji telephone. */
export function IconPhone(props: IconProps) {
  return (
    <Icon {...props}>
      <Path d="M6.5 3.5h-2A2 2 0 0 0 2.5 5.7C3.3 12.6 8.9 18.2 15.8 19c1.2.1 2.2-.8 2.2-2v-2a1.6 1.6 0 0 0-1.3-1.6l-2.2-.4a1.6 1.6 0 0 0-1.6.7l-.7 1a12.6 12.6 0 0 1-5.2-5.2l1-.7a1.6 1.6 0 0 0 .7-1.6l-.4-2.2A1.6 1.6 0 0 0 6.5 3.5Z" />
    </Icon>
  );
}

/** Video call. A camera body with the lens barrel that reads as "video". */
export function IconVideo(props: IconProps) {
  return (
    <Icon {...props}>
      <Rect x="2" y="6" width="13" height="12" rx="2.5" />
      <Path d="M15 10.5 21.2 7.2a.6.6 0 0 1 .8.5v8.6a.6.6 0 0 1-.8.5L15 13.5Z" />
    </Icon>
  );
}

/** Hold to record a voice message. */
export function IconMic(props: IconProps) {
  return (
    <Icon {...props}>
      <Rect x="9" y="2.5" width="6" height="11" rx="3" />
      <Path d="M5.5 11a6.5 6.5 0 0 0 13 0" />
      <Path d="M12 17.5V21" />
    </Icon>
  );
}

/** Recording in progress — a filled stop square, the standard "release to end". */
export function IconStop({ size = DEFAULT_SIZE, color = palette.accent }: IconProps) {
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24">
      <Rect x="7" y="7" width="10" height="10" rx="2" fill={color} />
    </Svg>
  );
}

/** Send. */
export function IconSend(props: IconProps) {
  return (
    <Icon {...props}>
      <Path d="M12 19.5V5" />
      <Polyline points="5.5,11.5 12,5 18.5,11.5" />
    </Icon>
  );
}

/** Attach a photo. */
export function IconPlus(props: IconProps) {
  return (
    <Icon {...props}>
      <Path d="M12 5.5v13" />
      <Path d="M5.5 12h13" />
    </Icon>
  );
}

/** New group. */
export function IconUsers(props: IconProps) {
  return (
    <Icon {...props}>
      <Circle cx="9" cy="8" r="3.5" />
      <Path d="M2.5 19.5a6.5 6.5 0 0 1 13 0" />
      <Path d="M16 5.2a3.5 3.5 0 0 1 0 5.6" />
      <Path d="M18 14.6a6.5 6.5 0 0 1 3.5 4.9" />
    </Icon>
  );
}

// ---------------------------------------------------------------------------
// Message state
// ---------------------------------------------------------------------------
//
// One tick left this device, two ticks reached theirs, two accent ticks were
// read. The shapes differ as well as the colour, because "delivered" and "read"
// separated by hue alone is exactly the distinction a colour-blind user cannot
// make — and it is the one people check most often.

/** Waiting to go out. */
export function IconClock(props: IconProps) {
  return (
    <Icon {...props}>
      <Circle cx="12" cy="12" r="8.5" />
      <Polyline points="12,7.5 12,12 15,13.5" />
    </Icon>
  );
}

/** Sent: accepted by the server for at least one of their devices. */
export function IconCheck(props: IconProps) {
  return (
    <Icon {...props}>
      <Polyline points="4.5,12.5 9.5,17.5 19.5,6.5" />
    </Icon>
  );
}

/** Delivered, and — in the accent colour — read. */
export function IconCheckDouble(props: IconProps) {
  return (
    <Icon {...props}>
      <Polyline points="1.5,12.5 6,17 15,7" />
      <Polyline points="9,12.5 11.5,15.5 20.5,5.5" />
    </Icon>
  );
}

/** Nothing went out. */
export function IconAlert(props: IconProps) {
  return (
    <Icon {...props}>
      <Circle cx="12" cy="12" r="8.5" />
      <Path d="M12 7.5v5" />
      <Path d="M12 16.2v.3" />
    </Icon>
  );
}
