/**
 * Reading a code off the camera.
 *
 * A scanner is an input the attacker fully controls and the user barely looks
 * at. Anything printed on a poster, shown on a compromised screen, or left on a
 * table is a candidate, and the user's mental model is "I pointed my phone at a
 * square and the app did something". So the rules here are stricter than they
 * would be for something typed:
 *
 * - **Every code declares what it is, and a caller says what it wants.** The
 *   device-link screen must not act on a safety-verification code and the
 *   safety screen must not act on a link code. Two flows that both accept
 *   "whatever scanned" is how a user gets talked into pointing their camera at
 *   the wrong square.
 * - **The server URL inside a link code is hostile.** It is not used today —
 *   `approveDeviceLink` ignores it and talks to the client it is already
 *   authenticated against — but a field that is parsed and returned unchecked
 *   is a trap waiting for the next caller. It is validated here so that caller
 *   cannot exist.
 * - **A scanner fires repeatedly.** `onBarcodeScanned` delivers the same code
 *   many times a second for as long as it is in frame. Without a gate, one
 *   poster pointed at for two seconds adds fifty devices to an account.
 */

import { LinkOffer, ProvisioningError, decodeLinkOffer } from './provisioning';

export class ScanError extends Error {}

/**
 * Cap on what will be looked at. A QR code tops out around 3 KB, and a
 * scanner that hands over more than this is not handing over a QR code.
 */
export const MAX_SCAN_LENGTH = 4096;

const LINK_PREFIX = 'tildra://link?';
const SAFETY_PREFIX = 'tildra:verify:';

export type ScannedCode =
  | { kind: 'device-link'; offer: LinkOffer; serverUrl: string }
  | { kind: 'safety'; payload: string };

/**
 * Work out what was scanned, or refuse.
 *
 * Callers should use `readDeviceLink` or `readSafetyCode` instead of switching
 * on the result themselves — those refuse the wrong kind with a message that
 * says which screen the code belongs on, which is the difference between a
 * user who is confused and a user who is being steered.
 */
export function classifyScan(raw: string): ScannedCode {
  const payload = raw.trim();

  if (payload.length === 0) {
    throw new ScanError('nothing was scanned');
  }
  if (payload.length > MAX_SCAN_LENGTH) {
    throw new ScanError('that code is too large to be a Tildra code');
  }

  if (payload.startsWith(LINK_PREFIX)) {
    const { offer, serverUrl } = decodeLinkOffer(payload);
    return { kind: 'device-link', offer, serverUrl: assertUsableServerUrl(serverUrl) };
  }

  if (payload.startsWith(SAFETY_PREFIX)) {
    return { kind: 'safety', payload };
  }

  throw new ScanError('that is not a Tildra code');
}

/** A device-link code, refusing anything else by name. */
export function readDeviceLink(raw: string): { offer: LinkOffer; serverUrl: string } {
  const scanned = classifyScan(raw);
  if (scanned.kind !== 'device-link') {
    throw new ScanError(
      'that is a safety-number code, not a device-link code — scan it from the safety number screen',
    );
  }
  return { offer: scanned.offer, serverUrl: scanned.serverUrl };
}

/** A safety-verification code, refusing anything else by name. */
export function readSafetyCode(raw: string): string {
  const scanned = classifyScan(raw);
  if (scanned.kind !== 'safety') {
    throw new ScanError(
      'that is a device-link code, not a safety-number code — scan it from the link device screen',
    );
  }
  return scanned.payload;
}

/**
 * Refuse a server URL that would be dangerous to talk to.
 *
 * Plaintext HTTP is allowed only for loopback, which is what a developer runs
 * against. Everything else must be HTTPS: a scanned code that downgrades the
 * transport is the whole attack in one field. Embedded credentials are refused
 * because `fetch` would use them and nothing would say so.
 */
export function assertUsableServerUrl(raw: string, subject = 'the code'): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ScanError(`${subject} points at something that is not a URL`);
  }

  if (url.username || url.password) {
    throw new ScanError(`${subject} embeds credentials in its server address`);
  }
  if (url.search || url.hash) {
    throw new ScanError(`the server address in ${subject} is malformed`);
  }

  const loopback = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);
  if (url.protocol === 'https:') return raw;
  if (url.protocol === 'http:' && loopback) return raw;

  throw new ScanError(
    url.protocol === 'http:'
      ? `${subject} points at a plaintext server`
      : `${subject} points at an unsupported address (${url.protocol})`,
  );
}

// ---------------------------------------------------------------------------
// Scan gate
// ---------------------------------------------------------------------------

/**
 * How long the same code is ignored after it has been handled once. Long
 * enough to cover holding a phone steady over one square, short enough that a
 * user who genuinely rescans does not think the app is broken.
 */
export const SCAN_REPEAT_WINDOW_MS = 2500;

export interface ScanGate {
  /** Whether this payload should be acted on right now. */
  shouldHandle(payload: string, now?: number): boolean;
  /** Stop accepting anything. Call once a scan has been acted on. */
  close(): void;
  reset(): void;
}

/**
 * Suppress the repeats a camera produces.
 *
 * Deliberately *not* a plain debounce: a different code is let through
 * immediately, because a user who realises they are pointing at the wrong
 * square should not have to wait. Only repeats of the same value are dropped.
 *
 * `close()` exists because for a link approval even one extra call is one
 * extra device on the account — a time window is the wrong tool once the scan
 * has actually been acted on.
 */
export function createScanGate(
  options: { windowMs?: number } = {},
): ScanGate {
  const windowMs = options.windowMs ?? SCAN_REPEAT_WINDOW_MS;
  let closed = false;
  let last: { payload: string; at: number } | null = null;

  return {
    shouldHandle(payload: string, now = Date.now()): boolean {
      if (closed) return false;
      if (last && last.payload === payload && now - last.at < windowMs) return false;
      last = { payload, at: now };
      return true;
    },
    close() {
      closed = true;
    },
    reset() {
      closed = false;
      last = null;
    },
  };
}

/** Turn a scan failure into something worth putting in front of a person. */
export function describeScanError(err: unknown): string {
  if (err instanceof ScanError) return err.message;
  if (err instanceof ProvisioningError) return err.message;
  return 'that code could not be read';
}
