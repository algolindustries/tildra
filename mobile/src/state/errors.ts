/**
 * What the user reads when something fails.
 *
 * Its own module because it is the single funnel: every `set({ error })` in
 * `app.ts` goes through here, so this is the one place that decides whose
 * words reach the screen — and `app.ts` cannot be imported by a test, since
 * it reaches `react-native` transitively. A function this load-bearing should
 * not be untestable because of what its neighbours import.
 */

import { ApiError } from '../api/client';
import { ServerFrameError } from '../api/socket';
import { TransparencyError } from '../crypto/transparency';
import { Strings } from '../i18n';
import { IdentityChangedError, NoDevicesError } from '../session/manager';
import { serverText } from '../ui/format';

/**
 * Two rules.
 *
 * Text the server chose is never rendered on its own — it arrives either as
 * `ApiError.detail` over HTTP or as a `ServerFrameError` over the socket, and
 * both go through `serverText`, which attributes and bounds it. Everything
 * else here is a message this codebase wrote.
 *
 * And a failure the user can act on gets the sentence written for it rather
 * than the exception's. `IdentityChangedError` is the whole point: an
 * exception message is a developer's sentence, and this is the warning the
 * design most needs the user to read.
 */
export function describeError(err: unknown, t: Strings): string {
  if (err instanceof IdentityChangedError) return t.identityChangedTitle;
  if (err instanceof NoDevicesError) return t.errorNoDevices;
  if (err instanceof TransparencyError) return `${t.errorTransparency} ${err.message}`;
  if (err instanceof ApiError) return err.status === 0 ? t.errorNetwork : serverText(err.detail, t);
  if (err instanceof ServerFrameError) return serverText(err.message, t);
  if (err instanceof Error) return err.message;
  return t.errorGeneric;
}
