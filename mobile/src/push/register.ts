/**
 * Push registration.
 *
 * A notification from the server says only that something arrived. It carries
 * no sender, no preview and no conversation, because Apple and Google see
 * every payload and must not be handed the social graph along with the wake
 * signal.
 *
 * What the user actually sees is built here, on the device, after the message
 * has been decrypted — at which point showing a name costs nothing, because
 * the name never left the phone.
 */

import { TildraClient } from '../api/client';

export type PushPlatform = 'expo' | 'apns' | 'fcm';

export class PushError extends Error {}

/**
 * Ask for permission and register this device's token with the server.
 *
 * Returns false when the user declines or the device cannot receive push.
 * That is a supported state, not a failure: the app still delivers messages
 * whenever it is open, and pretending otherwise would push people into
 * granting a permission they said no to.
 */
export async function registerForPush(client: TildraClient): Promise<boolean> {
  const Notifications = await import('expo-notifications');
  const Device = await import('expo-device');

  if (!Device.isDevice) {
    // Simulators have no push token. Not worth an error dialog.
    return false;
  }

  const existing = await Notifications.getPermissionsAsync();
  let granted = existing.granted;
  if (!granted && existing.canAskAgain) {
    granted = (await Notifications.requestPermissionsAsync()).granted;
  }
  if (!granted) return false;

  const token = await Notifications.getExpoPushTokenAsync();
  await client.registerPushToken('expo', token.data);
  return true;
}

/**
 * Stop notifications for this device, and remove the token server-side.
 *
 * The local half is the one that matters. Deleting the server token only stops
 * what has not been sent yet; the notifications already sitting in the shade
 * were posted by `presentLocalNotification`, whose titles are contact names
 * and whose bodies are decrypted message text. A sign-out that wipes the
 * database and the master key but leaves those behind hands the next person
 * holding the phone exactly what the encryption existed to keep from them.
 *
 * `client` may be null: sign-out has to work on a device whose bootstrap never
 * finished, and the notifications still need clearing there.
 *
 * Nothing here may throw. This runs on the sign-out path, where failing early
 * once already left an account intact on a device the user believed was wiped.
 */
export async function unregisterForPush(client: TildraClient | null): Promise<void> {
  await dismissAllNotifications();
  if (!client) return;
  try {
    await client.deletePushToken();
  } catch {
    // A server we cannot reach must not block a local sign-out.
  }
}

/**
 * Clear every notification this app has put on the device — presented and
 * scheduled alike.
 *
 * Each step is guarded on its own rather than sharing one try block. They are
 * independent, and the first one failing is not a reason to skip the second on
 * a path whose whole job is to leave nothing behind.
 */
async function dismissAllNotifications(): Promise<void> {
  let Notifications: typeof import('expo-notifications');
  try {
    Notifications = await import('expo-notifications');
  } catch {
    return;
  }
  try {
    await Notifications.dismissAllNotificationsAsync();
  } catch {
    // Best effort: a platform that cannot enumerate the shade is not a reason
    // to abandon the rest of the wipe.
  }
  try {
    await Notifications.cancelAllScheduledNotificationsAsync();
  } catch {
    // As above.
  }
}

/**
 * Replace the server's placeholder with something meaningful.
 *
 * Called after a message is decrypted. The title is the contact's name, which
 * the device knows and the push service does not.
 */
export async function presentLocalNotification(options: {
  title: string;
  body: string;
  data?: Record<string, unknown>;
}): Promise<void> {
  const Notifications = await import('expo-notifications');
  await Notifications.scheduleNotificationAsync({
    content: { title: options.title, body: options.body, data: options.data ?? {} },
    trigger: null,
  });
}

/** Clear the content-free placeholders once their messages have been shown. */
export async function dismissWakeNotifications(): Promise<void> {
  const Notifications = await import('expo-notifications');
  const presented = await Notifications.getPresentedNotificationsAsync();
  for (const notification of presented) {
    if (notification.request.content.data?.type === 'wake') {
      await Notifications.dismissNotificationAsync(notification.request.identifier);
    }
  }
}
