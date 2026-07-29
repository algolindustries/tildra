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

/** Stop notifications for this device, and remove the token server-side. */
export async function unregisterForPush(client: TildraClient): Promise<void> {
  try {
    await client.deletePushToken();
  } catch {
    // A server we cannot reach must not block a local sign-out.
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
