import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { TildraClient } from '../../api/client';
import {
  dismissWakeNotifications,
  presentLocalNotification,
  registerForPush,
  unregisterForPush,
} from '../register';

/**
 * Push registration, which until now had no test of its own.
 *
 * The interesting half is not the registering. It is what is left on the
 * device afterwards: `presentLocalNotification` posts the contact's name as
 * the title and the decrypted message as the body, deliberately, because the
 * device knows both and the push service must not. That is the right trade
 * while the account exists and the wrong thing to leave behind once it does
 * not — so the sign-out path is tested here as hard as the happy path.
 *
 * `expo-notifications` and `expo-device` are the only native modules this file
 * reaches, and both are dynamically imported, so both are replaced. The fake
 * shade below models the one platform behaviour the code depends on: a
 * notification scheduled with `trigger: null` is presented immediately.
 */

type Presented = {
  request: { identifier: string; content: { title: string; body: string; data: Record<string, unknown> } };
};

const shade = {
  presented: [] as Presented[],
  scheduled: [] as Presented[],
  nextId: 0,
  failDismissAll: null as Error | null,
  failCancelAll: null as Error | null,
  failGetPresented: null as Error | null,
};

const permissions = {
  granted: false,
  canAskAgain: true,
  requestCalls: 0,
  grantOnRequest: true,
};

const device = { isDevice: true };

vi.mock('expo-device', () => ({
  get isDevice() {
    return device.isDevice;
  },
}));

vi.mock('expo-notifications', () => ({
  async getPermissionsAsync() {
    return { granted: permissions.granted, canAskAgain: permissions.canAskAgain };
  },
  async requestPermissionsAsync() {
    permissions.requestCalls += 1;
    return { granted: permissions.grantOnRequest, canAskAgain: false };
  },
  async getExpoPushTokenAsync() {
    return { data: 'ExponentPushToken[test]' };
  },
  async scheduleNotificationAsync(request: {
    content: { title: string; body: string; data: Record<string, unknown> };
    trigger: unknown;
  }) {
    const entry: Presented = {
      request: { identifier: `n${shade.nextId++}`, content: request.content },
    };
    // trigger: null means "show it now" — anything else is a future delivery.
    if (request.trigger === null) shade.presented.push(entry);
    else shade.scheduled.push(entry);
    return entry.request.identifier;
  },
  async getPresentedNotificationsAsync() {
    if (shade.failGetPresented) throw shade.failGetPresented;
    return shade.presented;
  },
  async dismissNotificationAsync(identifier: string) {
    shade.presented = shade.presented.filter((n) => n.request.identifier !== identifier);
  },
  async dismissAllNotificationsAsync() {
    if (shade.failDismissAll) throw shade.failDismissAll;
    shade.presented = [];
  },
  async cancelAllScheduledNotificationsAsync() {
    if (shade.failCancelAll) throw shade.failCancelAll;
    shade.scheduled = [];
  },
}));

/** A client that records what the server was asked to do. */
function fakeClient(options: { failDelete?: Error } = {}) {
  const calls = { registered: [] as Array<{ platform: string; token: string }>, deletes: 0 };
  const client = {
    async registerPushToken(platform: string, token: string) {
      calls.registered.push({ platform, token });
    },
    async deletePushToken() {
      calls.deletes += 1;
      if (options.failDelete) throw options.failDelete;
    },
  };
  return { client: client as unknown as TildraClient, calls };
}

/** The two kinds of notification Tildra puts on a device. */
async function aWakePlaceholder() {
  await presentLocalNotification({ title: 'Tildra', body: 'New message', data: { type: 'wake' } });
}

async function aDecryptedMessage() {
  await presentLocalNotification({
    title: 'Ayşe',
    body: 'the plaintext of a message',
    data: { accountId: 'acct-1' },
  });
}

beforeEach(() => {
  shade.presented = [];
  shade.scheduled = [];
  shade.nextId = 0;
  shade.failDismissAll = null;
  shade.failCancelAll = null;
  shade.failGetPresented = null;
  permissions.granted = false;
  permissions.canAskAgain = true;
  permissions.requestCalls = 0;
  permissions.grantOnRequest = true;
  device.isDevice = true;
});

describe('asking for permission', () => {
  it('does not bother a simulator, which has no push token to give', async () => {
    device.isDevice = false;
    const { client, calls } = fakeClient();

    expect(await registerForPush(client)).toBe(false);
    expect(permissions.requestCalls).toBe(0);
    expect(calls.registered).toEqual([]);
  });

  it('does not re-prompt someone who has already said no', async () => {
    // The module's own promise: declining is a supported state, not a failure.
    // Re-asking a user whose answer is final is how apps train people to deny
    // permissions they might otherwise have granted later.
    permissions.granted = false;
    permissions.canAskAgain = false;
    const { client, calls } = fakeClient();

    expect(await registerForPush(client)).toBe(false);
    expect(permissions.requestCalls).toBe(0);
    expect(calls.registered).toEqual([]);
  });

  it('asks once when it still can, and registers the token on yes', async () => {
    permissions.granted = false;
    permissions.canAskAgain = true;
    permissions.grantOnRequest = true;
    const { client, calls } = fakeClient();

    expect(await registerForPush(client)).toBe(true);
    expect(permissions.requestCalls).toBe(1);
    expect(calls.registered).toEqual([{ platform: 'expo', token: 'ExponentPushToken[test]' }]);
  });

  it('registers nothing when the answer is still no', async () => {
    // The token must not reach the server on a refusal — a registered token is
    // the server holding a routable handle for a device the user opted out of.
    permissions.canAskAgain = true;
    permissions.grantOnRequest = false;
    const { client, calls } = fakeClient();

    expect(await registerForPush(client)).toBe(false);
    expect(calls.registered).toEqual([]);
  });

  it('skips the prompt entirely when permission is already granted', async () => {
    permissions.granted = true;
    const { client, calls } = fakeClient();

    expect(await registerForPush(client)).toBe(true);
    expect(permissions.requestCalls).toBe(0);
    expect(calls.registered).toHaveLength(1);
  });
});

describe('what a sign-out leaves on the device', () => {
  it('clears the notifications that name contacts and quote their messages', async () => {
    // This is the one that used to go wrong. signOut wiped the database and
    // dropped the master key, and the lock screen went on showing the sender's
    // name and the decrypted text of the last message — on a device the user
    // had just been told was wiped.
    await aDecryptedMessage();
    await aWakePlaceholder();
    expect(shade.presented).toHaveLength(2);

    const { client } = fakeClient();
    await unregisterForPush(client);

    expect(shade.presented).toEqual([]);
  });

  it('clears the shade even when the server cannot be reached', async () => {
    // The network being down is the ordinary case for "delete my account and
    // hand the phone over", not the exotic one.
    await aDecryptedMessage();
    const { client, calls } = fakeClient({ failDelete: new Error('offline') });

    await expect(unregisterForPush(client)).resolves.toBeUndefined();
    expect(calls.deletes).toBe(1);
    expect(shade.presented).toEqual([]);
  });

  it('clears the shade on a device whose bootstrap never finished', async () => {
    // No runtime means no client, and that device can still be holding
    // notifications from before the failure.
    await aDecryptedMessage();

    await expect(unregisterForPush(null)).resolves.toBeUndefined();
    expect(shade.presented).toEqual([]);
  });

  it('cancels what was scheduled but not yet shown', async () => {
    await presentLocalNotification({ title: 'Ayşe', body: 'later', data: {} });
    shade.scheduled.push({
      request: { identifier: 'future', content: { title: 'Ayşe', body: 'later', data: {} } },
    });

    await unregisterForPush(null);
    expect(shade.scheduled).toEqual([]);
  });

  it('still deletes the server token when the shade will not clear', async () => {
    // A local failure must not cost the server-side revocation, or an
    // unreachable notification centre leaves the account push-addressable.
    shade.failDismissAll = new Error('notification centre unavailable');
    const { client, calls } = fakeClient();

    await expect(unregisterForPush(client)).resolves.toBeUndefined();
    expect(calls.deletes).toBe(1);
  });

  it('cancels the scheduled ones even when dismissing the presented ones fails', async () => {
    // The two steps are independent, and are guarded independently. Sharing
    // one try block would make the first failure silently skip the second.
    shade.failDismissAll = new Error('notification centre unavailable');
    shade.scheduled.push({
      request: { identifier: 'future', content: { title: 'Ayşe', body: 'later', data: {} } },
    });

    await unregisterForPush(null);
    expect(shade.scheduled).toEqual([]);
  });
});

describe('the wake placeholder sweep', () => {
  it('dismisses the content-free placeholders and leaves the real ones', async () => {
    // This runs after a message is decrypted, to retire the "something
    // arrived" notification the server sent once the named one has replaced
    // it. Note what it does not do.
    await aWakePlaceholder();
    await aDecryptedMessage();

    await dismissWakeNotifications();

    expect(shade.presented.map((n) => n.request.content.title)).toEqual(['Ayşe']);
  });

  it('is not a wipe, which is why sign-out does not use it', async () => {
    // Kept as a live assertion rather than a comment: if someone ever reaches
    // for this on the sign-out path, the message body survives the call and
    // this test says so.
    await aDecryptedMessage();

    await dismissWakeNotifications();

    expect(shade.presented).toHaveLength(1);
    expect(shade.presented[0].request.content.body).toBe('the plaintext of a message');
  });
});

describe('the notification the user actually sees', () => {
  it('is shown immediately rather than scheduled', async () => {
    await presentLocalNotification({ title: 'Ayşe', body: 'hello', data: { accountId: 'a' } });

    expect(shade.scheduled).toEqual([]);
    expect(shade.presented).toHaveLength(1);
    expect(shade.presented[0].request.content).toMatchObject({ title: 'Ayşe', body: 'hello' });
  });

  it('defaults its payload to an object rather than undefined', async () => {
    // dismissWakeNotifications reads `data?.type` off every presented
    // notification; a missing payload there is a crash on the sweep path.
    await presentLocalNotification({ title: 'Ayşe', body: 'hello' });

    expect(shade.presented[0].request.content.data).toEqual({});
    await expect(dismissWakeNotifications()).resolves.toBeUndefined();
  });
});
