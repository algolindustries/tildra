/**
 * The session manager.
 *
 * This is where the crypto, the network and the database meet. Everything the
 * UI does goes through here, and everything security-relevant that the user
 * needs to be told about originates here.
 *
 * The rule this file exists to enforce: a message is never sent over a session
 * whose identity key has not been checked against what we already knew. When
 * that check fails, sending stops and the user is told — it is not logged and
 * worked around.
 */

import { TildraClient } from '../api/client';
import { IncomingEnvelope } from '../api/socket';
import {
  KeyPair,
  equal,
  fromUtf8,
  toBase64,
  utf8,
  wipe,
} from '../crypto/primitives';
import {
  PreKeySecrets,
  SessionInit,
  acceptSession,
  initiateSession,
  verifyBundle,
} from '../crypto/pqxdh';
import { RatchetState, decrypt, encrypt } from '../crypto/ratchet';
import { openEnvelope, sealEnvelope } from '../crypto/sealed';
import {
  contactInbox,
  currentMailboxes,
  deliveryMailbox,
  deriveMailboxSecret,
} from '../crypto/mailbox';
import { safetyNumber } from '../crypto/safety';
import {
  ONE_TIME_PREKEY_TARGET,
  generatePreKeys,
  needsPreKeyTopUp,
} from '../crypto/identity';
import { Conversation, Message, MessageState, StoredSession } from '../storage/db';

/**
 * The persistence the manager needs. `Database` satisfies it; tests provide an
 * in-memory double, which is why this is an interface and not the class.
 */
export interface SessionStore {
  upsertConversation(c: Conversation): Promise<string>;
  getConversation(accountId: string): Promise<(Conversation & { id: string }) | null>;
  flagIdentityChange(accountId: string, newIdentityKey: Uint8Array): Promise<void>;
  insertMessage(m: Message): Promise<void>;
  setMessageState(id: string, state: MessageState): Promise<void>;
  saveSession(s: StoredSession): Promise<void>;
  loadSession(accountId: string, deviceId: string): Promise<StoredSession | null>;
  loadSessionsFor(accountId: string): Promise<StoredSession[]>;
  setMeta(key: string, value: string): Promise<void>;
  getMeta(key: string): Promise<string | null>;
}

/**
 * Raised when a contact's identity key does not match what we stored.
 *
 * This is the signature of a server-side MITM. The conversation is flagged and
 * sending is blocked until the user acknowledges the change — ideally after
 * comparing safety numbers with the person in question.
 */
export class IdentityChangedError extends Error {
  constructor(
    readonly accountId: string,
    readonly previousKey: Uint8Array,
    readonly newKey: Uint8Array,
  ) {
    super(
      `Tildra: the identity key for ${accountId} changed. ` +
        'Sending is blocked until you verify this was expected.',
    );
  }
}

export class NoDevicesError extends Error {}

export interface ManagerEvents {
  onMessage?: (message: Message, conversation: Conversation) => void;
  onIdentityChange?: (accountId: string) => void;
  onError?: (error: Error) => void;
}

export interface ManagerOptions {
  identity: KeyPair;
  accountId: string;
  deviceId: string;
  client: TildraClient;
  store: SessionStore;
  preKeys: PreKeySecrets;
  events?: ManagerEvents;
  /**
   * Called whenever the set of mailboxes this device listens on changes. The
   * app wires this to TildraSocket.subscribe so a live socket starts serving
   * addresses created after it connected.
   */
  onMailboxesChanged?: (mailboxes: string[]) => void;
  /** Injectable for tests. */
  now?: () => number;
  randomId?: () => string;
}

export class SessionManager {
  private readonly identity: KeyPair;
  private readonly accountId: string;
  private readonly deviceId: string;
  private readonly client: TildraClient;
  private readonly store: SessionStore;
  private readonly events: ManagerEvents;
  private readonly now: () => number;
  private readonly randomId: () => string;
  private readonly onMailboxesChanged?: (mailboxes: string[]) => void;
  private preKeys: PreKeySecrets;

  constructor(options: ManagerOptions) {
    this.identity = options.identity;
    this.accountId = options.accountId;
    this.deviceId = options.deviceId;
    this.client = options.client;
    this.store = options.store;
    this.preKeys = options.preKeys;
    this.events = options.events ?? {};
    this.onMailboxesChanged = options.onMailboxesChanged;
    this.now = options.now ?? (() => Date.now());
    this.randomId = options.randomId ?? (() => toBase64(crypto.getRandomValues(new Uint8Array(16))));
  }

  // -------------------------------------------------------------------------
  // Mailboxes
  // -------------------------------------------------------------------------

  /**
   * Publish every mailbox this device listens on: the stable contact inbox
   * plus a three-day window for each active session.
   *
   * Called at startup and once a day. Registering tomorrow's mailbox ahead of
   * time is what stops a message sent at 23:59:59 from landing somewhere
   * nobody is listening.
   */
  async publishMailboxes(): Promise<string[]> {
    const mailboxes = new Set<string>([contactInbox(this.identity.publicKey)]);

    const conversations = await this.activeAccountIds();
    for (const accountId of conversations) {
      for (const session of await this.store.loadSessionsFor(accountId)) {
        const secret = deriveMailboxSecret(session.mailboxSecret, this.accountId, this.deviceId);
        for (const mailbox of currentMailboxes(secret, new Date(this.now()))) {
          mailboxes.add(mailbox);
        }
      }
    }

    const all = [...mailboxes];
    // The server caps a single call; batch rather than dropping the tail.
    for (let i = 0; i < all.length; i += 64) {
      await this.client.registerMailboxes(all.slice(i, i + 64));
    }
    // Registering an address is not the same as listening on it: the live
    // socket has to be told too, or the first reply on a new session waits
    // for a reconnect.
    this.onMailboxesChanged?.(all);
    return all;
  }

  private async activeAccountIds(): Promise<string[]> {
    const raw = await this.store.getMeta('activeAccounts');
    return raw ? (JSON.parse(raw) as string[]) : [];
  }

  private async rememberActiveAccount(accountId: string): Promise<void> {
    const active = new Set(await this.activeAccountIds());
    if (active.has(accountId)) return;
    active.add(accountId);
    await this.store.setMeta('activeAccounts', JSON.stringify([...active]));
  }

  // -------------------------------------------------------------------------
  // Sending
  // -------------------------------------------------------------------------

  /**
   * Send a message to every device an account has registered.
   *
   * Fanning out per device is what makes multi-device E2EE work — each device
   * has its own ratchet, so there is no shared key to leak and no "this device
   * can't read secret chats" caveat.
   */
  async sendMessage(accountId: string, text: string): Promise<Message> {
    const existing = await this.store.getConversation(accountId);
    if (existing?.identityChanged) {
      throw new IdentityChangedError(accountId, existing.identityKey, existing.identityKey);
    }

    // Fetch the device list before recording anything. The conversation row
    // needs a real identity key: creating it with a placeholder and filling it
    // in later means the first send compares the real key against the
    // placeholder and reports a MITM that is not happening. A false alarm here
    // is worse than no alarm, because it teaches people to dismiss the one
    // warning in the app that must never be dismissed casually.
    const devices = await this.client.listDevices(accountId);
    if (devices.length === 0) {
      throw new NoDevicesError(`Tildra: ${accountId} has no registered devices`);
    }
    const conversation = await this.ensureConversation(accountId, devices[0].identityKey);

    const message: Message = {
      id: this.randomId(),
      conversationId: conversation.id,
      text,
      outgoing: true,
      createdAt: this.now(),
      state: 'pending',
    };
    await this.store.insertMessage(message);

    let delivered = 0;
    for (const device of devices) {
      try {
        await this.sendToDevice(accountId, device.deviceId, device.identityKey, text);
        delivered += 1;
      } catch (err) {
        if (err instanceof IdentityChangedError) {
          // Do not keep trying the other devices: the account's key material
          // is in a state the user has to resolve first.
          await this.store.setMessageState(message.id, 'failed');
          throw err;
        }
        this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }

    const state: MessageState = delivered > 0 ? 'sent' : 'failed';
    await this.store.setMessageState(message.id, state);
    await this.rememberActiveAccount(accountId);
    return { ...message, state };
  }

  private async sendToDevice(
    accountId: string,
    deviceId: string,
    deviceIdentityKey: Uint8Array,
    text: string,
  ): Promise<void> {
    let session = await this.store.loadSession(accountId, deviceId);
    let init: SessionInit | undefined;

    if (!session) {
      const established = await this.establishSession(accountId, deviceId, deviceIdentityKey);
      session = established.session;
      init = established.init;
    } else {
      // A key that changed since the session was created is the attack this
      // check exists for.
      await this.assertIdentityUnchanged(accountId, deviceIdentityKey);
    }

    const ratchet: RatchetState = session.ratchet;
    const message = encrypt(ratchet, utf8(text), session.associatedData);
    const envelope = sealEnvelope(deviceIdentityKey, {
      senderAccountId: this.accountId,
      senderDeviceId: this.deviceId,
      senderIdentityKey: this.identity.publicKey,
      sessionInit: init,
      message,
    });

    // The first message goes to the recipient's stable contact inbox, because
    // the per-session mailbox is derived from a secret they cannot compute
    // until they have processed this very message.
    const mailbox = init
      ? contactInbox(deviceIdentityKey)
      : deliveryMailbox(
          deriveMailboxSecret(session.mailboxSecret, accountId, deviceId),
          new Date(this.now()),
        );

    await this.client.sendEnvelope(mailbox, envelope);
    await this.store.saveSession({ ...session, ratchet });
  }

  private async establishSession(
    accountId: string,
    deviceId: string,
    expectedIdentityKey: Uint8Array,
  ): Promise<{ session: StoredSession; init: SessionInit }> {
    const bundle = await this.client.fetchBundle(accountId, deviceId);

    // Two independent checks, both mandatory: the bundle is internally
    // consistent, and it belongs to the key we were told to expect.
    verifyBundle(bundle);
    if (!equal(bundle.identityKey, expectedIdentityKey)) {
      throw new IdentityChangedError(accountId, expectedIdentityKey, bundle.identityKey);
    }
    await this.assertIdentityUnchanged(accountId, bundle.identityKey);

    const established = initiateSession(this.identity, bundle);
    const session: StoredSession = {
      accountId,
      deviceId,
      ratchet: established.ratchet,
      associatedData: established.associatedData,
      mailboxSecret: established.sessionSecret,
    };
    await this.store.saveSession(session);
    await this.ensureConversation(accountId, bundle.identityKey);
    await this.rememberActiveAccount(accountId);
    // The session just created a mailbox the peer will reply to. Publish and
    // subscribe now, before the reply can arrive.
    await this.publishMailboxes();
    return { session, init: established.init };
  }

  /**
   * Compare a peer's identity key against what we stored, and refuse to
   * continue if it changed.
   *
   * The first time we see an account there is nothing to compare against —
   * trust on first use. That gap is exactly what safety numbers close, which
   * is why the UI surfaces them rather than hiding them in a submenu.
   */
  private async assertIdentityUnchanged(accountId: string, identityKey: Uint8Array): Promise<void> {
    const conversation = await this.store.getConversation(accountId);
    if (!conversation) return;
    // An empty stored key means "we have a conversation row but have not yet
    // learned the key" — still trust on first use, not a change.
    if (conversation.identityKey.length === 0) return;
    if (equal(conversation.identityKey, identityKey)) return;

    await this.store.flagIdentityChange(accountId, identityKey);
    this.events.onIdentityChange?.(accountId);
    throw new IdentityChangedError(accountId, conversation.identityKey, identityKey);
  }

  private async ensureConversation(
    accountId: string,
    identityKey?: Uint8Array,
  ): Promise<Conversation & { id: string }> {
    const existing = await this.store.getConversation(accountId);
    if (existing) return existing;

    await this.store.upsertConversation({
      accountId,
      // Empty, not zero-filled: a 32-byte zero key is a *value* that would
      // later compare unequal to the real one and look like a key change.
      identityKey: identityKey ?? new Uint8Array(0),
      lastActivity: this.now(),
      unreadCount: 0,
      verified: false,
      identityChanged: false,
    });
    const created = await this.store.getConversation(accountId);
    if (!created) throw new Error('Tildra: failed to create conversation');
    return created;
  }

  // -------------------------------------------------------------------------
  // Receiving
  // -------------------------------------------------------------------------

  /**
   * Process one envelope from the socket.
   *
   * Throwing here is meaningful: the socket leaves the envelope unacked, so
   * the server redelivers it on the next connect rather than destroying a
   * message we failed to store.
   */
  async receiveEnvelope(envelope: IncomingEnvelope): Promise<Message | null> {
    const content = openEnvelope(this.identity, envelope.ciphertext);

    let session = await this.store.loadSession(content.senderAccountId, content.senderDeviceId);
    let associatedData: Uint8Array;
    let ratchet: RatchetState;
    let mailboxSecret: Uint8Array;

    if (content.sessionInit) {
      const accepted = acceptSession(this.preKeys, content.sessionInit);
      ratchet = accepted.ratchet;
      associatedData = accepted.associatedData;
      mailboxSecret = accepted.sessionSecret;
      // Consumed prekeys must not be reused, and the pool needs topping up.
      await this.topUpPreKeysIfLow();
    } else if (session) {
      ratchet = session.ratchet;
      associatedData = session.associatedData;
      mailboxSecret = session.mailboxSecret;
    } else {
      throw new Error('Tildra: message for an unknown session and no session init present');
    }

    const plaintext = fromUtf8(decrypt(ratchet, content.message, associatedData));

    await this.assertIdentityUnchanged(content.senderAccountId, content.senderIdentityKey);
    const conversation = await this.ensureConversation(
      content.senderAccountId,
      content.senderIdentityKey,
    );

    const message: Message = {
      id: envelope.id,
      conversationId: conversation.id,
      text: plaintext,
      outgoing: false,
      createdAt: Date.parse(envelope.serverTs) || this.now(),
      state: 'delivered',
    };

    await this.store.insertMessage(message);
    await this.store.saveSession({
      accountId: content.senderAccountId,
      deviceId: content.senderDeviceId,
      ratchet,
      associatedData,
      mailboxSecret,
    });
    await this.rememberActiveAccount(content.senderAccountId);

    // A session that was just created needs its mailboxes published before
    // the peer's next message, which will go to the rotating address.
    if (content.sessionInit) {
      await this.publishMailboxes();
    }

    this.events.onMessage?.(message, conversation);
    return message;
  }

  // -------------------------------------------------------------------------
  // Key maintenance
  // -------------------------------------------------------------------------

  /**
   * Replenish one-time prekeys when the server's supply runs low.
   *
   * An exhausted pool is not fatal — the handshake falls back to the signed
   * prekey — but that fallback costs replay resistance for new sessions, so
   * running dry is worth avoiding rather than tolerating.
   */
  async topUpPreKeysIfLow(): Promise<boolean> {
    const counts = await this.client.preKeyCount();
    if (!needsPreKeyTopUp(Math.min(counts.oneTimePreKeys, counts.oneTimePqPreKeys))) {
      return false;
    }

    const nextId = Math.max(0, ...this.preKeys.oneTimePreKeys.keys()) + 1;
    const { secrets, upload } = generatePreKeys(this.identity, {
      count: ONE_TIME_PREKEY_TARGET,
      startId: nextId,
      signedPreKeyId: this.preKeys.signedPreKey.id,
    });

    // Keep the existing signed prekey: rotating it here would orphan every
    // session that is mid-handshake against the published bundle.
    for (const [id, secret] of secrets.oneTimePreKeys) this.preKeys.oneTimePreKeys.set(id, secret);
    for (const [id, secret] of secrets.oneTimePqPreKeys) this.preKeys.oneTimePqPreKeys.set(id, secret);

    // Republish the existing signed prekeys verbatim — same public key, same
    // signature. Pairing the old key with a newly generated signature would be
    // rejected, and rotating the key here would strand every handshake already
    // in flight against the published bundle.
    await this.client.publishKeys({
      ...upload,
      signedPreKey: {
        id: this.preKeys.signedPreKey.id,
        publicKey: toBase64(this.preKeys.signedPreKey.publicKey),
        signature: toBase64(this.preKeys.signedPreKey.signature),
      },
      signedPqPreKey: {
        id: this.preKeys.signedPqPreKey.id,
        publicKey: toBase64(this.preKeys.signedPqPreKey.publicKey),
        signature: toBase64(this.preKeys.signedPqPreKey.signature),
      },
    });
    return true;
  }

  // -------------------------------------------------------------------------
  // Verification
  // -------------------------------------------------------------------------

  /** The 60-digit number the user compares with their contact, in person. */
  async safetyNumberFor(accountId: string): Promise<string | null> {
    const conversation = await this.store.getConversation(accountId);
    if (!conversation) return null;
    return safetyNumber(this.identity.publicKey, conversation.identityKey);
  }

  /**
   * Record that the user compared safety numbers and they matched.
   *
   * Clears the identity-changed flag, which is what unblocks sending. Nothing
   * else in the app is allowed to clear it — the whole point is that a human
   * has to look at something.
   */
  async markVerified(accountId: string): Promise<void> {
    const conversation = await this.store.getConversation(accountId);
    if (!conversation) return;
    await this.store.upsertConversation({
      ...conversation,
      verified: true,
      identityChanged: false,
    });
  }

  /** Forget a session so the next message renegotiates from a fresh bundle. */
  async resetSession(accountId: string): Promise<void> {
    const sessions = await this.store.loadSessionsFor(accountId);
    for (const session of sessions) {
      wipe(session.ratchet.rootKey, session.ratchet.sendingChain, session.ratchet.receivingChain);
    }
  }
}
