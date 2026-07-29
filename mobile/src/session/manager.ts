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
  concat,
  equal,
  fromUtf8,
  hash,
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
  Content,
  ContentType,
  decodeContent,
  encodeContent,
  senderKeyContent,
  textContent,
} from '../crypto/content';
import {
  ReceiverKeyState,
  SenderKeyState,
  createSenderKey,
  decodeDistribution,
  decodeGroupMessage,
  decryptGroupMessage,
  encodeDistribution,
  encodeGroupMessage,
  encryptGroupMessage,
} from '../crypto/group';
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
import { frame, unframe } from '../crypto/wire';
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

  // Groups
  saveGroup(group: StoredGroup): Promise<void>;
  loadGroup(groupId: string): Promise<StoredGroup | null>;
  listGroups(): Promise<StoredGroup[]>;
  saveSenderKey(groupId: string, state: SenderKeyState): Promise<void>;
  loadSenderKey(groupId: string): Promise<SenderKeyState | null>;
  saveReceiverKey(groupId: string, memberId: string, state: ReceiverKeyState): Promise<void>;
  loadReceiverKey(groupId: string, memberId: string): Promise<ReceiverKeyState | null>;
  deleteGroupKeys(groupId: string): Promise<void>;
}

/** A group as this device knows it. Membership is client-side; see §4. */
export interface StoredGroup {
  groupId: string;
  name?: string;
  members: GroupMember[];
  createdAt: number;
}

export interface GroupMember {
  accountId: string;
  deviceId: string;
}

function memberKey(m: GroupMember): string {
  return `${m.accountId}/${m.deviceId}`;
}

/**
 * What travels to each member when a sender key is distributed: the key
 * itself, plus who else is in the group.
 *
 * The membership list is inside the pairwise-encrypted payload, so the server
 * never sees it — it only ever learns how many mailboxes a fanout touches.
 */
interface GroupInvite {
  distribution: Uint8Array;
  members: GroupMember[];
  name?: string;
}

function encodeGroupInvite(invite: GroupInvite): Uint8Array {
  return frame(
    invite.distribution,
    utf8(JSON.stringify(invite.members)),
    utf8(invite.name ?? ''),
  );
}

function decodeGroupInvite(data: Uint8Array): GroupInvite {
  const [distribution, membersJson, name] = unframe(data, 3);
  const parsed: unknown = JSON.parse(fromUtf8(membersJson));
  if (!Array.isArray(parsed)) throw new Error('Tildra: malformed group member list');

  const members: GroupMember[] = [];
  for (const entry of parsed) {
    if (
      typeof entry === 'object' &&
      entry !== null &&
      typeof (entry as GroupMember).accountId === 'string' &&
      typeof (entry as GroupMember).deviceId === 'string'
    ) {
      members.push({
        accountId: (entry as GroupMember).accountId,
        deviceId: (entry as GroupMember).deviceId,
      });
    }
  }
  return { distribution, members, name: fromUtf8(name) || undefined };
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

/**
 * Identify a handshake.
 *
 * The ephemeral key and KEM ciphertext are unique per handshake, so hashing
 * them is enough to tell "the sender re-sent the init we already processed"
 * from "this is a genuinely new session".
 */
function initFingerprint(init: SessionInit): string {
  return toBase64(hash(concat(init.ephemeralKey, init.kemCiphertext)));
}

export interface ManagerEvents {
  onMessage?: (message: Message, conversation: Conversation) => void;
  onGroupMessage?: (groupId: string, message: Message) => void;
  onGroupChange?: (groupId: string) => void;
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
        await this.sendToDevice(accountId, device.deviceId, device.identityKey, textContent(text));
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
    content: Content,
  ): Promise<void> {
    let session = await this.store.loadSession(accountId, deviceId);
    let pendingInit: SessionInit | undefined;

    if (!session) {
      const established = await this.establishSession(accountId, deviceId, deviceIdentityKey);
      session = established.session;
      pendingInit = established.init;
    } else {
      // A key that changed since the session was created is the attack this
      // check exists for.
      await this.assertIdentityUnchanged(accountId, deviceIdentityKey);
      if (!session.confirmed) {
        // The peer has not replied yet, so we have no evidence they processed
        // our handshake. Keep attaching the init and keep using the contact
        // inbox — the per-session mailbox is one they have not registered, and
        // the server refuses delivery to an unknown mailbox. Dropping the init
        // here is what made a quick second message to a new contact vanish.
        pendingInit = session.pendingInit;
      }
    }

    const ratchet: RatchetState = session.ratchet;
    const message = encrypt(ratchet, encodeContent(content), session.associatedData);
    const envelope = sealEnvelope(deviceIdentityKey, {
      senderAccountId: this.accountId,
      senderDeviceId: this.deviceId,
      senderIdentityKey: this.identity.publicKey,
      sessionInit: pendingInit,
      message,
    });

    await this.client.sendEnvelope(
      this.mailboxFor(session, accountId, deviceId, deviceIdentityKey),
      envelope,
    );
    await this.store.saveSession({ ...session, ratchet, pendingInit });
  }

  /**
   * Where to deliver to a device.
   *
   * Before a session is confirmed the peer has not registered the per-session
   * mailbox, so the stable contact inbox is the only address that works.
   */
  private mailboxFor(
    session: StoredSession,
    accountId: string,
    deviceId: string,
    deviceIdentityKey: Uint8Array,
  ): string {
    return session.confirmed
      ? deliveryMailbox(
          deriveMailboxSecret(session.mailboxSecret, accountId, deviceId),
          new Date(this.now()),
        )
      : contactInbox(deviceIdentityKey);
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
      confirmed: false,
      pendingInit: established.init,
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

    // A group message rides outside the pairwise ratchet — it was encrypted
    // once with the sender's group chain and fanned out unchanged.
    if (content.groupMessage) {
      return this.receiveGroupEnvelope(envelope, content.senderAccountId, content.senderDeviceId, content.groupMessage);
    }
    if (!content.message) {
      throw new Error('Tildra: envelope carries no message');
    }

    const session = await this.store.loadSession(content.senderAccountId, content.senderDeviceId);
    const fingerprint = content.sessionInit && initFingerprint(content.sessionInit);

    let associatedData: Uint8Array;
    let ratchet: RatchetState;
    let mailboxSecret: Uint8Array;
    let newSession = false;

    if (content.sessionInit && session && session.initFingerprint === fingerprint) {
      // A repeat of the handshake we already accepted: the sender had not yet
      // seen a reply and re-attached it. Re-running acceptSession would fail,
      // because the one-time prekeys it names are gone — and it would throw
      // away a session that is working.
      ratchet = session.ratchet;
      associatedData = session.associatedData;
      mailboxSecret = session.mailboxSecret;
    } else if (content.sessionInit) {
      const accepted = acceptSession(this.preKeys, content.sessionInit);
      ratchet = accepted.ratchet;
      associatedData = accepted.associatedData;
      mailboxSecret = accepted.sessionSecret;
      newSession = true;
      await this.topUpPreKeysIfLow();
    } else if (session) {
      ratchet = session.ratchet;
      associatedData = session.associatedData;
      mailboxSecret = session.mailboxSecret;
    } else {
      throw new Error('Tildra: message for an unknown session and no session init present');
    }

    const decoded = decodeContent(decrypt(ratchet, content.message, associatedData));

    await this.assertIdentityUnchanged(content.senderAccountId, content.senderIdentityKey);
    const conversation = await this.ensureConversation(
      content.senderAccountId,
      content.senderIdentityKey,
    );

    // Receiving over a session is the only proof the peer processed our
    // handshake, so this is where a session becomes confirmed — and where the
    // pending init is dropped. Saved before dispatching on content type, so a
    // control message still advances the session it arrived on.
    await this.store.saveSession({
      accountId: content.senderAccountId,
      deviceId: content.senderDeviceId,
      ratchet,
      associatedData,
      mailboxSecret,
      confirmed: true,
      pendingInit: undefined,
      initFingerprint: fingerprint ?? session?.initFingerprint,
    });
    await this.rememberActiveAccount(content.senderAccountId);

    // A session that was just created needs its mailboxes published, and its
    // socket subscribed, before the peer's next message goes to the rotating
    // address.
    if (newSession) {
      await this.publishMailboxes();
    }

    if (decoded.type === ContentType.SenderKeyDistribution) {
      await this.acceptSenderKey(
        decoded.groupId!,
        { accountId: content.senderAccountId, deviceId: content.senderDeviceId },
        decoded.payload!,
      );
      return null;
    }
    if (decoded.type === ContentType.GroupRotation) {
      // The sender is about to publish a fresh chain; drop what we hold so a
      // stale key cannot be used to read past this point.
      await this.store.saveGroup(
        (await this.store.loadGroup(decoded.groupId!)) ?? {
          groupId: decoded.groupId!,
          members: [],
          createdAt: this.now(),
        },
      );
      return null;
    }

    const message: Message = {
      id: envelope.id,
      conversationId: conversation.id,
      text: decoded.text ?? '',
      outgoing: false,
      createdAt: Date.parse(envelope.serverTs) || this.now(),
      state: 'delivered',
    };
    await this.store.insertMessage(message);

    this.events.onMessage?.(message, conversation);
    return message;
  }

  // -------------------------------------------------------------------------
  // Groups — docs/PROTOCOL.md §4
  // -------------------------------------------------------------------------

  /**
   * Create a group and distribute our sender key to every member.
   *
   * Distribution costs one pairwise message per member device, once. After
   * that a group message is encrypted a single time regardless of how many
   * people are in the group — that is the economy sender keys buy, and it is
   * why encrypted groups are practical at all.
   */
  async createGroup(groupId: string, members: GroupMember[], name?: string): Promise<StoredGroup> {
    const group: StoredGroup = { groupId, name, members, createdAt: this.now() };
    await this.store.saveGroup(group);

    const senderKey = createSenderKey(groupId);
    await this.store.saveSenderKey(groupId, senderKey);
    await this.distributeSenderKey(groupId, members);
    return group;
  }

  /** Send our sender key to each member over their pairwise session. */
  private async distributeSenderKey(groupId: string, members: GroupMember[]): Promise<void> {
    const senderKey = await this.store.loadSenderKey(groupId);
    if (!senderKey) throw new Error(`Tildra: no sender key for group ${groupId}`);

    const group = await this.store.loadGroup(groupId);
    // The distribution carries the member list, not just the key. Without it a
    // recipient only ever learns about the members who happen to have written
    // to them, and their own messages would silently miss everyone else.
    const blob = encodeGroupInvite({
      distribution: encodeDistribution(senderKey),
      members: group?.members ?? members,
      name: group?.name,
    });

    for (const m of members) {
      if (m.accountId === this.accountId && m.deviceId === this.deviceId) continue;
      const devices = await this.client.listDevices(m.accountId);
      const device = devices.find((d) => d.deviceId === m.deviceId);
      if (!device) {
        this.events.onError?.(new Error(`Tildra: ${memberKey(m)} has no such device`));
        continue;
      }
      await this.sendToDevice(
        m.accountId,
        m.deviceId,
        device.identityKey,
        senderKeyContent(groupId, blob),
      );
    }
  }

  private async acceptSenderKey(
    groupId: string,
    from: GroupMember,
    blob: Uint8Array,
  ): Promise<void> {
    const invite = decodeGroupInvite(blob);
    const receiver = decodeDistribution(memberKey(from), invite.distribution);
    if (receiver.groupId !== groupId) {
      throw new Error('Tildra: sender key distribution names a different group');
    }
    await this.store.saveReceiverKey(groupId, memberKey(from), receiver);

    // Merge the membership the sender told us about with what we already knew.
    // We take the union rather than trusting their list wholesale: a member
    // should not be able to silently drop someone from everyone else's view of
    // the group.
    const existing = await this.store.loadGroup(groupId);
    const members = new Map<string, GroupMember>();
    for (const m of existing?.members ?? []) members.set(memberKey(m), m);
    for (const m of invite.members) members.set(memberKey(m), m);
    members.set(memberKey(from), from);
    members.set(`${this.accountId}/${this.deviceId}`, {
      accountId: this.accountId,
      deviceId: this.deviceId,
    });

    await this.store.saveGroup({
      groupId,
      name: existing?.name ?? invite.name,
      members: [...members.values()],
      createdAt: existing?.createdAt ?? this.now(),
    });

    this.events.onGroupChange?.(groupId);
  }

  /**
   * Encrypt once, fan out to every member device.
   *
   * The server sees one opaque blob per recipient mailbox and a count. It does
   * not learn the group's membership, because it never sees the list.
   */
  async sendGroupMessage(groupId: string, text: string): Promise<number> {
    const group = await this.store.loadGroup(groupId);
    if (!group) throw new Error(`Tildra: unknown group ${groupId}`);

    let senderKey = await this.store.loadSenderKey(groupId);
    if (!senderKey) {
      senderKey = createSenderKey(groupId);
      await this.store.saveSenderKey(groupId, senderKey);
      await this.distributeSenderKey(groupId, group.members);
    }

    const groupMessage = encodeGroupMessage(
      encryptGroupMessage(senderKey, encodeContent(textContent(text))),
    );
    await this.store.saveSenderKey(groupId, senderKey);

    let delivered = 0;
    for (const m of group.members) {
      if (m.accountId === this.accountId && m.deviceId === this.deviceId) continue;
      try {
        await this.sendGroupToDevice(m, groupMessage);
        delivered += 1;
      } catch (err) {
        this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }
    return delivered;
  }

  private async sendGroupToDevice(m: GroupMember, groupMessage: Uint8Array): Promise<void> {
    const session = await this.store.loadSession(m.accountId, m.deviceId);
    if (!session) {
      // Sender keys are distributed over pairwise sessions, so a member we
      // have no session with cannot have our chain key either.
      throw new Error(`Tildra: no session with ${memberKey(m)}`);
    }
    const devices = await this.client.listDevices(m.accountId);
    const device = devices.find((d) => d.deviceId === m.deviceId);
    if (!device) throw new Error(`Tildra: ${memberKey(m)} has no such device`);

    await this.assertIdentityUnchanged(m.accountId, device.identityKey);

    const envelope = sealEnvelope(device.identityKey, {
      senderAccountId: this.accountId,
      senderDeviceId: this.deviceId,
      senderIdentityKey: this.identity.publicKey,
      groupMessage,
    });
    await this.client.sendEnvelope(
      this.mailboxFor(session, m.accountId, m.deviceId, device.identityKey),
      envelope,
    );
  }

  private async receiveGroupEnvelope(
    envelope: IncomingEnvelope,
    senderAccountId: string,
    senderDeviceId: string,
    payload: Uint8Array,
  ): Promise<Message | null> {
    const groupMessage = decodeGroupMessage(payload);
    const from = memberKey({ accountId: senderAccountId, deviceId: senderDeviceId });

    const receiver = await this.store.loadReceiverKey(groupMessage.groupId, from);
    if (!receiver) {
      // Their distribution has not arrived yet, or arrived after this message.
      // Throwing leaves the envelope unacked so the server redelivers it.
      throw new Error(`Tildra: no sender key from ${from} for group ${groupMessage.groupId}`);
    }

    const decoded = decodeContent(decryptGroupMessage(receiver, groupMessage));
    await this.store.saveReceiverKey(groupMessage.groupId, from, receiver);

    const conversation = await this.ensureConversation(senderAccountId);
    const message: Message = {
      id: envelope.id,
      conversationId: conversation.id,
      text: decoded.text ?? '',
      outgoing: false,
      createdAt: Date.parse(envelope.serverTs) || this.now(),
      state: 'delivered',
    };
    await this.store.insertMessage(message);
    this.events.onGroupMessage?.(groupMessage.groupId, message);
    return message;
  }

  /**
   * Remove a member and rotate.
   *
   * Rotation is the whole security property: without a fresh chain the removed
   * member keeps a key that derives every future message. Everyone remaining
   * generates a new sender key and redistributes only among themselves.
   */
  async removeGroupMember(groupId: string, member: GroupMember): Promise<StoredGroup> {
    const group = await this.store.loadGroup(groupId);
    if (!group) throw new Error(`Tildra: unknown group ${groupId}`);

    group.members = group.members.filter((m) => memberKey(m) !== memberKey(member));
    await this.store.saveGroup(group);

    // Drop everything tied to the old epoch, ours and theirs, before the new
    // chain exists — so there is no window where the old key is still live.
    await this.store.deleteGroupKeys(groupId);
    await this.store.saveSenderKey(groupId, createSenderKey(groupId));
    await this.distributeSenderKey(groupId, group.members);

    this.events.onGroupChange?.(groupId);
    return group;
  }

  async addGroupMember(groupId: string, member: GroupMember): Promise<StoredGroup> {
    const group = await this.store.loadGroup(groupId);
    if (!group) throw new Error(`Tildra: unknown group ${groupId}`);
    if (group.members.some((m) => memberKey(m) === memberKey(member))) return group;

    group.members.push(member);
    await this.store.saveGroup(group);

    // The new member receives the chain from its current position, so nothing
    // said before they joined is readable to them.
    await this.distributeSenderKey(groupId, [member]);
    this.events.onGroupChange?.(groupId);
    return group;
  }

  async listGroups(): Promise<StoredGroup[]> {
    return this.store.listGroups();
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
