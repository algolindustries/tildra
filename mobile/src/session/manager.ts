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
  fromBase64,
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
  Profile,
  attachmentContent,
  callSignalContent,
  gossipContent,
  decodeContent,
  decodeProfile,
  encodeContent,
  profileContent,
  senderKeyContent,
  textContent,
} from '../crypto/content';
import {
  CallEndReason,
  CallError,
  CallSession,
  CallSignal,
  CALL_RINGING_TIMEOUT_MS,
  CallSignalKind,
  IceConfiguration,
  IceTransportPolicy,
  TurnCredential,
  advanceCall,
  beginIncomingCall,
  beginOutgoingCall,
  callHasTimedOut,
  decodeCallSignal,
  encodeCallSignal,
  filterIceCandidates,
  iceConfigurationFor,
  iceTransportPolicyFor,
  signCallSdp,
  toCallId,
  verifyCallSdp,
} from '../crypto/calling';
import {
  LogCheckpoint,
  SignedTreeHead,
  SplitViewError,
  crossCheckTreeHead,
  deserializeTreeHead,
  serializeTreeHead,
} from '../crypto/transparency';
import {
  AttachmentRef,
  decryptAttachment,
  deserializeAttachmentRef,
  encryptAttachment,
  serializeAttachmentRef,
} from '../crypto/attachment';
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
import {
  PinnedAuditor,
  crossCheckAuditor,
  verifyAuditorCheckpoint,
} from '../crypto/auditor';
import { safetyNumber, safetyQrPayload, verifyQrPayload } from '../crypto/safety';
import {
  ONE_TIME_PREKEY_TARGET,
  generatePreKeys,
  needsPreKeyTopUp,
  rotateSignedPreKeys,
  signedPreKeyIsStale,
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
 * A group's conversation key.
 *
 * A group is stored as a conversation whose account id is this, which is the
 * whole reason the chat list, the unread counts and the message list work for
 * one without a second implementation. The prefix is not a valid account id —
 * those are Crockford base32 — so a group can never collide with a person.
 *
 * Before this, a received group message was filed under the *sender's*
 * pairwise conversation: a group of five scattered its history across five
 * one-to-one chats, and an outgoing group message was not stored at all, so
 * the sender never saw what they had said.
 */
export function groupConversationKey(groupId: string): string {
  return `group:${groupId}`;
}

/** Profiles hold image bytes, so they cannot go through JSON unchanged. */
interface SerializedProfile {
  displayName: string;
  about?: string;
  avatar?: string;
  updatedAt: number;
}

function serializeProfile(profile: Profile): SerializedProfile {
  return {
    displayName: profile.displayName,
    about: profile.about,
    avatar: profile.avatar ? toBase64(profile.avatar) : undefined,
    updatedAt: profile.updatedAt,
  };
}

function deserializeProfile(data: SerializedProfile): Profile {
  return {
    displayName: data.displayName,
    about: data.about,
    avatar: data.avatar ? fromBase64(data.avatar) : undefined,
    updatedAt: data.updatedAt,
  };
}

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
  /**
   * This device and somebody else were shown different transparency logs.
   * This is the alarm that means the server is lying to somebody, and it is
   * deliberately a separate event from onError — it is not a transient failure
   * and must not be rendered as one.
   *
   * `source` is the contact's account id when it came from gossip, or the
   * auditor's name when it came from `checkAuditors`. The UI says which,
   * because "your contact and you disagree" and "an independent watcher and
   * you disagree" are different amounts of evidence.
   */
  onSplitView?: (source: string, error: SplitViewError) => void;
  onGroupMessage?: (groupId: string, message: Message) => void;
  onGroupChange?: (groupId: string) => void;
  onProfileChange?: (accountId: string, profile: Profile) => void;
  onIdentityChange?: (accountId: string) => void;
  /**
   * The phone should ring. Only fires once the offer's DTLS fingerprint has
   * been verified against the caller's identity key — an offer that fails that
   * check never reaches the user, because a call they answer is a call they
   * believe is private.
   */
  onIncomingCall?: (call: CallSession, offerSdp: string) => void;
  /** The peer picked up; `answerSdp` is theirs to feed to the peer connection. */
  onCallAnswer?: (call: CallSession, answerSdp: string) => void;
  /** One remote ICE candidate, already filtered by the call's address policy. */
  onCallCandidate?: (call: CallSession, candidate: string) => void;
  /**
   * The peer re-offered a live call. Its fingerprint has been verified *and*
   * checked against the one the call is pinned to — a renegotiation that
   * changes it ends the call instead of reaching here.
   */
  onCallRenegotiate?: (call: CallSession, offerSdp: string) => void;
  onCallRenegotiateAnswer?: (call: CallSession, answerSdp: string) => void;
  /** Any change to the live call's phase, including it ending. */
  onCallChange?: (call: CallSession) => void;
  onError?: (error: Error) => void;
}

const OWN_PROFILE_META_KEY = 'profile.v1';
/** Shared with the app state, which writes it after verifying a lookup. */
export const CHECKPOINT_META_KEY = 'transparency.checkpoint.v1';
/** When the current signed prekey was generated, for the rotation clock. */
export const SIGNED_PREKEY_META_KEY = 'prekeys.signedAt.v1';

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
  /**
   * STUN servers offered once a call is answered. Never used while an
   * incoming call is still ringing — a STUN binding request discloses the
   * device's address, which is the thing the ringing phase withholds.
   */
  stunUrls?: string[];
  /**
   * Called whenever this device's prekey secrets change — a one-time top-up or
   * a signed-prekey rotation. The app persists them.
   *
   * Not optional in practice, and the reason is a bug that shipped: the top-up
   * generated a hundred new one-time secrets, published their public halves,
   * and nothing wrote the secrets to disk. On the next restart the server was
   * still handing out keys this device no longer held, and every handshake
   * that drew one failed with no way to tell why.
   */
  onPreKeysChanged?: (secrets: PreKeySecrets) => Promise<void>;
  /** How long a call rings before this device gives up. Injectable for tests. */
  ringingTimeoutMs?: number;
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
  private readonly stunUrls: string[];
  private readonly ringingTimeoutMs: number;
  private readonly onPreKeysChanged?: (secrets: PreKeySecrets) => Promise<void>;
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
    this.stunUrls = options.stunUrls ?? [];
    this.ringingTimeoutMs = options.ringingTimeoutMs ?? CALL_RINGING_TIMEOUT_MS;
    this.onPreKeysChanged = options.onPreKeysChanged;
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
    // Startup and once a day, which is the cadence a 48-hour rotation needs.
    await this.rotateSignedPreKeysIfStale().catch((err) =>
      this.events.onError?.(err instanceof Error ? err : new Error(String(err))),
    );

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

    // First contact: introduce ourselves before the message, so the recipient
    // sees a person rather than a 26-character identifier. Best effort — a
    // failure here must not stop the message from going out.
    const introduce = !(await this.store.loadSession(accountId, devices[0].deviceId));

    let delivered = 0;
    for (const device of devices) {
      try {
        if (introduce) {
          const profile = await this.getProfile();
          if (profile) {
            await this.sendToDevice(
              accountId,
              device.deviceId,
              device.identityKey,
              profileContent(profile),
            );
          }
          // Gossip on first contact: the earliest point at which comparing
          // logs with this person is possible.
          await this.gossipTo(accountId, device.deviceId, device.identityKey);
        }
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
    if (decoded.type === ContentType.TransparencyGossip) {
      await this.acceptGossip(content.senderAccountId, decoded.payload!);
      return null;
    }
    if (decoded.type === ContentType.CallSignal) {
      await this.receiveCallSignal(
        content.senderAccountId,
        content.senderDeviceId,
        content.senderIdentityKey,
        decoded.payload!,
      );
      return null;
    }
    if (decoded.type === ContentType.Profile) {
      await this.acceptProfile(content.senderAccountId, decoded.payload!);
      // Someone we did not know just introduced themselves. Send ours back so
      // the introduction is mutual rather than one-sided.
      if (newSession) {
        const ours = await this.getProfile();
        if (ours) {
          await this.sendToDevice(
            content.senderAccountId,
            content.senderDeviceId,
            content.senderIdentityKey,
            profileContent(ours),
          ).catch((err) => this.events.onError?.(err));
        }
      }
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

    if (decoded.type === ContentType.Attachment) {
      // A malformed reference must not take down the message: the caption is
      // still worth showing, and the file can be reported as unavailable.
      try {
        message.attachment = deserializeAttachmentRef(JSON.parse(fromUtf8(decoded.payload!)));
      } catch (err) {
        this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }

    await this.store.insertMessage(message);

    this.events.onMessage?.(message, conversation);
    return message;
  }

  // -------------------------------------------------------------------------
  // Attachments
  // -------------------------------------------------------------------------

  /**
   * Encrypt a file, upload the ciphertext, and send the reference.
   *
   * The upload happens once no matter how many devices the recipient has: the
   * blob is keyed independently of any session, and every device gets the same
   * reference through its own encrypted message. The server holds a blob it
   * cannot decrypt and has no record of who uploaded it.
   */
  async sendAttachment(
    accountId: string,
    file: {
      bytes: Uint8Array;
      mimeType: string;
      fileName?: string;
      width?: number;
      height?: number;
      /** Voice notes: rendered from the message, before any download. */
      durationMs?: number;
      waveform?: Uint8Array;
    },
    caption = '',
  ): Promise<Message> {
    const conversation = await this.store.getConversation(accountId);
    if (conversation?.identityChanged) {
      throw new IdentityChangedError(accountId, conversation.identityKey, conversation.identityKey);
    }

    const devices = await this.client.listDevices(accountId);
    if (devices.length === 0) {
      throw new NoDevicesError(`Tildra: ${accountId} has no registered devices`);
    }
    const target = await this.ensureConversation(accountId, devices[0].identityKey);

    const { ciphertext, key } = encryptAttachment(file.bytes);
    const uploaded = await this.client.uploadAttachment(ciphertext);
    const ref: AttachmentRef = {
      ...key,
      id: uploaded.id,
      mimeType: file.mimeType,
      fileName: file.fileName,
      width: file.width,
      height: file.height,
      durationMs: file.durationMs,
      waveform: file.waveform,
    };

    const message: Message = {
      id: this.randomId(),
      conversationId: target.id,
      text: caption,
      outgoing: true,
      createdAt: this.now(),
      state: 'pending',
      attachment: ref,
    };
    await this.store.insertMessage(message);

    const payload = utf8(JSON.stringify(serializeAttachmentRef(ref)));
    let delivered = 0;
    for (const device of devices) {
      try {
        await this.sendToDevice(
          accountId,
          device.deviceId,
          device.identityKey,
          attachmentContent(payload, caption),
        );
        delivered += 1;
      } catch (err) {
        if (err instanceof IdentityChangedError) {
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

  /**
   * Fetch and decrypt an attachment a message referenced.
   *
   * Kept separate from receiving the message so a large download never blocks
   * message delivery, and so a failed or cancelled download can be retried
   * without the message being lost.
   */
  async fetchAttachment(ref: AttachmentRef): Promise<Uint8Array> {
    const ciphertext = await this.client.downloadAttachment(ref.id);
    return decryptAttachment(ciphertext, ref);
  }

  // -------------------------------------------------------------------------
  // Transparency gossip
  // -------------------------------------------------------------------------

  /**
   * Attach our verified tree head to a message for this contact.
   *
   * Sent opportunistically rather than on a schedule: piggybacking on traffic
   * that was happening anyway costs nothing and leaks no new timing. A device
   * that has never verified a log has nothing to gossip and stays quiet.
   */
  private async gossipTo(
    accountId: string,
    deviceId: string,
    identityKey: Uint8Array,
  ): Promise<void> {
    const checkpoint = await this.loadCheckpoint();
    const head = checkpoint?.head;
    if (!head) return;

    await this.sendToDevice(
      accountId,
      deviceId,
      identityKey,
      gossipContent(utf8(JSON.stringify(serializeTreeHead(head)))),
    );
  }

  /**
   * Compare a contact's tree head with ours.
   *
   * If the two cannot both be true, the server is running a split view — the
   * one attack the log's own proofs cannot catch, because each view is
   * internally consistent.
   */
  private async acceptGossip(accountId: string, payload: Uint8Array): Promise<void> {
    const stored = await this.loadCheckpoint();
    if (!stored) return;

    let theirs: SignedTreeHead;
    try {
      theirs = deserializeTreeHead(JSON.parse(fromUtf8(payload)));
    } catch (err) {
      this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    try {
      await crossCheckTreeHead(stored.checkpoint, theirs, (first, second) =>
        this.client.transparencyConsistency(first, second),
      );
    } catch (err) {
      if (err instanceof SplitViewError) {
        this.events.onSplitView?.(accountId, err);
        return;
      }
      this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
  }

  /** The verified checkpoint, and the head it came from, if any. */
  private async loadCheckpoint(): Promise<{ checkpoint: LogCheckpoint; head?: SignedTreeHead } | null> {
    const raw = await this.store.getMeta(CHECKPOINT_META_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as {
      size: number;
      rootHash: string;
      logKey: string;
      head?: ReturnType<typeof serializeTreeHead>;
    };
    return {
      checkpoint: {
        size: parsed.size,
        rootHash: fromBase64(parsed.rootHash),
        logKey: fromBase64(parsed.logKey),
      },
      head: parsed.head ? deserializeTreeHead(parsed.head) : undefined,
    };
  }

  /**
   * Ask the auditors this device listens to whether they saw the same log.
   *
   * Gossip needs a contact who was also targeted and who is talking to you.
   * An auditor needs neither: it watches continuously and has no account. The
   * tool has shipped for a while with nothing consuming its output, which is
   * most of why running one had no obvious point.
   *
   * Returns how many auditors were successfully checked. A network failure is
   * not a split view and is reported as an error, not an alarm — an alarm the
   * server can trigger by dropping a request is an alarm people learn to
   * ignore.
   */
  async checkAuditors(auditors: PinnedAuditor[]): Promise<number> {
    const stored = await this.loadCheckpoint();
    if (!stored || auditors.length === 0) return 0;

    let checked = 0;
    for (const auditor of auditors) {
      const name = auditor.name ?? auditor.url;
      let body: string;
      try {
        const response = await fetch(auditor.url);
        if (!response.ok) throw new Error(`${response.status}`);
        body = await response.text();
      } catch (err) {
        this.events.onError?.(
          new Error(`could not reach ${name}: ${err instanceof Error ? err.message : String(err)}`),
        );
        continue;
      }

      try {
        const checkpoint = verifyAuditorCheckpoint(body, auditor.publicKey, this.now());
        await crossCheckAuditor(
          stored.checkpoint,
          checkpoint,
          (first, second) => this.client.transparencyConsistency(first, second),
          name,
        );
        checked += 1;
      } catch (err) {
        if (err instanceof SplitViewError) {
          // Same alarm as gossip, and for the same reason: two views that
          // cannot both be true means somebody is being lied to.
          this.events.onSplitView?.(name, err);
          continue;
        }
        // A checkpoint that does not verify is a broken or hostile publisher,
        // not evidence about the operator — exactly the distinction the gossip
        // path already makes.
        this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }
    return checked;
  }

  // -------------------------------------------------------------------------
  // Profiles
  // -------------------------------------------------------------------------

  /**
   * Set our own profile and push it to everyone we already talk to.
   *
   * The profile is a message like any other: encrypted to each contact over
   * their pairwise session. The server never sees a name or a picture, and
   * cannot enumerate who anyone is — but the people you actually talk to see
   * exactly who you are, which is the point.
   */
  async setProfile(profile: Omit<Profile, 'updatedAt'>): Promise<Profile> {
    const stored: Profile = { ...profile, updatedAt: this.now() };
    await this.store.setMeta(OWN_PROFILE_META_KEY, JSON.stringify(serializeProfile(stored)));

    for (const accountId of await this.activeAccountIds()) {
      try {
        await this.sendProfileTo(accountId, stored);
      } catch (err) {
        // A contact we cannot reach right now is not a reason to fail the
        // whole update; they get it with the next message we send them.
        this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }
    return stored;
  }

  async getProfile(): Promise<Profile | null> {
    const raw = await this.store.getMeta(OWN_PROFILE_META_KEY);
    return raw ? deserializeProfile(JSON.parse(raw)) : null;
  }

  private async sendProfileTo(accountId: string, profile: Profile): Promise<void> {
    const devices = await this.client.listDevices(accountId);
    for (const device of devices) {
      await this.sendToDevice(accountId, device.deviceId, device.identityKey, profileContent(profile));
    }
  }

  /**
   * Record a contact's profile.
   *
   * Older profiles are ignored: fanout to multiple devices plus redelivery
   * means an update can arrive after a newer one, and a stale name silently
   * replacing a current one would look like the contact renamed themselves.
   */
  private async acceptProfile(accountId: string, payload: Uint8Array): Promise<void> {
    const profile = decodeProfile(payload);
    const conversation = await this.store.getConversation(accountId);
    if (!conversation) return;
    if (conversation.profileUpdatedAt && conversation.profileUpdatedAt > profile.updatedAt) {
      return;
    }

    await this.store.upsertConversation({
      ...conversation,
      displayName: profile.displayName,
      about: profile.about,
      avatar: profile.avatar,
      profileUpdatedAt: profile.updatedAt,
    });
    this.events.onProfileChange?.(accountId, profile);
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

    // Stored on this device too. Sending something and not seeing it is not a
    // subtle bug, and until now it was the behaviour.
    const conversation = await this.ensureGroupConversation(groupId);
    const message: Message = {
      id: this.randomId(),
      conversationId: conversation.id,
      text,
      outgoing: true,
      createdAt: this.now(),
      state: delivered > 0 ? 'sent' : 'failed',
      senderAccountId: this.accountId,
    };
    await this.store.insertMessage(message);
    this.events.onGroupMessage?.(groupId, message);

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

    // Filed under the group, not under whoever sent it.
    const conversation = await this.ensureGroupConversation(groupMessage.groupId);
    const message: Message = {
      id: envelope.id,
      conversationId: conversation.id,
      text: decoded.text ?? '',
      outgoing: false,
      createdAt: Date.parse(envelope.serverTs) || this.now(),
      state: 'delivered',
      senderAccountId,
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

  /**
   * The conversation row a group's messages live in, created on demand.
   *
   * Named from the group rather than from any member, so every device files
   * the same history in the same place.
   */
  private async ensureGroupConversation(
    groupId: string,
  ): Promise<Conversation & { id: string }> {
    const key = groupConversationKey(groupId);
    const existing = await this.store.getConversation(key);
    if (existing) return existing;

    const group = await this.store.loadGroup(groupId);
    await this.store.upsertConversation({
      accountId: key,
      displayName: group?.name,
      // A group has no identity key: there is no single "other end" to compare
      // against, and the per-member checks happen on the pairwise sessions the
      // sender keys travel over.
      identityKey: new Uint8Array(0),
      lastActivity: this.now(),
      unreadCount: 0,
      verified: false,
      identityChanged: false,
    });
    const created = await this.store.getConversation(key);
    if (!created) throw new Error('Tildra: failed to create a group conversation');
    return created;
  }

  async listGroups(): Promise<StoredGroup[]> {
    return this.store.listGroups();
  }

  // -------------------------------------------------------------------------
  // Calls
  // -------------------------------------------------------------------------

  /**
   * Calls are not persisted. A call that outlives the process is not a call —
   * it is a stale row that would ring a phone about something that stopped
   * happening when the app was killed.
   */
  private call: CallSession | null = null;

  /**
   * Devices an outgoing offer went to. The first to answer wins the call and
   * the rest are told to stop ringing.
   */
  private ringing: { deviceId: string; identityKey: Uint8Array }[] = [];

  /** The relay credential, cached until shortly before it expires. */
  private turn: TurnCredential | null = null;

  /** Fires when a call has rung long enough that nobody is coming. */
  private ringingTimer: ReturnType<typeof setTimeout> | null = null;

  /** The live call, if any. */
  currentCall(): CallSession | null {
    return this.call && this.call.phase !== 'ended' ? this.call : null;
  }

  /**
   * Ring every device on an account.
   *
   * Fanning out is what makes a call reach the phone the person is actually
   * holding. The offer is signed once and delivered per device, each through
   * its own session, so the signature covers the same fingerprint everywhere
   * and there is nothing per-device to get wrong.
   */
  async placeCall(
    accountId: string,
    params: { sdp: string; video?: boolean },
  ): Promise<CallSession> {
    if (this.currentCall()) {
      throw new CallError('already in a call');
    }

    const devices = await this.client.listDevices(accountId);
    if (devices.length === 0) {
      throw new NoDevicesError(`Tildra: ${accountId} has no registered devices`);
    }
    await this.ensureConversation(accountId, devices[0].identityKey);

    const callId = toCallId(this.randomId());
    const signal = signCallSdp(this.identity, {
      kind: CallSignalKind.Offer,
      callId,
      sdp: params.sdp,
      fromAccountId: this.accountId,
      toAccountId: accountId,
      video: params.video,
      now: this.now(),
    });

    const call = beginOutgoingCall({
      callId,
      peerAccountId: accountId,
      video: params.video,
      now: this.now(),
    });
    this.call = call;
    this.ringing = devices.map((d) => ({ deviceId: d.deviceId, identityKey: d.identityKey }));

    let delivered = 0;
    for (const device of devices) {
      try {
        await this.sendToDevice(
          accountId,
          device.deviceId,
          device.identityKey,
          callSignalContent(encodeCallSignal(signal)),
        );
        delivered += 1;
      } catch (err) {
        if (err instanceof IdentityChangedError) {
          this.finishCall('failed');
          throw err;
        }
        this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }

    if (delivered === 0) {
      this.finishCall('failed');
      throw new CallError('the call could not be delivered to any device');
    }

    this.armRingingTimer();
    this.events.onCallChange?.(call);
    return call;
  }

  /** Pick up a ringing call with our own SDP answer. */
  async answerCall(callId: string, sdp: string): Promise<CallSession> {
    const call = this.requireCall(callId);
    if (call.direction !== 'incoming') {
      throw new CallError('only the receiving side can answer');
    }
    if (!call.peerDeviceId) {
      throw new CallError('the call has no device to answer to');
    }

    // Validate the transition before sending anything: `advanceCall` throws on
    // an illegal one, and an answer that goes out for a call that is already
    // connecting is a second answer at the far end.
    const next = advanceCall(call, { type: 'accept' }, this.now());

    const signal = signCallSdp(this.identity, {
      kind: CallSignalKind.Answer,
      callId,
      sdp,
      fromAccountId: this.accountId,
      toAccountId: call.peerAccountId,
      now: this.now(),
    });
    await this.sendCallSignalTo(call.peerAccountId, call.peerDeviceId, signal);

    this.call = next;
    this.clearRingingTimer();
    this.events.onCallChange?.(next);
    return next;
  }

  /**
   * Offer one of our ICE candidates to the peer.
   *
   * Returns whether it was sent. A candidate the policy withholds is not an
   * error — it is the policy working — so this reports rather than throws.
   */
  async sendCallCandidate(callId: string, candidate: string): Promise<boolean> {
    const call = this.requireCall(callId);
    if (filterIceCandidates([candidate], iceTransportPolicyFor(call)).length === 0) {
      return false;
    }

    const signal: CallSignal = { kind: CallSignalKind.Candidate, callId, body: candidate };
    // Before a device has answered, we do not know which one will, so the
    // candidate goes to all of them — they are all still ringing.
    const targets = call.peerDeviceId
      ? [call.peerDeviceId]
      : this.ringing.map((d) => d.deviceId);
    for (const deviceId of targets) {
      await this.sendCallSignalTo(call.peerAccountId, deviceId, signal);
    }
    return true;
  }

  /**
   * Re-offer a live call.
   *
   * Used when the address policy widens on answer: an ICE restart changes the
   * ICE credentials, and new credentials are a new offer/answer exchange
   * whether or not anything else moved.
   */
  async renegotiateCall(callId: string, sdp: string): Promise<void> {
    const call = this.requireCall(callId);
    if (!call.peerDeviceId) {
      throw new CallError('the call has no device to renegotiate with');
    }
    await this.sendCallSignalTo(
      call.peerAccountId,
      call.peerDeviceId,
      signCallSdp(this.identity, {
        kind: CallSignalKind.Renegotiate,
        callId,
        sdp,
        fromAccountId: this.accountId,
        toAccountId: call.peerAccountId,
        now: this.now(),
      }),
    );
  }

  /** Answer a re-offer. */
  async answerRenegotiation(callId: string, sdp: string): Promise<void> {
    const call = this.requireCall(callId);
    if (!call.peerDeviceId) {
      throw new CallError('the call has no device to renegotiate with');
    }
    await this.sendCallSignalTo(
      call.peerAccountId,
      call.peerDeviceId,
      signCallSdp(this.identity, {
        kind: CallSignalKind.RenegotiateAnswer,
        callId,
        sdp,
        fromAccountId: this.accountId,
        toAccountId: call.peerAccountId,
        now: this.now(),
      }),
    );
  }

  /** Media is up. */
  markCallConnected(callId: string): CallSession {
    const call = this.requireCall(callId);
    this.call = advanceCall(call, { type: 'connected' }, this.now());
    this.events.onCallChange?.(this.call);
    return this.call;
  }

  /** Hang up, decline, or give up on a call, and tell the far end. */
  async endCall(callId: string, reason: CallEndReason = 'hangup'): Promise<void> {
    const call = this.call;
    if (!call || call.callId !== callId || call.phase === 'ended') return;

    const signal: CallSignal = { kind: CallSignalKind.Hangup, callId, body: reason };
    const targets = call.peerDeviceId
      ? [call.peerDeviceId]
      : this.ringing.map((d) => d.deviceId);
    for (const deviceId of targets) {
      // Best effort. A hangup that fails to send must still end the call
      // locally, or the UI stays on a call screen for a call that is over.
      await this.sendCallSignalTo(call.peerAccountId, deviceId, signal).catch((err) =>
        this.events.onError?.(err instanceof Error ? err : new Error(String(err))),
      );
    }
    this.finishCall(reason);
  }

  /**
   * The peer-connection configuration for a call at its current phase.
   *
   * Ties the address policy to the relay: a ringing incoming call is
   * relay-only, and relay-only with no TURN server gathers nothing rather
   * than falling back to direct paths. `relayAvailable` on the result is how
   * the caller tells "safely gathering nothing" from "working".
   *
   * The credential is cached until shortly before it expires. Fetching one per
   * call would be a request the server can count and time — a weak signal, but
   * a free one to not give away.
   */
  async iceConfiguration(target: CallSession | IceTransportPolicy): Promise<IceConfiguration> {
    // A policy can be named directly, because a peer connection has to exist
    // before there is a call to place — the offer comes out of it.
    const policy = typeof target === 'string' ? target : iceTransportPolicyFor(target);
    return iceConfigurationFor(policy, await this.relayCredential(), {
      stunUrls: this.stunUrls,
      now: this.now(),
    });
  }

  private async relayCredential(): Promise<TurnCredential | null> {
    const now = this.now();
    // Renewed a minute early: a credential that expires between building the
    // configuration and allocating the relay fails as a call that never
    // connects, which is the least diagnosable outcome available.
    if (this.turn && this.turn.expiresAt * 1000 > now + 60_000) return this.turn;

    try {
      this.turn = await this.client.turnCredentials();
    } catch (err) {
      // A relay we could not fetch is a relay we do not have. Reported, not
      // thrown: the call may still connect directly.
      this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      this.turn = null;
    }
    return this.turn;
  }

  private requireCall(callId: string): CallSession {
    const call = this.currentCall();
    if (!call || call.callId !== callId) {
      throw new CallError(`no live call with id ${callId}`);
    }
    return call;
  }

  private finishCall(reason: CallEndReason): void {
    if (!this.call) return;
    this.clearRingingTimer();
    this.call = advanceCall(this.call, { type: 'end', reason }, this.now());
    this.ringing = [];
    this.events.onCallChange?.(this.call);
  }

  /**
   * Give up on a call nobody answered.
   *
   * `CALL_RINGING_TIMEOUT_MS` and `callHasTimedOut` existed for several
   * commits with nothing calling them, which meant an outgoing call rang
   * forever: no missed-call entry, the line held against a second call, and on
   * the receiving side a notification for something that stopped being true.
   */
  private armRingingTimer(): void {
    this.clearRingingTimer();
    const callId = this.call?.callId;
    if (!callId) return;

    this.ringingTimer = setTimeout(() => {
      this.ringingTimer = null;
      const call = this.currentCall();
      if (!call || call.callId !== callId || call.phase !== 'ringing') return;
      if (!callHasTimedOut(call, this.now(), this.ringingTimeoutMs)) return;
      // Told to the far end rather than dropped: a caller who walked away
      // should stop the other phone ringing too.
      void this.endCall(callId, 'unanswered').catch((err) =>
        this.events.onError?.(err instanceof Error ? err : new Error(String(err))),
      );
    }, this.ringingTimeoutMs);
  }

  private clearRingingTimer(): void {
    if (this.ringingTimer) clearTimeout(this.ringingTimer);
    this.ringingTimer = null;
  }

  private async sendCallSignalTo(
    accountId: string,
    deviceId: string,
    signal: CallSignal,
  ): Promise<void> {
    const identityKey =
      this.ringing.find((d) => d.deviceId === deviceId)?.identityKey ??
      (await this.store.getConversation(accountId))?.identityKey;
    if (!identityKey || identityKey.length === 0) {
      throw new CallError(`no identity key known for ${accountId}/${deviceId}`);
    }
    await this.sendToDevice(
      accountId,
      deviceId,
      identityKey,
      callSignalContent(encodeCallSignal(signal)),
    );
  }

  // ---------------------------------------------------------------------------
  // Receiving call signals
  // ---------------------------------------------------------------------------

  /**
   * Handle a signal from the peer.
   *
   * Nothing in here throws to the caller: a malformed or unwanted signal must
   * not leave the envelope unacked, because the server would then redeliver it
   * forever. Everything that goes wrong is reported and dropped.
   */
  private async receiveCallSignal(
    senderAccountId: string,
    senderDeviceId: string,
    senderIdentityKey: Uint8Array,
    payload: Uint8Array,
  ): Promise<void> {
    let signal: CallSignal;
    try {
      signal = decodeCallSignal(payload);
    } catch (err) {
      this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    try {
      switch (signal.kind) {
        case CallSignalKind.Offer:
          await this.receiveCallOffer(senderAccountId, senderDeviceId, senderIdentityKey, signal);
          return;
        case CallSignalKind.Answer:
          await this.receiveCallAnswer(senderAccountId, senderDeviceId, senderIdentityKey, signal);
          return;
        case CallSignalKind.Renegotiate:
        case CallSignalKind.RenegotiateAnswer:
          await this.receiveRenegotiation(
            senderAccountId,
            senderDeviceId,
            senderIdentityKey,
            signal,
          );
          return;
        case CallSignalKind.Candidate:
          this.receiveCallCandidate(senderAccountId, senderDeviceId, signal);
          return;
        case CallSignalKind.Hangup:
        case CallSignalKind.Busy:
          this.receiveCallEnd(senderAccountId, senderDeviceId, signal);
          return;
      }
    } catch (err) {
      this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private async receiveCallOffer(
    senderAccountId: string,
    senderDeviceId: string,
    senderIdentityKey: Uint8Array,
    signal: CallSignal,
  ): Promise<void> {
    const live = this.currentCall();
    if (live) {
      // The same offer twice is the server redelivering an envelope, not a
      // second call. Ringing again, or replying busy to ourselves, would both
      // be wrong.
      if (live.callId === signal.callId) return;

      await this.sendCallSignalTo(senderAccountId, senderDeviceId, {
        kind: CallSignalKind.Busy,
        callId: signal.callId,
        body: 'busy',
      }).catch((err) => this.events.onError?.(err instanceof Error ? err : new Error(String(err))));
      return;
    }

    // `senderIdentityKey` has already been checked against the conversation by
    // assertIdentityUnchanged, which runs before content is dispatched — so
    // this is the key the user's safety number covers, not one the envelope
    // asserted for itself.
    //
    // A failure here does not ring the phone. That is the point: an
    // unverifiable fingerprint means the media could be terminated by someone
    // else, and a call the user answers is a call they believe is private.
    const fingerprint = verifyCallSdp(signal, senderIdentityKey, {
      callId: signal.callId,
      fromAccountId: senderAccountId,
      toAccountId: this.accountId,
      now: this.now(),
    });

    const call = beginIncomingCall({
      callId: signal.callId,
      peerAccountId: senderAccountId,
      peerDeviceId: senderDeviceId,
      peerFingerprint: fingerprint,
      video: signal.video,
      now: this.now(),
    });
    this.call = call;
    this.ringing = [{ deviceId: senderDeviceId, identityKey: senderIdentityKey }];
    this.armRingingTimer();

    this.events.onIncomingCall?.(call, signal.body);
    this.events.onCallChange?.(call);
  }

  private async receiveCallAnswer(
    senderAccountId: string,
    senderDeviceId: string,
    senderIdentityKey: Uint8Array,
    signal: CallSignal,
  ): Promise<void> {
    const call = this.currentCall();
    if (!call || call.callId !== signal.callId || call.peerAccountId !== senderAccountId) return;
    // An answer from a device we never rang is not this call's answer.
    if (!this.ringing.some((d) => d.deviceId === senderDeviceId)) return;

    const fingerprint = verifyCallSdp(signal, senderIdentityKey, {
      callId: signal.callId,
      fromAccountId: senderAccountId,
      toAccountId: this.accountId,
      now: this.now(),
    });

    const next = advanceCall(
      call,
      { type: 'signal', kind: CallSignalKind.Answer, fingerprint, deviceId: senderDeviceId },
      this.now(),
    );
    this.call = next;
    this.clearRingingTimer();

    // Every other device is still ringing for a call that has been picked up.
    const losers = this.ringing.filter((d) => d.deviceId !== senderDeviceId);
    this.ringing = this.ringing.filter((d) => d.deviceId === senderDeviceId);
    for (const device of losers) {
      await this.sendToDevice(
        senderAccountId,
        device.deviceId,
        device.identityKey,
        callSignalContent(
          encodeCallSignal({
            kind: CallSignalKind.Hangup,
            callId: signal.callId,
            body: 'answered elsewhere',
          }),
        ),
      ).catch((err) => this.events.onError?.(err instanceof Error ? err : new Error(String(err))));
    }

    this.events.onCallAnswer?.(next, signal.body);
    this.events.onCallChange?.(next);
  }

  /**
   * A re-offer or its answer, on a call already in progress.
   *
   * The fingerprint is verified against the sender's identity key exactly as
   * for the original offer, and then `advanceCall` insists it is the *same*
   * fingerprint the call was pinned to. A peer can legitimately restart ICE;
   * it cannot legitimately become somebody else halfway through, and a
   * signature does not distinguish those on its own.
   *
   * A renegotiation that fails either check ends the call rather than being
   * ignored. Carrying on would mean media continuing under terms this device
   * has refused.
   */
  private async receiveRenegotiation(
    senderAccountId: string,
    senderDeviceId: string,
    senderIdentityKey: Uint8Array,
    signal: CallSignal,
  ): Promise<void> {
    const call = this.currentCall();
    if (!call || call.callId !== signal.callId || call.peerAccountId !== senderAccountId) return;
    if (call.peerDeviceId && call.peerDeviceId !== senderDeviceId) return;

    let fingerprint;
    try {
      fingerprint = verifyCallSdp(signal, senderIdentityKey, {
        callId: signal.callId,
        fromAccountId: senderAccountId,
        toAccountId: this.accountId,
        now: this.now(),
      });
      this.call = advanceCall(
        call,
        { type: 'signal', kind: signal.kind, fingerprint, deviceId: senderDeviceId },
        this.now(),
      );
    } catch (err) {
      this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
      await this.endCall(call.callId, 'failed');
      return;
    }

    if (signal.kind === CallSignalKind.Renegotiate) {
      this.events.onCallRenegotiate?.(this.call, signal.body);
    } else {
      this.events.onCallRenegotiateAnswer?.(this.call, signal.body);
    }
  }

  private receiveCallCandidate(
    senderAccountId: string,
    senderDeviceId: string,
    signal: CallSignal,
  ): void {
    const call = this.currentCall();
    if (!call || call.callId !== signal.callId || call.peerAccountId !== senderAccountId) return;
    if (call.peerDeviceId && call.peerDeviceId !== senderDeviceId) return;

    // The same policy applies to what we accept as to what we send. Adding a
    // peer's host candidate while our phone is still ringing makes our ICE
    // agent probe their address, which tells them where we are — the leak the
    // send-side policy exists to prevent, arriving from the other direction.
    if (filterIceCandidates([signal.body], iceTransportPolicyFor(call)).length === 0) return;

    this.events.onCallCandidate?.(call, signal.body);
  }

  private receiveCallEnd(
    senderAccountId: string,
    senderDeviceId: string,
    signal: CallSignal,
  ): void {
    const call = this.currentCall();
    if (!call || call.callId !== signal.callId || call.peerAccountId !== senderAccountId) return;
    if (call.peerDeviceId && call.peerDeviceId !== senderDeviceId) return;

    this.call = advanceCall(
      call,
      { type: 'signal', kind: signal.kind, deviceId: senderDeviceId },
      this.now(),
    );
    this.ringing = [];
    this.events.onCallChange?.(this.call);
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

    await this.persistPreKeys();
    return true;
  }

  /**
   * Replace the signed prekeys once they are old enough.
   *
   * A signed prekey serves every sender who fetches this bundle and lives
   * until it is replaced, so its whole security argument is a bounded
   * lifetime. `docs/PROTOCOL.md` has specified 48 hours since the beginning;
   * nothing rotated until now, which meant the bound was whatever the lifetime
   * of the install happened to be.
   *
   * The outgoing pair is kept for one more window — see
   * `PreKeySecrets.previousSignedPreKey`.
   */
  async rotateSignedPreKeysIfStale(): Promise<boolean> {
    const raw = await this.store.getMeta(SIGNED_PREKEY_META_KEY);
    const generatedAt = raw ? Number(raw) : undefined;

    if (generatedAt === undefined || Number.isNaN(generatedAt)) {
      // First run against a store that predates this: record now rather than
      // rotating immediately. An install of unknown age is not evidence the
      // key is old, and rotating every existing device at once on upgrade
      // would strand every handshake in flight at that moment.
      await this.store.setMeta(SIGNED_PREKEY_META_KEY, String(this.now()));
      return false;
    }
    if (!signedPreKeyIsStale(generatedAt, this.now())) return false;

    const { secrets, upload } = rotateSignedPreKeys(this.identity, this.preKeys);
    // Published before it is adopted locally: if the upload fails, this device
    // keeps serving the key the server is still handing out.
    await this.client.publishKeys(upload);

    this.preKeys = secrets;
    await this.store.setMeta(SIGNED_PREKEY_META_KEY, String(this.now()));
    await this.persistPreKeys();
    return true;
  }

  private async persistPreKeys(): Promise<void> {
    if (!this.onPreKeysChanged) return;
    try {
      await this.onPreKeysChanged(this.preKeys);
    } catch (err) {
      // Reported loudly rather than swallowed: secrets that were published but
      // not stored are the shape of the bug this callback exists for.
      this.events.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
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

  /** The same value as a QR payload, for the camera path. */
  async safetyQrFor(accountId: string): Promise<string | null> {
    const conversation = await this.store.getConversation(accountId);
    if (!conversation || conversation.identityKey.length === 0) return null;
    return safetyQrPayload(this.identity.publicKey, conversation.identityKey);
  }

  /**
   * Check a scanned code against this conversation.
   *
   * Returns false rather than throwing, and does *not* mark anything verified:
   * a match is evidence for the user, and recording the verification stays an
   * explicit act. A scanner that silently verified on a match would make the
   * one screen in the app that requires a human decision not require one.
   */
  async matchesSafetyCode(accountId: string, scanned: string): Promise<boolean> {
    const conversation = await this.store.getConversation(accountId);
    if (!conversation || conversation.identityKey.length === 0) return false;
    return verifyQrPayload(scanned, this.identity.publicKey, conversation.identityKey);
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
