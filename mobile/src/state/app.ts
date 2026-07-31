/**
 * Application state.
 *
 * Owns the startup sequence — keystore, vault, database, identity, network,
 * session manager, socket — and exposes it to the screens. The ordering here
 * is not incidental: nothing can be decrypted before the master key is loaded,
 * and no message can be sent before the manager has published mailboxes.
 */

import { create } from 'zustand';

import { TildraClient, Credentials, ApiError } from '../api/client';
import { TildraSocket, SocketState } from '../api/socket';
import { Database, Conversation, Message } from '../storage/db';
import { Vault } from '../storage/vault';
import {
  eraseKeystore,
  loadCredentials,
  loadOrCreateMasterKey,
  saveCredentials,
} from '../storage/keystore';
import {
  KeyPair,
  fromBase64,
  toBase64,
} from '../crypto/primitives';
import { generateIdentity, generatePreKeys } from '../crypto/identity';
import {
  RecoveryError,
  generateRecoveryPhrase,
  openBackup,
  recoveryKeys,
  sealBackup,
} from '../crypto/recovery';
import { PreKeySecrets } from '../crypto/pqxdh';
import { SerializedPreKeys, decodePreKeys, encodePreKeys } from '../storage/prekeys';
import { decodeIdentity, encodeIdentity } from '../storage/identity';
import { IdentityChangedError, NoDevicesError, SessionManager } from '../session/manager';
import { Locale, Strings, resolveLocale, strings } from '../i18n';
import { describeError } from './errors';
import {
  LogCheckpoint,
  SignedTreeHead,
  TransparencyError,
  serializeTreeHead,
  verifyHandleProof,
} from '../crypto/transparency';
import {
  CHECKPOINT_META_KEY,
  GroupMember,
  StoredGroup,
  groupConversationKey,
  groupIdFromConversationKey,
} from '../session/manager';
import { PinnedAuditor, parsePinnedAuditors } from '../crypto/auditor';
import { CallEndReason, CallSession } from '../crypto/calling';
import { CallDriver, CallDriverDeps } from '../session/call-driver';
import type { WebRtcPeer } from '../session/webrtc-peer';
import {
  dismissWakeNotifications,
  presentLocalNotification,
  registerForPush,
  unregisterForPush,
} from '../push/register';

const IDENTITY_META_KEY = 'identity.v1';
const PREKEYS_META_KEY = 'prekeys.v1';

export const DEFAULT_SERVER_URL = 'https://api.tildra.chat';

/**
 * How often the pinned auditors are asked again.
 *
 * A fork is not a moment, it is a state the operator has to keep up; checking
 * a few times a day is enough to catch one and cheap enough not to be a
 * beacon. Also run once at startup, because the first check is the one most
 * likely to happen at all.
 */
export const AUDITOR_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

/**
 * The auditors this build listens to, from the environment at build time.
 *
 * Empty by default and that is the honest default: Tildra operates no public
 * auditor, so there is nobody to pin. A deployment that runs one sets
 * `EXPO_PUBLIC_TILDRA_AUDITORS` to a JSON array of `{name, url, publicKey}`.
 *
 * A malformed list throws rather than yielding a shorter one — see
 * `parsePinnedAuditors`. It surfaces as a startup error, which is the loudest
 * available place for "the security control you configured is not running".
 */
function pinnedAuditors(): PinnedAuditor[] {
  return parsePinnedAuditors(process.env.EXPO_PUBLIC_TILDRA_AUDITORS);
}

export type Phase = 'starting' | 'onboarding' | 'ready' | 'error';

export interface AppState {
  phase: Phase;
  error: string | null;
  locale: Locale;
  t: Strings;

  accountId: string | null;
  handle: string | null;
  displayName: string | null;
  about: string | null;
  avatar: Uint8Array | null;
  socketState: SocketState;
  recording: boolean;

  conversations: (Conversation & { id: string })[];
  activeAccountId: string | null;
  messages: Message[];
  safetyNumber: string | null;
  safetyQr: string | null;

  /**
   * The new device's side of a link, while it is happening. `code` arrives
   * only once the other device has approved — until then there is nothing for
   * the user to compare, and showing a placeholder where a security-critical
   * value goes is how people learn to skim past it.
   */
  pendingLink: { payload: string; code: string | null } | null;

  /**
   * Two views of the transparency log that cannot both be true.
   *
   * Its own field, not `error`. This used to be written to `error` with a
   * comment saying it was not the ordinary error path — which it then was, so
   * the next network hiccup overwrote it, and since `error` is only rendered
   * while the app is failing to start, the one alarm that means the operator
   * is attacking somebody was never shown at all.
   *
   * Persistent until the user dismisses it deliberately.
   */
  splitView: { source: string; detail: string } | null;

  /** How many pinned auditors last answered, and when. Null before the first check. */
  auditorStatus: { checked: number; of: number; at: number } | null;

  /**
   * The recovery phrase, held only until the user says they have written it
   * down. Never persisted: a phrase on disk is a phrase in a backup of the
   * disk, and this one is the account.
   */
  pendingPhrase: string | null;
  /** The group the open conversation belongs to, if it is one. */
  activeGroup: StoredGroup | null;
  /** The live call, mirrored from the manager so screens can render it. */
  call: CallSession | null;
  /** Set while the media stack is being brought up or torn down. */
  callBusy: boolean;

  // Actions
  bootstrap: (options?: { serverUrl?: string; localeTag?: string }) => Promise<void>;
  createAccount: (deviceName: string, displayName?: string) => Promise<void>;
  setProfile: (profile: { displayName: string; about?: string; avatar?: Uint8Array }) => Promise<void>;
  approveLink: (scanned: string) => Promise<string>;
  /** New-device side: open a provisioning channel and show a code. */
  startLinking: (deviceName: string) => Promise<void>;
  /** New-device side: the user says the digits match, so finish signing in. */
  confirmLink: () => Promise<void>;
  cancelLinking: () => void;
  openConversation: (accountId: string) => Promise<void>;
  closeConversation: () => void;
  send: (text: string) => Promise<void>;
  sendPhoto: () => Promise<void>;
  startVoice: () => Promise<void>;
  finishVoice: (send: boolean) => Promise<void>;
  loadAttachment: (messageId: string) => Promise<Uint8Array | null>;
  startConversation: (input: string) => Promise<string>;
  markVerified: (accountId: string) => Promise<void>;
  /**
   * Start a group with people already in the contact list.
   *
   * Only contacts with a session, because a sender key travels over the
   * pairwise ratchet: somebody this device has never messaged has no channel
   * to receive one on.
   */
  createGroup: (name: string, accountIds: string[]) => Promise<string>;
  /** The user says the phrase is written down. Forgets it. */
  confirmPhraseWritten: () => void;
  /** Sign in on a new device with nothing but the words. */
  recoverAccount: (phrase: string) => Promise<void>;
  /** Add or remove a person — every device they have — from the open group. */
  addToGroup: (accountId: string) => Promise<void>;
  removeFromGroup: (accountId: string) => Promise<void>;
  /** Ask every pinned auditor whether it saw the same log. */
  checkAuditors: () => Promise<void>;
  placeCall: (accountId: string, options?: { video?: boolean }) => Promise<void>;
  answerCall: () => Promise<void>;
  endCall: (reason?: CallEndReason) => Promise<void>;
  setCallMuted: (muted: boolean) => void;
  dismissSplitView: () => void;
  /** Whether a scanned code belongs to this conversation. Verifying stays a separate act. */
  matchesSafetyCode: (accountId: string, scanned: string) => Promise<boolean>;
  claimHandle: (handle: string) => Promise<void>;
  signOut: () => Promise<void>;
  setLocale: (locale: Locale) => void;
  refreshConversations: () => Promise<void>;
}

/** Everything built during bootstrap. Kept out of the store to avoid re-renders. */
interface Runtime {
  vault: Vault;
  db: Database;
  client: TildraClient;
  identity: KeyPair;
  preKeys: PreKeySecrets;
  manager: SessionManager;
  socket: TildraSocket;
  serverUrl: string;
}

let runtime: Runtime | null = null;

/** The in-flight voice recorder, if any. Not store state: it is a live handle. */
let activeRecording: import('../media/voice').Recording | null = null;

/**
 * The secret half of an in-flight device link. Kept out of the store because
 * it holds an identity secret key, and store state is read by every screen.
 */
interface ActiveLink {
  identity: KeyPair;
  deviceName: string;
  approval?: import('../crypto/provisioning').LinkApproval;
  cancelled: boolean;
}

let activeLink: ActiveLink | null = null;

/**
 * The live call, and the media stack under it. Handles, not state: a peer
 * connection is not something a screen should be holding a reference to.
 */
/**
 * Where this device's recovery blob is published, and the key it is sealed
 * with. Not store state: the backup key is a secret derived from the phrase.
 */
let recoveryTarget: {
  accountId: string;
  deviceId: string;
  backupKey: Uint8Array;
  lookupId: string;
} | null = null;

/**
 * Republish the blob.
 *
 * Called when what it holds changes — a new contact, a new group — rather than
 * on a timer, because the blob is only worth what it last knew and a stale one
 * recovers somebody into an empty app.
 */
async function publishRecoveryBackup(parts: { client: TildraClient; db: Database }): Promise<void> {
  if (!recoveryTarget) return;
  const conversations = await parts.db.listConversations();

  await parts.client.putRecoveryBlob(
    recoveryTarget.lookupId,
    sealBackup(recoveryTarget.backupKey, {
      accountId: recoveryTarget.accountId,
      deviceId: recoveryTarget.deviceId,
      contacts: conversations
        .filter((c) => groupIdFromConversationKey(c.accountId) === null)
        .map((c) => ({ accountId: c.accountId, handle: c.handle, displayName: c.displayName })),
      groups: (await runtime!.manager.listGroups()).map((g) => ({
        groupId: g.groupId,
        name: g.name,
        members: g.members,
      })),
      updatedAt: Date.now(),
    }),
  );
}

let activeCall: CallDriver | null = null;
let activePeer: WebRtcPeer | null = null;

/**
 * How the driver reaches the media stack.
 *
 * `react-native-webrtc` is imported lazily so that touching a native module
 * only happens when somebody actually places or answers a call. Importing it
 * at module load would make the whole app — messaging included — require a
 * development build, when only calls do.
 */
function callDeps(
  set: (partial: Partial<AppState>) => void,
  get: () => AppState,
): CallDriverDeps {
  return {
    signalling: runtime!.manager,
    onError: (error) => set({ error: describeError(error, get().t) }),
    async createPeerConnection(config, handlers) {
      const { createWebRtcPeer } = await import('../session/webrtc-peer');
      activePeer = await createWebRtcPeer({
        config,
        handlers,
        video: get().call?.video ?? false,
        onRemoteStream: () => set({ call: activeCall?.call ?? get().call }),
      });
      return activePeer;
    },
  };
}

export function currentRuntime(): Runtime | null {
  return runtime;
}

export const useApp = create<AppState>((set, get) => ({
  phase: 'starting',
  error: null,
  locale: 'en',
  t: strings('en'),

  accountId: null,
  handle: null,
  displayName: null,
  about: null,
  avatar: null,
  socketState: 'closed',
  recording: false,

  conversations: [],
  activeAccountId: null,
  messages: [],
  safetyNumber: null,
  safetyQr: null,
  pendingLink: null,
  splitView: null,
  auditorStatus: null,
  pendingPhrase: null,
  activeGroup: null,
  call: null,
  callBusy: false,

  setLocale: (locale) => set({ locale, t: strings(locale) }),

  async bootstrap(options = {}) {
    const locale = resolveLocale(options.localeTag);
    set({ phase: 'starting', error: null, locale, t: strings(locale) });

    try {
      const masterKey = await loadOrCreateMasterKey();
      const vault = new Vault(masterKey);
      const db = await Database.open(vault);
      const serverUrl = options.serverUrl ?? DEFAULT_SERVER_URL;
      const client = new TildraClient({ baseUrl: serverUrl });

      const credentials = await loadCredentials<Credentials>();
      const storedIdentity = await db.getMeta(IDENTITY_META_KEY);

      if (!credentials || !storedIdentity) {
        // No account on this device yet. Keep the vault and database — they
        // are needed the moment onboarding finishes.
        runtime = {
          vault,
          db,
          client,
          serverUrl,
          identity: { publicKey: new Uint8Array(0), secretKey: new Uint8Array(0) },
          preKeys: null as unknown as PreKeySecrets,
          manager: null as unknown as SessionManager,
          socket: null as unknown as TildraSocket,
        };
        set({ phase: 'onboarding' });
        return;
      }

      const identity = decodeIdentity(vault.decrypt('identity', IDENTITY_META_KEY, storedIdentity));
      const preKeysBlob = await db.getMeta(PREKEYS_META_KEY);
      if (!preKeysBlob) throw new Error('Tildra: prekey material is missing from storage');
      const preKeys = decodePreKeys(
        identity,
        vault.decryptJson<SerializedPreKeys>('prekeys', PREKEYS_META_KEY, preKeysBlob),
      );

      client.setCredentials(credentials);
      await startSession({ vault, db, client, identity, preKeys, serverUrl, credentials }, set, get);
      const profile = await runtime?.manager.getProfile();
      set({
        phase: 'ready',
        accountId: credentials.accountId,
        displayName: profile?.displayName ?? null,
        about: profile?.about ?? null,
        avatar: profile?.avatar ?? null,
      });
      await get().refreshConversations();
    } catch (err) {
      set({ phase: 'error', error: describeError(err, get().t) });
    }
  },

  async createAccount(deviceName, displayName) {
    const base = runtime;
    if (!base) throw new Error('Tildra: bootstrap has not run');

    try {
      set({ error: null });
      // The identity comes out of a recovery phrase rather than the CSPRNG,
      // so that losing the device is survivable. See docs/PROTOCOL.md §1.1 —
      // the trade is that whoever holds the phrase is this account.
      const phrase = generateRecoveryPhrase();
      const { identity, backupKey, lookupId } = recoveryKeys(phrase);
      const { accountId, deviceId } = await base.client.register(identity, deviceName);
      const credentials = await base.client.login(identity, accountId, deviceId);

      const { secrets, upload } = generatePreKeys(identity);
      await base.client.publishKeys(upload);

      // Persist before going online: a crash between registering and storing
      // the key would leave an account nobody can ever log into again.
      await base.db.setMeta(
        IDENTITY_META_KEY,
        base.vault.encrypt('identity', IDENTITY_META_KEY, encodeIdentity(identity)),
      );
      await base.db.setMeta(
        PREKEYS_META_KEY,
        base.vault.encryptJson('prekeys', PREKEYS_META_KEY, encodePreKeys(secrets)),
      );
      await saveCredentials(credentials);

      await startSession(
        { ...base, identity, preKeys: secrets, credentials },
        set,
        get,
      );
      // Store the profile after the manager exists, so it is on disk before
      // the first conversation needs to introduce us.
      if (displayName?.trim()) {
        await runtime?.manager.setProfile({ displayName: displayName.trim() });
      }
      // Published before the phrase is shown: a phrase the user writes down
      // that has nothing to recover is worse than no phrase.
      recoveryTarget = { accountId, deviceId, backupKey, lookupId };
      await publishRecoveryBackup(base).catch((err) =>
        set({ error: describeError(err, get().t) }),
      );

      set({
        phase: 'ready',
        accountId,
        displayName: displayName?.trim() || null,
        pendingPhrase: phrase,
      });
    } catch (err) {
      set({ error: describeError(err, get().t) });
      throw err;
    }
  },

  async refreshConversations() {
    if (!runtime?.db) return;
    set({ conversations: await runtime.db.listConversations() });
  },

  async openConversation(accountId) {
    if (!runtime?.db || !runtime.manager) return;
    const conversation = await runtime.db.getConversation(accountId);
    if (!conversation) return;

    await runtime.db.markRead(conversation.id);
    // A group has no single other end, so there is no safety number to show.
    // Leaving a stale one on screen would be worse than none.
    const group = groupIdFromConversationKey(accountId);
    set({
      activeAccountId: accountId,
      messages: await runtime.db.listMessages(conversation.id),
      safetyNumber: group ? null : await runtime.manager.safetyNumberFor(accountId),
      safetyQr: group ? null : await runtime.manager.safetyQrFor(accountId),
      activeGroup: group ? ((await runtime.manager.listGroups()).find((g) => g.groupId === group) ?? null) : null,
    });
    await get().refreshConversations();
  },

  closeConversation() {
    set({ activeAccountId: null, messages: [], safetyNumber: null, safetyQr: null, activeGroup: null });
  },

  async send(text) {
    const accountId = get().activeAccountId;
    if (!runtime?.manager || !accountId || !text.trim()) return;

    try {
      // A group is a conversation whose account id says so, which is what
      // lets one composer serve both.
      const groupId = groupIdFromConversationKey(accountId);
      if (groupId) await runtime.manager.sendGroupMessage(groupId, text.trim());
      else await runtime.manager.sendMessage(accountId, text.trim());
    } catch (err) {
      set({ error: describeError(err, get().t) });
    } finally {
      // Reload either way: a failed send still leaves a message row, marked
      // failed, so the user can see what did not go out.
      await get().openConversation(accountId);
    }
  },

  /**
   * Pick a photo and send it to the open conversation.
   *
   * Reuses the avatar pipeline's downscale-and-compress step, with a larger
   * budget: a photo message should look like a photo, while an avatar only
   * ever renders at 88pt.
   */
  async sendPhoto() {
    const accountId = get().activeAccountId;
    if (!runtime?.manager || !accountId) return;

    try {
      const { pickPhoto } = await import('../media/photo');
      const picked = await pickPhoto();
      if (!picked) return;

      await runtime.manager.sendAttachment(
        accountId,
        {
          bytes: picked.bytes,
          mimeType: picked.mimeType,
          width: picked.width,
          height: picked.height,
        },
        '',
      );
    } catch (err) {
      set({ error: describeError(err, get().t) });
    } finally {
      await get().openConversation(accountId);
    }
  },

  /**
   * Begin recording. Held in module scope rather than store state because a
   * recorder handle is not serialisable and must not trigger re-renders.
   */
  async startVoice() {
    if (!runtime?.manager || !get().activeAccountId || activeRecording) return;
    try {
      const { startRecording } = await import('../media/voice');
      activeRecording = await startRecording();
      set({ recording: true });
    } catch (err) {
      activeRecording = null;
      set({ recording: false, error: describeError(err, get().t) });
    }
  },

  /**
   * Stop recording, and send unless the user cancelled.
   *
   * Cancelling still stops the recorder — a released microphone matters more
   * than a discarded file.
   */
  async finishVoice(send) {
    const accountId = get().activeAccountId;
    const current = activeRecording;
    activeRecording = null;
    set({ recording: false });
    if (!current || !runtime?.manager || !accountId) return;

    try {
      if (!send) {
        await current.cancel();
        return;
      }
      const note = await current.stop();
      // A mis-tap produces nothing rather than a half-second of silence.
      if (!note) return;

      await runtime.manager.sendAttachment(accountId, {
        bytes: note.bytes,
        mimeType: note.mimeType,
        durationMs: note.durationMs,
        waveform: note.waveform,
      });
    } catch (err) {
      set({ error: describeError(err, get().t) });
    } finally {
      await get().openConversation(accountId);
    }
  },

  async loadAttachment(messageId) {
    const message = get().messages.find((m) => m.id === messageId);
    if (!runtime?.manager || !message?.attachment) return null;
    try {
      return await runtime.manager.fetchAttachment(message.attachment);
    } catch (err) {
      set({ error: describeError(err, get().t) });
      return null;
    }
  },

  async startConversation(input) {
    if (!runtime?.client || !runtime.db) throw new Error('Tildra: not ready');
    const { parseContactInput } = await import('../ui/format');
    const parsed = parseContactInput(input);

    let accountId: string;
    if (parsed.kind === 'accountId') {
      accountId = parsed.value;
    } else {
      // A handle is a pointer the server controls, so it is only worth
      // following if the server can prove what it published. Verifying the
      // proof — and that today's log extends the one we saw last time — is
      // what makes a silent key swap impossible rather than merely rude.
      const checkpoint = await loadCheckpoint(runtime.db);
      const resolved = await runtime.client.resolveHandle(parsed.value, checkpoint?.size ?? 0);

      if (resolved.proof) {
        const next = verifyHandleProof(resolved.proof, parsed.value, checkpoint);
        await saveCheckpoint(runtime.db, next, resolved.proof.head);
      } else if (checkpoint) {
        // We have verified this log before and the server has stopped
        // answering with proofs. That is a downgrade, and taking it silently
        // would undo every check made so far.
        throw new TransparencyError(
          'the server stopped providing key transparency proofs for handle lookups',
        );
      }
      accountId = resolved.accountId;
    }

    // Learn the identity key up front so the conversation row is created with
    // the real key rather than a placeholder.
    const devices = await runtime.client.listDevices(accountId);
    if (devices.length === 0) throw new NoDevicesError(get().t.errorNoDevices);

    await runtime.db.upsertConversation({
      accountId,
      handle: parsed.kind === 'handle' ? parsed.value : undefined,
      identityKey: devices[0].identityKey,
      lastActivity: Date.now(),
      unreadCount: 0,
      verified: false,
      identityChanged: false,
    });
    await get().refreshConversations();
    await publishRecoveryBackup(runtime).catch(() => undefined);
    return accountId;
  },

  async matchesSafetyCode(accountId, scanned) {
    if (!runtime?.manager) return false;
    return runtime.manager.matchesSafetyCode(accountId, scanned);
  },

  confirmPhraseWritten() {
    set({ pendingPhrase: null });
  },

  async recoverAccount(phrase) {
    const base = runtime;
    if (!base) throw new Error('Tildra: bootstrap has not run');

    try {
      set({ error: null });
      const { identity, backupKey, lookupId } = recoveryKeys(phrase);

      const sealed = await base.client.getRecoveryBlob(lookupId);
      if (!sealed) {
        throw new RecoveryError('no account was found for that phrase on this server');
      }

      // The blob names the account this phrase belongs to, which is the thing
      // the lost device knew and this one does not.
      const backup = openBackup(backupKey, sealed);
      const credentials = await base.client.login(identity, backup.accountId, backup.deviceId);

      const { secrets, upload } = generatePreKeys(identity);
      await base.client.publishKeys(upload);

      await base.db.setMeta(
        IDENTITY_META_KEY,
        base.vault.encrypt('identity', IDENTITY_META_KEY, encodeIdentity(identity)),
      );
      await base.db.setMeta(
        PREKEYS_META_KEY,
        base.vault.encryptJson('prekeys', PREKEYS_META_KEY, encodePreKeys(secrets)),
      );
      await saveCredentials(credentials);

      // Contacts come back as rows with no identity key: trust on first use
      // again, and the safety number is what closes that. Restoring a key from
      // a blob would mean a stolen phrase could pin a contact to a key of the
      // thief's choosing.
      for (const contact of backup.contacts) {
        await base.db.upsertConversation({
          accountId: contact.accountId,
          handle: contact.handle,
          displayName: contact.displayName,
          identityKey: new Uint8Array(0),
          lastActivity: Date.now(),
          unreadCount: 0,
          verified: false,
          identityChanged: false,
        });
      }

      recoveryTarget = { accountId: backup.accountId, deviceId: backup.deviceId, backupKey, lookupId };
      await startSession({ ...base, identity, preKeys: secrets, credentials }, set, get);

      // Groups come back as membership, not as keys. Sender keys are per
      // epoch and were on the device that is gone; a restored group is one
      // this device can send to — which distributes a fresh chain — and can
      // read from once each member next distributes theirs.
      for (const group of backup.groups) {
        await runtime!.db.saveGroup({
          groupId: group.groupId,
          name: group.name,
          members: group.members,
          createdAt: Date.now(),
        });
      }
      set({ phase: 'ready', accountId: backup.accountId });
      await get().refreshConversations();
    } catch (err) {
      set({ error: describeError(err, get().t) });
      throw err;
    }
  },

  async createGroup(name, accountIds) {
    if (!runtime?.manager || !runtime.db) throw new Error('Tildra: not ready');
    const me = get().accountId;
    if (!me) throw new Error('Tildra: not signed in');

    // Every device of every member, because a sender key is distributed per
    // device and a member's second phone is not covered by the first.
    const members: GroupMember[] = [];
    for (const accountId of [me, ...accountIds]) {
      for (const device of await runtime.client.listDevices(accountId)) {
        members.push({ accountId, deviceId: device.deviceId });
      }
    }

    const groupId = toBase64(crypto.getRandomValues(new Uint8Array(16)))
      .replace(/[^A-Za-z0-9]/g, '')
      .slice(0, 22);
    await runtime.manager.createGroup(groupId, members, name.trim() || undefined);
    await get().refreshConversations();
    // The blob is only worth what it last knew; a stale one recovers somebody
    // into an app with none of their groups.
    await publishRecoveryBackup(runtime).catch(() => undefined);
    return groupConversationKey(groupId);
  },

  async addToGroup(accountId) {
    const group = get().activeGroup;
    if (!runtime?.manager || !group) return;
    try {
      set({ activeGroup: await runtime.manager.addGroupAccount(group.groupId, accountId) });
    } catch (err) {
      set({ error: describeError(err, get().t) });
    }
  },

  async removeFromGroup(accountId) {
    const group = get().activeGroup;
    if (!runtime?.manager || !group) return;
    try {
      set({ activeGroup: await runtime.manager.removeGroupAccount(group.groupId, accountId) });
    } catch (err) {
      set({ error: describeError(err, get().t) });
    }
  },

  async checkAuditors() {
    if (!runtime?.manager) return;
    const auditors = pinnedAuditors();
    if (auditors.length === 0) return;

    const checked = await runtime.manager.checkAuditors(auditors);
    set({ auditorStatus: { checked, of: auditors.length, at: Date.now() } });
  },

  async placeCall(accountId, options = {}) {
    if (!runtime?.manager || get().callBusy || get().call) return;
    set({ callBusy: true, error: null });
    try {
      activeCall = await CallDriver.place(callDeps(set, get), accountId, {
        video: options.video,
      });
      set({ call: activeCall.call });
    } catch (err) {
      activeCall = null;
      set({ call: null, error: describeError(err, get().t) });
    } finally {
      set({ callBusy: false });
    }
  },

  async answerCall() {
    if (!activeCall || get().callBusy) return;
    set({ callBusy: true, error: null });
    try {
      set({ call: await activeCall.accept() });
    } catch (err) {
      set({ error: describeError(err, get().t) });
      await get().endCall('failed');
    } finally {
      set({ callBusy: false });
    }
  },

  async endCall(reason = 'hangup') {
    const driver = activeCall;
    activeCall = null;
    // Cleared before the hangup goes out. A hangup that fails to send must
    // still take the call screen down, or the user is looking at a call that
    // is over and cannot leave it.
    set({ call: null, callBusy: false });
    if (driver) {
      await driver.hangUp(reason).catch((err: unknown) =>
        set({ error: describeError(err, get().t) }),
      );
    }
  },

  setCallMuted(muted) {
    activePeer?.setMuted(muted);
  },

  dismissSplitView() {
    set({ splitView: null });
  },

  async markVerified(accountId) {
    if (!runtime?.manager) return;
    await runtime.manager.markVerified(accountId);
    await get().refreshConversations();
    if (get().activeAccountId === accountId) await get().openConversation(accountId);
  },

  async setProfile(profile) {
    if (!runtime?.manager) return;
    const saved = await runtime.manager.setProfile(profile);
    set({
      displayName: saved.displayName,
      about: saved.about ?? null,
      avatar: saved.avatar ?? null,
    });
  },

  /**
   * Approve a new device. Returns the pairing code for the user to compare.
   *
   * The code is returned rather than acted on: only the person holding both
   * devices can say whether the digits match, and deciding on their behalf
   * would remove the one check that catches a server in the middle.
   */
  async approveLink(scanned) {
    if (!runtime?.client) throw new Error('Tildra: not ready');
    const accountId = get().accountId;
    if (!accountId) throw new Error('Tildra: not signed in');

    const { approveDeviceLink } = await import('../session/linking');
    const { code } = await approveDeviceLink(
      runtime.client,
      scanned,
      runtime.identity,
      accountId,
    );
    return code;
  },

  async startLinking(deviceName) {
    const base = runtime;
    if (!base) throw new Error('Tildra: bootstrap has not run');

    set({ error: null });
    // A fresh identity key, generated here and never sent anywhere. What
    // travels is its public half, through the server, and a hash of it over
    // the camera — the hash is what makes a substituted key detectable.
    const identity = generateIdentity();
    const { beginDeviceLink } = await import('../session/linking');
    const pending = await beginDeviceLink(base.client, base.serverUrl, identity);

    const link: ActiveLink = { identity, deviceName, cancelled: false };
    activeLink = link;
    set({ pendingLink: { payload: pending.payload, code: null } });

    // Poll in the background so the code is on screen immediately. The user
    // has to carry this device to the other one; blocking the render until
    // approval arrives would show a spinner for as long as that takes.
    void pending
      .await({ timeoutMs: 5 * 60_000, pollMs: 1_000 })
      .then(({ approval, code }) => {
        if (activeLink !== link || link.cancelled) return;
        link.approval = approval;
        set({ pendingLink: { payload: pending.payload, code } });
      })
      .catch((err) => {
        if (activeLink !== link || link.cancelled) return;
        activeLink = null;
        set({ pendingLink: null, error: describeError(err, get().t) });
      });
  },

  async confirmLink() {
    const base = runtime;
    const link = activeLink;
    if (!base || !link?.approval) return;
    const approval = link.approval;

    try {
      set({ error: null });
      const credentials = await base.client.login(
        link.identity,
        approval.accountId,
        approval.deviceId,
      );

      const { secrets, upload } = generatePreKeys(link.identity);
      await base.client.publishKeys(upload);

      // Persisted before going online, for the same reason as account
      // creation: a crash in between would leave a device on the account that
      // can never sign in again, and no way to notice from this side.
      await base.db.setMeta(
        IDENTITY_META_KEY,
        base.vault.encrypt('identity', IDENTITY_META_KEY, encodeIdentity(link.identity)),
      );
      await base.db.setMeta(
        PREKEYS_META_KEY,
        base.vault.encryptJson('prekeys', PREKEYS_META_KEY, encodePreKeys(secrets)),
      );
      await saveCredentials(credentials);

      await startSession({ ...base, identity: link.identity, preKeys: secrets, credentials }, set, get);
      activeLink = null;

      // No profile and no history come across. Message history is not synced
      // between devices by design, and the profile lives in the other
      // device's encrypted store — the user sets it again here, or leaves it.
      set({ phase: 'ready', accountId: approval.accountId, pendingLink: null });
      await get().refreshConversations();
    } catch (err) {
      set({ error: describeError(err, get().t) });
      throw err;
    }
  },

  cancelLinking() {
    if (activeLink) activeLink.cancelled = true;
    activeLink = null;
    set({ pendingLink: null, error: null });
  },

  async claimHandle(handle) {
    if (!runtime?.client) return;
    const result = await runtime.client.claimHandle(handle);
    set({ handle: result.handle });
  },

  async signOut() {
    // Order matters: revoke the token first, then destroy the keys. Doing it
    // the other way round leaves a live session nobody can revoke.
    // Unconditional, and not guarded on the client: this also dismisses the
    // notifications already on the lock screen, which name contacts and quote
    // decrypted messages. A device whose bootstrap never finished has no
    // client and can still have those.
    await unregisterForPush(runtime?.client ?? null);
    try {
      await runtime?.client.logout();
    } catch {
      // A server we cannot reach must not stop a local wipe.
    }
    runtime?.socket?.close();

    // The keystore is erased even if the database wipe fails. Data without
    // its key is unreadable, which is closer to what the user asked for than
    // keeping both — and this used to throw before reaching the second line,
    // leaving the account intact on a device the user believed they had
    // wiped. The failure is still reported, after the wipe rather than
    // instead of it.
    let wipeFailure: unknown = null;
    try {
      await runtime?.db.eraseAll();
    } catch (err) {
      wipeFailure = err;
    }
    await eraseKeystore();
    runtime = null;
    set({
      phase: 'onboarding',
      accountId: null,
      handle: null,
      displayName: null,
      about: null,
      avatar: null,
      conversations: [],
      messages: [],
      activeAccountId: null,
      safetyNumber: null,
      error: wipeFailure ? describeError(wipeFailure, get().t) : null,
    });
  },
}));

// ---------------------------------------------------------------------------
// Startup helpers
// ---------------------------------------------------------------------------

async function startSession(
  parts: Omit<Runtime, 'manager' | 'socket'> & { credentials: Credentials },
  set: (partial: Partial<AppState>) => void,
  get: () => AppState,
): Promise<void> {
  let socket: TildraSocket | undefined;

  const manager = new SessionManager({
    identity: parts.identity,
    accountId: parts.credentials.accountId,
    deviceId: parts.credentials.deviceId,
    client: parts.client,
    store: parts.db,
    preKeys: parts.preKeys,
    // The manager changes these — a one-time top-up, a signed-prekey
    // rotation — and secrets that were published but never written down are
    // keys the server hands out and this device cannot use.
    onPreKeysChanged: async (secrets) => {
      await parts.db.setMeta(
        PREKEYS_META_KEY,
        parts.vault.encryptJson('prekeys', PREKEYS_META_KEY, encodePreKeys(secrets)),
      );
    },
    onMailboxesChanged: (mailboxes) => socket?.subscribe(mailboxes),
    events: {
      onMessage: (message, conversation) => {
        void get().refreshConversations();
        const active = get().activeAccountId;
        if (active) void get().openConversation(active);

        // The server's notification said only that something arrived. Now that
        // the message is decrypted, replace it with one that names the sender —
        // which the device can do because the name never left it.
        if (!message.outgoing && active !== conversation.accountId) {
          void presentLocalNotification({
            title: conversation.displayName ?? get().t.appName,
            body: message.text || get().t.attachment,
            data: { accountId: conversation.accountId },
          }).catch(() => undefined);
          void dismissWakeNotifications().catch(() => undefined);
        }
      },
      onGroupMessage: (groupId, message) => {
        // Same shape as a pairwise message. Without this a group thread only
        // updated when it was reopened, which reads as messages arriving late.
        void get().refreshConversations();
        const active = get().activeAccountId;
        const key = groupConversationKey(groupId);
        if (active) void get().openConversation(active);

        if (!message.outgoing && active !== key) {
          void presentLocalNotification({
            title: get().conversations.find((c) => c.accountId === key)?.displayName ?? get().t.appName,
            body: message.text || get().t.attachment,
            data: { accountId: key },
          }).catch(() => undefined);
          void dismissWakeNotifications().catch(() => undefined);
        }
      },
      onIdentityChange: () => {
        void get().refreshConversations();
      },
      onIncomingCall: (call, offerSdp) => {
        // The offer's fingerprint was verified against the caller's identity
        // key before this fired — an offer that failed never rings.
        set({ call });
        void CallDriver.receive(callDeps(set, get), call, offerSdp)
          .then((driver) => {
            activeCall = driver;
          })
          .catch((err) => {
            set({ call: null, error: describeError(err, get().t) });
            void runtime?.manager.endCall(call.callId, 'failed');
          });
      },
      onCallAnswer: (call, answerSdp) => {
        set({ call });
        void activeCall?.acceptAnswer(call, answerSdp).catch((err) => {
          set({ error: describeError(err, get().t) });
          void get().endCall('failed');
        });
      },
      onCallRenegotiate: (call, offerSdp) => {
        // Reached only after the fingerprint was verified and checked against
        // the one this call is pinned to; a re-offer that changed it ended the
        // call instead of arriving here.
        set({ call });
        void activeCall?.acceptRenegotiation(call, offerSdp).catch((err) => {
          set({ error: describeError(err, get().t) });
          void get().endCall('failed');
        });
      },
      onCallRenegotiateAnswer: (call, answerSdp) => {
        set({ call });
        void activeCall?.acceptRenegotiationAnswer(call, answerSdp).catch((err) =>
          set({ error: describeError(err, get().t) }),
        );
      },
      onCallCandidate: (_call, candidate) => {
        void activeCall?.addRemoteCandidate(candidate).catch(() => undefined);
      },
      onCallChange: (call) => {
        if (call.phase === 'ended') {
          // The far end hung up, or the manager gave up. Tear down the media
          // without sending a second hangup back.
          activeCall = null;
          activePeer?.close();
          activePeer = null;
          set({ call: null, callBusy: false });
          return;
        }
        set({ call });
      },
      onSplitView: (source, error) => {
        // Its own field, deliberately. This is not a request that failed, it
        // is evidence the operator is lying to somebody, and it must survive
        // the next transient error rather than being replaced by it.
        set({ splitView: { source, detail: error.message } });
      },
      onError: (error) => set({ error: describeError(error, get().t) }),
    },
  });

  await manager.publishMailboxes();

  socket = new TildraSocket(parts.serverUrl, parts.credentials.token, {
    onEnvelope: async (envelope) => {
      await manager.receiveEnvelope(envelope);
    },
    onStateChange: (socketState) => set({ socketState }),
    onError: (error) => set({ error: describeError(error, get().t) }),
  });
  socket.connect();

  runtime = { ...parts, manager, socket };

  // Best effort, and after the socket is up: a device that declines push still
  // receives everything while the app is open.
  void registerForPush(parts.client).catch(() => undefined);

  // Auditors, once now and then on an interval. Not awaited: a slow or
  // unreachable auditor must not hold up the app starting, and an auditor
  // that cannot be reached is an error rather than an alarm anyway.
  startAuditorChecks(get);
}

let auditorTimer: ReturnType<typeof setInterval> | null = null;

function startAuditorChecks(get: () => AppState): void {
  if (auditorTimer) clearInterval(auditorTimer);
  void get().checkAuditors().catch(() => undefined);
  auditorTimer = setInterval(() => {
    void get().checkAuditors().catch(() => undefined);
  }, AUDITOR_CHECK_INTERVAL_MS);
}

/**
 * The last verified tree head.
 *
 * Stored unencrypted on purpose: it is a public commitment the server already
 * published, and there is nothing about it worth hiding from someone holding
 * the device. What matters is that it cannot be *changed* without the vault,
 * which is why it lives in the same database as everything else.
 */
async function loadCheckpoint(db: Database): Promise<LogCheckpoint | null> {
  const raw = await db.getMeta(CHECKPOINT_META_KEY);
  if (!raw) return null;
  const parsed = JSON.parse(raw) as { size: number; rootHash: string; logKey: string };
  return {
    size: parsed.size,
    rootHash: fromBase64(parsed.rootHash),
    logKey: fromBase64(parsed.logKey),
  };
}

async function saveCheckpoint(
  db: Database,
  checkpoint: LogCheckpoint,
  head: SignedTreeHead,
): Promise<void> {
  // The head is kept alongside the checkpoint because gossip has to send a
  // *signed* head, not just the root we derived from it — a contact has no
  // reason to believe an unsigned assertion about what we saw.
  await db.setMeta(
    CHECKPOINT_META_KEY,
    JSON.stringify({
      size: checkpoint.size,
      rootHash: toBase64(checkpoint.rootHash),
      logKey: toBase64(checkpoint.logKey),
      head: serializeTreeHead(head),
    }),
  );
}


// ---------------------------------------------------------------------------
// Serialization of long-lived key material
// ---------------------------------------------------------------------------
