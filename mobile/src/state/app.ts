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
import { PreKeySecrets } from '../crypto/pqxdh';
import { IdentityChangedError, NoDevicesError, SessionManager } from '../session/manager';
import { Locale, Strings, resolveLocale, strings } from '../i18n';

const IDENTITY_META_KEY = 'identity.v1';
const PREKEYS_META_KEY = 'prekeys.v1';

export const DEFAULT_SERVER_URL = 'https://api.tildra.chat';

export type Phase = 'starting' | 'onboarding' | 'ready' | 'error';

interface SerializedPreKeys {
  signedPreKey: { id: number; publicKey: string; secretKey: string; signature: string };
  signedPqPreKey: { id: number; publicKey: string; secretKey: string; signature: string };
  oneTimePreKeys: [number, string][];
  oneTimePqPreKeys: [number, string][];
}

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

  conversations: (Conversation & { id: string })[];
  activeAccountId: string | null;
  messages: Message[];
  safetyNumber: string | null;

  // Actions
  bootstrap: (options?: { serverUrl?: string; localeTag?: string }) => Promise<void>;
  createAccount: (deviceName: string, displayName?: string) => Promise<void>;
  setProfile: (profile: { displayName: string; about?: string; avatar?: Uint8Array }) => Promise<void>;
  openConversation: (accountId: string) => Promise<void>;
  closeConversation: () => void;
  send: (text: string) => Promise<void>;
  startConversation: (input: string) => Promise<string>;
  markVerified: (accountId: string) => Promise<void>;
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

  conversations: [],
  activeAccountId: null,
  messages: [],
  safetyNumber: null,

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
      const identity = generateIdentity();
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
      set({ phase: 'ready', accountId, displayName: displayName?.trim() || null });
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
    set({
      activeAccountId: accountId,
      messages: await runtime.db.listMessages(conversation.id),
      safetyNumber: await runtime.manager.safetyNumberFor(accountId),
    });
    await get().refreshConversations();
  },

  closeConversation() {
    set({ activeAccountId: null, messages: [], safetyNumber: null });
  },

  async send(text) {
    const accountId = get().activeAccountId;
    if (!runtime?.manager || !accountId || !text.trim()) return;

    try {
      await runtime.manager.sendMessage(accountId, text.trim());
    } catch (err) {
      set({ error: describeError(err, get().t) });
    } finally {
      // Reload either way: a failed send still leaves a message row, marked
      // failed, so the user can see what did not go out.
      await get().openConversation(accountId);
    }
  },

  async startConversation(input) {
    if (!runtime?.client || !runtime.db) throw new Error('Tildra: not ready');
    const { parseContactInput } = await import('../ui/format');
    const parsed = parseContactInput(input);

    const accountId =
      parsed.kind === 'accountId'
        ? parsed.value
        : (await runtime.client.resolveHandle(parsed.value)).accountId;

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
    return accountId;
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

  async claimHandle(handle) {
    if (!runtime?.client) return;
    const result = await runtime.client.claimHandle(handle);
    set({ handle: result.handle });
  },

  async signOut() {
    // Order matters: revoke the token first, then destroy the keys. Doing it
    // the other way round leaves a live session nobody can revoke.
    try {
      await runtime?.client.logout();
    } catch {
      // A server we cannot reach must not stop a local wipe.
    }
    runtime?.socket?.close();
    await runtime?.db.eraseAll();
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
    onMailboxesChanged: (mailboxes) => socket?.subscribe(mailboxes),
    events: {
      onMessage: () => {
        void get().refreshConversations();
        const active = get().activeAccountId;
        if (active) void get().openConversation(active);
      },
      onIdentityChange: () => {
        void get().refreshConversations();
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
}

function describeError(err: unknown, t: Strings): string {
  if (err instanceof IdentityChangedError) return t.identityChangedTitle;
  if (err instanceof NoDevicesError) return t.errorNoDevices;
  if (err instanceof ApiError) return err.status === 0 ? t.errorNetwork : err.detail;
  if (err instanceof Error) return err.message;
  return t.errorGeneric;
}

// ---------------------------------------------------------------------------
// Serialization of long-lived key material
// ---------------------------------------------------------------------------

function encodeIdentity(identity: KeyPair): Uint8Array {
  const out = new Uint8Array(identity.publicKey.length + identity.secretKey.length);
  out.set(identity.publicKey, 0);
  out.set(identity.secretKey, identity.publicKey.length);
  return out;
}

function decodeIdentity(bytes: Uint8Array): KeyPair {
  return { publicKey: bytes.slice(0, 32), secretKey: bytes.slice(32) };
}

function encodePreKeys(secrets: PreKeySecrets): SerializedPreKeys {
  return {
    signedPreKey: {
      id: secrets.signedPreKey.id,
      publicKey: toBase64(secrets.signedPreKey.publicKey),
      secretKey: toBase64(secrets.signedPreKey.secretKey),
      signature: toBase64(secrets.signedPreKey.signature),
    },
    signedPqPreKey: {
      id: secrets.signedPqPreKey.id,
      publicKey: toBase64(secrets.signedPqPreKey.publicKey),
      secretKey: toBase64(secrets.signedPqPreKey.secretKey),
      signature: toBase64(secrets.signedPqPreKey.signature),
    },
    oneTimePreKeys: [...secrets.oneTimePreKeys].map(([id, key]) => [id, toBase64(key)]),
    oneTimePqPreKeys: [...secrets.oneTimePqPreKeys].map(([id, key]) => [id, toBase64(key)]),
  };
}

function decodePreKeys(identity: KeyPair, data: SerializedPreKeys): PreKeySecrets {
  return {
    identity,
    signedPreKey: {
      id: data.signedPreKey.id,
      publicKey: fromBase64(data.signedPreKey.publicKey),
      secretKey: fromBase64(data.signedPreKey.secretKey),
      signature: fromBase64(data.signedPreKey.signature),
    },
    signedPqPreKey: {
      id: data.signedPqPreKey.id,
      publicKey: fromBase64(data.signedPqPreKey.publicKey),
      secretKey: fromBase64(data.signedPqPreKey.secretKey),
      signature: fromBase64(data.signedPqPreKey.signature),
    },
    oneTimePreKeys: new Map(data.oneTimePreKeys.map(([id, key]) => [id, fromBase64(key)])),
    oneTimePqPreKeys: new Map(data.oneTimePqPreKeys.map(([id, key]) => [id, fromBase64(key)])),
  };
}

export { encodePreKeys, decodePreKeys, encodeIdentity, decodeIdentity };
