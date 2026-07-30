/**
 * REST client for the Tildra server.
 *
 * Byte fields cross the wire as standard base64, matching how Go marshals
 * `[]byte`. The conversion happens here and nowhere else — code above this
 * layer works in Uint8Array, code below in JSON.
 */

import { TurnCredential } from '../crypto/calling';
import {
  KeyPair,
  fromBase64,
  toBase64,
} from '../crypto/primitives';
import { KeyUploadPayload, registrationProof, signAuthChallenge } from '../crypto/identity';
import { PreKeyBundle } from '../crypto/pqxdh';
import { HandleProof, SignedTreeHead } from '../crypto/transparency';

export interface Credentials {
  accountId: string;
  deviceId: string;
  token: string;
  expiresAt: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`Tildra API ${status}: ${detail}`);
  }

  /** True when re-authenticating might help. */
  get isAuthFailure(): boolean {
    return this.status === 401;
  }
}

export interface ClientOptions {
  baseUrl: string;
  /** Overridable for tests. Defaults to the global fetch. */
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export class TildraClient {
  private readonly baseUrl: string;
  private readonly doFetch: typeof fetch;
  private readonly timeoutMs: number;
  private credentials: Credentials | null = null;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  setCredentials(credentials: Credentials | null): void {
    this.credentials = credentials;
  }

  getCredentials(): Credentials | null {
    return this.credentials;
  }

  // -------------------------------------------------------------------------
  // Accounts and authentication
  // -------------------------------------------------------------------------

  /**
   * Create an account. The server learns a public key and nothing else — no
   * phone number, no email, no name it can attribute to a person.
   */
  async register(identity: KeyPair, deviceName: string): Promise<{ accountId: string; deviceId: string }> {
    const { proofTs, proof } = registrationProof(identity);
    return this.request('POST', '/v1/accounts', {
      body: {
        identityKey: toBase64(identity.publicKey),
        deviceName,
        proofTs,
        proof,
      },
      authenticated: false,
    });
  }

  /** Prove possession of the device key and receive a bearer token. */
  async login(identity: KeyPair, accountId: string, deviceId: string): Promise<Credentials> {
    const challenge = await this.request<{ challenge: string; expiresAt: string }>(
      'GET',
      `/v1/auth/challenge?account=${encodeURIComponent(accountId)}&device=${encodeURIComponent(deviceId)}`,
      { authenticated: false },
    );

    const issued = await this.request<{ token: string; expiresAt: string }>('POST', '/v1/auth/token', {
      body: {
        accountId,
        deviceId,
        challenge: challenge.challenge,
        signature: signAuthChallenge(identity, fromBase64(challenge.challenge)),
      },
      authenticated: false,
    });

    const credentials: Credentials = { accountId, deviceId, ...issued };
    this.credentials = credentials;
    return credentials;
  }

  async logout(): Promise<void> {
    await this.request('POST', '/v1/auth/logout', { expectEmpty: true });
    this.credentials = null;
  }

  // -------------------------------------------------------------------------
  // Keys
  // -------------------------------------------------------------------------

  async publishKeys(upload: KeyUploadPayload): Promise<void> {
    await this.request('PUT', '/v1/keys', { body: upload, expectEmpty: true });
  }

  async preKeyCount(): Promise<{ oneTimePreKeys: number; oneTimePqPreKeys: number }> {
    return this.request('GET', '/v1/keys/count');
  }

  /**
   * A short-lived TURN relay credential, or null if this deployment has none.
   *
   * Null is a real answer, not an error: a server without a relay still
   * carries calls between devices that can reach each other directly. The
   * caller has to handle it, because "relay only until this call is answered"
   * is a promise that needs somewhere to relay through — see
   * `iceConfigurationFor`.
   */
  async turnCredentials(): Promise<TurnCredential | null> {
    try {
      return await this.request<TurnCredential>('GET', '/v1/turn');
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) return null;
      throw err;
    }
  }

  /**
   * Publish the blob a lost device is recovered from.
   *
   * Addressed by a value derived from the recovery phrase rather than by this
   * account, because whoever fetches it will not know the account id — that
   * was on the device they lost.
   */
  async putRecoveryBlob(lookupId: string, blob: Uint8Array): Promise<void> {
    await this.request('PUT', `/v1/recovery/${encodeURIComponent(lookupId)}`, {
      body: { blob: toBase64(blob) },
      expectEmpty: true,
    });
  }

  /**
   * Fetch it. Unauthenticated, because the caller has nothing to authenticate
   * with yet. Null when there is nothing there, which is the ordinary answer
   * for a phrase that was never used on this server.
   */
  async getRecoveryBlob(lookupId: string): Promise<Uint8Array | null> {
    try {
      const raw = await this.request<{ blob: string }>(
        'GET',
        `/v1/recovery/${encodeURIComponent(lookupId)}`,
        { authenticated: false },
      );
      return fromBase64(raw.blob);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return null;
      throw err;
    }
  }

  /**
   * Fetch a bundle for a device. The caller must run verifyBundle() on the
   * result before using it — this method deliberately does not, so that the
   * verification failure surfaces where the session is being established and
   * can be shown to the user as the security event it is.
   */
  async fetchBundle(accountId: string, deviceId: string): Promise<PreKeyBundle> {
    const raw = await this.request<{
      accountId: string;
      deviceId: string;
      identityKey: string;
      signedPreKey: { id: number; publicKey: string; signature: string };
      signedPqPreKey: { id: number; publicKey: string; signature: string };
      oneTimePreKey?: { id: number; publicKey: string };
      oneTimePqPreKey?: { id: number; publicKey: string };
    }>('GET', `/v1/keys/${encodeURIComponent(accountId)}/${encodeURIComponent(deviceId)}`);

    return {
      accountId: raw.accountId,
      deviceId: raw.deviceId,
      identityKey: fromBase64(raw.identityKey),
      signedPreKey: {
        id: raw.signedPreKey.id,
        publicKey: fromBase64(raw.signedPreKey.publicKey),
        signature: fromBase64(raw.signedPreKey.signature),
      },
      signedPqPreKey: {
        id: raw.signedPqPreKey.id,
        publicKey: fromBase64(raw.signedPqPreKey.publicKey),
        signature: fromBase64(raw.signedPqPreKey.signature),
      },
      oneTimePreKey: raw.oneTimePreKey && {
        id: raw.oneTimePreKey.id,
        publicKey: fromBase64(raw.oneTimePreKey.publicKey),
      },
      oneTimePqPreKey: raw.oneTimePqPreKey && {
        id: raw.oneTimePqPreKey.id,
        publicKey: fromBase64(raw.oneTimePqPreKey.publicKey),
      },
    };
  }

  async listDevices(accountId: string): Promise<{ deviceId: string; name: string; identityKey: Uint8Array }[]> {
    const raw = await this.request<{ deviceId: string; name: string; identityKey: string }[]>(
      'GET',
      `/v1/devices/${encodeURIComponent(accountId)}`,
    );
    return raw.map((d) => ({ ...d, identityKey: fromBase64(d.identityKey) }));
  }

  // -------------------------------------------------------------------------
  // Handles
  // -------------------------------------------------------------------------

  async claimHandle(handle: string): Promise<{ handle: string }> {
    return this.request('PUT', '/v1/handle', { body: { handle } });
  }

  /**
   * Resolve a handle to an account ID.
   *
   * A handle is a convenience pointer the server controls, so this result is
   * not authority over who someone is — only a safety-number comparison is.
   */
  async resolveHandle(
    handle: string,
    since = 0,
  ): Promise<{ accountId: string; handle: string; proof?: HandleProof }> {
    const raw = await this.request<{
      accountId: string;
      handle: string;
      proof?: {
        entry: { index: number; handle: string; accountId: string; identityKey: string; recordedAt: string };
        inclusion: string[] | null;
        consistency: string[] | null;
        head: { size: number; rootHash: string; timestamp: string; signature: string; logKey: string };
      };
    }>('GET', `/v1/handles/${encodeURIComponent(handle)}?since=${since}`, { authenticated: false });

    if (!raw.proof) return { accountId: raw.accountId, handle: raw.handle };

    return {
      accountId: raw.accountId,
      handle: raw.handle,
      proof: {
        entry: {
          index: raw.proof.entry.index,
          handle: raw.proof.entry.handle,
          accountId: raw.proof.entry.accountId,
          identityKey: fromBase64(raw.proof.entry.identityKey),
          // Go marshals time as RFC3339; the log hashed whole seconds.
          recordedAt: Math.floor(Date.parse(raw.proof.entry.recordedAt) / 1000),
        },
        inclusion: (raw.proof.inclusion ?? []).map(fromBase64),
        consistency: (raw.proof.consistency ?? []).map(fromBase64),
        head: {
          size: raw.proof.head.size,
          rootHash: fromBase64(raw.proof.head.rootHash),
          timestamp: Math.floor(Date.parse(raw.proof.head.timestamp) / 1000),
          signature: fromBase64(raw.proof.head.signature),
          logKey: fromBase64(raw.proof.head.logKey),
        },
      },
    };
  }

  /** A consistency proof between two tree sizes, for gossip cross-checks. */
  async transparencyConsistency(first: number, second: number): Promise<{ proof: Uint8Array[] }> {
    const raw = await this.request<{ proof: string[] | null }>(
      'GET',
      `/v1/transparency/consistency?first=${first}&second=${second}`,
      { authenticated: false },
    );
    return { proof: (raw.proof ?? []).map(fromBase64) };
  }

  /** The log's current signed tree head. Unauthenticated, like the log itself. */
  async transparencyHead(): Promise<SignedTreeHead> {
    const raw = await this.request<{
      size: number;
      rootHash: string;
      timestamp: string;
      signature: string;
      logKey: string;
    }>('GET', '/v1/transparency/head', { authenticated: false });

    return {
      size: raw.size,
      rootHash: fromBase64(raw.rootHash),
      timestamp: Math.floor(Date.parse(raw.timestamp) / 1000),
      signature: fromBase64(raw.signature),
      logKey: fromBase64(raw.logKey),
    };
  }

  // -------------------------------------------------------------------------
  // Mailboxes and messages
  // -------------------------------------------------------------------------

  async registerMailboxes(mailboxes: string[], ttlHours = 48): Promise<void> {
    await this.request('POST', '/v1/mailboxes', {
      body: { mailboxes, ttlHours },
      expectEmpty: true,
    });
  }

  async sendEnvelope(mailbox: string, ciphertext: Uint8Array): Promise<{ id: string }> {
    return this.request('POST', '/v1/messages', {
      body: { mailbox, ciphertext: toBase64(ciphertext) },
    });
  }

  // -------------------------------------------------------------------------
  // Encrypted backup
  // -------------------------------------------------------------------------

  async putBackup(blob: Uint8Array): Promise<void> {
    await this.request('PUT', '/v1/backup', { body: { blob: toBase64(blob) }, expectEmpty: true });
  }

  async getBackup(): Promise<Uint8Array | null> {
    try {
      const raw = await this.request<{ blob: string }>('GET', '/v1/backup');
      return fromBase64(raw.blob);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return null;
      throw err;
    }
  }

  // -------------------------------------------------------------------------
  // Device linking
  // -------------------------------------------------------------------------

  /** Open a provisioning channel. Called by the device with no account yet. */
  async createProvisioning(
    identityKey: Uint8Array,
    ephemeralKey: Uint8Array,
  ): Promise<{ id: string; expiresAt: string }> {
    return this.request('POST', '/v1/provisioning', {
      body: { identityKey: toBase64(identityKey), ephemeralKey: toBase64(ephemeralKey) },
      authenticated: false,
    });
  }

  async getProvisioning(id: string): Promise<{
    identityKey: Uint8Array;
    ephemeralKey: Uint8Array;
    approval?: Uint8Array;
  }> {
    const raw = await this.request<{
      identityKey: string;
      ephemeralKey: string;
      approval?: string;
    }>('GET', `/v1/provisioning/${encodeURIComponent(id)}`, { authenticated: false });

    return {
      identityKey: fromBase64(raw.identityKey),
      ephemeralKey: fromBase64(raw.ephemeralKey),
      approval: raw.approval ? fromBase64(raw.approval) : undefined,
    };
  }

  /** Register a second device under the authenticated account. */
  async addDevice(identityKey: Uint8Array, name: string): Promise<{ deviceId: string }> {
    return this.request('POST', '/v1/devices', {
      body: { identityKey: toBase64(identityKey), name },
    });
  }

  async approveProvisioning(id: string, approval: Uint8Array): Promise<void> {
    await this.request('PUT', `/v1/provisioning/${encodeURIComponent(id)}/approval`, {
      body: { approval: toBase64(approval) },
      expectEmpty: true,
    });
  }

  // -------------------------------------------------------------------------
  // Push
  // -------------------------------------------------------------------------

  async registerPushToken(platform: 'expo' | 'apns' | 'fcm', token: string): Promise<void> {
    await this.request('PUT', '/v1/push', { body: { platform, token }, expectEmpty: true });
  }

  async deletePushToken(): Promise<void> {
    await this.request('DELETE', '/v1/push', { expectEmpty: true });
  }

  // -------------------------------------------------------------------------
  // Attachments
  // -------------------------------------------------------------------------

  /**
   * Upload an encrypted blob. The body is raw bytes rather than JSON: base64
   * would inflate a photo by a third, and the server treats it as opaque
   * either way.
   */
  async uploadAttachment(ciphertext: Uint8Array): Promise<{ id: string; expiresAt: string }> {
    const response = await this.raw('POST', '/v1/attachments', ciphertext);
    if (!response.ok) {
      throw new ApiError(response.status, await this.errorDetail(response));
    }
    return (await response.json()) as { id: string; expiresAt: string };
  }

  async downloadAttachment(id: string): Promise<Uint8Array> {
    const response = await this.raw('GET', `/v1/attachments/${encodeURIComponent(id)}`);
    if (!response.ok) {
      throw new ApiError(response.status, await this.errorDetail(response));
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  async health(): Promise<boolean> {
    try {
      await this.request('GET', '/healthz', { authenticated: false });
      return true;
    } catch {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------

  /** Bytes in, bytes out — used by the attachment endpoints. */
  private async raw(method: string, path: string, body?: Uint8Array): Promise<Response> {
    if (!this.credentials) throw new ApiError(401, 'not authenticated');

    const controller = new AbortController();
    // Attachments are far larger than an API call, so they get their own,
    // longer deadline; the request timeout would abort a legitimate upload.
    const timer = setTimeout(() => controller.abort(), this.timeoutMs * 8);
    try {
      return await this.doFetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.credentials.token}`,
          ...(body ? { 'Content-Type': 'application/octet-stream' } : {}),
        },
        body: body as BodyInit | undefined,
        signal: controller.signal,
      });
    } catch (err) {
      throw new ApiError(0, err instanceof Error ? err.message : 'network request failed');
    } finally {
      clearTimeout(timer);
    }
  }

  private async errorDetail(response: Response): Promise<string> {
    try {
      const parsed = (await response.json()) as { error?: string };
      return parsed.error ?? response.statusText;
    } catch {
      return response.statusText;
    }
  }

  private async request<T>(
    method: string,
    path: string,
    options: { body?: unknown; authenticated?: boolean; expectEmpty?: boolean } = {},
  ): Promise<T> {
    const authenticated = options.authenticated ?? true;
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (authenticated) {
      if (!this.credentials) {
        throw new ApiError(401, 'not authenticated');
      }
      headers.Authorization = `Bearer ${this.credentials.token}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.doFetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        signal: controller.signal,
      });
    } catch (err) {
      // A network failure and a server error are different problems for the
      // caller: one is worth retrying silently, the other is not.
      throw new ApiError(0, err instanceof Error ? err.message : 'network request failed');
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      let detail = response.statusText;
      try {
        const parsed = (await response.json()) as { error?: string };
        if (parsed.error) detail = parsed.error;
      } catch {
        // Non-JSON error body; the status line is all we have.
      }
      throw new ApiError(response.status, detail);
    }

    if (options.expectEmpty || response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }
}
