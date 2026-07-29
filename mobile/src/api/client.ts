/**
 * REST client for the Tildra server.
 *
 * Byte fields cross the wire as standard base64, matching how Go marshals
 * `[]byte`. The conversion happens here and nowhere else — code above this
 * layer works in Uint8Array, code below in JSON.
 */

import {
  KeyPair,
  fromBase64,
  toBase64,
} from '../crypto/primitives';
import { KeyUploadPayload, registrationProof, signAuthChallenge } from '../crypto/identity';
import { PreKeyBundle } from '../crypto/pqxdh';

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
  async resolveHandle(handle: string): Promise<{ accountId: string; handle: string }> {
    return this.request('GET', `/v1/handles/${encodeURIComponent(handle)}`, { authenticated: false });
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
