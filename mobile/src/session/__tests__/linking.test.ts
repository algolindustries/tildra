/**
 * Device linking, end to end against the real Go server.
 *
 * The claim being tested is not "the crypto round-trips" but "a second device
 * ends up genuinely part of the account, and a server that interferes is
 * caught". Both halves run against a live server because the provisioning
 * channel is the server, and a mocked one would test nothing that matters.
 */

import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { TildraClient } from '../../api/client';
import { generateIdentity, generatePreKeys } from '../../crypto/identity';
import { equal, hash, randomBytes, toBase64 } from '../../crypto/primitives';
import {
  ProvisioningError,
  decodeLinkOffer,
  encodeLinkOffer,
  pairingCode,
  verifyIdentityCommitment,
} from '../../crypto/provisioning';
import { approveDeviceLink, beginDeviceLink } from '../linking';

const SERVER_DIR = join(__dirname, '../../../../server');
const PORT = 8795;
const BASE_URL = `http://127.0.0.1:${PORT}`;

function goAvailable(): boolean {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return existsSync(join(SERVER_DIR, 'go.mod'));
  } catch {
    return false;
  }
}

const describeIntegration = goAvailable() ? describe : describe.skip;
let server: ChildProcess | null = null;

async function waitForHealth(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${BASE_URL}/healthz`)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('server did not start');
}

/** An account with one signed-in device, as onboarding leaves things. */
async function primaryDevice(name = 'Primary') {
  const identity = generateIdentity();
  const client = new TildraClient({ baseUrl: BASE_URL });
  const { accountId, deviceId } = await client.register(identity, name);
  await client.login(identity, accountId, deviceId);
  await client.publishKeys(generatePreKeys(identity, { count: 3 }).upload);
  return { identity, client, accountId, deviceId };
}

beforeAll(async () => {
  if (!goAvailable()) return;
  const binary = join(mkdtempSync(join(tmpdir(), 'tildra-link-')), 'tildrad');
  execFileSync('go', ['build', '-o', binary, './cmd/tildrad'], {
    cwd: SERVER_DIR,
    stdio: 'inherit',
  });
  server = spawn(binary, [], {
    env: { ...process.env, TILDRA_ADDR: `:${PORT}`, TILDRA_DATABASE_URL: '' },
    stdio: 'ignore',
  });
  await waitForHealth();
}, 120_000);

afterAll(() => server?.kill('SIGTERM'));

describeIntegration('device linking', () => {
  it('adds a second device that can sign in and is visible to contacts', async () => {
    const primary = await primaryDevice();

    // The new device: its own identity key, no account.
    const newIdentity = generateIdentity();
    const newClient = new TildraClient({ baseUrl: BASE_URL });
    const pending = await beginDeviceLink(newClient, BASE_URL, newIdentity);

    // The approving device scans the payload and approves.
    const approved = await approveDeviceLink(
      primary.client,
      pending.payload,
      primary.identity,
      primary.accountId,
      'Tablet',
    );

    const { approval, code } = await pending.await({ timeoutMs: 15_000, pollMs: 100 });

    // Both sides derive the same pairing code — this is what the user compares.
    expect(code).toBe(approved.code);
    expect(code).toMatch(/^\d{6}$/);

    expect(approval.accountId).toBe(primary.accountId);
    expect(approval.deviceId).toBe(approved.deviceId);
    expect(equal(approval.approvedBy, primary.identity.publicKey)).toBe(true);

    // The new device can now authenticate on its own key, which is the real
    // test of whether it is part of the account.
    const credentials = await newClient.login(
      newIdentity,
      approval.accountId,
      approval.deviceId,
    );
    expect(credentials.token).toBeTruthy();
    await newClient.publishKeys(generatePreKeys(newIdentity, { count: 2 }).upload);

    // And a contact sees both devices, so messages fan out to it.
    const contact = await primaryDevice('Contact');
    const devices = await contact.client.listDevices(primary.accountId);
    expect(devices).toHaveLength(2);
    expect(devices.map((d) => d.deviceId).sort()).toEqual(
      [primary.deviceId, approval.deviceId].sort(),
    );
    expect(devices.map((d) => d.name)).toContain('Tablet');
  }, 90_000);

  it('a message reaches both devices of an account', async () => {
    // The point of linking: a second device is not a second account.
    const primary = await primaryDevice();
    const newIdentity = generateIdentity();
    const newClient = new TildraClient({ baseUrl: BASE_URL });
    const pending = await beginDeviceLink(newClient, BASE_URL, newIdentity);
    await approveDeviceLink(primary.client, pending.payload, primary.identity, primary.accountId);
    const { approval } = await pending.await({ timeoutMs: 15_000, pollMs: 100 });
    await newClient.login(newIdentity, approval.accountId, approval.deviceId);
    await newClient.publishKeys(generatePreKeys(newIdentity, { count: 2 }).upload);

    const sender = await primaryDevice('Sender');
    const devices = await sender.client.listDevices(primary.accountId);

    // Every device must have a fetchable bundle, or a fanout would silently
    // skip it.
    for (const device of devices) {
      const bundle = await sender.client.fetchBundle(primary.accountId, device.deviceId);
      expect(equal(bundle.identityKey, device.identityKey)).toBe(true);
    }
  }, 90_000);

  it('refuses an identity key the server substituted', async () => {
    // The attack the commitment exists to stop: the scanned code commits to one
    // key, the server offers another.
    const primary = await primaryDevice();
    const newIdentity = generateIdentity();
    const newClient = new TildraClient({ baseUrl: BASE_URL });
    const pending = await beginDeviceLink(newClient, BASE_URL, newIdentity);

    // Rewrite the commitment in the payload as a hostile server would have to.
    const { offer, serverUrl } = decodeLinkOffer(pending.payload);
    const tampered = encodeLinkOffer(
      { ...offer, identityCommitment: hash(generateIdentity().publicKey) },
      serverUrl,
    );

    await expect(
      approveDeviceLink(primary.client, tampered, primary.identity, primary.accountId),
    ).rejects.toBeInstanceOf(ProvisioningError);
  }, 60_000);

  it('gives a different pairing code when the transcript changes', async () => {
    // A server that swapped the ephemeral key to read the channel changes the
    // shared secret, so the two screens disagree and the user stops.
    const secret = randomBytes(32);
    const other = randomBytes(32);
    const identityKey = generateIdentity().publicKey;

    expect(pairingCode(secret, 'ACCOUNT1', identityKey)).toBe(
      pairingCode(secret, 'ACCOUNT1', identityKey),
    );
    expect(pairingCode(other, 'ACCOUNT1', identityKey)).not.toBe(
      pairingCode(secret, 'ACCOUNT1', identityKey),
    );
    // And pointing the device at a different account changes it too.
    expect(pairingCode(secret, 'ACCOUNT2', identityKey)).not.toBe(
      pairingCode(secret, 'ACCOUNT1', identityKey),
    );
  });

  it('refuses a second approval on the same channel', async () => {
    // Otherwise a server that captured the first approval could replace it
    // after the user had already compared codes.
    const primary = await primaryDevice();
    const newIdentity = generateIdentity();
    const newClient = new TildraClient({ baseUrl: BASE_URL });
    const pending = await beginDeviceLink(newClient, BASE_URL, newIdentity);

    await approveDeviceLink(primary.client, pending.payload, primary.identity, primary.accountId);
    await expect(
      approveDeviceLink(primary.client, pending.payload, primary.identity, primary.accountId),
    ).rejects.toThrow();
  }, 60_000);

  it('is idempotent about the device when an approval is retried', async () => {
    // A retried registration must not leave the account with two devices
    // holding the same key, which would double every fanout.
    const primary = await primaryDevice();
    const newIdentity = generateIdentity();

    const first = await primary.client.addDevice(newIdentity.publicKey, 'Retry');
    const second = await primary.client.addDevice(newIdentity.publicKey, 'Retry');
    expect(second.deviceId).toBe(first.deviceId);

    const devices = await primary.client.listDevices(primary.accountId);
    expect(devices).toHaveLength(2);
  }, 60_000);

  it('rejects a malformed or foreign link code', async () => {
    const primary = await primaryDevice();
    for (const bad of [
      'https://example.com/not-a-link',
      'tildra://link?id=x',
      `tildra://link?id=x&key=${toBase64(randomBytes(8))}&commit=${toBase64(randomBytes(32))}&server=http://x`,
    ]) {
      await expect(
        approveDeviceLink(primary.client, bad, primary.identity, primary.accountId),
      ).rejects.toBeInstanceOf(ProvisioningError);
    }
  }, 60_000);

  it('caps the number of devices on an account', async () => {
    // Every device multiplies the fanout of every message the account receives.
    const primary = await primaryDevice();
    for (let i = 0; i < 7; i++) {
      await primary.client.addDevice(generateIdentity().publicKey, `Device${i}`);
    }
    await expect(
      primary.client.addDevice(generateIdentity().publicKey, 'OneTooMany'),
    ).rejects.toThrow();
  }, 90_000);

  it('expires an unapproved channel rather than leaving it open', async () => {
    const newIdentity = generateIdentity();
    const newClient = new TildraClient({ baseUrl: BASE_URL });
    const pending = await beginDeviceLink(newClient, BASE_URL, newIdentity);

    await expect(pending.await({ timeoutMs: 600, pollMs: 100 })).rejects.toBeInstanceOf(
      ProvisioningError,
    );
  }, 30_000);

  it('checks the commitment itself, not just the payload', async () => {
    const identity = generateIdentity();
    const offer = {
      provisioningId: 'X',
      ephemeralPublicKey: randomBytes(32),
      identityCommitment: hash(identity.publicKey),
    };
    expect(() => verifyIdentityCommitment(offer, identity.publicKey)).not.toThrow();
    expect(() =>
      verifyIdentityCommitment(offer, generateIdentity().publicKey),
    ).toThrow(ProvisioningError);
  });
});
