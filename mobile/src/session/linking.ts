/**
 * Driving a device link from both ends.
 *
 * Split out from SessionManager because the two halves run on devices in
 * different states: the new device has no account, no session store and no
 * credentials, while the approving device has all three. Putting both in the
 * manager would mean a manager that has to work before it can exist.
 */

import { TildraClient } from '../api/client';
import { KeyPair } from '../crypto/primitives';
import {
  LinkApproval,
  LinkOffer,
  ProvisioningError,
  createLinkOffer,
  decodeLinkOffer,
  generateProvisioningKey,
  encodeLinkOffer,
  openApproval,
  sealApproval,
  verifyEphemeralKey,
  verifyIdentityCommitment,
} from '../crypto/provisioning';

/** The new device's side, from showing a code to being part of the account. */
export interface PendingLink {
  /** Render this as a QR code, and as text for anyone who cannot scan. */
  payload: string;
  offer: LinkOffer;
  /**
   * Wait for approval. Resolves with the account the device now belongs to and
   * the pairing code to display, so the user can compare it with the other
   * screen *before* trusting the link.
   */
  await(options?: { timeoutMs?: number; pollMs?: number }): Promise<{
    approval: LinkApproval;
    code: string;
  }>;
}

/**
 * Begin linking. Call on the device being added.
 *
 * The identity key is generated here and never leaves the device; what travels
 * is its public half and a hash of it, and the hash goes over the camera.
 */
export async function beginDeviceLink(
  client: TildraClient,
  serverUrl: string,
  identity: KeyPair,
): Promise<PendingLink> {
  // Ephemeral key first: the server stores its public half when the channel is
  // opened, so generating it afterwards would mean opening a second channel and
  // showing a code for the wrong one.
  const ephemeral = generateProvisioningKey();
  const channel = await client.createProvisioning(identity.publicKey, ephemeral.publicKey);
  const offer = createLinkOffer(channel.id, identity, ephemeral);

  return {
    payload: encodeLinkOffer(offer, serverUrl),
    offer,
    async await(options = {}) {
      const timeoutMs = options.timeoutMs ?? 5 * 60_000;
      const pollMs = options.pollMs ?? 1_000;
      const deadline = Date.now() + timeoutMs;

      for (;;) {
        const state = await client.getProvisioning(offer.provisioningId);
        if (state.approval) {
          return openApproval(ephemeral, identity.publicKey, state.approval);
        }
        if (Date.now() > deadline) {
          throw new ProvisioningError('the device-link window expired before it was approved');
        }
        await new Promise((r) => setTimeout(r, pollMs));
      }
    },
  };
}

/**
 * Approve a scanned link. Call on a device that is already signed in.
 *
 * Returns the pairing code to show the user. The link is complete as far as the
 * server is concerned at that point — the comparison is what tells the *user*
 * whether to trust it, which is why the code is returned rather than swallowed.
 */
export async function approveDeviceLink(
  client: TildraClient,
  scanned: string,
  approver: KeyPair,
  accountId: string,
  deviceName = 'Linked device',
): Promise<{ code: string; deviceId: string }> {
  const { offer } = decodeLinkOffer(scanned);

  const channel = await client.getProvisioning(offer.provisioningId);
  // The step that makes the camera the root of trust: the key the server
  // offered must be the key the other screen committed to.
  verifyIdentityCommitment(offer, channel.identityKey);
  // And the same for the ephemeral key the approval is sealed to. The QR
  // carries it, so this device already has it from the camera; it used to take
  // the server's copy instead and seal to that, which left a server free to
  // insert its own key and read the channel with nothing but the pairing-code
  // comparison to stop it.
  verifyEphemeralKey(offer, channel.ephemeralKey);

  const { deviceId } = await client.addDevice(channel.identityKey, deviceName);
  // Sealed to the scanned key, not the fetched one. They are equal by the check
  // above; using the scanned one is what makes that check load-bearing rather
  // than advisory.
  const sealed = sealApproval(offer, approver, accountId, deviceId, channel.identityKey);
  await client.approveProvisioning(offer.provisioningId, sealed.payload);

  return { code: sealed.code, deviceId };
}
