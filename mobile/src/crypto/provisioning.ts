/**
 * Linking a second device to an existing account.
 *
 * The README has claimed multi-device support for a while on the strength of
 * the protocol handling it — messages fan out per device, each device has its
 * own ratchet, and that is all tested. What was missing is the part a person
 * uses: a way to actually add a device. This is that.
 *
 * The threat this has to survive is the server pairing a device the user never
 * approved, or pairing the user's device to an account it does not own. The
 * provisioning channel runs through the server, so nothing it says can be
 * trusted:
 *
 * 1. The new device generates its identity key and an ephemeral X25519 key,
 *    and shows a QR containing the ephemeral key and a *hash of the identity
 *    key*. That hash is the out-of-band commitment — it travels over the
 *    camera, not the network.
 * 2. The existing device fetches the identity key through the server and
 *    checks it against the hash it scanned. A substituted key fails here.
 * 3. Both devices derive a six-digit pairing code from the transcript. The
 *    user compares them. A server that inserted its own ephemeral key gets a
 *    different code, so the substitution shows up on two screens.
 *
 * Only after that does the existing device register the new one.
 */

import {
  KeyPair,
  concat,
  dh,
  equal,
  fromBase64,
  fromUtf8,
  generateDhKeyPair,
  hash,
  kdf,
  open,
  seal,
  sign,
  toBase64,
  utf8,
  verify,
} from './primitives';

export class ProvisioningError extends Error {}

const QR_SCHEME = 'tildra://link';
const PAIRING_INFO = 'Tildra_PairingCode_v1';
const PAYLOAD_INFO = 'Tildra_Provisioning_v1';
const APPROVAL_CONTEXT = 'tildra-provisioning-approval-v1:';

/** What the new device shows on screen. */
export interface LinkOffer {
  provisioningId: string;
  ephemeralPublicKey: Uint8Array;
  /** SHA-256 of the new device's identity public key. */
  identityCommitment: Uint8Array;
}

/** What the existing device sends back, sealed to the ephemeral key. */
export interface LinkApproval {
  accountId: string;
  deviceId: string;
  /** The approving device's identity key, so the transcript is attributable. */
  approvedBy: Uint8Array;
  signature: Uint8Array;
}

// ---------------------------------------------------------------------------
// The new device
// ---------------------------------------------------------------------------

/**
 * The ephemeral key the approval will be sealed to.
 *
 * Generated before the channel is opened, because the server needs the public
 * half at creation time — deriving it afterwards would mean either a second
 * channel or a channel the new device cannot read.
 */
export function generateProvisioningKey(): KeyPair {
  return generateDhKeyPair();
}

export function createLinkOffer(
  provisioningId: string,
  newDeviceIdentity: KeyPair,
  ephemeral: KeyPair,
): LinkOffer {
  return {
    provisioningId,
    ephemeralPublicKey: ephemeral.publicKey,
    identityCommitment: hash(newDeviceIdentity.publicKey),
  };
}

/**
 * The QR payload.
 *
 * Deliberately compact and self-describing. It carries no secret — the
 * ephemeral public key and a hash are both public — so a photograph of the
 * screen is not a compromise on its own; it is only useful within the
 * provisioning window, and only alongside the pairing-code comparison.
 */
export function encodeLinkOffer(offer: LinkOffer, serverUrl: string): string {
  const params = new URLSearchParams({
    id: offer.provisioningId,
    key: toBase64(offer.ephemeralPublicKey),
    commit: toBase64(offer.identityCommitment),
    server: serverUrl,
  });
  return `${QR_SCHEME}?${params.toString()}`;
}

export function decodeLinkOffer(payload: string): { offer: LinkOffer; serverUrl: string } {
  if (!payload.startsWith(`${QR_SCHEME}?`)) {
    throw new ProvisioningError('not a Tildra device-link code');
  }
  const params = new URLSearchParams(payload.slice(`${QR_SCHEME}?`.length));

  const id = params.get('id');
  const key = params.get('key');
  const commit = params.get('commit');
  const server = params.get('server');
  if (!id || !key || !commit || !server) {
    throw new ProvisioningError('device-link code is missing fields');
  }

  // A scanned code is arbitrary bytes from a camera, so every field is
  // treated as hostile until it parses and measures correctly.
  let ephemeralPublicKey: Uint8Array;
  let identityCommitment: Uint8Array;
  try {
    ephemeralPublicKey = fromBase64(key);
    identityCommitment = fromBase64(commit);
  } catch {
    throw new ProvisioningError('device-link code contains invalid base64');
  }
  if (ephemeralPublicKey.length !== 32 || identityCommitment.length !== 32) {
    throw new ProvisioningError('device-link code is malformed');
  }

  return {
    serverUrl: server,
    offer: { provisioningId: id, ephemeralPublicKey, identityCommitment },
  };
}

// ---------------------------------------------------------------------------
// Pairing code
// ---------------------------------------------------------------------------

/**
 * Six digits both devices display, derived from the whole transcript.
 *
 * A server that swapped the ephemeral key to read the channel, or that pointed
 * the new device at a different account, changes the transcript — so the two
 * screens disagree and the user stops. Six digits is short enough that people
 * will actually compare them, which matters more here than the extra bits.
 */
export function pairingCode(
  sharedSecret: Uint8Array,
  accountId: string,
  newDeviceIdentityKey: Uint8Array,
): string {
  const digest = kdf(
    concat(sharedSecret, utf8(accountId), newDeviceIdentityKey),
    undefined,
    PAIRING_INFO,
    4,
  );
  const value =
    ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
  return (value % 1_000_000).toString().padStart(6, '0');
}

// ---------------------------------------------------------------------------
// The existing device
// ---------------------------------------------------------------------------

/**
 * Check the identity key the server handed over against the scanned hash.
 *
 * This is the step that makes the camera the root of trust rather than the
 * network. Without it the server could offer any key it liked and the user
 * would end up approving a device they have never seen.
 */
export function verifyIdentityCommitment(
  offer: LinkOffer,
  identityKey: Uint8Array,
): void {
  if (!equal(hash(identityKey), offer.identityCommitment)) {
    throw new ProvisioningError(
      'the identity key the server offered does not match the code that was scanned',
    );
  }
}

/**
 * Check the ephemeral key the server handed over against the scanned one.
 *
 * The QR carries this key, so the approving device already has it from the
 * camera and never has to ask the network for it. Taking the server's copy
 * instead leaves the swap available and demotes the defence to the pairing
 * code — a step that only works if a person actually compares six digits.
 * Checking it here refuses the swap outright, and the comparison goes back to
 * being the backstop it was meant to be.
 */
export function verifyEphemeralKey(offer: LinkOffer, ephemeralKey: Uint8Array): void {
  if (!equal(ephemeralKey, offer.ephemeralPublicKey)) {
    throw new ProvisioningError(
      'the ephemeral key the server offered is not the one that was scanned',
    );
  }
}

/** Seal the approval to the new device's ephemeral key. */
export function sealApproval(
  offer: LinkOffer,
  approver: KeyPair,
  accountId: string,
  newDeviceId: string,
  newDeviceIdentityKey: Uint8Array,
): { payload: Uint8Array; sharedSecret: Uint8Array; code: string } {
  const ephemeral = generateDhKeyPair();
  const shared = dh(ephemeral.secretKey, offer.ephemeralPublicKey);
  const key = kdf(shared, concat(ephemeral.publicKey, offer.ephemeralPublicKey), PAYLOAD_INFO, 32);

  const transcript = approvalTranscript(accountId, newDeviceId, newDeviceIdentityKey);
  const approval = {
    accountId,
    deviceId: newDeviceId,
    approvedBy: toBase64(approver.publicKey),
    signature: toBase64(sign(approver.secretKey, transcript)),
  };

  return {
    payload: concat(ephemeral.publicKey, seal(key, utf8(JSON.stringify(approval)))),
    sharedSecret: shared,
    code: pairingCode(shared, accountId, newDeviceIdentityKey),
  };
}

/** Open an approval on the new device. */
export function openApproval(
  ephemeral: KeyPair,
  newDeviceIdentityKey: Uint8Array,
  payload: Uint8Array,
): { approval: LinkApproval; code: string } {
  if (payload.length < 32) {
    throw new ProvisioningError('approval payload is too short');
  }
  const senderEphemeral = payload.slice(0, 32);
  const sealed = payload.slice(32);

  const shared = dh(ephemeral.secretKey, senderEphemeral);
  const key = kdf(shared, concat(senderEphemeral, ephemeral.publicKey), PAYLOAD_INFO, 32);

  const plaintext = open(key, sealed);
  if (!plaintext) {
    throw new ProvisioningError('approval failed to authenticate');
  }

  const parsed = JSON.parse(fromUtf8(plaintext)) as {
    accountId: string;
    deviceId: string;
    approvedBy: string;
    signature: string;
  };
  if (!parsed.accountId || !parsed.deviceId || !parsed.approvedBy || !parsed.signature) {
    throw new ProvisioningError('approval is missing fields');
  }

  const approval: LinkApproval = {
    accountId: parsed.accountId,
    deviceId: parsed.deviceId,
    approvedBy: fromBase64(parsed.approvedBy),
    signature: fromBase64(parsed.signature),
  };

  // The signature does not prove *which* device approved — the new device has
  // no way to know the account's keys yet. It proves the approval was authored
  // by whoever holds that key, so the transcript is attributable after the
  // fact, and it binds the account and device IDs so the server cannot swap
  // them on the way through.
  const transcript = approvalTranscript(
    approval.accountId,
    approval.deviceId,
    newDeviceIdentityKey,
  );
  if (!verify(approval.approvedBy, transcript, approval.signature)) {
    throw new ProvisioningError('approval signature does not verify');
  }

  return { approval, code: pairingCode(shared, approval.accountId, newDeviceIdentityKey) };
}

function approvalTranscript(
  accountId: string,
  deviceId: string,
  newDeviceIdentityKey: Uint8Array,
): Uint8Array {
  return concat(
    utf8(APPROVAL_CONTEXT),
    utf8(accountId),
    utf8(':'),
    utf8(deviceId),
    utf8(':'),
    newDeviceIdentityKey,
  );
}
