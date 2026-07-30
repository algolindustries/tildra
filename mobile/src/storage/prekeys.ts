/**
 * Turning prekey secrets into something a vault can hold, and back.
 *
 * Lives here rather than in the store that calls it because this is where the
 * secrets are: getting it wrong means published keys whose private halves are
 * gone, which looks to every sender like the recipient stopped existing. It
 * also means it can be tested, which — in `state/app.ts`, which pulls in React
 * Native — it could not be.
 */

import { PreKeySecrets } from '../crypto/pqxdh';
import { KeyPair, fromBase64, toBase64 } from '../crypto/primitives';

export interface SerializedSignedPreKey {
  id: number;
  publicKey: string;
  secretKey: string;
  signature: string;
}

export interface SerializedPreKeys {
  signedPreKey: SerializedSignedPreKey;
  signedPqPreKey: SerializedSignedPreKey;
  /**
   * The pair replaced at the last rotation. Persisted because the grace period
   * is measured in wall-clock hours and an app restart lands inside it more
   * often than not — losing them here would defeat the point of keeping them
   * in memory.
   */
  previousSignedPreKey?: SerializedSignedPreKey;
  previousSignedPqPreKey?: SerializedSignedPreKey;
  oneTimePreKeys: [number, string][];
  oneTimePqPreKeys: [number, string][];
}

type SignedPreKeySecret = PreKeySecrets['signedPreKey'];

export function encodeSigned(key: SignedPreKeySecret): SerializedSignedPreKey {
  return {
    id: key.id,
    publicKey: toBase64(key.publicKey),
    secretKey: toBase64(key.secretKey),
    signature: toBase64(key.signature),
  };
}

export function decodeSigned(data: SerializedSignedPreKey): SignedPreKeySecret {
  return {
    id: data.id,
    publicKey: fromBase64(data.publicKey),
    secretKey: fromBase64(data.secretKey),
    signature: fromBase64(data.signature),
  };
}

export function encodePreKeys(secrets: PreKeySecrets): SerializedPreKeys {
  return {
    signedPreKey: encodeSigned(secrets.signedPreKey),
    signedPqPreKey: encodeSigned(secrets.signedPqPreKey),
    previousSignedPreKey:
      secrets.previousSignedPreKey && encodeSigned(secrets.previousSignedPreKey),
    previousSignedPqPreKey:
      secrets.previousSignedPqPreKey && encodeSigned(secrets.previousSignedPqPreKey),
    oneTimePreKeys: [...secrets.oneTimePreKeys].map(([id, key]) => [id, toBase64(key)]),
    oneTimePqPreKeys: [...secrets.oneTimePqPreKeys].map(([id, key]) => [id, toBase64(key)]),
  };
}

export function decodePreKeys(identity: KeyPair, data: SerializedPreKeys): PreKeySecrets {
  return {
    identity,
    signedPreKey: decodeSigned(data.signedPreKey),
    signedPqPreKey: decodeSigned(data.signedPqPreKey),
    previousSignedPreKey: data.previousSignedPreKey && decodeSigned(data.previousSignedPreKey),
    previousSignedPqPreKey: data.previousSignedPqPreKey && decodeSigned(data.previousSignedPqPreKey),
    oneTimePreKeys: new Map(data.oneTimePreKeys.map(([id, key]) => [id, fromBase64(key)])),
    oneTimePqPreKeys: new Map(data.oneTimePqPreKeys.map(([id, key]) => [id, fromBase64(key)])),
  };
}
