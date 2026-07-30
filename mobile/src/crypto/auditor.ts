/**
 * Checking the log against somebody who is not the operator and not a contact.
 *
 * `tildra-auditor` has shipped for a while: it reads the whole log, re-derives
 * every root, and publishes what it saw. Nothing consumed that. Gossip catches
 * a fork when two *contacts* compare heads, which needs both of them to be
 * targets and to be talking; the auditor watches continuously and needs
 * neither — but its findings had no path to a phone. An auditor nobody reads
 * is a log nobody audits, which is most of why nobody was running one.
 *
 * This is the consumer. Two things make it worth anything:
 *
 * - **The checkpoint is signed and the key is pinned.** An unsigned JSON blob
 *   fetched over the network is worth nothing — whoever serves it, including
 *   the operator being audited, can write whatever makes the two views agree.
 *   The auditor's public key is configured out of band, once, the same way you
 *   would decide to trust an auditor at all.
 * - **The signature covers a length-framed encoding, not the JSON.** JSON has
 *   no canonical form; signing the bytes would mean an equivalent document
 *   re-serialised by a different encoder stops verifying, and that two
 *   different documents could share one signature.
 *
 * An auditor is not more trusted than the operator. It is a *second* party,
 * and what protects the user is the two of them disagreeing.
 */

import {
  ConsistencyFetcher,
  LogCheckpoint,
  SplitViewError,
  TransparencyError,
  verifyConsistency,
} from './transparency';
import { concat, equal, fromBase64, u32, utf8, verify } from './primitives';

/** Must match `CheckpointContext` in server/internal/auditor/signed.go. */
const CHECKPOINT_CONTEXT = 'tildra-auditor-checkpoint-v1:';

const HASH_BYTES = 32;
const KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

/** Raised when a published checkpoint is not what the pinned auditor signed. */
export class AuditorError extends TransparencyError {}

/** An auditor a client has decided to listen to. */
export interface PinnedAuditor {
  /** Where the signed checkpoint is published. */
  url: string;
  /** The auditor's Ed25519 public key, configured out of band. */
  publicKey: Uint8Array;
  /** For showing the user which auditor disagreed. */
  name?: string;
}

export interface AuditorCheckpoint {
  size: number;
  rootHash: Uint8Array;
  logKey: Uint8Array;
  /** Seconds. When the auditor last read the log. */
  checkedAt: number;
  auditorKey: Uint8Array;
  signature: Uint8Array;
}

/**
 * How stale a checkpoint may be before it stops meaning anything.
 *
 * An auditor that stopped running a month ago cannot testify about today's
 * log, and treating its last word as current is how a fork survives: the
 * operator only has to make the auditor's fetches fail and wait.
 */
export const AUDITOR_CHECKPOINT_MAX_AGE_MS = 48 * 60 * 60 * 1000;

/**
 * The bytes the auditor signed. Length-framed, mirroring
 * `checkpointTranscript` on the Go side — the two are kept honest by a
 * cross-language test, not by reading both files.
 */
function transcript(c: {
  size: number;
  rootHash: Uint8Array;
  logKey: Uint8Array;
  checkedAt: number;
}): Uint8Array {
  return concat(
    utf8(CHECKPOINT_CONTEXT),
    framed(u64(c.size)),
    framed(c.rootHash),
    framed(c.logKey),
    framed(u64(c.checkedAt)),
  );
}

function framed(field: Uint8Array): Uint8Array {
  return concat(u32(field.length), field);
}

/** Big-endian int64, matching Go's binary.BigEndian.PutUint64. */
function u64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, BigInt(Math.trunc(value)), false);
  return out;
}

/**
 * Parse and verify a published checkpoint against a pinned key.
 *
 * Parsing and verifying are one call on purpose: the intermediate value — a
 * checkpoint that parsed but was not checked — has no legitimate use, and
 * every codebase that returns it eventually acts on it.
 */
export function verifyAuditorCheckpoint(
  body: string,
  pinnedKey: Uint8Array,
  now: number = Date.now(),
): AuditorCheckpoint {
  if (pinnedKey.length !== KEY_BYTES) {
    throw new AuditorError('an auditor checkpoint can only be checked against a pinned key');
  }

  let raw: {
    size?: unknown;
    rootHash?: unknown;
    logKey?: unknown;
    checkedAt?: unknown;
    auditorKey?: unknown;
    signature?: unknown;
  };
  try {
    raw = JSON.parse(body);
  } catch {
    throw new AuditorError('the published checkpoint is not JSON');
  }

  if (typeof raw.size !== 'number' || !Number.isInteger(raw.size) || raw.size < 0) {
    throw new AuditorError('the checkpoint has no usable tree size');
  }
  if (typeof raw.signature !== 'string' || raw.signature.length === 0) {
    throw new AuditorError('the checkpoint is not signed');
  }

  const rootHash = decodeField(raw.rootHash, 'rootHash');
  const logKey = decodeField(raw.logKey, 'logKey');
  const signature = decodeField(raw.signature, 'signature');
  const auditorKey =
    raw.auditorKey === undefined ? pinnedKey : decodeField(raw.auditorKey, 'auditorKey');

  if (rootHash.length !== HASH_BYTES) throw new AuditorError('rootHash is not 32 bytes');
  if (logKey.length !== KEY_BYTES) throw new AuditorError('logKey is not 32 bytes');
  if (signature.length !== SIGNATURE_BYTES) throw new AuditorError('signature is not 64 bytes');

  // The key inside the document is a label, not authority: anyone can generate
  // a key, sign, and publish both.
  if (!equal(auditorKey, pinnedKey)) {
    throw new AuditorError('the checkpoint is signed by a different auditor than the one pinned');
  }

  const checkedAt = parseTimestamp(raw.checkedAt);
  if (!verify(pinnedKey, transcript({ size: raw.size, rootHash, logKey, checkedAt }), signature)) {
    throw new AuditorError('the checkpoint signature does not verify');
  }

  if (now - checkedAt * 1000 > AUDITOR_CHECKPOINT_MAX_AGE_MS) {
    throw new AuditorError(
      'the auditor has not read the log recently enough for its checkpoint to mean anything',
    );
  }

  return { size: raw.size, rootHash, logKey, checkedAt, auditorKey, signature };
}

function decodeField(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new AuditorError(`the checkpoint has no ${name}`);
  }
  try {
    return fromBase64(value);
  } catch {
    throw new AuditorError(`${name} is not valid base64`);
  }
}

/** Go marshals time.Time as RFC 3339; accept a Unix second count too. */
function parseTimestamp(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return Math.floor(parsed / 1000);
  }
  throw new AuditorError('the checkpoint has no usable timestamp');
}

/**
 * Compare what an auditor saw with what this device was shown.
 *
 * Same shape as the gossip check, and for the same reason: two heads of the
 * same size with different roots cannot both be true, and two of different
 * sizes must be linked by a consistency proof the server can produce. A server
 * that cannot link two heads it signed should not have signed both.
 *
 * The difference from gossip is who is on the other side. A contact has to be
 * targeted too, and has to be talking to you. An auditor is watching all the
 * time and does not need an account.
 */
export async function crossCheckAuditor(
  ours: LogCheckpoint,
  theirs: AuditorCheckpoint,
  fetchConsistency: ConsistencyFetcher,
  auditorName = 'the auditor',
): Promise<void> {
  if (!equal(ours.logKey, theirs.logKey)) {
    throw new SplitViewError(
      `${auditorName} is watching a log signed by a different key than this device was shown`,
    );
  }

  if (ours.size === theirs.size) {
    if (!equal(ours.rootHash, theirs.rootHash)) {
      throw new SplitViewError(
        `${auditorName} saw a different log of the same size; the server is running a split view`,
      );
    }
    return;
  }

  const [first, second, firstRoot, secondRoot] =
    ours.size < theirs.size
      ? [ours.size, theirs.size, ours.rootHash, theirs.rootHash]
      : [theirs.size, ours.size, theirs.rootHash, ours.rootHash];

  let proof: Uint8Array[];
  try {
    ({ proof } = await fetchConsistency(first, second));
  } catch (cause) {
    throw new SplitViewError(
      `the server could not prove the head it showed this device and the one ${auditorName} saw are consistent (${first} → ${second})`,
      { cause },
    );
  }

  try {
    verifyConsistency(first, second, proof, firstRoot, secondRoot);
  } catch (cause) {
    throw new SplitViewError(
      `${auditorName} and this device were shown logs that cannot both be true`,
      { cause },
    );
  }
}
