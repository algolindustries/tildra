/**
 * Verifying the key transparency log.
 *
 * This is the client half of the mechanism described in
 * docs/PROTOCOL.md §7.1. The server publishes a signed tree head and proves
 * that a handle's binding is in the tree; the client checks that proof, and
 * also that the tree it is being shown today extends the tree it saw last time.
 *
 * A hostile server that swaps a key therefore has two options, and both are
 * bad for it: append a visible entry, which anyone auditing the log can see,
 * or fork the log, which fails the consistency check the moment this client
 * compares its stored head against the new one.
 *
 * Deliberately a mirror of server/internal/transparency in Go. Two
 * implementations of the same algorithm is a liability, so the cross-language
 * integration test — Go produces proofs, this verifies them — is what keeps
 * them honest rather than the reading of either file.
 */

import { concat, equal, fromBase64, hash, toBase64, u32, utf8, verify } from './primitives';

export class TransparencyError extends Error {}

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
const STH_CONTEXT = 'tildra-sth-v1:';
const HASH_SIZE = 32;

export interface LogEntry {
  index: number;
  handle: string;
  accountId: string;
  identityKey: Uint8Array;
  /** Seconds since the epoch, matching what the log hashed. */
  recordedAt: number;
}

export interface SignedTreeHead {
  size: number;
  rootHash: Uint8Array;
  timestamp: number;
  signature: Uint8Array;
  logKey: Uint8Array;
}

export interface HandleProof {
  entry: LogEntry;
  inclusion: Uint8Array[];
  consistency: Uint8Array[];
  head: SignedTreeHead;
}

/** What a client remembers between lookups. */
export interface LogCheckpoint {
  size: number;
  rootHash: Uint8Array;
  logKey: Uint8Array;
}

/** Fetches a consistency proof between two tree sizes. */
export type ConsistencyFetcher = (
  first: number,
  second: number,
) => Promise<{ proof: Uint8Array[] }>;

/**
 * Raised when two verified tree heads cannot both be true.
 *
 * This is the split-view attack: a server showing one log to one person and a
 * different log to another. Every other transparency failure means "this
 * response is wrong"; this one means "this server is lying to somebody, and
 * one of us is the target".
 */
export class SplitViewError extends TransparencyError {}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

export function hashLeaf(entry: Uint8Array): Uint8Array {
  return hash(concat(new Uint8Array([LEAF_PREFIX]), entry));
}

export function hashChildren(left: Uint8Array, right: Uint8Array): Uint8Array {
  return hash(concat(new Uint8Array([NODE_PREFIX]), left, right));
}

/**
 * Canonical bytes for an entry — must match Entry.Encode in Go exactly.
 *
 * Length-prefixed rather than delimited: without it a handle containing the
 * delimiter could make two different entries encode identically, and the log
 * would attest to something other than what it recorded.
 */
export function encodeEntry(entry: LogEntry): Uint8Array {
  const field = (bytes: Uint8Array) => concat(u32(bytes.length), bytes);
  return concat(
    field(utf8(entry.handle)),
    field(utf8(entry.accountId)),
    field(entry.identityKey),
    u64(entry.recordedAt),
  );
}

function u64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(Math.trunc(value)), false);
  return out;
}

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

/** RFC 6962 §2.1.1. The path is bottom-up and consumed in that order. */
export function verifyInclusion(
  leafHash: Uint8Array,
  index: number,
  size: number,
  path: Uint8Array[],
  root: Uint8Array,
): void {
  if (index < 0 || size <= 0 || index >= size) {
    throw new TransparencyError(`index ${index} out of range for size ${size}`);
  }

  let computed = leafHash;
  let fn = index;
  let sn = size - 1;

  for (const sibling of path) {
    if (sibling.length !== HASH_SIZE) {
      throw new TransparencyError('malformed sibling hash');
    }
    if (sn === 0) {
      throw new TransparencyError('proof is longer than the tree is deep');
    }
    if ((fn & 1) === 1 || fn === sn) {
      computed = hashChildren(sibling, computed);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      computed = hashChildren(computed, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }

  if (sn !== 0) {
    throw new TransparencyError('proof is shorter than the tree is deep');
  }
  if (!equal(computed, root)) {
    throw new TransparencyError('inclusion proof does not reproduce the root hash');
  }
}

/** RFC 6962 §2.1.2. Proves the old tree is a prefix of the new one. */
export function verifyConsistency(
  first: number,
  second: number,
  path: Uint8Array[],
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
): void {
  if (first < 0 || second < first) {
    throw new TransparencyError(`invalid sizes: ${first} then ${second}`);
  }
  if (first === 0) {
    // A client's very first lookup has no prior tree. Demanding a proof here
    // would make the mechanism impossible to bootstrap.
    return;
  }
  if (first === second) {
    if (path.length !== 0) {
      throw new TransparencyError('unexpected path for an unchanged tree');
    }
    if (!equal(oldRoot, newRoot)) {
      throw new TransparencyError('tree size unchanged but the root differs');
    }
    return;
  }
  if (path.length === 0) {
    throw new TransparencyError('a grown tree requires a consistency path');
  }

  let fn = first - 1;
  let sn = second - 1;
  while ((fn & 1) === 1) {
    fn >>= 1;
    sn >>= 1;
  }

  let start = 0;
  let seed: Uint8Array;
  if (fn === 0) {
    seed = oldRoot;
  } else {
    seed = path[0];
    start = 1;
  }

  let fr = seed;
  let sr = seed;

  for (const node of path.slice(start)) {
    if (node.length !== HASH_SIZE) {
      throw new TransparencyError('malformed node hash');
    }
    if (sn === 0) {
      throw new TransparencyError('path is longer than the tree is deep');
    }
    if ((fn & 1) === 1 || fn === sn) {
      fr = hashChildren(node, fr);
      sr = hashChildren(node, sr);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = hashChildren(sr, node);
    }
    fn >>= 1;
    sn >>= 1;
  }

  if (sn !== 0) {
    throw new TransparencyError('path is shorter than the tree is deep');
  }
  if (!equal(fr, oldRoot)) {
    // The failure that matters: the entries this client already saw are not
    // the entries the server now claims.
    throw new TransparencyError(
      'the log was rewritten: the previously seen tree head cannot be reproduced',
    );
  }
  if (!equal(sr, newRoot)) {
    throw new TransparencyError('consistency proof does not reproduce the new root');
  }
}

/** Check the signature on a tree head. */
export function verifyTreeHead(head: SignedTreeHead, expectedLogKey?: Uint8Array): void {
  if (head.logKey.length !== 32) {
    throw new TransparencyError('malformed log key');
  }
  if (expectedLogKey && !equal(head.logKey, expectedLogKey)) {
    // A different signing key is a different log. Accepting one would let a
    // server escape its own history simply by rotating keys.
    throw new TransparencyError('the log key changed; this is a different log');
  }

  const signed = concat(utf8(STH_CONTEXT), u64(head.size), head.rootHash, u64(head.timestamp));
  if (!verify(head.logKey, signed, head.signature)) {
    throw new TransparencyError('tree head signature does not verify');
  }
}

/**
 * The whole check a client runs on a handle lookup.
 *
 * Returns the checkpoint to store for next time. Throwing here means the
 * binding must not be used — which is the point: an unproven key is exactly
 * the situation this exists to refuse.
 */
export function verifyHandleProof(
  proof: HandleProof,
  expectedHandle: string,
  checkpoint: LogCheckpoint | null,
): LogCheckpoint {
  verifyTreeHead(proof.head, checkpoint?.logKey);

  if (proof.entry.handle.toLowerCase() !== expectedHandle.toLowerCase()) {
    // Without this a server could answer any lookup with a proof for some
    // other handle it had legitimately logged.
    throw new TransparencyError('the proof is for a different handle');
  }

  verifyInclusion(
    hashLeaf(encodeEntry(proof.entry)),
    proof.entry.index,
    proof.head.size,
    proof.inclusion,
    proof.head.rootHash,
  );

  if (checkpoint) {
    if (proof.head.size < checkpoint.size) {
      throw new TransparencyError('the log shrank; entries were removed');
    }
    verifyConsistency(
      checkpoint.size,
      proof.head.size,
      proof.consistency,
      checkpoint.rootHash,
      proof.head.rootHash,
    );
  }

  return { size: proof.head.size, rootHash: proof.head.rootHash, logKey: proof.head.logKey };
}

// ---------------------------------------------------------------------------
// Gossip
// ---------------------------------------------------------------------------

/**
 * Cross-check a tree head someone else verified against our own.
 *
 * The log's inclusion and consistency proofs stop a server rewriting history
 * for *one* client. They do nothing about a server that keeps two internally
 * consistent logs and shows a different one to each person. Detecting that
 * needs two clients to compare what they were told — which is exactly what
 * this does, using the messages they already exchange as the transport.
 *
 * Whichever head is smaller must be a prefix of the larger. If the server
 * cannot produce a proof linking them, or the proof does not verify, the two
 * heads describe different logs and the server is running a split view.
 */
export async function crossCheckTreeHead(
  ours: LogCheckpoint,
  theirs: SignedTreeHead,
  fetchConsistency: ConsistencyFetcher,
): Promise<void> {
  verifyTreeHead(theirs, ours.logKey);

  if (ours.size === theirs.size) {
    if (!equal(ours.rootHash, theirs.rootHash)) {
      throw new SplitViewError(
        'two devices were shown different logs of the same size; the server is running a split view',
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
    // A server that cannot link two heads it signed is a server that should
    // not have signed both.
    throw new SplitViewError(
      `the server could not prove its own tree heads are consistent (${first} → ${second})`,
      { cause },
    );
  }

  try {
    verifyConsistency(first, second, proof, firstRoot, secondRoot);
  } catch (cause) {
    throw new SplitViewError(
      'two verified tree heads are not on the same log; the server is running a split view',
      { cause },
    );
  }
}

/** Wire form of a gossiped tree head. */
export interface SerializedTreeHead {
  size: number;
  rootHash: string;
  timestamp: number;
  signature: string;
  logKey: string;
}

export function serializeTreeHead(head: SignedTreeHead): SerializedTreeHead {
  return {
    size: head.size,
    rootHash: toBase64(head.rootHash),
    timestamp: head.timestamp,
    signature: toBase64(head.signature),
    logKey: toBase64(head.logKey),
  };
}

export function deserializeTreeHead(data: SerializedTreeHead): SignedTreeHead {
  const head: SignedTreeHead = {
    size: data.size,
    rootHash: fromBase64(data.rootHash),
    timestamp: data.timestamp,
    signature: fromBase64(data.signature),
    logKey: fromBase64(data.logKey),
  };
  if (!Number.isInteger(head.size) || head.size < 0) {
    throw new TransparencyError('gossiped tree head has an invalid size');
  }
  if (head.rootHash.length !== HASH_SIZE || head.logKey.length !== 32) {
    throw new TransparencyError('gossiped tree head is malformed');
  }
  return head;
}
