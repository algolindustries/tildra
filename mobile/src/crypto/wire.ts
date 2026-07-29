/**
 * Length-prefixed binary framing.
 *
 * Used for everything that goes inside a ciphertext. JSON would be easier to
 * read but base64-inflates every key by a third, and message size is metadata
 * the server can see — so the wire format is bytes.
 */

import { concat, readU32, u32 } from './primitives';

/** Encode a list of byte fields as u32-length-prefixed frames. */
export function frame(...fields: Uint8Array[]): Uint8Array {
  return concat(...fields.flatMap((f) => [u32(f.length), f]));
}

/**
 * Decode exactly `count` frames. Throws on truncation or trailing garbage —
 * both mean the input is not what the sender produced, and guessing is how
 * parsers become attack surface.
 */
export function unframe(data: Uint8Array, count: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  let offset = 0;
  for (let i = 0; i < count; i++) {
    if (offset + 4 > data.length) {
      throw new Error(`Tildra: truncated frame ${i} of ${count}`);
    }
    const length = readU32(data, offset);
    offset += 4;
    if (offset + length > data.length) {
      throw new Error(`Tildra: frame ${i} claims ${length} bytes, only ${data.length - offset} left`);
    }
    out.push(data.slice(offset, offset + length));
    offset += length;
  }
  if (offset !== data.length) {
    throw new Error(`Tildra: ${data.length - offset} trailing bytes after ${count} frames`);
  }
  return out;
}

/**
 * Size buckets for envelope padding — docs/PROTOCOL.md §6.
 *
 * Exact ciphertext length leaks the length of what you wrote. Bucketing costs
 * bandwidth and buys the fact that "ok" and "no, and here is why" look the same
 * on the wire.
 */
const BUCKETS = [256, 1024, 4096, 16384, 65536];
const LARGE_INCREMENT = 65536;

export function bucketSize(length: number): number {
  for (const b of BUCKETS) {
    if (length <= b) return b;
  }
  return Math.ceil(length / LARGE_INCREMENT) * LARGE_INCREMENT;
}

/** Pad to the next bucket, prefixing the true length so it can be recovered. */
export function pad(payload: Uint8Array): Uint8Array {
  const target = bucketSize(payload.length + 4);
  const out = new Uint8Array(target);
  out.set(u32(payload.length), 0);
  out.set(payload, 4);
  return out;
}

export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) {
    throw new Error('Tildra: padded payload is too short to hold a length prefix');
  }
  const length = readU32(padded, 0);
  if (4 + length > padded.length) {
    throw new Error('Tildra: padding length prefix exceeds the buffer');
  }
  return padded.slice(4, 4 + length);
}
