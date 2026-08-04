import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { bucketSize } from '../wire';
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from '../recovery';

/**
 * The protocol document, checked against the code.
 *
 * `docs/PROTOCOL.md` §9 lists the primitives Tildra uses. It listed one it does
 * not: RSA-PSS blind signatures, for delivery tokens, which appear nowhere in
 * the client or the server. That row had a consequence rather than being
 * cosmetic — §5 described the sender proving they are a real account with a
 * blind-signed token, and `docs/THREAT_MODEL.md` then told the reader the
 * server learns "Nothing" about who sent a message. It learns the account, from
 * the bearer token on the request.
 *
 * One unbuilt mechanism, named in a table, had propagated into the guarantee a
 * user is told to read. So the table is checked now.
 *
 * What this proves is narrow and worth stating: that every primitive the
 * document names is *used somewhere*. It cannot tell whether it is used
 * correctly — that is what the rest of `crypto/` is for. What it catches is the
 * failure that happened, which is a primitive named and never implemented.
 */

const REPO = join(__dirname, '../../../..');
const CRYPTO_DIR = join(__dirname, '..');

/**
 * The symbol each documented primitive is implemented by.
 *
 * Written out rather than inferred: a mapping that guesses would either miss a
 * removal or invent a match. Adding a row here is a deliberate act, the same as
 * adding one to the table it mirrors.
 */
const IMPLEMENTED_BY: Record<string, string> = {
  Signatures: 'ed25519',
  'Key agreement (classical)': 'x25519',
  'Key agreement (post-quantum)': 'ml_kem768',
  AEAD: 'xchacha20poly1305',
  Hash: 'sha256',
  KDF: 'hkdf',
  'Password/phrase stretching': 'argon2id',
};

function protocolDoc(): string {
  return readFileSync(join(REPO, 'docs/PROTOCOL.md'), 'utf8');
}

/** Every line of the primitives table in §9, as [purpose, primitive]. */
function primitiveRows(doc: string): Array<[string, string]> {
  const section = doc.slice(doc.indexOf('## 9. Cryptographic primitives'));
  const table = section.slice(0, section.indexOf('\n\n', section.indexOf('|')));
  return table
    .split('\n')
    .filter((line) => line.startsWith('|'))
    .map((line) => line.split('|').map((c) => c.trim()))
    .filter((cells) => cells.length >= 4 && cells[1] !== 'Purpose' && !cells[1].startsWith('---'))
    .map((cells) => [cells[1], cells[2]] as [string, string]);
}

/** Every source file under src/crypto, concatenated. */
function cryptoSource(): string {
  return readdirSync(CRYPTO_DIR)
    .filter((f) => f.endsWith('.ts'))
    .map((f) => readFileSync(join(CRYPTO_DIR, f), 'utf8'))
    .join('\n');
}

describe('the primitives table in PROTOCOL.md §9', () => {
  it('is not empty, and the parser found it', () => {
    // A parser that silently matched nothing would make every assertion below
    // vacuously true, which is the usual way a test like this stops working.
    const rows = primitiveRows(protocolDoc());
    expect(rows.length).toBeGreaterThanOrEqual(6);
    expect(rows.map(([purpose]) => purpose)).toContain('AEAD');
  });

  it('names only primitives the code actually uses', () => {
    const source = cryptoSource();
    const rows = primitiveRows(protocolDoc());

    const unimplemented = rows.filter(([purpose]) => {
      const symbol = IMPLEMENTED_BY[purpose];
      return !symbol || !source.includes(symbol);
    });

    expect(
      unimplemented.map(([purpose, primitive]) => `${purpose}: ${primitive}`),
      'the document names a primitive with nothing behind it — either implement it, ' +
        'or move it to §11 where the unbuilt things go',
    ).toEqual([]);
  });

  it('has a row for every primitive the mapping knows about', () => {
    // The other direction: a primitive dropped from the table while the code
    // still uses it would leave the document describing less than it does,
    // which is the failure mode this project is least likely to notice.
    const purposes = primitiveRows(protocolDoc()).map(([purpose]) => purpose);
    for (const purpose of Object.keys(IMPLEMENTED_BY)) {
      expect(purposes, `${purpose} is implemented but no longer documented`).toContain(purpose);
    }
  });
});

describe('the Argon2id parameters', () => {
  it('are the ones the document states', () => {
    // The row most likely to drift quietly: somebody tunes the cost for a slow
    // phone and the document keeps claiming the old figure, which is the number
    // a reviewer would use to judge whether a stolen phrase is worth grinding.
    const row = primitiveRows(protocolDoc()).find(
      ([purpose]) => purpose === 'Password/phrase stretching',
    );
    expect(row).toBeDefined();

    const documented = row![1];
    const memory = /(\d+)\s*MiB/.exec(documented);
    const iterations = /t\s*=\s*(\d+)/.exec(documented);
    const parallelism = /p\s*=\s*(\d+)/.exec(documented);

    expect(memory, `no memory cost in ${documented}`).not.toBeNull();
    expect(iterations, `no iteration count in ${documented}`).not.toBeNull();
    expect(parallelism, `no parallelism in ${documented}`).not.toBeNull();

    expect(Number(memory![1]) * 1024).toBe(ARGON2_MEMORY_KIB);
    expect(Number(iterations![1])).toBe(ARGON2_ITERATIONS);
    expect(Number(parallelism![1])).toBe(ARGON2_PARALLELISM);
  });
});

describe('the KDF labels', () => {
  /**
   * Scoped to `src/crypto`, which is the protocol layer.
   *
   * `storage/vault.ts` has its own `Tildra_Vault_*` domains and a blind-index
   * label; those encrypt the local database and are deliberately not in a
   * document about what goes over the wire. Nothing else is exempt — if a label
   * under `src/crypto` is not in `PROTOCOL.md`, a second implementation cannot
   * be built from the document, which is the document's whole job.
   */
  const LABEL = /Tildra_[A-Za-z0-9_]*/g;

  function labelsIn(text: string): Set<string> {
    return new Set(text.match(LABEL) ?? []);
  }

  it('found labels on both sides, so the comparison means something', () => {
    expect(labelsIn(cryptoSource()).size).toBeGreaterThanOrEqual(15);
    expect(labelsIn(protocolDoc()).size).toBeGreaterThanOrEqual(15);
  });

  it('are every one of them documented', () => {
    // Six were not, until 2026-07-31: the root-key ratchet step, the header
    // keys, the group message-key expansion, the group signature transcript,
    // the sealed-sender key and the provisioning payload key. An implementer
    // reading §§3-5 could not have built a client that interoperates.
    const undocumented = [...labelsIn(cryptoSource())].filter(
      (label) => !labelsIn(protocolDoc()).has(label),
    );
    expect(
      undocumented.sort(),
      'these derivations exist in the code and nowhere in PROTOCOL.md',
    ).toEqual([]);
  });

  it('are not named by the document unless the code has them', () => {
    // The other direction, and the one that has bitten hardest: a label in the
    // document with nothing behind it is how "blind-signed delivery token"
    // became a guarantee in the threat model.
    const invented = [...labelsIn(protocolDoc())].filter(
      (label) => !labelsIn(cryptoSource()).has(label),
    );
    expect(invented.sort(), 'the document names a derivation the code does not do').toEqual([]);
  });
});

/**
 * §6's padding buckets, checked against the code that pads.
 *
 * The section states five sizes and an increment. They are the observable
 * shape of every envelope on the wire, so an implementer reads them as
 * normative and a reader of a packet capture uses them to decide whether the
 * padding is working. Nothing checked that the two agree, and §6 was the
 * section where three other claims had drifted away from the code entirely.
 */
describe('the padding buckets in §6', () => {
  /** "256 B", "1 KiB", "64 KiB" — the units the document actually writes. */
  function documentedBuckets(): { sizes: number[]; increment: number } {
    const doc = protocolDoc();
    const match = doc.match(/padded to bucketed sizes \(([^)]*)\)/);
    if (!match) throw new Error('§6 no longer states its bucket sizes in a form this can read');

    const bytes = (value: string): number => {
      const m = value.trim().match(/^(\d+)\s*(B|KiB|MiB)$/);
      if (!m) throw new Error(`cannot read a size out of "${value}"`);
      return Number(m[1]) * { B: 1, KiB: 1024, MiB: 1024 * 1024 }[m[2] as 'B' | 'KiB' | 'MiB'];
    };

    const parts = match[1].split(',').map((p) => p.trim());
    const incrementPart = parts.pop()!;
    const increment = incrementPart.match(/then\s+(.*?)\s+increments/);
    if (!increment) throw new Error('§6 no longer states its increment in a form this can read');

    return { sizes: parts.map(bytes), increment: bytes(increment[1]) };
  }

  it('states sizes this can read, so the comparison means something', () => {
    const { sizes, increment } = documentedBuckets();
    expect(sizes).toEqual([256, 1024, 4096, 16384, 65536]);
    expect(increment).toBe(65536);
  });

  it('are the boundaries the code actually rounds to', () => {
    const { sizes } = documentedBuckets();
    for (const size of sizes) {
      // Exactly on the boundary stays there, one byte under lands on it, and
      // one byte over does not — which is what makes it a boundary rather than
      // a number that happens to appear in a list.
      expect(bucketSize(size), `${size} exactly`).toBe(size);
      expect(bucketSize(size - 1), `${size} - 1`).toBe(size);
      if (size !== sizes.at(-1)) {
        expect(bucketSize(size + 1), `${size} + 1`).toBeGreaterThan(size);
      }
    }
  });

  it('grow by the documented increment past the last bucket', () => {
    const { sizes, increment } = documentedBuckets();
    const last = sizes.at(-1)!;
    expect(bucketSize(last + 1)).toBe(last + increment);
    expect(bucketSize(last + increment)).toBe(last + increment);
    expect(bucketSize(last + increment + 1)).toBe(last + 2 * increment);
  });
});
