import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

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
