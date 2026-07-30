import { describe, expect, it } from 'vitest';

import {
  AUDITOR_CHECKPOINT_MAX_AGE_MS,
  AuditorError,
  parsePinnedAuditors,
  verifyAuditorCheckpoint,
} from '../auditor';
import { generateSigningKeyPair, toBase64 } from '../primitives';

const KEY_A = toBase64(generateSigningKeyPair().publicKey);
const KEY_B = toBase64(generateSigningKeyPair().publicKey);
const URL_A = 'https://auditor.example/checkpoint.json';

function config(entries: unknown): string {
  return JSON.stringify(entries);
}

describe('pinning auditors from configuration', () => {
  it('reads a well-formed list', () => {
    const auditors = parsePinnedAuditors(
      config([
        { name: 'First', url: URL_A, publicKey: KEY_A },
        { url: 'https://second.example/c.json', publicKey: KEY_B },
      ]),
    );

    expect(auditors).toHaveLength(2);
    expect(auditors[0].name).toBe('First');
    expect(auditors[0].publicKey).toHaveLength(32);
    expect(auditors[1].name).toBeUndefined();
  });

  it('treats no configuration as no auditors', () => {
    // The honest default: Tildra operates no public auditor, so there is
    // nobody to pin.
    expect(parsePinnedAuditors(undefined)).toEqual([]);
    expect(parsePinnedAuditors(null)).toEqual([]);
    expect(parsePinnedAuditors('')).toEqual([]);
    expect(parsePinnedAuditors('   ')).toEqual([]);
    expect(parsePinnedAuditors('[]')).toEqual([]);
  });

  it('fails the whole list rather than quietly dropping an entry', () => {
    // An operator who mistypes one key and gets a shorter list believes their
    // users are checking an auditor that is not being checked.
    expect(() =>
      parsePinnedAuditors(
        config([
          { url: URL_A, publicKey: KEY_A },
          { url: 'https://second.example/c.json', publicKey: 'not-base64!!' },
        ]),
      ),
    ).toThrow(/auditor 2/);
  });

  it('refuses a plaintext auditor anywhere but loopback', () => {
    // A checkpoint fetched over plaintext can be replaced in transit, which
    // turns the whole check into theatre.
    expect(() => parsePinnedAuditors(config([{ url: 'http://a.example/c.json', publicKey: KEY_A }]))).toThrow(
      /plaintext/,
    );
    expect(
      parsePinnedAuditors(config([{ url: 'http://localhost:9000/c.json', publicKey: KEY_A }])),
    ).toHaveLength(1);
  });

  it('refuses a key that is not 32 bytes', () => {
    expect(() => parsePinnedAuditors(config([{ url: URL_A, publicKey: toBase64(new Uint8Array(31)) }]))).toThrow(
      /not 32 bytes/,
    );
  });

  it('refuses the same key listed twice', () => {
    // Either a copy-paste mistake or an attempt to make one auditor look like
    // two independent ones.
    expect(() =>
      parsePinnedAuditors(
        config([
          { url: URL_A, publicKey: KEY_A },
          { url: 'https://second.example/c.json', publicKey: KEY_A },
        ]),
      ),
    ).toThrow(/repeats a publicKey/);
  });

  it('refuses malformed shapes', () => {
    for (const bad of [
      'not json',
      '{"url":"https://a.example"}',
      config([null]),
      config(['a string']),
      config([{ publicKey: KEY_A }]),
      config([{ url: URL_A }]),
      config([{ url: URL_A, publicKey: KEY_A, name: 7 }]),
      config([{ url: 'not a url', publicKey: KEY_A }]),
    ]) {
      expect(() => parsePinnedAuditors(bad), bad).toThrow(AuditorError);
    }
  });

  it('drops a blank name rather than showing an empty label', () => {
    const [auditor] = parsePinnedAuditors(config([{ url: URL_A, publicKey: KEY_A, name: '   ' }]));
    expect(auditor.name).toBeUndefined();
  });
});

describe('checkpoint freshness', () => {
  it('refuses a checkpoint from an auditor that stopped watching', () => {
    // The way a fork survives is the operator making the auditor's fetches
    // fail and waiting, so a stale checkpoint has to stop counting.
    const key = generateSigningKeyPair();
    const stale = JSON.stringify({
      size: 1,
      rootHash: toBase64(new Uint8Array(32)),
      logKey: toBase64(new Uint8Array(32)),
      checkedAt: '2020-01-01T00:00:00Z',
      auditorKey: toBase64(key.publicKey),
      signature: toBase64(new Uint8Array(64)),
    });
    expect(() => verifyAuditorCheckpoint(stale, key.publicKey)).toThrow(AuditorError);
  });

  it('states how old is too old', () => {
    expect(AUDITOR_CHECKPOINT_MAX_AGE_MS).toBe(48 * 60 * 60 * 1000);
  });
});
