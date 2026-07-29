import { describe, expect, it, vi } from 'vitest';

import { AvatarError, QUALITY_STEPS, compressToBudget } from '../avatar';

/** A compressor whose output size falls as quality falls. */
function sizedBy(sizes: Record<number, number>) {
  return vi.fn(async (quality: number) => new Uint8Array(sizes[quality] ?? 0));
}

describe('avatar compression', () => {
  it('keeps the first quality that fits, without trying lower ones', () => {
    const compress = sizedBy({ 0.8: 1000 });
    return compressToBudget(compress, 2000).then((out) => {
      expect(out.length).toBe(1000);
      expect(compress).toHaveBeenCalledTimes(1);
      expect(compress).toHaveBeenCalledWith(0.8);
    });
  });

  it('steps down until the image fits', async () => {
    const compress = sizedBy({ 0.8: 5000, 0.6: 3000, 0.45: 1500 });
    const out = await compressToBudget(compress, 2000);

    expect(out.length).toBe(1500);
    expect(compress).toHaveBeenCalledTimes(3);
  });

  it('fails loudly rather than sending something oversized', async () => {
    // Truncating or sending it anyway would produce an image the recipient
    // cannot decode, which looks like a bug in their client, not ours.
    const compress = vi.fn(async () => new Uint8Array(999_999));
    await expect(compressToBudget(compress, 2000)).rejects.toBeInstanceOf(AvatarError);
    expect(compress).toHaveBeenCalledTimes(QUALITY_STEPS.length);
  });

  it('reports the smallest attempt in the failure message', async () => {
    const compress = sizedBy({ 0.8: 9000, 0.6: 8000, 0.45: 7000, 0.3: 6000, 0.2: 5000 });
    await expect(compressToBudget(compress, 1000)).rejects.toThrow(/5000/);
  });

  it('accepts an image exactly at the budget', async () => {
    const compress = sizedBy({ 0.8: 2000 });
    const out = await compressToBudget(compress, 2000);
    expect(out.length).toBe(2000);
  });

  it('tries every quality step in descending order', async () => {
    const seen: number[] = [];
    const compress = vi.fn(async (quality: number) => {
      seen.push(quality);
      return new Uint8Array(999_999);
    });
    await expect(compressToBudget(compress, 10)).rejects.toThrow();

    expect(seen).toEqual(QUALITY_STEPS);
    expect([...seen].sort((a, b) => b - a)).toEqual(seen);
  });
});
