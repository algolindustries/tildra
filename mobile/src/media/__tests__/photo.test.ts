import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AvatarError, pickAvatar } from '../avatar';
import { MAX_PHOTO_BYTES, PHOTO_DIMENSION, pickPhoto } from '../photo';

/**
 * Picking a photo to send, which had no test of its own, and the encode step
 * both pickers share.
 *
 * `avatar.test.ts` already covers `compressToBudget` — the arithmetic of
 * walking quality down until the bytes fit. What nothing covered is the part
 * that touches the platform, and that is where the bug was: every quality step
 * calls `saveAsync`, which writes a JPEG to the cache directory, and nothing
 * deleted any of them.
 *
 * `pickAvatar` is exercised here too rather than in `avatar.test.ts`, because
 * it is the twin of the path under test and shares these doubles. A fix
 * applied to one and not the other is this project's most repeated mistake, so
 * the assertion that both leave nothing behind lives in one place.
 */

const picker = {
  granted: true,
  canceled: false,
  asset: { uri: 'file:///photos/IMG_0001.HEIC', width: 4032, height: 3024 },
  lastOptions: null as Record<string, unknown> | null,
};

vi.mock('expo-image-picker', () => ({
  async requestMediaLibraryPermissionsAsync() {
    return { granted: picker.granted };
  },
  async launchImageLibraryAsync(options: Record<string, unknown>) {
    picker.lastOptions = options;
    if (picker.canceled) return { canceled: true, assets: null };
    return { canceled: false, assets: [picker.asset] };
  },
}));

const fs = {
  files: new Map<string, string>(),
  failRead: null as Error | null,
  failDelete: null as Error | null,
};

vi.mock('expo-file-system/legacy', () => ({
  async readAsStringAsync(uri: string) {
    if (fs.failRead) throw fs.failRead;
    const contents = fs.files.get(uri);
    if (contents === undefined) throw new Error(`no such file: ${uri}`);
    return contents;
  },
  async deleteAsync(uri: string) {
    if (fs.failDelete) throw fs.failDelete;
    fs.files.delete(uri);
  },
}));

const encoder = {
  saves: [] as Array<{ source: string; size: { width: number; height: number }; quality: number }>,
  nextId: 0,
  /** Encoded byte length for a given quality. Small enough to fit by default. */
  bytesFor: (_quality: number) => 2_000,
};

/** A file of exactly `n` bytes, in the base64 the platform hands back. */
function fileOfBytes(n: number): string {
  return globalThis.btoa('a'.repeat(n));
}

vi.mock('expo-image-manipulator', () => ({
  SaveFormat: { JPEG: 'jpeg' },
  ImageManipulator: {
    manipulate(source: string) {
      let size = { width: 0, height: 0 };
      const context = {
        resize(next: { width: number; height: number }) {
          size = next;
          return context;
        },
        async renderAsync() {
          return {
            async saveAsync(options: { compress: number; format: string }) {
              const uri = `file:///cache/ImageManipulator/${encoder.nextId++}.jpg`;
              encoder.saves.push({ source, size, quality: options.compress });
              fs.files.set(uri, fileOfBytes(encoder.bytesFor(options.compress)));
              return { uri, width: size.width, height: size.height };
            },
          };
        },
      };
      return context;
    },
  },
}));

/** Every file the encoder wrote and did not take back. */
const leftOnDisk = () => Array.from(fs.files.keys());

beforeEach(() => {
  picker.granted = true;
  picker.canceled = false;
  picker.asset = { uri: 'file:///photos/IMG_0001.HEIC', width: 4032, height: 3024 };
  picker.lastOptions = null;
  fs.files.clear();
  fs.failRead = null;
  fs.failDelete = null;
  encoder.saves = [];
  encoder.nextId = 0;
  encoder.bytesFor = () => 2_000;
});

describe('picking a photo', () => {
  it('is null when the user backs out, which is not an error', async () => {
    picker.canceled = true;

    expect(await pickPhoto()).toBeNull();
  });

  it('refuses without the photo library', async () => {
    picker.granted = false;

    await expect(pickPhoto()).rejects.toThrow(/permission/);
  });

  it('returns jpeg bytes with the size it actually produced', async () => {
    const photo = await pickPhoto();

    expect(photo).not.toBeNull();
    expect(photo!.mimeType).toBe('image/jpeg');
    expect(photo!.bytes).toHaveLength(2_000);
  });

  it('scales the longest edge to the cap and keeps the shape', async () => {
    // 4032x3024 is a 4:3 phone photo. Squashing it would be visible.
    const photo = await pickPhoto();

    expect(photo!.width).toBe(PHOTO_DIMENSION);
    expect(photo!.height).toBe(1200);
    expect(encoder.saves[0].size).toEqual({ width: PHOTO_DIMENSION, height: 1200 });
  });

  it('does not blow a small photo up to the cap', async () => {
    // Upscaling costs bytes and adds nothing: the cap is a ceiling, not a
    // target.
    picker.asset = { uri: 'file:///photos/small.png', width: 800, height: 600 };

    const photo = await pickPhoto();

    expect(photo!.width).toBe(800);
    expect(photo!.height).toBe(600);
  });
});

describe('the copies left in the cache directory', () => {
  /**
   * `saveAsync` writes the encoded image to the cache directory. Nothing
   * deleted it, and `compressToBudget` calls the encoder once per quality
   * step — so sending one photo left up to five unencrypted copies of it on
   * the device, and setting an avatar left five more.
   *
   * The cache directory is not a wipe. The OS may reclaim it or may not, and
   * it was the one place a plaintext copy of a sent message survived
   * everything the vault does.
   */
  it('are gone after a photo is picked', async () => {
    await pickPhoto();

    expect(leftOnDisk()).toEqual([]);
  });

  it('are gone for every step, not just the last one', async () => {
    // The first encode is over budget, so the loop runs twice. Both files
    // existed; both had to go.
    encoder.bytesFor = (quality) => (quality > 0.8 ? MAX_PHOTO_BYTES + 1 : 3_000);

    const photo = await pickPhoto();

    expect(encoder.saves).toHaveLength(2);
    expect(photo!.bytes).toHaveLength(3_000);
    expect(leftOnDisk()).toEqual([]);
  });

  it('are gone when no quality fit and the pick failed', async () => {
    // The failure path is the one with the most files on disk: every step ran.
    encoder.bytesFor = () => MAX_PHOTO_BYTES + 1;

    await expect(pickPhoto()).rejects.toBeInstanceOf(AvatarError);

    expect(encoder.saves.length).toBeGreaterThan(1);
    expect(leftOnDisk()).toEqual([]);
  });

  it('are gone when reading the encode fails', async () => {
    // A throw on the way out is exactly when a temporary file gets forgotten,
    // and it is on disk either way.
    fs.failRead = new Error('the encode is unreadable');

    await expect(pickPhoto()).rejects.toThrow();

    expect(leftOnDisk()).toEqual([]);
  });

  it('do not turn an undeletable cache file into a failed send', async () => {
    fs.failDelete = new Error('the file is locked');

    const photo = await pickPhoto();

    expect(photo).not.toBeNull();
  });

  it('are gone after an avatar is picked, on the same path', async () => {
    // The twin. Both pickers go through the same encode now, so this is the
    // assertion that keeps them from drifting apart again.
    const avatar = await pickAvatar();

    expect(avatar).not.toBeNull();
    expect(leftOnDisk()).toEqual([]);
  });
});
