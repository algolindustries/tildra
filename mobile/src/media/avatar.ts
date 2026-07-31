/**
 * Turning a photo from the camera roll into an avatar small enough to send.
 *
 * A modern phone photo is several megabytes. An avatar has a hard budget
 * (MAX_AVATAR_BYTES) because it travels inside an encrypted message, gets
 * padded to a size bucket, and is stored on every contact's device. So the
 * image is downscaled and then re-compressed at decreasing quality until it
 * fits — or the attempt fails loudly rather than sending something the far
 * side cannot decode.
 *
 * The shrink loop is separated from Expo so it can be tested; the platform
 * calls live in pickAvatar below.
 */

import { MAX_AVATAR_BYTES } from '../crypto/content';

/** Longest edge of a stored avatar. Displayed at 46-96pt, so 512 is generous. */
export const AVATAR_DIMENSION = 512;

/** Quality steps tried in order. Stops at the first that fits. */
export const QUALITY_STEPS = [0.8, 0.6, 0.45, 0.3, 0.2];

export class AvatarError extends Error {}

/** Compresses at a given quality and reports the encoded size. */
export type Compressor = (quality: number) => Promise<Uint8Array>;

/**
 * Render a resized JPEG and return its bytes, keeping nothing.
 *
 * `saveAsync` writes the encoded image to the cache directory and hands back a
 * uri. The bytes are all anyone here wants, so the file goes as soon as it has
 * been read. Nothing did that before: `compressToBudget` calls this once per
 * quality step, so picking a single photo left up to five unencrypted copies
 * of it in app storage, and picking an avatar left five more. The cache
 * directory is not a wipe — the OS may reclaim it, or may not, and it is the
 * one place on the device where a plaintext copy of a message the user sent
 * survives everything the vault does.
 *
 * Shared by both pickers rather than written twice, because a fix applied to
 * one path and not its twin is this project's most repeated mistake.
 */
export async function renderJpegBytes(
  source: string,
  size: { width: number; height: number },
  quality: number,
): Promise<Uint8Array> {
  const ImageManipulator = await import('expo-image-manipulator');
  // expo-file-system's modern File API is not typed for reads and writes yet,
  // and its top-level readAsStringAsync/writeAsStringAsync now throw at
  // runtime with a pointer here. The legacy entrypoint is Expo's documented
  // path and is fully typed, so that is what this uses.
  const FileSystem = await import('expo-file-system/legacy');

  const context = ImageManipulator.ImageManipulator.manipulate(source);
  context.resize(size);
  const image = await context.renderAsync();
  const saved = await image.saveAsync({
    compress: quality,
    format: ImageManipulator.SaveFormat.JPEG,
  });

  try {
    const base64 = await FileSystem.readAsStringAsync(saved.uri, { encoding: 'base64' });
    const binary = globalThis.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } finally {
    // In a finally: a read that throws is exactly when the temporary file is
    // most likely to be forgotten, and it is on disk either way.
    try {
      await FileSystem.deleteAsync(saved.uri, { idempotent: true });
    } catch {
      // Best effort. A cache file that will not delete must not turn a
      // successful encode into a failed send.
    }
  }
}

/**
 * Find the highest quality that fits the budget.
 *
 * Walks down rather than binary-searching: each step is an image encode, the
 * list is short, and the common case succeeds on the first try.
 */
export async function compressToBudget(
  compress: Compressor,
  budget: number = MAX_AVATAR_BYTES,
  steps: number[] = QUALITY_STEPS,
): Promise<Uint8Array> {
  let smallest: Uint8Array | null = null;

  for (const quality of steps) {
    const encoded = await compress(quality);
    if (encoded.length <= budget) return encoded;
    if (!smallest || encoded.length < smallest.length) smallest = encoded;
  }

  throw new AvatarError(
    `Tildra: could not compress the image below ${budget} bytes ` +
      `(smallest attempt was ${smallest?.length ?? 0}). Try a smaller picture.`,
  );
}

/**
 * Prompt for a photo and return it as avatar-sized JPEG bytes.
 *
 * Returns null if the user cancels — a cancellation is not an error and must
 * not surface as one.
 *
 * The Expo modules are imported lazily so this file can be loaded (and the
 * logic above tested) in an environment without them.
 */
export async function pickAvatar(): Promise<Uint8Array | null> {
  const ImagePicker = await import('expo-image-picker');

  const permission = await ImagePicker.requestMediaLibraryPermissionsAsync();
  if (!permission.granted) {
    throw new AvatarError('Tildra: permission to open the photo library was refused');
  }

  const result = await ImagePicker.launchImageLibraryAsync({
    mediaTypes: ['images'],
    allowsEditing: true,
    aspect: [1, 1],
    quality: 1,
  });
  if (result.canceled || !result.assets?.length) return null;

  const source = result.assets[0].uri;

  return compressToBudget((quality) =>
    renderJpegBytes(source, { width: AVATAR_DIMENSION, height: AVATAR_DIMENSION }, quality),
  );
}
