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
  const ImageManipulator = await import('expo-image-manipulator');
  const FileSystem = await import('expo-file-system');

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

  return compressToBudget(async (quality) => {
    const context = ImageManipulator.ImageManipulator.manipulate(source);
    context.resize({ width: AVATAR_DIMENSION, height: AVATAR_DIMENSION });
    const image = await context.renderAsync();
    const saved = await image.saveAsync({
      compress: quality,
      format: ImageManipulator.SaveFormat.JPEG,
    });

    const base64 = await FileSystem.readAsStringAsync(saved.uri, { encoding: 'base64' });
    const binary = globalThis.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  });
}
