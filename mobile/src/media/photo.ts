/**
 * Picking a photo to send.
 *
 * Shares the shrink-until-it-fits approach with avatars but with a much larger
 * budget: a photo message should look like a photo, whereas an avatar only
 * ever renders at 88pt. The cap still exists — an unbounded upload is a way to
 * fill someone else's disk, and the server enforces its own limit anyway.
 */

import { compressToBudget } from './avatar';

/** Longest edge of a sent photo. */
export const PHOTO_DIMENSION = 1600;

/** Client-side budget, comfortably under the server's 32 MiB ceiling. */
export const MAX_PHOTO_BYTES = 4 * 1024 * 1024;

const PHOTO_QUALITY_STEPS = [0.85, 0.7, 0.55, 0.4, 0.25];

export interface PickedPhoto {
  bytes: Uint8Array;
  mimeType: string;
  width: number;
  height: number;
}

/** Returns null when the user cancels, which is not an error. */
export async function pickPhoto(): Promise<PickedPhoto | null> {
  const ImagePicker = await import('expo-image-picker');
  const ImageManipulator = await import('expo-image-manipulator');
  // expo-file-system's modern File API is not typed for reads and writes yet,
  // and its top-level readAsStringAsync/writeAsStringAsync now throw at
  // runtime with a pointer here. The legacy entrypoint is Expo's documented
  // path and is fully typed, so that is what this uses.
  const FileSystem = await import('expo-file-system/legacy');

  const permission = await ImagePicker.requestMediaLibraryPermissionsAsync();
  if (!permission.granted) {
    throw new Error('Tildra: permission to open the photo library was refused');
  }

  const result = await ImagePicker.launchImageLibraryAsync({
    mediaTypes: ['images'],
    quality: 1,
  });
  if (result.canceled || !result.assets?.length) return null;

  const asset = result.assets[0];
  const scale = Math.min(1, PHOTO_DIMENSION / Math.max(asset.width || 1, asset.height || 1));
  const width = Math.max(1, Math.round((asset.width || PHOTO_DIMENSION) * scale));
  const height = Math.max(1, Math.round((asset.height || PHOTO_DIMENSION) * scale));

  const bytes = await compressToBudget(
    async (quality) => {
      const context = ImageManipulator.ImageManipulator.manipulate(asset.uri);
      context.resize({ width, height });
      const image = await context.renderAsync();
      const saved = await image.saveAsync({
        compress: quality,
        format: ImageManipulator.SaveFormat.JPEG,
      });
      const base64 = await FileSystem.readAsStringAsync(saved.uri, { encoding: 'base64' });
      const binary = globalThis.atob(base64);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
      return out;
    },
    MAX_PHOTO_BYTES,
    PHOTO_QUALITY_STEPS,
  );

  return { bytes, mimeType: 'image/jpeg', width, height };
}
