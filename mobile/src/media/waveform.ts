/**
 * Waveform rendering data for voice messages.
 *
 * The waveform and the duration travel in the *message*, not inside the
 * encrypted blob. A voice note should show its shape and length the moment it
 * arrives — waiting for a download to know whether it is three seconds or three
 * minutes makes the feature feel broken.
 *
 * That means the waveform is metadata a recipient sees before fetching, and
 * therefore metadata worth keeping small and coarse: 48 buckets of 4 bits each.
 * It is a picture of loudness over time, not a recoverable signal.
 */

/** Bars drawn in a voice bubble. Enough to read at a glance, few enough to stay small. */
export const WAVEFORM_BUCKETS = 48;

/** Amplitudes are stored one per byte, 0-15. */
export const WAVEFORM_MAX = 15;

export const MAX_VOICE_DURATION_MS = 5 * 60 * 1000;

/**
 * Reduce a stream of amplitude samples to a fixed-width waveform.
 *
 * Each bucket takes the *peak* of its window rather than the mean: a mean
 * flattens speech into a uniform smear, and the point of the picture is to show
 * where the words are.
 */
export function buildWaveform(samples: number[], buckets = WAVEFORM_BUCKETS): Uint8Array {
  const out = new Uint8Array(buckets);
  if (samples.length === 0) return out;

  const peaks = new Array<number>(buckets).fill(0);
  for (let i = 0; i < buckets; i++) {
    const start = Math.floor((i * samples.length) / buckets);
    const end = Math.max(start + 1, Math.floor(((i + 1) * samples.length) / buckets));
    let peak = 0;
    for (let j = start; j < end && j < samples.length; j++) {
      peak = Math.max(peak, Math.abs(samples[j]));
    }
    peaks[i] = peak;
  }

  // Normalise against the loudest bucket so a quiet recording is still legible.
  // A silent one stays flat rather than being amplified into noise.
  const loudest = Math.max(...peaks);
  if (loudest <= 0) return out;

  for (let i = 0; i < buckets; i++) {
    out[i] = Math.round((peaks[i] / loudest) * WAVEFORM_MAX);
  }
  return out;
}

/**
 * Convert a platform meter reading in dBFS to a linear amplitude.
 *
 * Recorders report loudness in decibels, where -160 is silence and 0 is the
 * loudest representable signal. Plotting decibels directly makes everything
 * look uniformly loud, because human speech occupies a narrow band near the
 * top; converting to linear amplitude first is what makes the picture readable.
 */
export function meteringToAmplitude(db: number): number {
  if (!Number.isFinite(db)) return 0;
  const floor = -60;
  if (db <= floor) return 0;
  if (db >= 0) return 1;
  return Math.pow(10, db / 20);
}

/** mm:ss for a bubble. Voice notes are minutes, never hours. */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

/**
 * Heights for the bars, as a fraction of the bubble.
 *
 * A floor of 0.12 keeps silence visible as a thin line rather than a gap —
 * a waveform with holes in it reads as a corrupted file.
 */
export function barHeights(waveform: Uint8Array, minimum = 0.12): number[] {
  return Array.from(waveform, (v) => minimum + (v / WAVEFORM_MAX) * (1 - minimum));
}

/** How much of the waveform has played, for the progress fill. */
export function playbackProgress(positionMs: number, durationMs: number): number {
  if (durationMs <= 0) return 0;
  return Math.min(1, Math.max(0, positionMs / durationMs));
}
