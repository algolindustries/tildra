/**
 * Recording and playing voice messages.
 *
 * The recording is encrypted like any other attachment. What is different is
 * that its duration and waveform travel in the message rather than the blob,
 * so a bubble is legible before anything is downloaded — see waveform.ts.
 */

import { MAX_VOICE_DURATION_MS, buildWaveform, meteringToAmplitude } from './waveform';

export class VoiceError extends Error {}

export interface Recording {
  /** Stop, encode, and return the finished note. */
  stop(): Promise<VoiceNote | null>;
  /** Abandon the recording and release the microphone. */
  cancel(): Promise<void>;
}

export interface VoiceNote {
  bytes: Uint8Array;
  mimeType: string;
  durationMs: number;
  waveform: Uint8Array;
}

/**
 * Begin recording.
 *
 * Returns a handle rather than a promise of the finished note, because the
 * caller controls when it ends — a hold-to-talk button has to be able to
 * cancel as well as stop, and those are different outcomes.
 */
export async function startRecording(): Promise<Recording> {
  const Audio = await import('expo-audio');
  // expo-file-system's modern File API is not typed for reads and writes yet,
  // and its top-level readAsStringAsync/writeAsStringAsync now throw at
  // runtime with a pointer here. The legacy entrypoint is Expo's documented
  // path and is fully typed, so that is what this uses.
  const FileSystem = await import('expo-file-system/legacy');

  const permission = await Audio.requestRecordingPermissionsAsync();
  if (!permission.granted) {
    throw new VoiceError('Tildra: permission to use the microphone was refused');
  }

  await Audio.setAudioModeAsync({ allowsRecording: true, playsInSilentMode: true });

  const recorder = new Audio.AudioRecorder(Audio.RecordingPresets.HIGH_QUALITY);
  await recorder.prepareToRecordAsync();
  recorder.record();

  const startedAt = Date.now();
  const samples: number[] = [];

  /**
   * Stop once, and let everyone who asks wait for the same stop.
   *
   * The cap below and the caller can both reach this, and `recorder.uri` is
   * only trustworthy once the recorder has finished. A plain boolean would let
   * the second caller past while the first was still flushing.
   */
  let stopping: Promise<void> | null = null;
  const stopRecorder = (): Promise<void> => {
    if (!stopping) {
      stopping = (async () => {
        try {
          await recorder.stop();
        } catch {
          // Already stopped, or never started cleanly. Nothing to salvage.
        }
      })();
    }
    return stopping;
  };

  // Sampled rather than continuous: 20 readings a second is far more than the
  // 48 bars ever need, and polling faster costs battery for no visible gain.
  const meter = setInterval(() => {
    const status = recorder.getStatus();
    samples.push(meteringToAmplitude(status.metering ?? -160));
    if (Date.now() - startedAt >= MAX_VOICE_DURATION_MS) {
      clearInterval(meter);
      // Stop the recorder, not just the sampling. Clearing the interval alone
      // left it running: a twenty-minute hold produced twenty minutes of audio
      // labelled with the five-minute cap, under a waveform drawn from the
      // first five. The receiver's bubble reads that duration, so the
      // discrepancy was visible as a note that kept playing past its end.
      void stopRecorder();
    }
  }, 50);

  const release = async () => {
    clearInterval(meter);
    try {
      await Audio.setAudioModeAsync({ allowsRecording: false, playsInSilentMode: false });
    } catch {
      // Restoring the audio mode is best effort; failing here must not mask
      // the recording result.
    }
  };

  /**
   * Delete the recording from disk.
   *
   * Everything Tildra keeps is encrypted; this file is not. It is the raw
   * microphone capture, written by the platform to app storage, and until now
   * nothing removed it — so every voice message a user ever recorded, and
   * every one they cancelled, stayed there in the clear for a forensic image
   * to find. `VoiceBubble` already does this for the file it writes to play a
   * received note; recording is the other half.
   */
  const discard = async (uri: string | null) => {
    if (!uri) return;
    try {
      await FileSystem.deleteAsync(uri, { idempotent: true });
    } catch {
      // Best effort. A file that will not delete must not turn a sent message
      // into a failed one, or a cancel into an error.
    }
  };

  return {
    async stop() {
      await release();
      await stopRecorder();
      const uri = recorder.uri;
      if (!uri) return null;

      const durationMs = Math.min(Date.now() - startedAt, MAX_VOICE_DURATION_MS);
      // Anything under half a second is a mis-tap, not a message.
      if (durationMs < 500) {
        await discard(uri);
        return null;
      }

      try {
        const base64 = await FileSystem.readAsStringAsync(uri, { encoding: 'base64' });
        const binary = globalThis.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

        return {
          bytes,
          mimeType: 'audio/m4a',
          durationMs,
          waveform: buildWaveform(samples),
        };
      } finally {
        // In a finally, so a read that throws does not leave the plaintext
        // behind on the way out.
        await discard(uri);
      }
    },

    async cancel() {
      await release();
      await stopRecorder();
      // The user who slid to cancel is the one who most expects nothing to be
      // kept.
      await discard(recorder.uri);
    },
  };
}
