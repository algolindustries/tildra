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

  // Sampled rather than continuous: 20 readings a second is far more than the
  // 48 bars ever need, and polling faster costs battery for no visible gain.
  const meter = setInterval(() => {
    const status = recorder.getStatus();
    samples.push(meteringToAmplitude(status.metering ?? -160));
    if (Date.now() - startedAt >= MAX_VOICE_DURATION_MS) {
      clearInterval(meter);
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

  return {
    async stop() {
      await release();
      await recorder.stop();
      const uri = recorder.uri;
      if (!uri) return null;

      const durationMs = Math.min(Date.now() - startedAt, MAX_VOICE_DURATION_MS);
      // Anything under half a second is a mis-tap, not a message.
      if (durationMs < 500) return null;

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
    },

    async cancel() {
      await release();
      try {
        await recorder.stop();
      } catch {
        // Already stopped, or never started cleanly. Nothing to salvage.
      }
    },
  };
}
