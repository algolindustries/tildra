import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { MAX_VOICE_DURATION_MS, WAVEFORM_BUCKETS } from '../waveform';
import { VoiceError, startRecording } from '../voice';

/**
 * Recording a voice message, which had no test of its own.
 *
 * `waveform.ts` — the arithmetic — was already covered. What was not is the
 * part that touches the device: the microphone, the clock, and the file the
 * platform writes. Two of those three were wrong.
 *
 * The recorder double throws when stopped twice, the way a real one does, so
 * "stopped once" is something the suite can observe rather than assume. The
 * file double is a map, so "left on disk" is a fact rather than a mock
 * assertion.
 */

class FakeRecorder {
  static instances: FakeRecorder[] = [];

  uri: string | null = 'file:///cache/recording.m4a';
  prepared = false;
  recording = false;
  stopCalls = 0;
  stoppedAt: number | null = null;
  metering: number | null = -20;

  constructor(public readonly preset: unknown) {
    FakeRecorder.instances.push(this);
  }

  async prepareToRecordAsync(): Promise<void> {
    this.prepared = true;
  }

  record(): void {
    this.recording = true;
  }

  getStatus(): { metering: number | null } {
    return { metering: this.metering };
  }

  async stop(): Promise<void> {
    this.stopCalls += 1;
    // A recorder that is not recording throws, so a double stop cannot pass
    // unnoticed.
    if (!this.recording) throw new Error('recorder is not recording');
    this.recording = false;
    this.stoppedAt = Date.now();
  }
}

const audio = {
  granted: true,
  modes: [] as Array<{ allowsRecording: boolean }>,
  failSetMode: null as Error | null,
};

vi.mock('expo-audio', () => ({
  async requestRecordingPermissionsAsync() {
    return { granted: audio.granted };
  },
  async setAudioModeAsync(mode: { allowsRecording: boolean }) {
    if (audio.failSetMode) throw audio.failSetMode;
    audio.modes.push(mode);
  },
  RecordingPresets: { HIGH_QUALITY: 'HIGH_QUALITY' },
  get AudioRecorder() {
    return FakeRecorder;
  },
}));

const RECORDING_URI = 'file:///cache/recording.m4a';

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

/** What the platform leaves in app storage: the raw, unencrypted capture. */
function aRecordingOnDisk() {
  fs.files.set(RECORDING_URI, globalThis.btoa('the raw microphone capture'));
}

const recorder = () => FakeRecorder.instances.at(-1)!;

beforeEach(() => {
  vi.useFakeTimers();
  FakeRecorder.instances = [];
  audio.granted = true;
  audio.modes = [];
  audio.failSetMode = null;
  fs.files.clear();
  fs.failRead = null;
  fs.failDelete = null;
  aRecordingOnDisk();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('starting', () => {
  it('refuses without the microphone, and touches nothing', async () => {
    audio.granted = false;

    await expect(startRecording()).rejects.toBeInstanceOf(VoiceError);
    expect(FakeRecorder.instances).toEqual([]);
    expect(audio.modes).toEqual([]);
  });

  it('prepares before it records', async () => {
    // record() on an unprepared recorder produces silence on Android.
    await startRecording();

    expect(recorder().prepared).toBe(true);
    expect(recorder().recording).toBe(true);
    expect(audio.modes[0]).toMatchObject({ allowsRecording: true });
  });
});

describe('a finished note', () => {
  it('carries the audio, the duration and a waveform', async () => {
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(2_000);

    const note = await recording.stop();

    expect(note).not.toBeNull();
    expect(new TextDecoder().decode(note!.bytes)).toBe('the raw microphone capture');
    expect(note!.durationMs).toBe(2_000);
    expect(note!.mimeType).toBe('audio/m4a');
    expect(note!.waveform).toHaveLength(WAVEFORM_BUCKETS);
  });

  it('is nothing at all for a mis-tap', async () => {
    // Under half a second is a fumbled button, not a message.
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(200);

    expect(await recording.stop()).toBeNull();
  });

  it('releases the microphone whether it is sent or cancelled', async () => {
    const sent = await startRecording();
    await vi.advanceTimersByTimeAsync(1_000);
    await sent.stop();
    expect(audio.modes.at(-1)).toMatchObject({ allowsRecording: false });

    audio.modes = [];
    aRecordingOnDisk();
    const abandoned = await startRecording();
    await vi.advanceTimersByTimeAsync(1_000);
    await abandoned.cancel();
    expect(audio.modes.at(-1)).toMatchObject({ allowsRecording: false });
  });

  it('survives an audio mode that will not restore', async () => {
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(1_000);
    audio.failSetMode = new Error('another app holds the session');

    const note = await recording.stop();

    expect(note).not.toBeNull();
  });
});

describe('the recording left on disk', () => {
  /**
   * The file the platform writes is the raw capture — not encrypted, not in
   * the vault, just an .m4a in app storage. Nothing deleted it, so every note
   * a user sent and every one they cancelled stayed there in the clear. The
   * database goes to some length to make sure a forensic image finds nothing
   * legible; this walked around all of it.
   */
  it('is gone once the note has been read', async () => {
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(2_000);

    await recording.stop();

    expect(fs.files.has(RECORDING_URI)).toBe(false);
  });

  it('is gone when the user cancels', async () => {
    // The person who slid to cancel is the one who most expects nothing kept.
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(2_000);

    await recording.cancel();

    expect(fs.files.has(RECORDING_URI)).toBe(false);
  });

  it('is gone after a mis-tap', async () => {
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(200);

    expect(await recording.stop()).toBeNull();
    expect(fs.files.has(RECORDING_URI)).toBe(false);
  });

  it('is gone even when reading it fails', async () => {
    // The read throwing is exactly when the file is most likely to be
    // forgotten, and the plaintext is on disk either way.
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(2_000);
    fs.failRead = new Error('the file is unreadable');

    await expect(recording.stop()).rejects.toThrow();
    expect(fs.files.has(RECORDING_URI)).toBe(false);
  });

  it('does not turn an undeletable file into a failed message', async () => {
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(2_000);
    fs.failDelete = new Error('the file is locked');

    const note = await recording.stop();

    expect(note).not.toBeNull();
  });
});

describe('the five-minute cap', () => {
  it('stops the recorder, not just the sampling', async () => {
    // Clearing the metering interval was all that happened at the cap. The
    // recorder kept going, so the audio outran the duration that travels with
    // it — and the receiver's bubble is drawn from that duration.
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(MAX_VOICE_DURATION_MS + 60_000);

    expect(recorder().recording).toBe(false);
    expect(recorder().stoppedAt).not.toBeNull();

    await recording.stop();
  });

  it('reports a duration the audio actually has', async () => {
    const startedAt = Date.now();
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(MAX_VOICE_DURATION_MS + 10 * 60_000);

    const note = await recording.stop();

    expect(note!.durationMs).toBe(MAX_VOICE_DURATION_MS);
    // The recorder stopped at the cap rather than ten minutes past it, within
    // one sampling tick. Without this the note claimed five minutes and held
    // fifteen.
    const recorded = recorder().stoppedAt! - startedAt;
    expect(recorded).toBeLessThanOrEqual(MAX_VOICE_DURATION_MS + 50);
  });

  it('does not stop the recorder a second time when the user lets go', async () => {
    // Two stops is an exception on a real recorder, and the second one would
    // land in the middle of producing the note.
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(MAX_VOICE_DURATION_MS + 1_000);

    const note = await recording.stop();

    expect(recorder().stopCalls).toBe(1);
    expect(note).not.toBeNull();
  });

  it('still clears the file when the cap has already fired', async () => {
    const recording = await startRecording();
    await vi.advanceTimersByTimeAsync(MAX_VOICE_DURATION_MS + 1_000);

    await recording.cancel();

    expect(fs.files.has(RECORDING_URI)).toBe(false);
  });
});
