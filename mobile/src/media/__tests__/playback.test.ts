import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { POLL_MS, startVoicePlayback } from '../playback';

/**
 * Playing a received voice note.
 *
 * `expo-audio` plays from a uri, so the decrypted audio has to be written to
 * disk first. That file is the only thing on the device that is not encrypted,
 * and the invariant is that it exists for exactly as long as it is being
 * played.
 *
 * This lived in `VoiceBubble.tsx`, where it held on exactly one path — playback
 * reaching its own end — and no test could reach any of them, because the
 * project has no React Native test renderer. The point of moving it was to be
 * able to write the four cases below, three of which were broken.
 *
 * The player double models the two things the real one does that matter:
 * `playing` is false before the first frame as well as after the last, and
 * `remove` is not safe to call twice.
 */

const CACHE = 'file:///cache/';

const fs = {
  files: new Map<string, string>(),
  failDelete: null as Error | null,
};

vi.mock('expo-file-system/legacy', () => ({
  get cacheDirectory() {
    return CACHE;
  },
  async writeAsStringAsync(path: string, contents: string) {
    fs.files.set(path, contents);
  },
  async deleteAsync(path: string) {
    if (fs.failDelete) throw fs.failDelete;
    fs.files.delete(path);
  },
}));

class FakePlayer {
  static instances: FakePlayer[] = [];

  playing = false;
  currentTime = 0;
  removeCalls = 0;
  removed = false;

  constructor(public readonly source: { uri: string }) {
    FakePlayer.instances.push(this);
  }

  play(): void {
    this.playing = true;
  }

  remove(): void {
    this.removeCalls += 1;
    // The real one throws if it is already gone, so a double remove cannot
    // pass unnoticed here either.
    if (this.removed) throw new Error('player has already been removed');
    this.removed = true;
    this.playing = false;
  }

  /** Advance as the platform would: time moves, then the track ends. */
  advanceTo(seconds: number): void {
    this.currentTime = seconds;
  }

  finish(): void {
    this.playing = false;
  }
}

const audio = { failCreate: null as Error | null };

vi.mock('expo-audio', () => ({
  createAudioPlayer(source: { uri: string }) {
    if (audio.failCreate) throw audio.failCreate;
    return new FakePlayer(source);
  },
}));

const player = () => FakePlayer.instances.at(-1)!;

/** What the store hands over once the attachment has been decrypted. */
const AUDIO = new Uint8Array([1, 2, 3, 4]);

function handlers() {
  const positions: number[] = [];
  let ended = 0;
  return {
    positions,
    endedCount: () => ended,
    onPosition: (ms: number) => positions.push(ms),
    onEnded: () => {
      ended += 1;
    },
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  FakePlayer.instances = [];
  fs.files.clear();
  fs.failDelete = null;
  audio.failCreate = null;
});

afterEach(() => {
  vi.useRealTimers();
});

describe('starting', () => {
  it('writes the decrypted audio where the player can reach it, and plays', async () => {
    const h = handlers();

    await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    expect(fs.files.size).toBe(1);
    expect(player().playing).toBe(true);
    expect(player().source.uri).toBe([...fs.files.keys()][0]);
  });

  it('keeps the file out of anything the system indexes, and names it safely', async () => {
    const h = handlers();

    await startVoicePlayback({ messageId: 'msg/../../etc/passwd', bytes: AUDIO, ...h });

    const path = [...fs.files.keys()][0];
    expect(path.startsWith(CACHE)).toBe(true);
    expect(path).not.toContain('/../');
  });

  it('reports the position as it plays', async () => {
    const h = handlers();
    await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    player().advanceTo(1.5);
    await vi.advanceTimersByTimeAsync(POLL_MS);

    expect(h.positions.at(-1)).toBe(1500);
  });
});

describe('the decrypted audio on disk', () => {
  it('is gone when the note finishes on its own', async () => {
    const h = handlers();
    await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    player().advanceTo(2);
    player().finish();
    await vi.advanceTimersByTimeAsync(POLL_MS);

    expect(fs.files.size).toBe(0);
    expect(h.endedCount()).toBe(1);
  });

  it('is gone when the user presses stop', async () => {
    // The path that used to keep it. Pressing stop removed the player and
    // returned, leaving the plaintext audio in the cache directory and the
    // position poll running for the life of the app.
    const h = handlers();
    const playback = await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    player().advanceTo(1);
    await playback.stop();

    expect(fs.files.size).toBe(0);
    expect(h.endedCount()).toBe(0);
  });

  it('is gone when the conversation is left mid-playback', async () => {
    // Unmount. The old cleanup called `player.remove()` and nothing else, so
    // scrolling away from a note left it decrypted on disk indefinitely.
    const h = handlers();
    const playback = await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    player().advanceTo(0.5);
    await playback.stop();

    expect(fs.files.size).toBe(0);
    expect(player().removed).toBe(true);
  });

  it('is gone when the player will not open at all', async () => {
    // The file is written before the player exists, so this is the path most
    // likely to forget it.
    audio.failCreate = new Error('no audio session available');
    const h = handlers();

    await expect(
      startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h }),
    ).rejects.toThrow(/no audio session/);

    expect(fs.files.size).toBe(0);
  });

  it('does not make a stuck file into an error the user has to dismiss', async () => {
    fs.failDelete = new Error('the file is locked');
    const h = handlers();
    const playback = await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    await expect(playback.stop()).resolves.toBeUndefined();
  });
});

describe('stopping', () => {
  it('stops the position poll', async () => {
    // Not cosmetic: the poll held the player and ran for the life of the app,
    // and every tick wrote state into a component that might be unmounted.
    const h = handlers();
    const playback = await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    player().advanceTo(1);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    const seen = h.positions.length;

    await playback.stop();
    await vi.advanceTimersByTimeAsync(POLL_MS * 10);

    expect(h.positions.length).toBe(seen);
  });

  it('can be called twice, because three things call it', async () => {
    // The poll noticing the end, the user pressing stop, and the unmount can
    // land in the same tick. The real player throws on a second remove.
    const h = handlers();
    const playback = await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    await playback.stop();
    await expect(playback.stop()).resolves.toBeUndefined();

    expect(player().removeCalls).toBe(1);
  });

  it('is already done by the time a natural end reports itself', async () => {
    // onEnded fires after the cleanup, not before: a component that reacts by
    // unmounting must not race a delete that has not happened yet.
    const h = handlers();
    const playback = await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    player().advanceTo(2);
    player().finish();
    await vi.advanceTimersByTimeAsync(POLL_MS);

    expect(h.endedCount()).toBe(1);
    expect(fs.files.size).toBe(0);
    await expect(playback.stop()).resolves.toBeUndefined();
    expect(player().removeCalls).toBe(1);
  });

  it('does not mistake the moment before the first frame for the end', async () => {
    // `playing` is false until the platform actually starts. Treating that as
    // the end would delete the audio out from under a note that never played.
    const h = handlers();
    await startVoicePlayback({ messageId: 'msg-1', bytes: AUDIO, ...h });

    player().playing = false;
    player().advanceTo(0);
    await vi.advanceTimersByTimeAsync(POLL_MS * 3);

    expect(fs.files.size).toBe(1);
    expect(h.endedCount()).toBe(0);
  });
});
