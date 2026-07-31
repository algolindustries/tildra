/**
 * Playing a received voice note.
 *
 * `expo-audio` plays from a uri, not from bytes, so the decrypted audio has to
 * be written to disk before it can be heard. That file is the one thing on the
 * device that is not encrypted — the whole point of the vault is that a
 * forensic image finds nothing legible — so the only acceptable arrangement is
 * that it exists for exactly as long as it is being played and is gone on
 * every path out.
 *
 * This lived inside `VoiceBubble.tsx` and deleted the file on exactly one of
 * those paths: playback reaching its natural end. Pressing stop, leaving the
 * conversation, and a player that would not open all kept it. It is here
 * instead because a screen cannot be tested in this project — there is no
 * React Native test renderer — and this is not screen logic, it is a lifecycle
 * with one invariant.
 */

/** The parts of `expo-audio`'s player this uses. */
interface Player {
  play(): void;
  remove(): void;
  readonly playing: boolean;
  readonly currentTime: number;
}

export interface Playback {
  /**
   * Stop, and leave nothing behind.
   *
   * Idempotent, because three different things call it: the poll noticing the
   * end, the user pressing stop, and the component unmounting. Two of those
   * can happen in the same tick.
   */
  stop(): Promise<void>;
}

/** How often the position is read. Fine for a progress bar, cheap enough. */
export const POLL_MS = 100;

export async function startVoicePlayback(options: {
  messageId: string;
  bytes: Uint8Array;
  onPosition: (positionMs: number) => void;
  /** Playback finished on its own. Not called when the caller stops it. */
  onEnded: () => void;
}): Promise<Playback> {
  const Audio = await import('expo-audio');
  // expo-file-system's modern File API is not typed for reads and writes yet,
  // and its top-level readAsStringAsync/writeAsStringAsync now throw at runtime
  // with a pointer here. The legacy entrypoint is Expo's documented path and is
  // fully typed, so that is what this uses.
  const FileSystem = await import('expo-file-system/legacy');

  // The cache directory rather than anywhere the system indexes or backs up.
  const path = `${FileSystem.cacheDirectory}tildra-voice-${options.messageId.replace(/[^a-zA-Z0-9]/g, '')}.m4a`;

  let binary = '';
  for (let i = 0; i < options.bytes.length; i++) binary += String.fromCharCode(options.bytes[i]);
  await FileSystem.writeAsStringAsync(path, globalThis.btoa(binary), { encoding: 'base64' });

  const discard = async (): Promise<void> => {
    try {
      await FileSystem.deleteAsync(path, { idempotent: true });
    } catch {
      // Best effort. A file that will not delete must not turn stopping a
      // voice note into an error the user has to dismiss.
    }
  };

  let player: Player;
  try {
    player = Audio.createAudioPlayer({ uri: path }) as unknown as Player;
  } catch (err) {
    // The audio is on disk by this point. A player that will not open is the
    // path most likely to forget that.
    await discard();
    throw err;
  }

  let stopped = false;
  let timer: ReturnType<typeof setInterval> | null = null;

  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    try {
      player.remove();
    } catch {
      // Already gone, or never opened cleanly.
    }
    await discard();
  };

  player.play();

  timer = setInterval(() => {
    const seconds = player.currentTime ?? 0;
    options.onPosition(seconds * 1000);
    // `playing` is false before the first frame as well as after the last, so
    // a position that has moved is what distinguishes finished from starting.
    if (!player.playing && seconds > 0) {
      void stop().then(options.onEnded, options.onEnded);
    }
  }, POLL_MS);

  return { stop };
}
