import React, { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from 'react-native';

import { useApp } from '../state/app';
import { Message } from '../storage/db';
import { barHeights, formatDuration, playbackProgress } from '../media/waveform';
import { palette, radius, spacing, typography } from './theme';

/**
 * A voice note.
 *
 * The waveform and duration come from the message, so the bubble is complete
 * before anything is fetched — pressing play is what triggers the download.
 * A conversation full of voice notes therefore costs nothing to scroll.
 */
export function VoiceBubble({ message, outgoing }: { message: Message; outgoing: boolean }) {
  const t = useApp((s) => s.t);
  const loadAttachment = useApp((s) => s.loadAttachment);

  const [playing, setPlaying] = useState(false);
  const [loading, setLoading] = useState(false);
  const [position, setPosition] = useState(0);
  const playerRef = useRef<{ remove: () => void } | null>(null);

  const durationMs = message.attachment?.durationMs ?? 0;
  const waveform = message.attachment?.waveform ?? new Uint8Array(0);
  const progress = playbackProgress(position, durationMs);

  useEffect(() => () => playerRef.current?.remove(), []);

  async function toggle() {
    if (playing) {
      playerRef.current?.remove();
      playerRef.current = null;
      setPlaying(false);
      setPosition(0);
      return;
    }

    setLoading(true);
    try {
      const bytes = await loadAttachment(message.id);
      if (!bytes) return;

      const Audio = await import('expo-audio');
      // expo-file-system's modern File API is not typed for reads and writes yet,
      // and its top-level readAsStringAsync/writeAsStringAsync now throw at runtime
      // with a pointer here. The legacy entrypoint is Expo's documented path and is
      // fully typed, so that is what this uses until the new API exposes the same
      // operations.
      const FileSystem = await import('expo-file-system/legacy');

      // expo-audio plays from a URI, so the decrypted bytes go to the app's
      // cache directory rather than anywhere the system indexes or backs up.
      const path = `${FileSystem.cacheDirectory}tildra-voice-${message.id.replace(/[^a-zA-Z0-9]/g, '')}.m4a`;
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      await FileSystem.writeAsStringAsync(path, globalThis.btoa(binary), { encoding: 'base64' });

      const player = Audio.createAudioPlayer({ uri: path });
      playerRef.current = player;
      player.play();
      setPlaying(true);

      const tick = setInterval(() => {
        const seconds = player.currentTime ?? 0;
        setPosition(seconds * 1000);
        if (!player.playing && seconds > 0) {
          clearInterval(tick);
          setPlaying(false);
          setPosition(0);
          // The plaintext audio does not linger on disk after playback.
          void FileSystem.deleteAsync(path, { idempotent: true }).catch(() => undefined);
        }
      }, 100);
    } finally {
      setLoading(false);
    }
  }

  const heights = barHeights(waveform);

  return (
    <View style={styles.row}>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={playing ? t.pause : t.play}
        onPress={() => void toggle()}
        style={styles.button}
      >
        {loading ? (
          <ActivityIndicator color={palette.onAccent} size="small" />
        ) : (
          <Text style={styles.buttonText}>{playing ? '■' : '▶'}</Text>
        )}
      </Pressable>

      <View style={styles.waveform}>
        {heights.map((height, index) => (
          <View
            key={index}
            style={[
              styles.bar,
              {
                height: `${height * 100}%`,
                backgroundColor:
                  index / Math.max(heights.length, 1) <= progress
                    ? palette.accent
                    : outgoing
                      ? palette.textMuted
                      : palette.textFaint,
              },
            ]}
          />
        ))}
      </View>

      <Text style={styles.duration}>
        {formatDuration(playing ? Math.max(0, durationMs - position) : durationMs)}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  row: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm, minWidth: 200 },
  button: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: palette.accent,
    alignItems: 'center',
    justifyContent: 'center',
  },
  buttonText: { color: palette.onAccent, fontSize: 14, lineHeight: 16 },
  waveform: {
    flex: 1,
    height: 30,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 2,
  },
  bar: { flex: 1, borderRadius: radius.sm / 4, minHeight: 3 },
  duration: { ...typography.tiny, color: palette.textMuted, minWidth: 34, textAlign: 'right' },
});
