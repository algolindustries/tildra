import React, { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from 'react-native';

import { useApp } from '../state/app';
import { Message } from '../storage/db';
import { Playback, startVoicePlayback } from '../media/playback';
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
  const playbackRef = useRef<Playback | null>(null);

  const durationMs = message.attachment?.durationMs ?? 0;
  const waveform = message.attachment?.waveform ?? new Uint8Array(0);
  const progress = playbackProgress(position, durationMs);

  // Leaving the conversation stops playback and takes the decrypted audio off
  // the disk with it. This used to remove the player and keep the file.
  useEffect(
    () => () => {
      void playbackRef.current?.stop();
      playbackRef.current = null;
    },
    [],
  );

  async function toggle() {
    if (playing) {
      const current = playbackRef.current;
      playbackRef.current = null;
      setPlaying(false);
      setPosition(0);
      await current?.stop();
      return;
    }

    setLoading(true);
    try {
      const bytes = await loadAttachment(message.id);
      if (!bytes) return;

      playbackRef.current = await startVoicePlayback({
        messageId: message.id,
        bytes,
        onPosition: setPosition,
        onEnded: () => {
          playbackRef.current = null;
          setPlaying(false);
          setPosition(0);
        },
      });
      setPlaying(true);
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
