import React, { useEffect, useState } from 'react';
import { ActivityIndicator, Image, Pressable, StyleSheet, Text, View } from 'react-native';

import { useApp } from '../state/app';
import { toBase64 } from '../crypto/primitives';
import { palette, radius, spacing, typography } from './theme';
import { Message } from '../storage/db';

/**
 * An attachment inside a message bubble.
 *
 * Images are fetched lazily and only once: a conversation full of photos must
 * not download every one of them the moment it opens. A failure is shown as a
 * retry rather than an empty box, because "nothing rendered" is
 * indistinguishable from "the sender sent nothing".
 */
export function AttachmentBubble({ message }: { message: Message }) {
  const t = useApp((s) => s.t);
  const loadAttachment = useApp((s) => s.loadAttachment);

  const [uri, setUri] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(false);

  const isImage = message.attachment?.mimeType.startsWith('image/') ?? false;

  async function load() {
    if (loading) return;
    setLoading(true);
    setFailed(false);
    try {
      const bytes = await loadAttachment(message.id);
      if (!bytes) {
        setFailed(true);
        return;
      }
      setUri(`data:${message.attachment!.mimeType};base64,${toBase64(bytes)}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (isImage && !uri && !failed) void load();
    // Intentionally keyed on the message alone: re-running on every state
    // change would refetch the image in a loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [message.id]);

  const ratio =
    message.attachment?.width && message.attachment.height
      ? message.attachment.width / message.attachment.height
      : 1;

  if (!isImage) {
    return (
      <View style={styles.file}>
        <Text style={styles.fileName} numberOfLines={1}>
          {message.attachment?.fileName ?? t.attachment}
        </Text>
        <Text style={styles.fileMeta}>{formatSize(message.attachment?.size ?? 0)}</Text>
      </View>
    );
  }

  if (failed) {
    return (
      <Pressable accessibilityRole="button" onPress={() => void load()} style={styles.failed}>
        <Text style={styles.failedText}>{t.attachmentFailed}</Text>
        <Text style={styles.retryText}>{t.retry}</Text>
      </Pressable>
    );
  }

  if (!uri) {
    return (
      <View style={[styles.placeholder, { aspectRatio: ratio }]}>
        <ActivityIndicator color={palette.accent} />
      </View>
    );
  }

  return (
    <Image
      source={{ uri }}
      accessibilityLabel={t.attachment}
      style={[styles.image, { aspectRatio: ratio }]}
      resizeMode="cover"
    />
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const styles = StyleSheet.create({
  image: { width: 220, borderRadius: radius.md, backgroundColor: palette.surface },
  placeholder: {
    width: 220,
    borderRadius: radius.md,
    backgroundColor: palette.surface,
    alignItems: 'center',
    justifyContent: 'center',
  },
  failed: {
    width: 220,
    padding: spacing.lg,
    borderRadius: radius.md,
    backgroundColor: palette.dangerDim,
    borderWidth: 1,
    borderColor: palette.danger,
    gap: spacing.xs,
  },
  failedText: { ...typography.small, color: palette.danger },
  retryText: { ...typography.small, color: palette.accent, fontWeight: '600' },
  file: {
    minWidth: 180,
    padding: spacing.md,
    borderRadius: radius.sm,
    backgroundColor: palette.surface,
    gap: 2,
  },
  fileName: { ...typography.bodyStrong, color: palette.text },
  fileMeta: { ...typography.tiny, color: palette.textFaint },
});
