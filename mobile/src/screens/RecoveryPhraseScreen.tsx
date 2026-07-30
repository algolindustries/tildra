import React from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Banner, Button } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { useApp } from '../state/app';
import { phraseRows } from '../crypto/recovery';

/**
 * The phrase, once, at the only moment it exists in memory.
 *
 * Deliberately not copyable and not screenshot-friendly advice: this is the
 * account, and the honest instruction is paper. The warning says "anyone
 * holding these words is you" rather than calling it a backup code, because
 * the second framing is how people end up storing it next to the device.
 *
 * There is no "remind me later". The phrase is not persisted — a phrase on
 * disk is a phrase in a backup of the disk — so this screen is the only time
 * it can be shown, and saying so is more honest than a button that would lie.
 */
export function RecoveryPhraseScreen() {
  const t = useApp((s) => s.t);
  const phrase = useApp((s) => s.pendingPhrase);
  const confirm = useApp((s) => s.confirmPhraseWritten);

  if (!phrase) return null;

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>{t.recoveryTitle}</Text>
        <Text style={styles.body}>{t.recoveryBody}</Text>

        <Banner tone="warning" title={t.recoveryTitle} body={t.recoveryWarning} />

        <View style={styles.card}>
          {phraseRows(phrase).map((row, index) => (
            <View key={index} style={styles.row}>
              {row.map((word) => (
                <View key={word.index} style={styles.word}>
                  <Text style={styles.number}>{word.index}</Text>
                  <Text style={styles.text}>{word.word}</Text>
                </View>
              ))}
            </View>
          ))}
        </View>

        <Button label={t.recoveryWritten} onPress={confirm} />
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.lg },
  title: { ...typography.title, color: palette.text },
  body: { ...typography.body, color: palette.textMuted, lineHeight: 23 },
  card: {
    backgroundColor: palette.surface,
    borderWidth: 1,
    borderColor: palette.accentDim,
    borderRadius: radius.md,
    padding: spacing.lg,
    gap: spacing.sm,
  },
  row: { flexDirection: 'row', gap: spacing.sm },
  word: { flex: 1, flexDirection: 'row', alignItems: 'baseline', gap: spacing.xs },
  number: { ...typography.tiny, color: palette.textFaint, minWidth: 18 },
  text: { ...typography.mono, color: palette.text },
});
