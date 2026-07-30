import React, { useState } from 'react';
import { ScrollView, StyleSheet, Text } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Banner, Button, Field } from '../ui/components';
import { palette, spacing, typography } from '../ui/theme';
import { useApp } from '../state/app';
import { isValidRecoveryPhrase } from '../crypto/recovery';

/**
 * Signing in with nothing but the words.
 *
 * The phrase is checked as it is typed, against BIP-39's checksum, so a wrong
 * word shows up before a minute of Argon2id and a network round trip. Stretching
 * a phrase that cannot be right, and then reporting "no account found", would
 * point the user at the wrong problem.
 */
export function RecoverAccountScreen({ onCancel }: { onCancel: () => void }) {
  const t = useApp((s) => s.t);
  const error = useApp((s) => s.error);
  const recoverAccount = useApp((s) => s.recoverAccount);

  const [phrase, setPhrase] = useState('');
  const [busy, setBusy] = useState(false);

  const complete = isValidRecoveryPhrase(phrase);

  async function onRecover() {
    setBusy(true);
    try {
      await recoverAccount(phrase);
    } catch {
      // The store has already put a readable message in `error`.
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>{t.recoverTitle}</Text>
        <Text style={styles.body}>{t.recoverBody}</Text>

        <Field
          label={t.recoveryTitle}
          placeholder={t.recoverPlaceholder}
          value={phrase}
          onChangeText={setPhrase}
          autoCapitalize="none"
          autoCorrect={false}
          editable={!busy}
          multiline
        />

        {error ? <Banner tone="warning" title={t.errorGeneric} body={error} /> : null}

        <Button label={t.recoverAction} onPress={onRecover} loading={busy} disabled={!complete} />
        <Button label={t.cancel} variant="secondary" onPress={onCancel} disabled={busy} />
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.lg },
  title: { ...typography.title, color: palette.text },
  body: { ...typography.body, color: palette.textMuted, lineHeight: 23 },
});
