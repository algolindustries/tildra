import React, { useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';

import { Banner, Button, Field } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { useApp } from '../state/app';

/**
 * Approving a new device from one that is already signed in.
 *
 * The pairing code is the whole point of this screen, so it is the largest
 * thing on it. A user who links a device without comparing the digits has the
 * security of no comparison at all, and burying the code would make that the
 * default outcome.
 *
 * Codes are pasted rather than scanned for now: a QR scanner needs a camera
 * permission and a rendering library, and the security property is identical —
 * what matters is that the code travels between two screens the user can see,
 * not which sensor carries it.
 */
export function LinkDeviceScreen({ onClose }: { onClose: () => void }) {
  const t = useApp((s) => s.t);
  const approveLink = useApp((s) => s.approveLink);

  const [scanned, setScanned] = useState('');
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onApprove() {
    setBusy(true);
    setError(null);
    try {
      setCode(await approveLink(scanned.trim()));
    } catch (err) {
      setError(err instanceof Error ? err.message : t.errorGeneric);
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>{t.linkDevice}</Text>
        <Text style={styles.body}>{t.linkDeviceBody}</Text>

        {code ? (
          <>
            <View style={styles.codeCard}>
              <Text style={styles.codeLabel}>{t.linkPairingCode}</Text>
              <Text style={styles.code}>{code}</Text>
            </View>
            <Banner
              tone="warning"
              title={t.linkPairingCode}
              body={t.linkDeviceBody}
              actionLabel={t.copy}
              onAction={() => void Clipboard.setStringAsync(code)}
            />
            <Button label={t.linkConfirm} onPress={onClose} />
          </>
        ) : (
          <>
            <Field
              label={t.linkScanCode}
              placeholder="tildra://link?..."
              value={scanned}
              onChangeText={setScanned}
              autoCapitalize="none"
              autoCorrect={false}
              editable={!busy}
              multiline
            />
            {error ? <Banner tone="warning" title={t.errorGeneric} body={error} /> : null}
            <Button
              label={t.linkDevice}
              onPress={onApprove}
              loading={busy}
              disabled={!scanned.trim()}
            />
            <Button label={t.cancel} variant="secondary" onPress={onClose} />
          </>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.lg },
  title: { ...typography.title, color: palette.text },
  body: { ...typography.body, color: palette.textMuted, lineHeight: 23 },
  codeCard: {
    backgroundColor: palette.surface,
    borderWidth: 1,
    borderColor: palette.accent,
    borderRadius: radius.md,
    padding: spacing.xl,
    alignItems: 'center',
    gap: spacing.sm,
  },
  codeLabel: { ...typography.tiny, color: palette.textFaint, textTransform: 'uppercase' },
  code: { ...typography.mono, fontSize: 40, color: palette.accent, letterSpacing: 6 },
});
