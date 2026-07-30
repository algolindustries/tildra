import React, { useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';

import { Banner, Button, Field } from '../ui/components';
import { QrScanner } from '../ui/qr';
import { palette, radius, spacing, typography } from '../ui/theme';
import { useApp } from '../state/app';
import { describeScanError, readDeviceLink } from '../crypto/scan';

/**
 * Approving a new device from one that is already signed in.
 *
 * The pairing code is the whole point of this screen, so it is the largest
 * thing on it. A user who links a device without comparing the digits has the
 * security of no comparison at all, and burying the code would make that the
 * default outcome.
 *
 * Pasting stays alongside scanning rather than being replaced by it. The
 * security property is the code crossing between two screens the user can see,
 * not which sensor carries it — so a denied camera permission, a device
 * without a camera, or a screen too cracked to focus on is an inconvenience
 * and not a dead end.
 */
export function LinkDeviceScreen({ onClose }: { onClose: () => void }) {
  const t = useApp((s) => s.t);
  const approveLink = useApp((s) => s.approveLink);

  const [scanned, setScanned] = useState('');
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);

  async function approve(payload: string) {
    setBusy(true);
    setError(null);
    try {
      // Validated before it reaches the link flow: this refuses a
      // safety-number code by name rather than failing somewhere deeper with
      // a message about base64.
      readDeviceLink(payload);
      setCode(await approveLink(payload));
      setScanning(false);
    } catch (err) {
      setError(describeScanError(err));
    } finally {
      setBusy(false);
    }
  }

  function onApprove() {
    void approve(scanned.trim());
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
        ) : scanning ? (
          <>
            <QrScanner
              paused={busy}
              onScan={(payload) => void approve(payload)}
              onCancel={() => setScanning(false)}
              strings={{
                cancel: t.cancel,
                permissionTitle: t.cameraPermissionTitle,
                permissionBody: t.cameraPermissionBody,
                permissionGrant: t.cameraPermissionGrant,
                permissionDenied: t.cameraPermissionDenied,
                hint: t.scanHint,
              }}
            />
            {error ? <Banner tone="warning" title={t.errorGeneric} body={error} /> : null}
          </>
        ) : (
          <>
            <Button label={t.scan} onPress={() => setScanning(true)} disabled={busy} />
            <Text style={styles.divider}>{t.scanOrPaste}</Text>
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
              variant="secondary"
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
  divider: { ...typography.small, color: palette.textFaint, textAlign: 'center' },
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
