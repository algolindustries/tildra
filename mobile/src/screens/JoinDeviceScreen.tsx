import React, { useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';

import { Banner, Button, Field } from '../ui/components';
import { QrCode } from '../ui/qr';
import { palette, radius, spacing, typography } from '../ui/theme';
import { useApp } from '../state/app';

/**
 * The new device's half of a link.
 *
 * The other half — approving from a device that is already signed in — has
 * existed for a while, which meant the app could approve a code that nothing
 * could produce. This is the screen that produces it.
 *
 * Two things carry the security and both are on screen at full size: the QR,
 * which puts a hash of this device's identity key in front of the other
 * device's camera rather than through the server, and the six digits, which
 * the user compares. A link approved without comparing the digits has the
 * security of no comparison at all, so the confirm button does not appear
 * until there is something to compare.
 */
export function JoinDeviceScreen({ onCancel }: { onCancel: () => void }) {
  const t = useApp((s) => s.t);
  const error = useApp((s) => s.error);
  const pendingLink = useApp((s) => s.pendingLink);
  const startLinking = useApp((s) => s.startLinking);
  const confirmLink = useApp((s) => s.confirmLink);
  const cancelLinking = useApp((s) => s.cancelLinking);

  const [deviceName, setDeviceName] = useState('');
  const [busy, setBusy] = useState(false);

  async function onStart() {
    setBusy(true);
    try {
      await startLinking(deviceName.trim() || 'Linked device');
    } catch {
      // The store has already put a readable message in `error`.
    } finally {
      setBusy(false);
    }
  }

  async function onConfirm() {
    setBusy(true);
    try {
      await confirmLink();
    } catch {
      // Same: `error` carries it.
    } finally {
      setBusy(false);
    }
  }

  function onBack() {
    cancelLinking();
    onCancel();
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>{t.joinTitle}</Text>
        <Text style={styles.body}>{t.joinBody}</Text>

        {!pendingLink ? (
          <>
            <Field
              label={t.deviceNameLabel}
              placeholder={t.deviceNamePlaceholder}
              value={deviceName}
              onChangeText={setDeviceName}
              autoCapitalize="sentences"
              editable={!busy}
              maxLength={64}
            />
            {error ? <Banner tone="warning" title={t.errorGeneric} body={error} /> : null}
            <Button label={t.joinStart} onPress={onStart} loading={busy} />
            <Button label={t.cancel} variant="secondary" onPress={onBack} />
          </>
        ) : !pendingLink.code ? (
          <>
            <Text style={styles.sectionLabel}>{t.joinShowThis}</Text>
            <QrCode value={pendingLink.payload} />
            {/* The same value as text. A camera that will not focus, a cracked
                screen, or a device with no camera at all must not be the end
                of the road — the security property is the value crossing
                between two screens, not which sensor carries it. */}
            <Text style={styles.payload} selectable>
              {pendingLink.payload}
            </Text>
            <Button
              label={t.copy}
              variant="secondary"
              onPress={() => void Clipboard.setStringAsync(pendingLink.payload)}
            />
            <Banner tone="info" title={t.linkWaiting} body={t.linkDeviceBody} />
            <Button label={t.cancel} variant="secondary" onPress={onBack} />
          </>
        ) : (
          <>
            <View style={styles.codeCard}>
              <Text style={styles.codeLabel}>{t.linkPairingCode}</Text>
              <Text style={styles.code}>{pendingLink.code}</Text>
            </View>
            <Banner tone="warning" title={t.linkPairingCode} body={t.joinCompare} />
            {error ? <Banner tone="warning" title={t.errorGeneric} body={error} /> : null}
            <Button label={t.linkConfirm} onPress={onConfirm} loading={busy} />
            <Button label={t.cancel} variant="secondary" onPress={onBack} />
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
  sectionLabel: { ...typography.tiny, color: palette.textFaint, textTransform: 'uppercase' },
  payload: {
    ...typography.mono,
    fontSize: 11,
    color: palette.textFaint,
    lineHeight: 16,
  },
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
