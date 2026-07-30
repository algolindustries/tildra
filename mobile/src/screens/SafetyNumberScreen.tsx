import React, { useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Banner, Button } from '../ui/components';
import { QrCode, QrScanner } from '../ui/qr';
import { palette, radius, spacing, typography } from '../ui/theme';
import { formatAccountId, safetyNumberRows } from '../ui/format';
import { useApp } from '../state/app';
import { describeScanError, readSafetyCode } from '../crypto/scan';

/**
 * Safety number comparison.
 *
 * This screen is the only defence against a server that substitutes keys, so
 * it is built to be *used*, not to be technically present: the number is large,
 * monospaced, and grouped for reading aloud, and the confirm button says what
 * the user is actually asserting ("they match") rather than "OK".
 */
export function SafetyNumberScreen({ accountId, onDone }: { accountId: string; onDone: () => void }) {
  const t = useApp((s) => s.t);
  const safetyNumber = useApp((s) => s.safetyNumber);
  const safetyQr = useApp((s) => s.safetyQr);
  const conversations = useApp((s) => s.conversations);
  const markVerified = useApp((s) => s.markVerified);
  const matchesSafetyCode = useApp((s) => s.matchesSafetyCode);

  const conversation = conversations.find((c) => c.accountId === accountId);
  const rows = safetyNumber ? safetyNumberRows(safetyNumber) : [];

  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<'match' | 'mismatch' | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  async function onConfirm() {
    await markVerified(accountId);
    onDone();
  }

  /**
   * A scan is evidence, not a decision. Even on a match the user still presses
   * the button that says the numbers match — the one screen in the app that
   * requires a human is not going to start verifying things by itself.
   */
  async function onScan(payload: string) {
    setChecking(true);
    setScanError(null);
    try {
      const code = readSafetyCode(payload);
      setScanResult((await matchesSafetyCode(accountId, code)) ? 'match' : 'mismatch');
      setScanning(false);
    } catch (err) {
      setScanError(describeScanError(err));
    } finally {
      setChecking(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Pressable accessibilityRole="button" onPress={onDone} hitSlop={12} style={styles.closeRow}>
          <Text style={styles.close}>‹</Text>
        </Pressable>

        <Text style={styles.title}>{t.verifyTitle}</Text>
        <Text style={styles.contact}>{formatAccountId(accountId)}</Text>

        {conversation?.identityChanged ? (
          <Banner tone="danger" title={t.identityChangedTitle} body={t.identityChangedBody} />
        ) : null}

        <Text style={styles.body}>{t.verifyBody}</Text>

        <View style={styles.numberCard}>
          <Text style={styles.numberLabel}>{t.safetyNumber}</Text>
          {rows.map((row, index) => (
            <Text key={index} style={styles.numberRow} accessibilityLabel={row.join(' ')}>
              {row.join('  ')}
            </Text>
          ))}
        </View>

        {safetyQr ? <QrCode value={safetyQr} size={180} /> : null}

        {scanning ? (
          <>
            <QrScanner
              paused={checking}
              onScan={(payload) => void onScan(payload)}
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
            {scanError ? <Banner tone="warning" title={t.errorGeneric} body={scanError} /> : null}
          </>
        ) : (
          <Button
            label={t.verifyScanTitle}
            variant="secondary"
            onPress={() => {
              setScanResult(null);
              setScanError(null);
              setScanning(true);
            }}
            disabled={!safetyQr}
          />
        )}

        {scanResult === 'match' ? (
          <Banner tone="info" title={t.verified} body={t.verifyScanMatch} />
        ) : scanResult === 'mismatch' ? (
          <Banner tone="danger" title={t.identityChangedTitle} body={t.verifyScanMismatch} />
        ) : null}

        <Button
          label={t.markVerified}
          onPress={onConfirm}
          disabled={!safetyNumber}
        />

        {conversation?.verified ? (
          <Text style={styles.verified}>✓ {t.verified}</Text>
        ) : null}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.lg },
  closeRow: { alignSelf: 'flex-start' },
  close: { color: palette.accent, fontSize: 34, lineHeight: 36 },
  title: { ...typography.title, color: palette.text, lineHeight: 34 },
  contact: { ...typography.small, color: palette.textFaint },
  body: { ...typography.body, color: palette.textMuted, lineHeight: 23 },
  numberCard: {
    backgroundColor: palette.surface,
    borderWidth: 1,
    borderColor: palette.border,
    borderRadius: radius.md,
    padding: spacing.lg,
    gap: spacing.md,
    alignItems: 'center',
  },
  numberLabel: { ...typography.tiny, color: palette.textFaint, textTransform: 'uppercase' },
  numberRow: { ...typography.mono, color: palette.text },
  verified: { ...typography.bodyStrong, color: palette.success, textAlign: 'center' },
});
