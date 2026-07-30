import React, { useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Banner, Button, Field } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { useApp } from '../state/app';

/**
 * Account creation.
 *
 * The only thing asked for is a device name, and that is for the user's own
 * device list. There is no phone number field to leave out, because there was
 * never a phone number.
 */
export function OnboardingScreen({
  onJoinExisting,
  onRecover,
}: {
  onJoinExisting: () => void;
  onRecover: () => void;
}) {
  const t = useApp((s) => s.t);
  const createAccount = useApp((s) => s.createAccount);
  const error = useApp((s) => s.error);

  const [displayName, setDisplayName] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [busy, setBusy] = useState(false);

  async function onCreate() {
    setBusy(true);
    try {
      await createAccount(deviceName.trim() || 'Phone', displayName.trim());
    } catch {
      // The store has already put a readable message in `error`.
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <View style={styles.mark}>
          <Text style={styles.markText}>~</Text>
        </View>

        <Text style={styles.title}>{t.welcomeTitle}</Text>
        <Text style={styles.body}>{t.welcomeBody}</Text>

        <View style={styles.badge}>
          <Text style={styles.badgeText}>{t.noPhoneNeeded}</Text>
        </View>

        <Field
          label={t.yourNameLabel}
          placeholder={t.yourNamePlaceholder}
          value={displayName}
          onChangeText={setDisplayName}
          autoCapitalize="words"
          editable={!busy}
          maxLength={48}
        />
        <Text style={styles.help}>{t.yourNameHelp}</Text>

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

        <Button
          label={busy ? t.creatingAccount : t.createAccount}
          onPress={onCreate}
          loading={busy}
        />

        {/* Someone installing on a second phone is not creating a second
            account, and until this button existed there was no way for them
            to say so. */}
        <Button
          label={t.joinExisting}
          variant="secondary"
          onPress={onJoinExisting}
          disabled={busy}
        />

        {/* For somebody whose device is gone, so there is no other device to
            approve a link from. */}
        <Button label={t.recoverEntry} variant="secondary" onPress={onRecover} disabled={busy} />

        {/* Stated at the point of account creation, not buried in an about
            page. Someone deciding whether to trust this deserves to read it
            before they start, not after. */}
        <Text style={styles.disclaimer}>{t.notAudited}</Text>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.lg, flexGrow: 1, justifyContent: 'center' },
  mark: {
    width: 64,
    height: 64,
    borderRadius: radius.lg,
    backgroundColor: palette.surfaceRaised,
    borderWidth: 1,
    borderColor: palette.accentDim,
    alignItems: 'center',
    justifyContent: 'center',
  },
  markText: { color: palette.accent, fontSize: 36, lineHeight: 42, fontWeight: '700' },
  title: { ...typography.title, color: palette.text, lineHeight: 34 },
  body: { ...typography.body, color: palette.textMuted, lineHeight: 23 },
  badge: {
    alignSelf: 'flex-start',
    backgroundColor: palette.accentDim,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xs,
    borderRadius: radius.pill,
  },
  badgeText: { ...typography.tiny, color: palette.accent, textTransform: 'uppercase' },
  help: { ...typography.small, color: palette.textFaint, lineHeight: 18, marginTop: -8 },
  disclaimer: {
    ...typography.small,
    color: palette.textFaint,
    lineHeight: 18,
    paddingTop: spacing.sm,
  },
});
