import React, { useEffect, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Switch, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';

import { Avatar, Banner, Button, Field } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { formatAccountId } from '../ui/format';
import { useApp } from '../state/app';
import { pickAvatar } from '../media/avatar';
import { MAX_ABOUT_LENGTH, MAX_DISPLAY_NAME_LENGTH } from '../crypto/content';

/**
 * Your own profile, plus the account facts you might need to hand someone.
 *
 * The name and picture here are the answer to "who am I talking to" for
 * everyone you message — and they never reach the server, which is stated on
 * the screen rather than left for the reader to discover in the docs.
 */
export function ProfileScreen({
  onClose,
  onLinkDevice,
}: {
  onClose: () => void;
  onLinkDevice: () => void;
}) {
  const t = useApp((s) => s.t);
  const accountId = useApp((s) => s.accountId);
  const handle = useApp((s) => s.handle);
  const storedName = useApp((s) => s.displayName);
  const storedAvatar = useApp((s) => s.avatar);
  const storedAbout = useApp((s) => s.about);
  const setProfile = useApp((s) => s.setProfile);
  const claimHandle = useApp((s) => s.claimHandle);
  const signOut = useApp((s) => s.signOut);
  const privacy = useApp((s) => s.privacy);
  const setPrivacy = useApp((s) => s.setPrivacy);

  const [displayName, setDisplayName] = useState(storedName ?? '');
  const [about, setAbout] = useState(storedAbout ?? '');
  const [avatar, setAvatar] = useState<Uint8Array | undefined>(storedAvatar ?? undefined);
  const [handleDraft, setHandleDraft] = useState(handle ?? '');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setDisplayName(storedName ?? '');
    setAbout(storedAbout ?? '');
    setAvatar(storedAvatar ?? undefined);
  }, [storedName, storedAbout, storedAvatar]);

  async function onPickPhoto() {
    setError(null);
    try {
      const picked = await pickAvatar();
      // Null means the user backed out, which is not a failure.
      if (picked) setAvatar(picked);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.errorGeneric);
    }
  }

  async function onSave() {
    if (!displayName.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await setProfile({
        displayName: displayName.trim(),
        about: about.trim() || undefined,
        avatar,
      });
      setStatus(t.profileSaved);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.errorGeneric);
    } finally {
      setBusy(false);
    }
  }

  async function onClaimHandle() {
    setBusy(true);
    setError(null);
    try {
      await claimHandle(handleDraft.trim().toLowerCase());
      setStatus(t.profileSaved);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.errorGeneric);
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Pressable accessibilityRole="button" onPress={onClose} hitSlop={12} style={styles.closeRow}>
          <Text style={styles.close}>‹</Text>
        </Pressable>

        <View style={styles.avatarRow}>
          <Avatar seed={accountId ?? '?'} label={displayName || accountId || '?'} image={avatar} size={88} />
          <View style={styles.avatarActions}>
            <Button label={t.changePhoto} variant="secondary" onPress={onPickPhoto} />
            {avatar ? (
              <Pressable accessibilityRole="button" onPress={() => setAvatar(undefined)}>
                <Text style={styles.removePhoto}>{t.removePhoto}</Text>
              </Pressable>
            ) : null}
          </View>
        </View>

        <Field
          label={t.yourNameLabel}
          placeholder={t.yourNamePlaceholder}
          value={displayName}
          onChangeText={setDisplayName}
          maxLength={MAX_DISPLAY_NAME_LENGTH}
          editable={!busy}
        />
        <Field
          label={t.aboutLabel}
          placeholder={t.aboutPlaceholder}
          value={about}
          onChangeText={setAbout}
          maxLength={MAX_ABOUT_LENGTH}
          editable={!busy}
        />
        <Text style={styles.help}>{t.yourNameHelp}</Text>

        <Button label={t.save} onPress={onSave} loading={busy} disabled={!displayName.trim()} />

        <View style={styles.divider} />

        <Text style={styles.sectionLabel}>{t.yourAccountId}</Text>
        <Pressable
          accessibilityRole="button"
          onPress={async () => {
            if (!accountId) return;
            await Clipboard.setStringAsync(accountId);
            setStatus(t.copied);
          }}
          style={styles.idCard}
        >
          <Text style={styles.idText}>{accountId ? formatAccountId(accountId) : '—'}</Text>
          <Text style={styles.idHint}>{t.copy}</Text>
        </Pressable>

        <Field
          label={t.yourHandle}
          placeholder="ayse"
          value={handleDraft}
          onChangeText={setHandleDraft}
          autoCapitalize="none"
          autoCorrect={false}
          editable={!busy}
          maxLength={24}
        />
        <Button
          label={t.setHandle}
          variant="secondary"
          onPress={onClaimHandle}
          disabled={!handleDraft.trim() || busy}
        />

        {status ? <Banner title={status} /> : null}
        {error ? <Banner tone="warning" title={t.errorGeneric} body={error} /> : null}

        <View style={styles.divider} />

        <Text style={styles.sectionHeading}>{t.privacyHeading}</Text>
        <PrivacyToggle
          label={t.readReceiptsLabel}
          help={t.readReceiptsHelp}
          value={privacy.readReceipts}
          onChange={(readReceipts) => void setPrivacy({ ...privacy, readReceipts })}
        />
        <PrivacyToggle
          label={t.typingIndicatorsLabel}
          help={t.typingIndicatorsHelp}
          value={privacy.typingIndicators}
          onChange={(typingIndicators) => void setPrivacy({ ...privacy, typingIndicators })}
        />

        <View style={styles.divider} />

        <Button label={t.linkDevice} variant="secondary" onPress={onLinkDevice} />

        <View style={styles.divider} />

        <Text style={styles.disclaimer}>{t.notAudited}</Text>
        <Button label={t.signOut} variant="danger" onPress={() => void signOut()} />
      </ScrollView>
    </SafeAreaView>
  );
}

/**
 * A setting whose explanation is as prominent as its switch.
 *
 * Both of these turn off something the user may not know they are sending,
 * and both are reciprocal, which is the part people get wrong. The help text
 * is not a footnote — a toggle labelled "Read receipts" with no further words
 * leaves the reader guessing whether it stops them sending, stops them
 * seeing, or both.
 */
function PrivacyToggle({
  label,
  help,
  value,
  onChange,
}: {
  label: string;
  help: string;
  value: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <View style={styles.toggleRow}>
      <View style={styles.toggleText}>
        <Text style={styles.toggleLabel}>{label}</Text>
        <Text style={styles.toggleHelp}>{help}</Text>
      </View>
      <Switch
        value={value}
        onValueChange={onChange}
        accessibilityLabel={label}
        trackColor={{ false: palette.border, true: palette.accentDim }}
        thumbColor={value ? palette.accent : palette.textFaint}
        ios_backgroundColor={palette.border}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  sectionHeading: { ...typography.bodyStrong, color: palette.text },
  toggleRow: { flexDirection: 'row', alignItems: 'flex-start', gap: spacing.lg },
  toggleText: { flex: 1, gap: 2 },
  toggleLabel: { ...typography.body, color: palette.text },
  toggleHelp: { ...typography.small, color: palette.textFaint, lineHeight: 18 },
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.lg, paddingBottom: spacing.xxl },
  closeRow: { alignSelf: 'flex-start' },
  close: { color: palette.accent, fontSize: 34, lineHeight: 36 },

  avatarRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.lg },
  avatarActions: { flex: 1, gap: spacing.sm },
  removePhoto: { ...typography.small, color: palette.danger, textAlign: 'center' },

  help: { ...typography.small, color: palette.textFaint, lineHeight: 18 },
  divider: { height: 1, backgroundColor: palette.border, marginVertical: spacing.sm },
  sectionLabel: { ...typography.tiny, color: palette.textFaint, textTransform: 'uppercase' },

  idCard: {
    backgroundColor: palette.surface,
    borderWidth: 1,
    borderColor: palette.border,
    borderRadius: radius.md,
    padding: spacing.lg,
    gap: spacing.xs,
  },
  idText: { ...typography.body, color: palette.text, letterSpacing: 1 },
  idHint: { ...typography.tiny, color: palette.accent },

  disclaimer: { ...typography.small, color: palette.textFaint, lineHeight: 18 },
});
