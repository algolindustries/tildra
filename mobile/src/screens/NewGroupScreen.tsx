import React, { useMemo, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Avatar, Banner, Button, EmptyState, Field } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { formatAccountId } from '../ui/format';
import { useApp } from '../state/app';
import { groupIdFromConversationKey } from '../session/manager';

/**
 * Starting a group.
 *
 * Only existing contacts can be added, and the screen says why rather than
 * silently offering a shorter list: a sender key is distributed over the
 * pairwise session, so somebody this device has never messaged has no channel
 * to receive one on. Offering them and failing later would be worse.
 */
export function NewGroupScreen({
  onCreated,
  onCancel,
}: {
  onCreated: (conversationKey: string) => void;
  onCancel: () => void;
}) {
  const t = useApp((s) => s.t);
  const conversations = useApp((s) => s.conversations);
  const createGroup = useApp((s) => s.createGroup);

  const [name, setName] = useState('');
  const [chosen, setChosen] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Groups are conversations too; they cannot be members of one.
  const contacts = useMemo(
    () => conversations.filter((c) => groupIdFromConversationKey(c.accountId) === null),
    [conversations],
  );

  function toggle(accountId: string) {
    setChosen((current) =>
      current.includes(accountId)
        ? current.filter((id) => id !== accountId)
        : [...current, accountId],
    );
  }

  async function onCreate() {
    setBusy(true);
    setError(null);
    try {
      onCreated(await createGroup(name, chosen));
    } catch (err) {
      setError(err instanceof Error ? err.message : t.errorGeneric);
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>{t.newGroup}</Text>
        <Text style={styles.body}>{t.groupBody}</Text>

        <Field
          label={t.groupNameLabel}
          placeholder={t.groupNamePlaceholder}
          value={name}
          onChangeText={setName}
          editable={!busy}
          maxLength={64}
        />

        <Text style={styles.sectionLabel}>{t.groupMembersLabel}</Text>
        <Text style={styles.help}>{t.groupMembersHelp}</Text>

        {contacts.length === 0 ? (
          <EmptyState title={t.newGroup} body={t.groupNoContacts} />
        ) : (
          contacts.map((contact) => {
            const picked = chosen.includes(contact.accountId);
            return (
              <Pressable
                key={contact.accountId}
                accessibilityRole="checkbox"
                accessibilityState={{ checked: picked }}
                onPress={() => toggle(contact.accountId)}
                style={[styles.row, picked && styles.rowPicked]}
              >
                <Avatar
                  seed={contact.accountId}
                  label={contact.displayName ?? contact.accountId}
                  image={contact.avatar}
                  size={34}
                />
                <Text style={styles.rowName} numberOfLines={1}>
                  {contact.displayName ?? formatAccountId(contact.accountId)}
                </Text>
                <Text style={styles.check}>{picked ? '✓' : ''}</Text>
              </Pressable>
            );
          })
        )}

        {error ? <Banner tone="warning" title={t.errorGeneric} body={error} /> : null}

        <Button
          label={t.groupCreate}
          onPress={onCreate}
          loading={busy}
          disabled={chosen.length === 0}
        />
        <Button label={t.cancel} variant="secondary" onPress={onCancel} />
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.md },
  title: { ...typography.title, color: palette.text },
  body: { ...typography.body, color: palette.textMuted, lineHeight: 23 },
  sectionLabel: { ...typography.tiny, color: palette.textFaint, textTransform: 'uppercase' },
  help: { ...typography.small, color: palette.textFaint, lineHeight: 18 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    padding: spacing.md,
    borderRadius: radius.md,
    borderWidth: 1,
    borderColor: palette.border,
  },
  rowPicked: { borderColor: palette.accent, backgroundColor: palette.surface },
  rowName: { ...typography.body, color: palette.text, flex: 1 },
  check: { color: palette.accent, fontSize: 18 },
});
