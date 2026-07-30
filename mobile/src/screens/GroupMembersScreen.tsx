import React, { useMemo, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Avatar, Banner, Button } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { formatAccountId } from '../ui/format';
import { useApp } from '../state/app';
import { groupIdFromConversationKey } from '../session/manager';

/**
 * Who is in a group, and changing it.
 *
 * People, not devices. The manager works in devices — a sender key is
 * distributed per device — but a person with two phones is one row here, and
 * removing them removes both in a single rotation. Doing it a device at a time
 * would hand them the new key on the way out.
 *
 * Removal says what it does before it does it. "Remove" reads as tidying a
 * list; what actually happens is that everybody still in the group gets a new
 * key, and that is the sentence under the button.
 */
export function GroupMembersScreen({ onBack }: { onBack: () => void }) {
  const t = useApp((s) => s.t);
  const group = useApp((s) => s.activeGroup);
  const conversations = useApp((s) => s.conversations);
  const me = useApp((s) => s.accountId);
  const addToGroup = useApp((s) => s.addToGroup);
  const removeFromGroup = useApp((s) => s.removeFromGroup);

  const [busy, setBusy] = useState<string | null>(null);

  /** One row per person, however many devices they have. */
  const people = useMemo(() => {
    const seen = new Set<string>();
    return (group?.members ?? [])
      .filter((m) => (seen.has(m.accountId) ? false : (seen.add(m.accountId), true)))
      .map((m) => ({
        accountId: m.accountId,
        devices: (group?.members ?? []).filter((o) => o.accountId === m.accountId).length,
      }));
  }, [group]);

  const candidates = useMemo(
    () =>
      conversations.filter(
        (c) =>
          groupIdFromConversationKey(c.accountId) === null &&
          !people.some((p) => p.accountId === c.accountId),
      ),
    [conversations, people],
  );

  if (!group) return null;

  async function act(accountId: string, action: (id: string) => Promise<void>) {
    setBusy(accountId);
    try {
      await action(accountId);
    } finally {
      setBusy(null);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Pressable accessibilityRole="button" onPress={onBack} hitSlop={12}>
          <Text style={styles.back}>‹</Text>
        </Pressable>

        <Text style={styles.title}>{group.name ?? t.newGroup}</Text>
        <Text style={styles.sectionLabel}>{t.groupMembers}</Text>

        {people.map((person) => {
          const known = conversations.find((c) => c.accountId === person.accountId);
          const isMe = person.accountId === me;
          return (
            <View key={person.accountId} style={styles.row}>
              <Avatar
                seed={person.accountId}
                label={known?.displayName ?? person.accountId}
                image={known?.avatar}
                size={34}
              />
              <View style={styles.rowText}>
                <Text style={styles.rowName} numberOfLines={1}>
                  {isMe ? t.groupYou : (known?.displayName ?? formatAccountId(person.accountId))}
                </Text>
                {person.devices > 1 ? (
                  <Text style={styles.rowSub}>{`${person.devices} ×`}</Text>
                ) : null}
              </View>
              {isMe ? null : (
                <Button
                  label={t.groupRemove}
                  variant="secondary"
                  loading={busy === person.accountId}
                  onPress={() => void act(person.accountId, removeFromGroup)}
                />
              )}
            </View>
          );
        })}

        <Banner tone="info" title={t.groupRemove} body={t.groupRemoveBody} />

        <Text style={styles.sectionLabel}>{t.groupAdd}</Text>
        {candidates.length === 0 ? (
          <Text style={styles.help}>{t.groupNoContacts}</Text>
        ) : (
          candidates.map((contact) => (
            <View key={contact.accountId} style={styles.row}>
              <Avatar
                seed={contact.accountId}
                label={contact.displayName ?? contact.accountId}
                image={contact.avatar}
                size={34}
              />
              <Text style={styles.rowName} numberOfLines={1}>
                {contact.displayName ?? formatAccountId(contact.accountId)}
              </Text>
              <Button
                label={t.groupAdd}
                variant="secondary"
                loading={busy === contact.accountId}
                onPress={() => void act(contact.accountId, addToGroup)}
              />
            </View>
          ))
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  content: { padding: spacing.xl, gap: spacing.md },
  back: { color: palette.accent, fontSize: 34, lineHeight: 36 },
  title: { ...typography.title, color: palette.text },
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
  rowText: { flex: 1 },
  rowName: { ...typography.body, color: palette.text, flex: 1 },
  rowSub: { ...typography.tiny, color: palette.textFaint },
});
