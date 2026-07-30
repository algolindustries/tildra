import React, { useMemo, useState } from 'react';
import { FlatList, Modal, Pressable, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Avatar, Banner, Button, EmptyState, Field, ScreenTitle } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { formatAccountId, relativeTime } from '../ui/format';
import { useApp } from '../state/app';
import { Conversation } from '../storage/db';

export function ChatListScreen({
  onOpen,
  onOpenProfile,
}: {
  onOpen: (accountId: string) => void;
  onOpenProfile: () => void;
}) {
  const t = useApp((s) => s.t);
  const locale = useApp((s) => s.locale);
  const conversations = useApp((s) => s.conversations);
  const socketState = useApp((s) => s.socketState);
  const startConversation = useApp((s) => s.startConversation);
  const myAccountId = useApp((s) => s.accountId);
  const myName = useApp((s) => s.displayName);
  const myAvatar = useApp((s) => s.avatar);
  const splitView = useApp((s) => s.splitView);
  const dismissSplitView = useApp((s) => s.dismissSplitView);

  const [adding, setAdding] = useState(false);
  const [input, setInput] = useState('');
  const [addError, setAddError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // A conversation whose key changed is the one thing worth pulling to the top
  // of the list regardless of when it was last active.
  const ordered = useMemo(
    () =>
      [...conversations].sort((a, b) => {
        if (a.identityChanged !== b.identityChanged) return a.identityChanged ? -1 : 1;
        return b.lastActivity - a.lastActivity;
      }),
    [conversations],
  );

  async function onStart() {
    setBusy(true);
    setAddError(null);
    try {
      const accountId = await startConversation(input);
      setAdding(false);
      setInput('');
      onOpen(accountId);
    } catch (err) {
      setAddError(err instanceof Error ? err.message : t.errorGeneric);
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen} edges={['top', 'left', 'right']}>
      {/* Above everything, on the screen the user is on most, and only
          dismissible by saying so. This is the one alarm in the app that means
          the operator is lying to somebody — it used to be written into the
          general `error` field, which is rendered only while the app is
          failing to start, so it was never shown at all. */}
      {splitView ? (
        <View style={styles.alarm}>
          <Banner
            tone="danger"
            title={t.errorSplitView}
            body={`${splitView.source}: ${splitView.detail}`}
            actionLabel={t.dismiss}
            onAction={dismissSplitView}
          />
        </View>
      ) : null}
      <ScreenTitle
        right={
          <View style={styles.titleActions}>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={t.newChat}
              onPress={() => setAdding(true)}
              style={styles.newButton}
            >
              <Text style={styles.newButtonText}>+</Text>
            </Pressable>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={t.profile}
              onPress={onOpenProfile}
            >
              <Avatar
                seed={myAccountId ?? '?'}
                label={myName ?? myAccountId ?? '?'}
                image={myAvatar ?? undefined}
                size={40}
              />
            </Pressable>
          </View>
        }
      >
        {t.chats}
      </ScreenTitle>

      {socketState !== 'open' ? (
        <View style={styles.connection}>
          <View style={styles.connectionDot} />
          <Text style={styles.connectionText}>
            {socketState === 'reconnecting' ? t.retry : t.sending}…
          </Text>
        </View>
      ) : null}

      <FlatList
        data={ordered}
        keyExtractor={(item) => item.id}
        contentContainerStyle={ordered.length === 0 ? styles.emptyWrap : undefined}
        ListEmptyComponent={<EmptyState title={t.noChatsTitle} body={t.noChatsBody} />}
        renderItem={({ item }) => (
          <ConversationRow
            conversation={item}
            locale={locale}
            timeLabel={relativeTime(item.lastActivity, t, Date.now(), locale)}
            warningLabel={t.identityChangedTitle}
            verifiedLabel={t.verified}
            onPress={() => onOpen(item.accountId)}
          />
        )}
      />

      <Modal visible={adding} animationType="slide" transparent onRequestClose={() => setAdding(false)}>
        <View style={styles.modalBackdrop}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>{t.addContactTitle}</Text>
            <Text style={styles.modalBody}>{t.addContactBody}</Text>
            <Field
              placeholder={t.accountIdOrHandle}
              value={input}
              onChangeText={setInput}
              autoCapitalize="none"
              autoCorrect={false}
              editable={!busy}
            />
            {addError ? <Banner tone="warning" title={t.errorGeneric} body={addError} /> : null}
            <View style={styles.modalActions}>
              <Button
                label={t.cancel}
                variant="secondary"
                onPress={() => {
                  setAdding(false);
                  setAddError(null);
                }}
                style={styles.modalButton}
              />
              <Button label={t.start} onPress={onStart} loading={busy} style={styles.modalButton} />
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

function ConversationRow({
  conversation,
  timeLabel,
  warningLabel,
  verifiedLabel,
  onPress,
}: {
  conversation: Conversation & { id: string };
  locale: string;
  timeLabel: string;
  warningLabel: string;
  verifiedLabel: string;
  onPress: () => void;
}) {
  const name = conversation.displayName ?? (conversation.handle ? `@${conversation.handle}` : null);
  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      style={({ pressed }) => [styles.row, pressed && styles.rowPressed]}
    >
      <Avatar
        seed={conversation.accountId}
        label={name ?? conversation.accountId}
        image={conversation.avatar}
      />
      <View style={styles.rowBody}>
        <View style={styles.rowTop}>
          <Text style={styles.rowName} numberOfLines={1}>
            {name ?? formatAccountId(conversation.accountId)}
          </Text>
          <Text style={styles.rowTime}>{timeLabel}</Text>
        </View>
        {conversation.identityChanged ? (
          <Text style={styles.rowWarning} numberOfLines={1}>
            {warningLabel}
          </Text>
        ) : conversation.verified ? (
          <Text style={styles.rowVerified} numberOfLines={1}>
            ✓ {verifiedLabel}
          </Text>
        ) : (
          <Text style={styles.rowPreview} numberOfLines={1}>
            {formatAccountId(conversation.accountId)}
          </Text>
        )}
      </View>
      {conversation.unreadCount > 0 ? (
        <View style={styles.unread}>
          <Text style={styles.unreadText}>{conversation.unreadCount}</Text>
        </View>
      ) : null}
    </Pressable>
  );
}

const styles = StyleSheet.create({
  alarm: { paddingHorizontal: spacing.lg, paddingTop: spacing.md },
  screen: { flex: 1, backgroundColor: palette.bg },
  newButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: palette.surfaceRaised,
    borderWidth: 1,
    borderColor: palette.border,
    alignItems: 'center',
    justifyContent: 'center',
  },
  newButtonText: { color: palette.accent, fontSize: 24, lineHeight: 28, fontWeight: '600' },
  titleActions: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm },

  connection: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    paddingHorizontal: spacing.lg,
    paddingBottom: spacing.sm,
  },
  connectionDot: { width: 7, height: 7, borderRadius: 4, backgroundColor: palette.warning },
  connectionText: { ...typography.small, color: palette.textMuted },

  emptyWrap: { flexGrow: 1, justifyContent: 'center' },

  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
  },
  rowPressed: { backgroundColor: palette.surface },
  rowBody: { flex: 1, gap: 3 },
  rowTop: { flexDirection: 'row', alignItems: 'baseline', justifyContent: 'space-between', gap: spacing.sm },
  rowName: { ...typography.bodyStrong, color: palette.text, flexShrink: 1 },
  rowTime: { ...typography.tiny, color: palette.textFaint },
  rowPreview: { ...typography.small, color: palette.textFaint },
  rowVerified: { ...typography.small, color: palette.success },
  rowWarning: { ...typography.small, color: palette.danger, fontWeight: '600' },
  unread: {
    minWidth: 22,
    height: 22,
    paddingHorizontal: 6,
    borderRadius: 11,
    backgroundColor: palette.accent,
    alignItems: 'center',
    justifyContent: 'center',
  },
  unreadText: { ...typography.tiny, color: palette.onAccent, fontWeight: '700' },

  modalBackdrop: { flex: 1, backgroundColor: '#000000AA', justifyContent: 'flex-end' },
  modalCard: {
    backgroundColor: palette.surface,
    borderTopLeftRadius: radius.lg,
    borderTopRightRadius: radius.lg,
    padding: spacing.xl,
    gap: spacing.lg,
  },
  modalTitle: { ...typography.heading, color: palette.text },
  modalBody: { ...typography.small, color: palette.textMuted },
  modalActions: { flexDirection: 'row', gap: spacing.md },
  modalButton: { flex: 1 },
});
