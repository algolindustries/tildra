import React, { useMemo, useRef, useState } from 'react';
import {
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Avatar, Banner } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { Row, buildRows, formatAccountId, messageTime } from '../ui/format';
import { useApp } from '../state/app';
import { Message } from '../storage/db';

export function ConversationScreen({
  accountId,
  onBack,
  onVerify,
}: {
  accountId: string;
  onBack: () => void;
  onVerify: () => void;
}) {
  const t = useApp((s) => s.t);
  const locale = useApp((s) => s.locale);
  const messages = useApp((s) => s.messages);
  const conversations = useApp((s) => s.conversations);
  const send = useApp((s) => s.send);

  const conversation = conversations.find((c) => c.accountId === accountId);
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const listRef = useRef<FlatList<Row>>(null);

  const rows = useMemo(
    () => buildRows(messages, t, Date.now(), locale),
    [messages, t, locale],
  );

  const blocked = conversation?.identityChanged ?? false;
  const name = conversation?.displayName ?? (conversation?.handle ? `@${conversation.handle}` : null);

  async function onSend() {
    const text = draft.trim();
    if (!text || sending || blocked) return;
    setSending(true);
    setDraft('');
    try {
      await send(text);
      listRef.current?.scrollToEnd({ animated: true });
    } finally {
      setSending(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen} edges={['top', 'left', 'right']}>
      <View style={styles.header}>
        <Pressable accessibilityRole="button" accessibilityLabel="Back" onPress={onBack} hitSlop={12}>
          <Text style={styles.back}>‹</Text>
        </Pressable>
        <Avatar seed={accountId} label={name ?? accountId} image={conversation?.avatar} size={34} />
        <Pressable style={styles.headerText} onPress={onVerify}>
          <Text style={styles.headerName} numberOfLines={1}>
            {name ?? formatAccountId(accountId)}
          </Text>
          <Text style={[styles.headerSub, conversation?.verified && styles.headerVerified]}>
            {conversation?.verified ? `✓ ${t.verified}` : t.notVerified}
          </Text>
        </Pressable>
      </View>

      {blocked ? (
        <View style={styles.bannerWrap}>
          <Banner
            tone="danger"
            title={t.identityChangedTitle}
            body={t.identityChangedBody}
            actionLabel={t.identityChangedAction}
            onAction={onVerify}
          />
        </View>
      ) : null}

      <KeyboardAvoidingView
        style={styles.flex}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        keyboardVerticalOffset={8}
      >
        <FlatList
          ref={listRef}
          data={rows}
          keyExtractor={(row) => row.key}
          contentContainerStyle={styles.list}
          ListHeaderComponent={<Text style={styles.notice}>{t.encryptedNotice}</Text>}
          renderItem={({ item }) =>
            item.kind === 'day' ? (
              <View style={styles.daySeparator}>
                <Text style={styles.dayText}>{item.label}</Text>
              </View>
            ) : (
              <Bubble
                message={item.message}
                showTail={item.showTail}
                locale={locale}
                stateLabel={stateLabel(item.message, t)}
              />
            )
          }
          onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: false })}
        />

        <View style={styles.composer}>
          <TextInput
            style={styles.input}
            value={draft}
            onChangeText={setDraft}
            placeholder={blocked ? t.sendingBlocked : t.messagePlaceholder}
            placeholderTextColor={palette.textFaint}
            multiline
            editable={!blocked}
            maxLength={4000}
          />
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={t.send}
            accessibilityState={{ disabled: blocked || !draft.trim() }}
            onPress={onSend}
            style={[styles.sendButton, (blocked || !draft.trim()) && styles.sendButtonInert]}
          >
            <Text style={styles.sendText}>↑</Text>
          </Pressable>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function stateLabel(message: Message, t: { sending: string; sent: string; delivered: string; failed: string }) {
  if (!message.outgoing) return null;
  switch (message.state) {
    case 'pending':
      return t.sending;
    case 'sent':
      return t.sent;
    case 'delivered':
      return t.delivered;
    case 'failed':
      return t.failed;
  }
}

function Bubble({
  message,
  showTail,
  locale,
  stateLabel: label,
}: {
  message: Message;
  showTail: boolean;
  locale: string;
  stateLabel: string | null;
}) {
  const outgoing = message.outgoing;
  const failed = message.state === 'failed';
  return (
    <View style={[styles.bubbleRow, outgoing ? styles.bubbleRowOut : styles.bubbleRowIn]}>
      <View
        style={[
          styles.bubble,
          outgoing ? styles.bubbleOut : styles.bubbleIn,
          showTail && (outgoing ? styles.tailOut : styles.tailIn),
          failed && styles.bubbleFailed,
        ]}
      >
        <Text style={[styles.bubbleText, outgoing && styles.bubbleTextOut]}>{message.text}</Text>
        <View style={styles.bubbleMeta}>
          <Text style={[styles.bubbleTime, outgoing && styles.bubbleTimeOut]}>
            {messageTime(message.createdAt, locale)}
          </Text>
          {label ? (
            <Text style={[styles.bubbleState, failed && styles.bubbleStateFailed]}>{label}</Text>
          ) : null}
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg },
  flex: { flex: 1 },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
    borderBottomWidth: 1,
    borderBottomColor: palette.border,
  },
  back: { color: palette.accent, fontSize: 34, lineHeight: 36, marginTop: -4 },
  headerText: { flex: 1 },
  headerName: { ...typography.bodyStrong, color: palette.text },
  headerSub: { ...typography.tiny, color: palette.textFaint },
  headerVerified: { color: palette.success },

  bannerWrap: { padding: spacing.lg },
  notice: {
    ...typography.tiny,
    color: palette.textFaint,
    textAlign: 'center',
    paddingVertical: spacing.lg,
  },

  list: { paddingHorizontal: spacing.md, paddingBottom: spacing.md },
  daySeparator: { alignItems: 'center', paddingVertical: spacing.md },
  dayText: {
    ...typography.tiny,
    color: palette.textFaint,
    backgroundColor: palette.surface,
    paddingHorizontal: spacing.md,
    paddingVertical: 4,
    borderRadius: radius.pill,
    overflow: 'hidden',
  },

  bubbleRow: { flexDirection: 'row', marginVertical: 2 },
  bubbleRowIn: { justifyContent: 'flex-start' },
  bubbleRowOut: { justifyContent: 'flex-end' },
  bubble: {
    maxWidth: '78%',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: radius.lg,
    gap: 2,
  },
  bubbleIn: { backgroundColor: palette.surfaceRaised },
  bubbleOut: { backgroundColor: palette.accentDim },
  tailIn: { borderBottomLeftRadius: radius.sm / 2 },
  tailOut: { borderBottomRightRadius: radius.sm / 2 },
  bubbleFailed: { borderWidth: 1, borderColor: palette.danger },
  bubbleText: { ...typography.body, color: palette.text, lineHeight: 21 },
  bubbleTextOut: { color: palette.text },
  bubbleMeta: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm, alignSelf: 'flex-end' },
  bubbleTime: { ...typography.tiny, color: palette.textFaint },
  bubbleTimeOut: { color: palette.textMuted },
  bubbleState: { ...typography.tiny, color: palette.textFaint },
  bubbleStateFailed: { color: palette.danger },

  composer: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    gap: spacing.sm,
    padding: spacing.md,
    borderTopWidth: 1,
    borderTopColor: palette.border,
    backgroundColor: palette.bg,
  },
  input: {
    flex: 1,
    maxHeight: 120,
    minHeight: 44,
    backgroundColor: palette.surface,
    borderRadius: radius.lg,
    borderWidth: 1,
    borderColor: palette.border,
    paddingHorizontal: spacing.lg,
    paddingTop: spacing.md,
    paddingBottom: spacing.md,
    color: palette.text,
    ...typography.body,
  },
  sendButton: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: palette.accent,
    alignItems: 'center',
    justifyContent: 'center',
  },
  sendButtonInert: { opacity: 0.35 },
  sendText: { color: palette.onAccent, fontSize: 22, lineHeight: 24, fontWeight: '700' },
});
