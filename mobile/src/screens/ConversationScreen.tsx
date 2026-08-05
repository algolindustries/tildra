import React, { useEffect, useMemo, useRef, useState } from 'react';
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
import { AttachmentBubble } from '../ui/AttachmentBubble';
import { VoiceBubble } from '../ui/VoiceBubble';
import {
  IconAlert,
  IconCheck,
  IconCheckDouble,
  IconClock,
  IconMic,
  IconPhone,
  IconPlus,
  IconSend,
  IconStop,
  IconVideo,
} from '../ui/icons';
import { Strings } from '../i18n';
import { palette, radius, spacing, typography } from '../ui/theme';
import { Row, buildRows, formatAccountId, messageTime } from '../ui/format';
import { useApp } from '../state/app';
import { groupIdFromConversationKey } from '../session/manager';
import { Message } from '../storage/db';

export function ConversationScreen({
  accountId,
  onBack,
  onVerify,
  onCall,
  onOpenMembers,
}: {
  accountId: string;
  onBack: () => void;
  onVerify: () => void;
  onCall: (video: boolean) => void;
  onOpenMembers: () => void;
}) {
  const t = useApp((s) => s.t);
  const activeGroup = useApp((s) => s.activeGroup);
  const isGroup = groupIdFromConversationKey(accountId) !== null;

  /**
   * Who sent a group message, by the name this device already has for them.
   * Falls back to the account id: a group member nobody has a profile for is
   * better shown as an identifier than as nothing.
   */
  function senderName(senderAccountId?: string): string | undefined {
    if (!senderAccountId) return undefined;
    const known = conversations.find((c) => c.accountId === senderAccountId);
    return known?.displayName ?? formatAccountId(senderAccountId);
  }
  const locale = useApp((s) => s.locale);
  const messages = useApp((s) => s.messages);
  const conversations = useApp((s) => s.conversations);
  const send = useApp((s) => s.send);
  const notifyTyping = useApp((s) => s.notifyTyping);
  const sendPhoto = useApp((s) => s.sendPhoto);
  const startVoice = useApp((s) => s.startVoice);
  const finishVoice = useApp((s) => s.finishVoice);
  const recording = useApp((s) => s.recording);

  const conversation = conversations.find((c) => c.accountId === accountId);
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const listRef = useRef<FlatList<Row>>(null);

  // A typing signal expires on this device's clock rather than on a "stopped"
  // that may never arrive, so the indicator needs something to re-render it
  // when the deadline passes. A tick that runs only while somebody is actually
  // typing costs nothing the rest of the time.
  const typingDeadline = useApp((s) => s.typingUntil.get(accountId)) ?? 0;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (typingDeadline <= Date.now()) return;
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(timer);
  }, [typingDeadline]);
  const peerTyping = typingDeadline > now;

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
        {isGroup ? (
          <Pressable style={styles.headerText} onPress={onOpenMembers}>
            <Text style={styles.headerName} numberOfLines={1}>
              {name ?? t.newGroup}
            </Text>
            {/* Member count, not a verification state: a group has no single
                other end, and every member's key is checked on the pairwise
                session its sender key travelled over. */}
            <Text style={styles.headerSub}>
              {`${activeGroup?.members.length ?? 0} · ${t.groupMembers}`}
            </Text>
          </Pressable>
        ) : (
          <Pressable style={styles.headerText} onPress={onVerify}>
            <Text style={styles.headerName} numberOfLines={1}>
              {name ?? formatAccountId(accountId)}
            </Text>
            {/* Composing replaces the verification state rather than sitting
                beside it, so the subtitle never says two things at once. It
                comes back the moment the signal lapses. */}
            {peerTyping ? (
              <Text style={[styles.headerSub, styles.headerTyping]}>{t.typing}</Text>
            ) : (
              <Text style={[styles.headerSub, conversation?.verified && styles.headerVerified]}>
                {conversation?.verified ? `✓ ${t.verified}` : t.notVerified}
              </Text>
            )}
          </Pressable>
        )}
        {/* Disabled while the key is in question rather than hidden: a
            missing button is a puzzle, a disabled one next to the banner
            explaining why is an answer. */}
        {/* No call buttons in a group: the fingerprint binding pins one
            certificate to one identity key, which is a two-party statement.
            Offering a button that cannot keep that promise would be worse
            than not offering one. */}
        {isGroup ? null : (
          <>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={t.callAudio}
              disabled={blocked}
              onPress={() => onCall(false)}
              hitSlop={10}
            >
              <IconPhone color={blocked ? palette.textFaint : palette.accent} />
            </Pressable>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={t.callVideo}
              disabled={blocked}
              onPress={() => onCall(true)}
              hitSlop={10}
            >
              <IconVideo color={blocked ? palette.textFaint : palette.accent} />
            </Pressable>
          </>
        )}
      </View>

      {recording ? (
        <View style={styles.recordingBar}>
          <View style={styles.recordingDot} />
          <Text style={styles.recordingText}>{t.recording}</Text>
          <Pressable accessibilityRole="button" onPress={() => void finishVoice(false)}>
            <Text style={styles.recordingCancel}>{t.cancel}</Text>
          </Pressable>
        </View>
      ) : null}

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
                t={t}
                senderName={
                  isGroup && !item.message.outgoing
                    ? senderName(item.message.senderAccountId)
                    : undefined
                }
              />
            )
          }
          onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: false })}
        />

        <View style={styles.composer}>
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={t.attachPhoto}
            onPress={() => void sendPhoto()}
            disabled={blocked}
            style={[styles.attachButton, blocked && styles.sendButtonInert]}
          >
            <IconPlus color={palette.accent} size={24} />
          </Pressable>
          <TextInput
            style={styles.input}
            value={draft}
            onChangeText={(next) => {
              setDraft(next);
              notifyTyping(next);
            }}
            placeholder={blocked ? t.sendingBlocked : t.messagePlaceholder}
            placeholderTextColor={palette.textFaint}
            multiline
            editable={!blocked}
            maxLength={4000}
          />
          {draft.trim() ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={t.send}
              accessibilityState={{ disabled: blocked }}
              onPress={onSend}
              style={[styles.sendButton, blocked && styles.sendButtonInert]}
            >
              <IconSend color={palette.onAccent} size={22} />
            </Pressable>
          ) : (
            // Hold to record, release to send, slide away to cancel. The
            // composer swaps rather than showing both, so the primary action
            // is never ambiguous.
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={t.recordVoice}
              accessibilityState={{ disabled: blocked, busy: recording }}
              onPressIn={() => void startVoice()}
              onPressOut={() => void finishVoice(true)}
              disabled={blocked}
              style={[
                styles.sendButton,
                recording && styles.recordingButton,
                blocked && styles.sendButtonInert,
              ]}
            >
              {recording ? (
                <IconStop color={palette.onAccent} size={20} />
              ) : (
                <IconMic color={palette.onAccent} size={22} />
              )}
            </Pressable>
          )}
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

/**
 * The ticks.
 *
 * One tick left this device, two ticks reached theirs, two accent ticks were
 * read. Colour is not the only signal — `delivered` and `read` differ in hue,
 * so the shape carries nothing there, and the accessibility label says which in
 * words for anyone who cannot see the difference.
 *
 * Incoming messages get nothing. A tick beside a message somebody sent *you*
 * tells you something you already know.
 */
function MessageStatus({ message, t }: { message: Message; t: Strings }) {
  if (!message.outgoing) return null;

  const label = {
    pending: t.sending,
    sent: t.sent,
    delivered: t.delivered,
    read: t.read,
    failed: t.failed,
  }[message.state];

  const icon = () => {
    switch (message.state) {
      case 'pending':
        return <IconClock color={palette.textFaint} size={13} />;
      case 'sent':
        return <IconCheck color={palette.textFaint} size={13} />;
      case 'delivered':
        return <IconCheckDouble color={palette.textFaint} size={13} />;
      case 'read':
        return <IconCheckDouble color={palette.accent} size={13} />;
      case 'failed':
        return <IconAlert color={palette.danger} size={13} />;
    }
  };

  return (
    <View accessibilityRole="image" accessibilityLabel={label} style={styles.bubbleStatus}>
      {icon()}
    </View>
  );
}

function Bubble({
  message,
  showTail,
  locale,
  t,
  senderName,
}: {
  message: Message;
  showTail: boolean;
  locale: string;
  t: Strings;
  /** Only in a group, where "the other one" is not an answer. */
  senderName?: string;
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
        {senderName ? <Text style={styles.bubbleSender}>{senderName}</Text> : null}
        {message.attachment?.mimeType.startsWith('audio/') ? (
          <VoiceBubble message={message} outgoing={outgoing} />
        ) : message.attachment ? (
          <AttachmentBubble message={message} />
        ) : null}
        {message.text ? (
          <Text style={[styles.bubbleText, outgoing && styles.bubbleTextOut]}>{message.text}</Text>
        ) : null}
        <View style={styles.bubbleMeta}>
          <Text style={[styles.bubbleTime, outgoing && styles.bubbleTimeOut]}>
            {messageTime(message.createdAt, locale)}
          </Text>
          <MessageStatus message={message} t={t} />
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  bubbleSender: { ...typography.tiny, color: palette.accent, marginBottom: 2 },
  headerAction: { color: palette.accent, fontSize: 22, paddingHorizontal: spacing.xs },
  headerActionOff: { color: palette.textFaint },
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
  headerTyping: { color: palette.accent },

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
  bubbleStatus: { justifyContent: 'center' },

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
  recordingButton: { backgroundColor: palette.danger },
  recordingBar: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.sm,
    backgroundColor: palette.surface,
  },
  recordingDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: palette.danger },
  recordingText: { ...typography.small, color: palette.text, flex: 1 },
  recordingCancel: { ...typography.small, color: palette.accent, fontWeight: '600' },
  attachButton: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: palette.surfaceRaised,
    borderWidth: 1,
    borderColor: palette.border,
    alignItems: 'center',
    justifyContent: 'center',
  },
  attachText: { color: palette.accent, fontSize: 24, lineHeight: 26, fontWeight: '600' },
  sendText: { color: palette.onAccent, fontSize: 22, lineHeight: 24, fontWeight: '700' },
});
