import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Banner, Button } from '../ui/components';
import { palette, radius, spacing, typography } from '../ui/theme';
import { formatAccountId } from '../ui/format';
import { useApp } from '../state/app';
import { callDurationLabel, callTrust } from '../crypto/calling';

/**
 * A call in progress, or one that is ringing.
 *
 * There is no spoken verification code in Tildra — the reasoning is at the top
 * of `crypto/calling.ts` — so this screen is where the identity state has to
 * be visible. A call is the moment somebody is most likely to act on believing
 * they know who they are talking to, and the least likely to go looking for a
 * safety-number screen. So the trust line is the second thing on the screen,
 * above the buttons, and says what it means rather than showing a badge.
 *
 * "Encrypted" is not the claim being made. The claim is about *whose* key the
 * media is pinned to, and for an unverified contact the honest version of that
 * is "bound to whatever key the server gave you", which is what the text says.
 */
export function CallScreen() {
  const t = useApp((s) => s.t);
  const call = useApp((s) => s.call);
  const busy = useApp((s) => s.callBusy);
  const conversations = useApp((s) => s.conversations);
  const answerCall = useApp((s) => s.answerCall);
  const endCall = useApp((s) => s.endCall);
  const setCallMuted = useApp((s) => s.setCallMuted);

  const [muted, setMuted] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  // A duration that does not move is worse than none: it reads as a frozen
  // call rather than as a missing feature.
  useEffect(() => {
    if (call?.phase !== 'active') return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [call?.phase]);

  if (!call) return null;

  const conversation = conversations.find((c) => c.accountId === call.peerAccountId);
  const trust = callTrust(conversation);
  const incoming = call.direction === 'incoming' && call.phase === 'ringing';

  const status = incoming
    ? t.callIncoming
    : call.phase === 'ringing'
      ? t.callRinging
      : call.phase === 'active'
        ? callDurationLabel(call, now)
        : t.callConnecting;

  return (
    <SafeAreaView style={styles.screen}>
      <View style={styles.body}>
        <Text style={styles.name}>
          {conversation?.displayName ?? formatAccountId(call.peerAccountId)}
        </Text>
        <Text style={styles.status}>{status}</Text>

        {trust === 'changed' ? (
          <Banner tone="danger" title={t.identityChangedTitle} body={t.callKeyChanged} />
        ) : trust === 'unverified' ? (
          <Banner tone="warning" title={t.verifyTitle} body={t.callUnverified} />
        ) : (
          <Banner tone="info" title={t.verified} body={t.callVerified} />
        )}

        {call.peerFingerprint ? (
          <Text style={styles.fingerprint} selectable>
            {call.peerFingerprint.hash} {call.peerFingerprint.value}
          </Text>
        ) : null}
      </View>

      <View style={styles.actions}>
        {incoming ? (
          <>
            <Button label={t.callAnswer} onPress={() => void answerCall()} loading={busy} />
            <Button
              label={t.callDecline}
              variant="secondary"
              onPress={() => void endCall('declined')}
            />
          </>
        ) : (
          <>
            <Button
              label={muted ? t.callUnmute : t.callMute}
              variant="secondary"
              onPress={() => {
                const next = !muted;
                setMuted(next);
                setCallMuted(next);
              }}
            />
            <Button label={t.callHangUp} onPress={() => void endCall('hangup')} />
          </>
        )}
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: palette.bg, justifyContent: 'space-between' },
  body: { padding: spacing.xl, gap: spacing.lg, flex: 1, justifyContent: 'center' },
  name: { ...typography.title, color: palette.text, textAlign: 'center' },
  status: { ...typography.mono, fontSize: 20, color: palette.textMuted, textAlign: 'center' },
  // The fingerprint is shown, small, because somebody comparing two devices
  // by hand should be able to. It is not a check the user is asked to make:
  // the signature already made it.
  fingerprint: {
    ...typography.mono,
    fontSize: 10,
    color: palette.textFaint,
    textAlign: 'center',
    lineHeight: 14,
  },
  actions: { padding: spacing.xl, gap: spacing.md, borderTopWidth: 1, borderColor: palette.border, borderRadius: radius.md },
});
