/**
 * Root component.
 *
 * Navigation is a small hand-rolled switch rather than a router: the app is
 * three screens deep and a router would be more configuration than code.
 */

import React, { useEffect, useState } from 'react';
import { ActivityIndicator, StyleSheet, View } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import * as Localization from 'expo-localization';

import { useApp } from './src/state/app';
import { OnboardingScreen } from './src/screens/OnboardingScreen';
import { ChatListScreen } from './src/screens/ChatListScreen';
import { ConversationScreen } from './src/screens/ConversationScreen';
import { SafetyNumberScreen } from './src/screens/SafetyNumberScreen';
import { ProfileScreen } from './src/screens/ProfileScreen';
import { LinkDeviceScreen } from './src/screens/LinkDeviceScreen';
import { JoinDeviceScreen } from './src/screens/JoinDeviceScreen';
import { CallScreen } from './src/screens/CallScreen';
import { Banner, Button } from './src/ui/components';
import { palette, spacing } from './src/ui/theme';

type Route =
  | { name: 'list' }
  | { name: 'conversation'; accountId: string }
  | { name: 'verify'; accountId: string }
  | { name: 'profile' }
  | { name: 'link' };

export default function App() {
  const phase = useApp((s) => s.phase);
  const error = useApp((s) => s.error);
  const t = useApp((s) => s.t);
  const bootstrap = useApp((s) => s.bootstrap);
  const openConversation = useApp((s) => s.openConversation);
  const closeConversation = useApp((s) => s.closeConversation);

  const [route, setRoute] = useState<Route>({ name: 'list' });
  const call = useApp((s) => s.call);
  const placeCall = useApp((s) => s.placeCall);
  const [joining, setJoining] = useState(false);

  // Leaving this set would drop the user back on the linking screen the next
  // time they signed out.
  useEffect(() => {
    if (phase !== 'onboarding') setJoining(false);
  }, [phase]);

  useEffect(() => {
    void bootstrap({
      localeTag: Localization.getLocales()[0]?.languageTag,
      serverUrl: process.env.EXPO_PUBLIC_TILDRA_SERVER,
    });
  }, [bootstrap]);

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <View style={styles.root}>
        {phase === 'starting' ? (
          <View style={styles.center}>
            <ActivityIndicator color={palette.accent} />
          </View>
        ) : phase === 'error' ? (
          <View style={styles.center}>
            <Banner tone="warning" title={t.errorGeneric} body={error ?? ''} />
            <Button label={t.retry} onPress={() => void bootstrap()} style={styles.retry} />
          </View>
        ) : call ? (
          // Above the route entirely. A ringing phone is not a place in a
          // navigation stack, and a call the user cannot see is a microphone
          // they have forgotten about.
          <CallScreen />
        ) : phase === 'onboarding' ? (
          joining ? (
            <JoinDeviceScreen onCancel={() => setJoining(false)} />
          ) : (
            <OnboardingScreen onJoinExisting={() => setJoining(true)} />
          )
        ) : route.name === 'conversation' ? (
          <ConversationScreen
            accountId={route.accountId}
            onBack={() => {
              closeConversation();
              setRoute({ name: 'list' });
            }}
            onVerify={() => setRoute({ name: 'verify', accountId: route.accountId })}
            onCall={(video) => void placeCall(route.accountId, { video })}
          />
        ) : route.name === 'verify' ? (
          <SafetyNumberScreen
            accountId={route.accountId}
            onDone={() => setRoute({ name: 'conversation', accountId: route.accountId })}
          />
        ) : route.name === 'profile' ? (
          <ProfileScreen
            onClose={() => setRoute({ name: 'list' })}
            onLinkDevice={() => setRoute({ name: 'link' })}
          />
        ) : route.name === 'link' ? (
          <LinkDeviceScreen onClose={() => setRoute({ name: 'profile' })} />
        ) : (
          <ChatListScreen
            onOpen={(accountId) => {
              void openConversation(accountId);
              setRoute({ name: 'conversation', accountId });
            }}
            onOpenProfile={() => setRoute({ name: 'profile' })}
          />
        )}
      </View>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: palette.bg },
  center: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: spacing.xl,
    gap: spacing.lg,
  },
  retry: { alignSelf: 'stretch' },
});
