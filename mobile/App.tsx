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
import { Banner, Button } from './src/ui/components';
import { palette, spacing } from './src/ui/theme';

type Route =
  | { name: 'list' }
  | { name: 'conversation'; accountId: string }
  | { name: 'verify'; accountId: string }
  | { name: 'profile' };

export default function App() {
  const phase = useApp((s) => s.phase);
  const error = useApp((s) => s.error);
  const t = useApp((s) => s.t);
  const bootstrap = useApp((s) => s.bootstrap);
  const openConversation = useApp((s) => s.openConversation);
  const closeConversation = useApp((s) => s.closeConversation);

  const [route, setRoute] = useState<Route>({ name: 'list' });

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
        ) : phase === 'onboarding' ? (
          <OnboardingScreen />
        ) : route.name === 'conversation' ? (
          <ConversationScreen
            accountId={route.accountId}
            onBack={() => {
              closeConversation();
              setRoute({ name: 'list' });
            }}
            onVerify={() => setRoute({ name: 'verify', accountId: route.accountId })}
          />
        ) : route.name === 'verify' ? (
          <SafetyNumberScreen
            accountId={route.accountId}
            onDone={() => setRoute({ name: 'conversation', accountId: route.accountId })}
          />
        ) : route.name === 'profile' ? (
          <ProfileScreen onClose={() => setRoute({ name: 'list' })} />
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
