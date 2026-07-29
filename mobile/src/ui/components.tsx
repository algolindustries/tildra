/**
 * Shared interface primitives.
 *
 * Small on purpose: a messaging app is four screens and a list. Anything that
 * needs more machinery than this is probably a screen, not a component.
 */

import React from 'react';
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  TextInputProps,
  View,
  ViewStyle,
} from 'react-native';

import { avatarColor, initials, palette, radius, spacing, typography } from './theme';

export function Button({
  label,
  onPress,
  variant = 'primary',
  disabled,
  loading,
  style,
}: {
  label: string;
  onPress: () => void;
  variant?: 'primary' | 'secondary' | 'danger';
  disabled?: boolean;
  loading?: boolean;
  style?: ViewStyle;
}) {
  const inert = disabled || loading;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: !!inert, busy: !!loading }}
      onPress={inert ? undefined : onPress}
      style={({ pressed }) => [
        styles.button,
        variant === 'primary' && styles.buttonPrimary,
        variant === 'secondary' && styles.buttonSecondary,
        variant === 'danger' && styles.buttonDanger,
        inert && styles.buttonInert,
        pressed && !inert && styles.buttonPressed,
        style,
      ]}
    >
      {loading ? (
        <ActivityIndicator color={variant === 'primary' ? palette.onAccent : palette.text} />
      ) : (
        <Text
          style={[
            styles.buttonLabel,
            variant === 'primary' && { color: palette.onAccent },
            variant === 'danger' && { color: palette.danger },
          ]}
        >
          {label}
        </Text>
      )}
    </Pressable>
  );
}

export function Field({ label, style, ...props }: TextInputProps & { label?: string }) {
  return (
    <View style={styles.fieldWrap}>
      {label ? <Text style={styles.fieldLabel}>{label}</Text> : null}
      <TextInput
        placeholderTextColor={palette.textFaint}
        style={[styles.field, style]}
        {...props}
      />
    </View>
  );
}

export function Avatar({ seed, label, size = 46 }: { seed: string; label?: string; size?: number }) {
  const color = avatarColor(seed);
  return (
    <View
      style={[
        styles.avatar,
        { width: size, height: size, borderRadius: size / 2, backgroundColor: `${color}22`, borderColor: color },
      ]}
    >
      <Text style={[styles.avatarText, { color, fontSize: size * 0.34 }]}>
        {initials(label ?? seed)}
      </Text>
    </View>
  );
}

/**
 * An inline notice.
 *
 * `danger` is reserved for the identity-change warning. If it starts appearing
 * for ordinary errors it stops meaning anything, which is precisely how
 * security warnings get trained away.
 */
export function Banner({
  tone = 'info',
  title,
  body,
  actionLabel,
  onAction,
}: {
  tone?: 'info' | 'danger' | 'warning';
  title: string;
  body?: string;
  actionLabel?: string;
  onAction?: () => void;
}) {
  const toneStyle =
    tone === 'danger' ? styles.bannerDanger : tone === 'warning' ? styles.bannerWarning : styles.bannerInfo;
  const accent = tone === 'danger' ? palette.danger : tone === 'warning' ? palette.warning : palette.accent;

  return (
    <View style={[styles.banner, toneStyle]}>
      <Text style={[styles.bannerTitle, { color: accent }]}>{title}</Text>
      {body ? <Text style={styles.bannerBody}>{body}</Text> : null}
      {actionLabel && onAction ? (
        <Pressable accessibilityRole="button" onPress={onAction} style={styles.bannerAction}>
          <Text style={[styles.bannerActionText, { color: accent }]}>{actionLabel}</Text>
        </Pressable>
      ) : null}
    </View>
  );
}

export function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <View style={styles.empty}>
      <Text style={styles.emptyTitle}>{title}</Text>
      <Text style={styles.emptyBody}>{body}</Text>
    </View>
  );
}

export function ScreenTitle({ children, right }: { children: string; right?: React.ReactNode }) {
  return (
    <View style={styles.titleRow}>
      <Text style={styles.title}>{children}</Text>
      {right}
    </View>
  );
}

const styles = StyleSheet.create({
  button: {
    minHeight: 50,
    paddingHorizontal: spacing.xl,
    borderRadius: radius.md,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: 'transparent',
  },
  buttonPrimary: { backgroundColor: palette.accent },
  buttonSecondary: { backgroundColor: palette.surfaceRaised, borderColor: palette.border },
  buttonDanger: { backgroundColor: palette.dangerDim, borderColor: palette.danger },
  buttonInert: { opacity: 0.45 },
  buttonPressed: { opacity: 0.8 },
  buttonLabel: { ...typography.bodyStrong, color: palette.text },

  fieldWrap: { gap: spacing.sm },
  fieldLabel: { ...typography.small, color: palette.textMuted },
  field: {
    minHeight: 50,
    backgroundColor: palette.surface,
    borderRadius: radius.md,
    borderWidth: 1,
    borderColor: palette.border,
    paddingHorizontal: spacing.lg,
    color: palette.text,
    ...typography.body,
  },

  avatar: { alignItems: 'center', justifyContent: 'center', borderWidth: 1 },
  avatarText: { fontWeight: '700' },

  banner: {
    borderRadius: radius.md,
    borderWidth: 1,
    padding: spacing.lg,
    gap: spacing.sm,
  },
  bannerInfo: { backgroundColor: palette.surface, borderColor: palette.border },
  bannerDanger: { backgroundColor: palette.dangerDim, borderColor: palette.danger },
  bannerWarning: { backgroundColor: palette.surfaceRaised, borderColor: palette.warning },
  bannerTitle: { ...typography.bodyStrong },
  bannerBody: { ...typography.small, color: palette.textMuted, lineHeight: 19 },
  bannerAction: { paddingTop: spacing.xs },
  bannerActionText: { ...typography.bodyStrong },

  empty: { alignItems: 'center', gap: spacing.sm, padding: spacing.xxl },
  emptyTitle: { ...typography.heading, color: palette.text },
  emptyBody: { ...typography.body, color: palette.textMuted, textAlign: 'center', lineHeight: 22 },

  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
  },
  title: { ...typography.title, color: palette.text },
});
