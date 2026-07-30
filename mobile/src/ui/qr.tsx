/**
 * Showing a code, and reading one.
 *
 * Both halves of a device link and both halves of a safety-number check are
 * the same shape: one screen displays a value, another screen's camera reads
 * it, and the security rests on a person being able to see both. So the QR
 * renderer and the scanner live together, and neither knows what the payload
 * means — validation is `crypto/scan.ts`'s job.
 */

import React, { useCallback, useRef, useState } from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import QRCodeSvg from 'react-native-qrcode-svg';

import { Button } from './components';
import { palette, radius, spacing, typography } from './theme';
import { ScanGate, createScanGate } from '../crypto/scan';

/**
 * A QR code on a light tile.
 *
 * Deliberately not themed to the dark surface around it. Scanners read dark
 * modules on a light background; inverting it is a well-known way to produce a
 * code that looks right and half the phones in the room cannot read.
 */
export function QrCode({ value, size = 220 }: { value: string; size?: number }) {
  return (
    <View style={[styles.qrTile, { width: size + spacing.lg * 2 }]}>
      <QRCodeSvg value={value} size={size} backgroundColor="#ffffff" color="#000000" />
    </View>
  );
}

export interface QrScannerProps {
  /** Called once per distinct code. Repeats while the code sits in frame are suppressed. */
  onScan: (payload: string) => void;
  onCancel: () => void;
  /** Stop handing over scans — set while the caller is acting on the last one. */
  paused?: boolean;
  strings: {
    cancel: string;
    permissionTitle: string;
    permissionBody: string;
    permissionGrant: string;
    permissionDenied: string;
    hint: string;
  };
}

/**
 * The camera, with the states a scanner actually has.
 *
 * Permission is asked for at the moment the camera is needed and not at
 * startup, because a messenger that asks for the camera before it has a reason
 * teaches people to grant permissions without reading them. A refusal is a
 * supported outcome, not an error screen: every code this app scans can also
 * be pasted.
 */
export function QrScanner({ onScan, onCancel, paused, strings }: QrScannerProps) {
  const [permission, requestPermission] = useCameraPermissions();
  const [asking, setAsking] = useState(false);
  // Built once and kept for the life of the scanner: a gate recreated on every
  // render would forget what it just saw, which is the whole job.
  const gateRef = useRef<ScanGate | null>(null);
  if (!gateRef.current) gateRef.current = createScanGate();
  const gate = gateRef.current;

  const handle = useCallback(
    ({ data }: { data: string }) => {
      if (paused) return;
      if (!gate.shouldHandle(data)) return;
      onScan(data);
    },
    [gate, onScan, paused],
  );

  if (!permission) {
    return (
      <View style={styles.state}>
        <ActivityIndicator color={palette.accent} />
      </View>
    );
  }

  if (!permission.granted) {
    const refused = !permission.canAskAgain;
    return (
      <View style={styles.state}>
        <Text style={styles.stateTitle}>{strings.permissionTitle}</Text>
        <Text style={styles.stateBody}>
          {refused ? strings.permissionDenied : strings.permissionBody}
        </Text>
        {refused ? null : (
          <Button
            label={strings.permissionGrant}
            loading={asking}
            onPress={() => {
              setAsking(true);
              void requestPermission().finally(() => setAsking(false));
            }}
          />
        )}
        <Button label={strings.cancel} variant="secondary" onPress={onCancel} />
      </View>
    );
  }

  return (
    <View style={styles.cameraWrap}>
      <CameraView
        style={StyleSheet.absoluteFill}
        facing="back"
        // Only QR. Leaving every symbology on means a loyalty card in the
        // background can fire the handler while the user lines up the code.
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={handle}
      />
      <View style={styles.reticle} pointerEvents="none" />
      <View style={styles.cameraFooter}>
        <Text style={styles.hint}>{strings.hint}</Text>
        <Button label={strings.cancel} variant="secondary" onPress={onCancel} />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  qrTile: {
    alignSelf: 'center',
    alignItems: 'center',
    backgroundColor: '#ffffff',
    padding: spacing.lg,
    borderRadius: radius.md,
  },
  state: {
    gap: spacing.md,
    padding: spacing.xl,
    backgroundColor: palette.surface,
    borderRadius: radius.md,
  },
  stateTitle: { ...typography.body, color: palette.text, fontWeight: '600' },
  stateBody: { ...typography.small, color: palette.textMuted, lineHeight: 19 },
  cameraWrap: {
    height: 340,
    borderRadius: radius.md,
    overflow: 'hidden',
    backgroundColor: '#000000',
    justifyContent: 'flex-end',
  },
  reticle: {
    position: 'absolute',
    top: 40,
    left: 40,
    right: 40,
    bottom: 110,
    borderWidth: 2,
    borderColor: palette.accent,
    borderRadius: radius.md,
  },
  cameraFooter: { padding: spacing.lg, gap: spacing.sm },
  hint: { ...typography.small, color: '#ffffff', textAlign: 'center' },
});
