#!/usr/bin/env bash
#
# Generate the native projects and assert the permissions and usage strings a
# working build needs are actually in them.
#
# This exists because the failure it catches is invisible until somebody
# builds. A config plugin that stops applying — because a package was removed
# from app.json, or an upstream release changed what it writes — leaves a
# project that compiles, installs, and then denies the camera at the moment a
# user answers a video call. Nothing in typecheck, the test suite or the bundle
# would say a word.
#
# What it does NOT prove: that the app runs. Xcode and Gradle are not
# involved. It proves the native configuration is the one the code expects.
#
# Never run in the project directory: `expo prebuild` writes back to app.json
# and package.json.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

COPY="$WORK/generated/mobile"
mkdir -p "$COPY"
(cd "$PROJECT_DIR" && tar -cf - .) | (cd "$COPY" && tar -xf -)
rm -rf "$COPY/.expo" "$COPY/.expo-export" "$COPY/dist" "$COPY/ios" "$COPY/android"

(cd "$COPY" && npx expo prebuild --no-install --platform all >/dev/null)

MANIFEST="$COPY/android/app/src/main/AndroidManifest.xml"
INFO_PLIST="$(find "$COPY/ios" -name 'Info.plist' -not -path '*/Pods/*' | head -1)"

status=0
check() {
  local label="$1" file="$2" needle="$3"
  if [ ! -f "$file" ]; then
    echo "MISSING   $file"
    status=1
    return
  fi
  if grep -q -- "$needle" "$file"; then
    echo "ok        $label"
  else
    echo "MISSING   $label  (no '$needle' in $(basename "$file"))"
    status=1
  fi
}

# WebRTC needs all of these on Android. RECORD_AUDIO and CAMERA are the ones a
# user notices; the rest are what the media stack needs to find a path at all.
#
# This list is the media stack's, not the app's. Android merges every library's
# manifest at build time, so permissions like POST_NOTIFICATIONS arrive from
# expo-notifications' own manifest and are not in what prebuild writes here —
# checked, rather than assumed, when this comment was written. Asserting them
# here would fail against a project that is correct.
for permission in \
  android.permission.INTERNET \
  android.permission.ACCESS_NETWORK_STATE \
  android.permission.CAMERA \
  android.permission.RECORD_AUDIO \
  android.permission.MODIFY_AUDIO_SETTINGS \
  android.permission.WAKE_LOCK \
  android.permission.BLUETOOTH; do
  check "android $permission" "$MANIFEST" "$permission"
done

# iOS refuses the camera, the microphone or the photo library outright, at
# runtime, without a usage string — and the crash log says nothing useful.
#
# The photo one was missing from this list while "send a photo" shipped. It is
# present in the generated project today, which is the point: the failure this
# script exists to catch is a key that stops being written, and an assertion
# only catches that if it is here before it happens.
#
# These three are the whole iOS surface. Unlike Android, an Info.plist key
# cannot arrive from a library at build time — it has to be in the app's own
# plist, so what prebuild produces is what ships.
check "ios NSCameraUsageDescription" "$INFO_PLIST" "NSCameraUsageDescription"
check "ios NSMicrophoneUsageDescription" "$INFO_PLIST" "NSMicrophoneUsageDescription"
check "ios NSPhotoLibraryUsageDescription" "$INFO_PLIST" "NSPhotoLibraryUsageDescription"

# A placeholder identifier means two people generating from the same source
# get different apps.
check "ios bundle identifier" "$COPY/app.json" "com.algolindustries.tildra"
if grep -q "com.anonymous" "$COPY/app.json"; then
  echo "MISSING   the bundle identifier is still a generated placeholder"
  status=1
fi

if [ "$status" -ne 0 ]; then
  echo
  echo "The generated native project is missing something the code depends on."
  echo "A build from it would compile and then fail at runtime."
  exit 1
fi
