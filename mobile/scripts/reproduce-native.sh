#!/usr/bin/env bash
#
# Generate the native iOS and Android projects twice, from two source
# directories at different depths, and refuse to succeed unless they are
# identical.
#
# What this proves and what it does not. `expo prebuild` turns app.json, the
# installed packages and the config plugins into an Xcode project and a Gradle
# project. This checks that step: two people running it on the same source get
# the same native project, so nothing about where or when they ran reached the
# files. It does **not** run Xcode or Gradle, so it says nothing about whether
# the resulting .ipa and .aab are reproducible — that is still unstarted, and
# docs/REPRODUCIBLE_BUILDS.md says so.
#
# It is still worth having: if project generation were non-deterministic, no
# amount of work on the compilers afterwards could produce a reproducible app.
#
# Never run in the project directory. `expo prebuild` writes back to app.json
# and package.json, so this works only in throwaway copies.
#
# Usage: scripts/reproduce-native.sh [platform]   (ios | android | all)
set -euo pipefail

PLATFORM="${1:-all}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

A="$WORK/a/mobile"
B="$WORK/b-a-considerably-longer-path/nested/deeper/mobile"

for dest in "$A" "$B"; do
  mkdir -p "$dest"
  # Copied whole and pruned afterwards: BSD tar matches an --exclude pattern
  # against trailing path components, so excluding `./dist` would also strip
  # node_modules/*/dist. That produced a silently broken copy once already.
  (cd "$PROJECT_DIR" && tar -cf - .) | (cd "$dest" && tar -xf -)
  rm -rf "$dest/.expo" "$dest/.expo-export" "$dest/dist" "$dest/ios" "$dest/android"
done

echo "platform: $PLATFORM"
for dest in "$A" "$B"; do
  echo "generating in $dest"
  (cd "$dest" && npx expo prebuild --no-install --platform "$PLATFORM" >/dev/null)
done
echo

status=0
targets=()
case "$PLATFORM" in
  ios) targets=(ios) ;;
  android) targets=(android) ;;
  all) targets=(ios android) ;;
  *) echo "unknown platform $PLATFORM" >&2; exit 2 ;;
esac

# app.json and package.json are written back by prebuild, and they are inputs
# to the build rather than incidental — a difference there is a difference in
# what gets compiled.
for artefact in "${targets[@]}" app.json package.json; do
  if [ ! -e "$A/$artefact" ]; then
    echo "MISSING   $artefact was not generated"
    status=1
    continue
  fi
  if diff -r "$A/$artefact" "$B/$artefact" >"$WORK/diff-$artefact.txt" 2>&1; then
    echo "ok        $artefact"
  else
    echo "MISMATCH  $artefact"
    sed 's/^/          /' "$WORK/diff-$artefact.txt" | head -40
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo
  echo "The generated native projects differ. Where the generator ran reached"
  echo "the output, so no work on the compilers afterwards could produce a"
  echo "reproducible app."
  exit 1
fi
