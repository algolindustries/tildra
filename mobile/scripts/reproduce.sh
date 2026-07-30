#!/usr/bin/env bash
#
# Build the app's JavaScript twice, from two source directories at different
# depths, and refuse to succeed unless both the bundle and its Hermes bytecode
# are byte-identical.
#
# Two builds in the same directory would pass while a build path was leaking
# into the output, because the path would be the same both times. That is not
# a hypothetical here: it is exactly the defect this pipeline works around, and
# it was found by running the export twice and diffing 3 MB of bytecode down to
# the 41 bytes that moved.
#
# What this does NOT cover: the native app. See docs/REPRODUCIBLE_BUILDS.md.
#
# Usage: scripts/reproduce.sh [platform]
set -euo pipefail

PLATFORM="${1:-ios}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

COPY="$WORK/second-checkout-at-a-different-depth/nested/mobile"
mkdir -p "$COPY"
# node_modules comes along rather than being reinstalled: the question is
# whether the *path* changes the output, and reinstalling would change the
# inputs too and answer a different question.
#
# Copied whole and pruned afterwards, rather than with `tar --exclude`. BSD
# tar matches an exclude pattern against trailing path components, so
# `--exclude=./dist` also removes `node_modules/<anything>/dist` — which
# quietly produced a copy that could not even run the bundler, and would just
# as quietly have produced a wrong answer if the missing package had been one
# that only affected output.
(cd "$PROJECT_DIR" && tar -cf - .) | (cd "$COPY" && tar -xf -)
rm -rf "$COPY/.expo" "$COPY/.expo-export" "$COPY/dist"

hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

echo "platform: $PLATFORM"
echo "building from $PROJECT_DIR"
A="$("$PROJECT_DIR/scripts/bundle.sh" "$WORK/out-a" "$PLATFORM")"
echo "building from $COPY"
B="$("$COPY/scripts/bundle.sh" "$WORK/out-b" "$PLATFORM")"
echo

status=0
for artefact in index.js index.hbc; do
  a="$(hash_of "$A/$artefact")"
  b="$(hash_of "$B/$artefact")"
  if [ "$a" = "$b" ]; then
    echo "ok        $artefact  $a"
  else
    echo "MISMATCH  $artefact"
    echo "          build A: $a"
    echo "          build B: $b"
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo
  echo "The two builds differ. Something about where the build ran reached the"
  echo "output, which means a third party cannot check a published bundle"
  echo "against this source."
  exit 1
fi

echo
echo "SHA256SUMS (JavaScript bundle, $PLATFORM):"
for artefact in index.js index.hbc; do
  echo "$(hash_of "$A/$artefact")  $artefact"
done
