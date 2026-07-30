#!/usr/bin/env bash
#
# Build the app's JavaScript deterministically, including the Hermes bytecode.
#
# `expo export` compiles Hermes for you, and the result is not reproducible:
# @expo/metro-config's exportHermes.js writes the bundle to
#
#   ${TMPDIR}/expo-bundler-${Math.random()}-${Date.now()}/index.js
#
# and hands that path to hermesc, which embeds it in the bytecode for stack
# traces. Two builds of identical source differ in exactly those bytes, plus
# the file hash Hermes appends at the end. So this script exports with
# --no-bytecode — the JavaScript alone is byte-identical across machines and
# directories — and then runs hermesc itself from inside the output directory
# with a relative filename, which is what makes the embedded path a constant.
#
# Usage: scripts/bundle.sh <output-dir> [platform]
set -euo pipefail

OUT="${1:?usage: scripts/bundle.sh <output-dir> [platform]}"
PLATFORM="${2:-ios}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

find_hermesc() {
  local host
  case "$(uname -s)" in
    Darwin) host=osx-bin ;;
    Linux) host=linux64-bin ;;
    *) echo "unsupported host $(uname -s)" >&2; return 1 ;;
  esac
  for candidate in \
    "$PROJECT_DIR/node_modules/hermes-compiler/hermesc/$host/hermesc" \
    "$PROJECT_DIR/node_modules/react-native/sdks/hermesc/$host/hermesc"; do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done
  echo "cannot find hermesc" >&2
  return 1
}

HERMESC="$(find_hermesc)"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
rm -rf "${OUT:?}/"*

(cd "$PROJECT_DIR" && npx expo export \
  --platform "$PLATFORM" \
  --no-bytecode \
  --output-dir "$OUT/export" >/dev/null)

# Metro names the file after a hash of its own contents, which is already a
# useful signal — but the name is not the artifact, so it is normalised away
# and the bytes are what get compared.
JS="$(find "$OUT/export/_expo/static/js/$PLATFORM" -name '*.js' -type f | head -1)"
if [ -z "$JS" ]; then
  echo "no JavaScript bundle was produced for $PLATFORM" >&2
  exit 1
fi

mkdir -p "$OUT/bundle"
cp "$JS" "$OUT/bundle/index.js"

# -O matches what `expo export` passes when minifying, which is the default.
# The relative `index.js` is the whole point: hermesc embeds the filename it
# was given, so an absolute path here would put the build directory back into
# the bytecode.
(cd "$OUT/bundle" && "$HERMESC" -emit-binary -O -out index.hbc index.js >/dev/null 2>&1)

echo "$OUT/bundle"
