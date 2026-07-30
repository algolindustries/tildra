#!/usr/bin/env bash
#
# Build the server binaries twice, from two different source paths, and refuse
# to succeed unless the results are byte-identical.
#
# The two copies live at deliberately different path depths. That is the part
# that actually tests something: without -trimpath, Go embeds the absolute
# build directory in the binary, so two builds of the same source from
# different checkouts differ — and a verifier who cloned into a different
# directory than the release builder would conclude the binary was tampered
# with. Building twice in the same place would pass while that bug was present.
#
# Usage: scripts/reproduce.sh [GOOS GOARCH]
set -euo pipefail

SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOOS_TARGET="${1:-$(go env GOOS)}"
GOARCH_TARGET="${2:-$(go env GOARCH)}"

BINARIES=(tildrad tildra-auditor)

# Everything that would otherwise vary between two machines building the same
# commit.
#
#   -trimpath      strips the build directory from the binary
#   -buildvcs=false  keeps git state out of it, so a build from a source
#                    tarball matches a build from a clone
#   -buildid=      drops the linker's content id, which is derived from
#                  toolchain paths
#   CGO_ENABLED=0  no host C toolchain, no host libc
export CGO_ENABLED=0
export GOFLAGS=-mod=readonly
export GOOS="$GOOS_TARGET"
export GOARCH="$GOARCH_TARGET"
LDFLAGS='-s -w -buildid='

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Two paths of different lengths and different depths.
COPY_A="$WORK/a/server"
COPY_B="$WORK/b-considerably-longer-path/nested/deeper/server"

for dest in "$COPY_A" "$COPY_B"; do
  mkdir -p "$dest"
  # Copied whole and pruned afterwards. BSD tar matches an exclude pattern
  # against trailing path components, so `--exclude=./bin` would also remove
  # any nested `bin/`. There is none in this module today, which is precisely
  # why it would be a silent problem the day there is one.
  (cd "$SERVER_DIR" && tar -cf - .) | (cd "$dest" && tar -xf -)
  rm -rf "$dest/bin"
done

hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

echo "toolchain: $(go version)"
echo "target:    $GOOS/$GOARCH"
echo

status=0
declare -a MANIFEST=()

for name in "${BINARIES[@]}"; do
  for copy in "$COPY_A" "$COPY_B"; do
    (cd "$copy" && go build -trimpath -buildvcs=false -ldflags="$LDFLAGS" \
      -o "$copy/out-$name" "./cmd/$name")
  done

  a="$(hash_of "$COPY_A/out-$name")"
  b="$(hash_of "$COPY_B/out-$name")"

  if [ "$a" = "$b" ]; then
    echo "ok        $name  $a"
    MANIFEST+=("$a  $name")
  else
    echo "MISMATCH  $name"
    echo "          build A: $a"
    echo "          build B: $b"
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo
  echo "The two builds differ. This is a real failure: it means a third party"
  echo "cannot check that a published binary was built from this source."
  exit 1
fi

echo
echo "SHA256SUMS ($GOOS/$GOARCH):"
printf '%s\n' "${MANIFEST[@]}"
