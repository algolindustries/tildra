#!/usr/bin/env bash
#
# The gate CI applies, run here instead.
#
# This exists because "green locally" and "green in CI" were not the same
# sentence. CI runs staticcheck; the habit here was `go vet`, which is clean on
# things staticcheck is not, and main went red on a lint nobody had run. The
# same gap covered `go build -trimpath`, the Metro bundle, and `-count=1` —
# several "the suite is green" reports were partly a test cache.
#
# So the rule is: everything CI can decide in a minute, this decides first.
# Steps that need a toolchain or several minutes are named at the end and run
# with --full, rather than being left out and forgotten.
#
#   scripts/check.sh          the fast gate — what CI's four quick jobs run
#   scripts/check.sh --full   plus the reproducible-build and native-config jobs
#
# Keep this in step with .github/workflows/ci.yml. A check that has drifted from
# the thing it mirrors is worse than no check, because it is believed.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FULL=0
[ "${1:-}" = "--full" ] && FULL=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }
note() { printf '  \033[2m%s\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
# Go server
# ---------------------------------------------------------------------------

cd "$ROOT/server"

step "gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "These files need gofmt:"
  echo "$unformatted"
  exit 1
fi

step "go vet"
go vet ./...

step "staticcheck"
# Run rather than install, so this works on a machine that has never installed
# it — which was the machine that pushed the lint failure.
go run honnef.co/go/tools/cmd/staticcheck@latest ./...

step "go test -race -count=1"
# -count=1 on purpose: without it a cached result reports a suite that has not
# run. CI always runs it cold.
if [ -z "${TILDRA_TEST_DATABASE_URL:-}" ]; then
  note "TILDRA_TEST_DATABASE_URL is unset, so the Postgres half of the store"
  note "conformance suite will skip. CI sets it and fails if it is missing —"
  note "the two store implementations are only held together where it runs."
  note "\`make test-postgres\` in server/ brings up a throwaway one and closes it."
fi
go test -race -count=1 ./...

step "go build -trimpath"
go build -trimpath ./...

# ---------------------------------------------------------------------------
# React Native client
# ---------------------------------------------------------------------------

cd "$ROOT/mobile"

step "typecheck"
npm run --silent typecheck

step "check:reachable"
npm run --silent check:reachable

step "npm test"
npm test

step "bundle"
# Metro resolves the graph the way the app does, which vitest does not: a module
# that imports something the bundler cannot find passes every test and fails
# here.
npm run --silent bundle >/dev/null

# ---------------------------------------------------------------------------
# The slow half
# ---------------------------------------------------------------------------

if [ "$FULL" -eq 1 ]; then
  cd "$ROOT/server"
  step "reproducible server build"
  ./scripts/reproduce.sh
  ./scripts/reproduce.sh linux arm64

  cd "$ROOT/mobile"
  step "reproducible app bundle"
  ./scripts/reproduce.sh ios
  ./scripts/reproduce.sh android

  step "native projects generate identically"
  ./scripts/reproduce-native.sh all

  step "native config has what the code depends on"
  ./scripts/check-native-config.sh
else
  printf '\n\033[2mSkipped (--full): reproducible builds, native project generation,\n'
  printf 'native config. They need Go and npm and nothing else — measured at a few\n'
  printf 'minutes on macOS — so run them before anything that touches the build.\n'
  printf 'CI runs them on every push.\033[0m\n'
fi

printf '\n\033[1;32m✓ the gate CI applies is green here\033[0m\n'
