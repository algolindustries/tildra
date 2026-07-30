# Reproducible builds

A binary nobody can check is a binary you have to trust. "Open source" on its
own only means the source is auditable — it says nothing about whether the
thing you downloaded was built from it.

## What is reproducible

**The Go server and `tildra-auditor`.** Two builds of the same commit, on
different machines, from different directories, produce byte-identical
binaries. `server/scripts/reproduce.sh` checks this and CI runs it on every
push, for the host target and cross-compiled for `linux/arm64`.

`tildra-auditor` is the one that matters most. Its entire purpose is to be run
by somebody who does not trust the server operator — it watches the
transparency log for a forked view. An auditor binary you cannot verify is an
auditor you have to trust, which defeats the point of having one.

## What is not reproducible

**The mobile app.** This is the gap that matters for most users, and it is not
closed. Expo/React Native release builds pull in the Android SDK and NDK, Gradle,
Hermes and the JavaScript bundler, and getting byte-identical output across
machines from that stack is a substantial piece of work that has not been done.
Until it is, an installed Tildra app is something you trust the publisher for.

`docs/THREAT_MODEL.md` says the same thing under "what we don't defend
against", and will keep saying it until this changes.

## Verifying a server binary

```sh
cd server
make reproduce           # build twice locally, compare
make release             # produce bin/tildrad and bin/tildra-auditor
sha256sum bin/tildrad bin/tildra-auditor
```

Compare the hashes against the ones published with the release. They must match
exactly. If they do not, something between the source and the binary you were
given is not what it claims to be — that is worth reporting, not working
around.

## What makes it deterministic

| Source of variance | How it is removed |
|---|---|
| Absolute build directory embedded in the binary | `-trimpath` |
| Git revision and dirty flag | `-buildvcs=false`, so a build from a tarball matches a build from a clone |
| Linker build id, derived from toolchain paths | `-ldflags=-buildid=` |
| Host C toolchain and libc | `CGO_ENABLED=0` |
| Go compiler patch version | `toolchain go1.25.3` pinned exactly in `go.mod`, and the same version in CI |
| Dependency versions | `go.sum`, with `GOFLAGS=-mod=readonly` so a build cannot quietly resolve something new |

The pinned toolchain is the one people get wrong. A `go` directive is a
*floor*: with `go 1.25.0` and nothing else, whoever has the newest patch
release builds a different binary, and it looks like tampering. CI used to
install Go 1.24 against a module requiring 1.25, which meant it downloaded
whatever the latest 1.25.x happened to be that day.

## Why the check builds from two different paths

Building twice in the same directory would pass while `-trimpath` was missing,
because the embedded path would be the same both times. The script copies the
module to two paths of different depths, which is the situation a real verifier
is in — they cloned somewhere else than the release builder did.

`make build` is deliberately *not* the same command as `make release`. It is
for development and has no reproducibility guarantee. Anything anybody else
will run goes through `make release`.
