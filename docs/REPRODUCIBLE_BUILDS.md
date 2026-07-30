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

**The app's JavaScript bundle, including its Hermes bytecode.** This is the
half of the app that matters most: every line of cryptography Tildra runs is in
there. Two builds on different machines from different directories produce
byte-identical `index.js` and `index.hbc`. `mobile/scripts/reproduce.sh`
checks it and CI runs it for both iOS and Android on every push.

## What is not reproducible

**The native app** — the `.ipa` and the `.aab`. Those come out of Xcode and
Gradle with the Android SDK and NDK involved, and making that byte-identical is
a substantial piece of work that has not been started. So an *installed* Tildra
app is still something you trust the publisher for, even though you can now
check the JavaScript inside it against this source.

That is a real narrowing rather than a solved problem, and
`docs/THREAT_MODEL.md` says so in the same terms.

## Why `expo export` alone is not enough

`expo export` compiles Hermes for you, and its output is not reproducible.
`@expo/metro-config`'s `exportHermes.js` writes the bundle to

```
${TMPDIR}/expo-bundler-${Math.random()}-${Date.now()}/index.js
```

and passes that path to `hermesc`, which embeds it in the bytecode for stack
traces. Two builds of identical source differ in exactly those bytes plus the
20-byte hash Hermes appends at the end — 41 bytes out of 3.1 MB, which is the
kind of difference that gets waved away as "probably a timestamp" if nobody
looks.

The fix is in `mobile/scripts/bundle.sh`: export with `--no-bytecode`, which
produces JavaScript that is already byte-identical, then run `hermesc` from
inside the output directory with a *relative* `index.js`. The embedded filename
is then a constant rather than wherever the build happened to run.

## Verifying an app bundle

```sh
cd mobile
npm ci
npm run reproduce          # build twice from different paths, compare
npm run bundle:release     # produce dist/bundle/index.js and index.hbc
sha256sum dist/bundle/index.js dist/bundle/index.hbc
```

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

## Why the checks build from two different paths

Building twice in the same directory would pass while `-trimpath` was missing,
because the embedded path would be the same both times. The scripts copy the
source to a second path at a different depth, which is the situation a real
verifier is in — they cloned somewhere else than the release builder did. That
is not a hypothetical: it is exactly how the Hermes defect above was found.

One trap worth knowing if you edit these scripts. BSD `tar` matches an
`--exclude` pattern against trailing path components, so `--exclude=./dist`
also removes `node_modules/<anything>/dist`. The first version of the mobile
script did that and produced a second checkout that could not run the bundler
at all — which was lucky, because a copy missing something less load-bearing
would have produced a confident, wrong answer. Both scripts now copy
everything and prune afterwards.

`make build` is deliberately *not* the same command as `make release`. It is
for development and has no reproducibility guarantee. Anything anybody else
will run goes through `make release`.
