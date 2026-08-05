# Contributing to Tildra

## The one unusual rule

**Cryptographic changes need a written rationale.** If your PR touches key
handling, session establishment, the ratchet, or what the server stores, the
description must explain what property changes and why that is acceptable, and
you must update [`docs/PROTOCOL.md`](docs/PROTOCOL.md) in the same PR. A PR that
changes crypto behaviour without changing the spec will be asked to do so before
review, no matter how small the diff.

Everything else works the way it did when this repository was public. Bug
fixes, UI work, docs, translations, tests — open a PR.

**The repository has been private since 2026-08-05.** That changes who can open
one and nothing about what is expected of it. Every rule below was written for
contributors who are not the author, and they are kept in that form
deliberately: they exist because they caught real defects, not because there was
an audience for them. The gate in particular — `./scripts/check.sh` before every
push — was added after main went red three times in one session, and a smaller
number of people makes that more likely to happen again, not less.

## Getting set up

```bash
git clone https://github.com/tildra/tildra
cd tildra

# Server
cd server && make dev        # starts on :8080 with the in-memory store
make test                    # go test -race

# Client
cd ../mobile && npm install && npm start
```

No database is required to develop — the server falls back to an in-memory store
and says so loudly at startup.

## Before you open a PR

```bash
./scripts/check.sh
```

That is the gate CI applies — gofmt, vet, staticcheck, `go test -race -count=1`,
`go build -trimpath`, typecheck, the reachability check, the whole client suite,
and the Metro bundle — in the same order, from one command. `--full` adds the
reproducible-build and native-config jobs, which need toolchains and minutes.

This section used to say `cd server && make fmt lint test` and
`cd ../mobile && npm run typecheck && npm run lint`, followed by "CI runs the
same commands ... if it passes locally it passes there". Neither part was true.
`make lint` skipped staticcheck whenever it was not installed, which is the
check CI fails on; `npm run lint` is not a script that exists, and there is no
linter configured for the client — typecheck and the reachability check are what
stands in for one. Main went red twice in one week on exactly that gap, which is
what `scripts/check.sh` exists to close.

Keep the script in step with `.github/workflows/ci.yml`. A check that has
drifted from the thing it mirrors is worse than no check, because it is
believed.

## Commit messages

Plain imperative subject lines: `add mailbox rotation`, `fix skipped-key cache
eviction`. No prefixes required, no format enforced. Explain *why* in the body if
the why isn't obvious from the diff.

## Design principles, when you're deciding between two implementations

1. **The server learns nothing it doesn't need to route.** If a feature is
   easier with server-side knowledge of who talks to whom, the feature is
   designed wrong, not the constraint.
2. **Failures are loud.** A signature that doesn't verify, an identity key that
   changed, a bundle that's missing — these stop the user, they don't warn in
   grey text. Silent degradation is how E2EE quietly stops being E2EE.
3. **No novel cryptography.** Every primitive is standard and boring. If you
   find yourself inventing a construction, that's a signal to stop and open an
   issue instead.
4. **Boring code beats clever code**, and it especially beats clever code near
   key material.

## Where help is most useful right now

- **Running the media half of a call.** The signalling is built and tested and
  no media has ever flowed: there is no TURN deployment and nothing has run on a
  device. See `docs/STATUS.md`.
- **Operating an auditor** that is not the server operator. The mechanism runs
  end to end and catches nothing while nobody is on the other end — see
  `docs/PROTOCOL.md` §7.3.
- Migrating groups from sender keys to MLS (RFC 9420).
- Reproducible compilation of the `.ipa` and `.aab`. The bundle, the native
  project generation and both binaries already reproduce; running Xcode and
  Gradle over them does not.
- Accessibility review of the client.

The first two items here were "the Postgres store, only the in-memory
implementation exists" and "key transparency — an auditable append-only log"
until 2026-08-05. Both have been built for weeks, with a conformance suite
across both stores and a standalone auditor; a help-wanted list that asks for
finished work is how a contributor's first afternoon gets spent.

## Code of conduct

Be decent. Disagree about the work, not the person. Maintainers will remove
people who can't manage that.
