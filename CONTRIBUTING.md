# Contributing to Tildra

## The one unusual rule

**Cryptographic changes need a written rationale.** If your PR touches key
handling, session establishment, the ratchet, or what the server stores, the
description must explain what property changes and why that is acceptable, and
you must update [`docs/PROTOCOL.md`](docs/PROTOCOL.md) in the same PR. A PR that
changes crypto behaviour without changing the spec will be asked to do so before
review, no matter how small the diff.

Everything else is a normal open-source project. Bug fixes, UI work, docs,
translations, tests — open a PR.

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
cd server && make fmt lint test
cd ../mobile && npm run typecheck && npm run lint
```

CI runs the same commands. It is not trying to be clever; if it passes locally it
passes there.

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

- The Postgres store (`server/internal/store/` has the interface; only the
  in-memory implementation exists).
- Key transparency — an auditable append-only log for the handle directory.
- Migrating groups from sender keys to MLS (RFC 9420).
- Reproducible builds for the Android APK.
- Accessibility review of the client.

## Code of conduct

Be decent. Disagree about the work, not the person. Maintainers will remove
people who can't manage that.
