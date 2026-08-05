<div align="center">

# Tildra

**Encrypted messaging that doesn't ask who you are.**

End-to-end encrypted by default — every chat, every group.
Post-quantum key agreement. No phone number. Fully self-hostable server.

[![CI](https://github.com/tildra/tildra/actions/workflows/ci.yml/badge.svg)](https://github.com/tildra/tildra/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8.svg?logo=go&logoColor=white)](server/go.mod)
[![React Native](https://img.shields.io/badge/react%20native-Expo%20SDK%2057-000020.svg?logo=expo&logoColor=white)](mobile/package.json)
[![Post-quantum](https://img.shields.io/badge/key%20agreement-X25519%20%2B%20ML--KEM--768-3DD6C0.svg)](docs/PROTOCOL.md)
[![Audit status](https://img.shields.io/badge/audit-not%20yet%20audited-orange.svg)](SECURITY.md)
[![Status](https://img.shields.io/badge/status-pre--alpha-lightgrey.svg)](#)

</div>

---

## Why Tildra exists

Telegram is fast, polished, and has a great UX. It is also, cryptographically, a
disappointment:

- Its default chats are **not** end-to-end encrypted. Cloud chats are encrypted in
  transit and at rest with keys the server holds.
- Its E2EE mode ("Secret Chats") is opt-in, one-to-one only, single-device only,
  and absent from the desktop client entirely.
- Group chats — where most conversations actually happen — have **no** E2EE option.
- The server is closed source. You are asked to trust a binary you cannot inspect.
- It requires a phone number, which ties your identity to a SIM and a carrier.

Tildra takes the parts of Telegram that are good (speed, multi-device, a client
that doesn't feel like homework) and rebuilds the parts that aren't.

## What's different

| | Telegram | Signal | Tildra |
|---|---|---|---|
| E2EE by default | ❌ opt-in, 1:1 only | ✅ | ✅ |
| E2EE group chats | ❌ | ✅ | ✅ |
| E2EE on every device/platform | ❌ no desktop secret chats | ✅ | ✅ |
| Linking a device without trusting the server | ❌ | ✅ | ✅ QR commitment + pairing code on both screens |
| Post-quantum key agreement | ❌ | ✅ (PQXDH) | ✅ (X25519 + ML-KEM-768) |
| Works without a phone number | ❌ | ❌ | ✅ |
| Profile name and photo hidden from the server | ❌ | ⚠️ stored encrypted | ✅ never uploaded |
| Server source available | ❌ | ✅ | ✅ |
| Self-hostable / federated-ready | ❌ | ⚠️ hard | ✅ |
| Sealed sender (server can't see who sent what) | ❌ | ✅ | ✅ |
| Key transparency log | ❌ | ⚠️ in progress | ✅ proofs verified per lookup |
| Message retention on server | ♾️ indefinite | until delivered | until delivered, hard TTL |
| Reproducible builds | ⚠️ partial | ✅ | ⚠️ server, auditor and the app's JS bundle; native shell not yet |

## Not anonymous — private

These are different things, and conflating them makes for a worse messenger.

You have a name and a photo, and the people you talk to see them. What is
different is where they live: your profile is sent to each contact over their
own encrypted session, exactly like a message. The server has no profile
endpoint, stores no name, no photo, and no contact list, so it cannot tell you
who anyone is. It *can* see who talks to whom: fetching somebody's keys is an
authenticated request that names them, and delivery is authenticated too, which
is what routing costs.
That is written up in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) rather
than smoothed over here. Your account is a key; your name is something
you hand to specific people rather than something you publish.

## Security design in one paragraph

Every device generates a long-term Ed25519 identity key and an X25519 signed
prekey, plus a batch of one-time prekeys and **ML-KEM-768** post-quantum
encapsulation keys. Sessions are established with a hybrid PQXDH-style handshake,
so an attacker who records traffic today and owns a quantum computer tomorrow
still gets nothing. Messages then flow through a Double Ratchet with encrypted
headers, giving forward secrecy and post-compromise security. Group messages use
per-sender ratchets with server-blind fanout. The server never sees plaintext. Sealed sender keeps the
sender out of the *envelope* — but not out of the request that delivers it,
which is authenticated, so the operator can still link a sender to a mailbox and
a mailbox to the device that registered it. This paragraph claimed otherwise
until 2026-08-04; the correction had been made in the protocol document and the
threat model and never reached the file most people read. The envelope is stored
until the recipient picks it up, then deleted.

Full details: [`docs/PROTOCOL.md`](docs/PROTOCOL.md) ·
Threat model and explicit non-goals: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

> [!IMPORTANT]
> Tildra is pre-alpha and has **not** been independently audited. Do not use it
> yet for anything where being wrong has consequences. We'll say clearly, here,
> when that changes.

## What works today

| | |
|---|---|
| Account creation without a phone number | ✅ |
| Account recovery from a 24-word phrase | ✅ |
| 1:1 messaging | ✅ |
| Multi-device: link a second device by QR, pairing code compared on both screens | ✅ |
| Encrypted group chats with membership rotation | ✅ |
| Encrypted profiles (name, photo, about) | ✅ |
| Safety numbers and identity-change blocking | ✅ |
| Sealed sender with rotating mailboxes | ✅ |
| Postgres-backed server, migrations on startup | ✅ |
| Encrypted local storage (keys, sessions, messages) | ✅ |
| Encrypted photo and file attachments | ✅ |
| Push notifications (content-free payload) | ✅ |
| Voice messages with waveforms | ✅ |
| Voice and video calls | ⬜ end to end in code — signalling, fingerprint binding, relay, media adapter, UI; **never run on a phone** |
| Key transparency for the handle directory | ✅ log, proofs verified by the client |
| Gossip between contacts for split-view detection | ✅ |
| Independent log auditor (`tildra-auditor`) | ✅ signs checkpoints, clients verify pinned auditors; no public instance |
| Reproducible builds | ⚠️ server, auditor and the app's JS bundle (Hermes included), checked in CI; native shell not yet |
| Independent security audit | ⬜ **not yet** |

Current state, in detail: [`docs/STATUS.md`](docs/STATUS.md) — what works, what
does not, and what needs a person rather than more code.

## Repository layout

```
tildra/
├── server/     Go — API, key directory, WebSocket gateway, sealed-sender relay
│               plus tildra-auditor, a standalone transparency log watcher
├── mobile/     React Native (Expo) + TypeScript — iOS & Android client
├── docs/       Protocol spec, threat model, current status
└── .github/    CI
```

## Quick start

**Server** (Go 1.25.3, pinned in `go.mod` so builds reproduce; Postgres 16+ optional):

```bash
cd server
cp .env.example .env
make dev            # in-memory store, starts on :8080
make test           # unit + store conformance
make test-postgres  # brings up Postgres in Docker and runs the same suite
make reproduce      # build twice from different paths, fail unless bytes match
```

With `TILDRA_DATABASE_URL` set, migrations are applied on startup.

**Mobile** (Node 22+):

```bash
cd mobile
npm install
npm start           # Expo — press i for iOS, a for Android
npm test            # includes end-to-end tests against a real Go server
```

To point the app at a local server:

```bash
EXPO_PUBLIC_TILDRA_SERVER=http://localhost:8080 npm start
```

## Testing

The client test suite builds and runs the **actual Go server** and pushes real
sealed messages through it. That is deliberate: unit tests on either side prove
each half is self-consistent, and have twice passed while real delivery was
completely broken. Anything that claims two components agree is tested by
making them agree.

The store has one conformance suite that both the in-memory and Postgres
implementations must pass, and it fails rather than skips in CI.

## Contributing

**This repository is private as of 2026-08-05.** It was public until then, and
the working practices are written for contributors rather than for one person
because that is what they were and what they are expected to become again —
[CONTRIBUTING.md](CONTRIBUTING.md) still applies to anyone with access, and
cryptographic changes still need a written rationale and a matching update to
`docs/PROTOCOL.md`.

Found a vulnerability? [SECURITY.md](SECURITY.md) has the disclosure process.

## License

The licences are unchanged and are not affected by the repository being private:
distributing the source is what a licence governs, and going private is a
decision not to distribute rather than a change to the terms for anyone who
already has it.

Server: [AGPL-3.0](LICENSE) — if you run a modified Tildra server for others, they
get the source. Client: GPL-3.0. The protocol spec is CC BY 4.0, so anyone can
implement it.
