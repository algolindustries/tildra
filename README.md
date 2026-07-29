<div align="center">

# Tildra

**Encrypted messaging that doesn't ask who you are.**

Open-source, end-to-end encrypted by default — every chat, every group, every call.
Post-quantum key agreement. No phone number. Fully self-hostable server.

[![CI](https://github.com/tildra/tildra/actions/workflows/ci.yml/badge.svg)](https://github.com/tildra/tildra/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

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
| Post-quantum key agreement | ❌ | ✅ (PQXDH) | ✅ (X25519 + ML-KEM-768) |
| Works without a phone number | ❌ | ❌ | ✅ |
| Server source available | ❌ | ✅ | ✅ |
| Self-hostable / federated-ready | ❌ | ⚠️ hard | ✅ |
| Sealed sender (server can't see who sent what) | ❌ | ✅ | ✅ |
| Message retention on server | ♾️ indefinite | until delivered | until delivered, hard TTL |
| Reproducible builds | ⚠️ partial | ✅ | ✅ (goal, tracked in CI) |

## Security design in one paragraph

Every device generates a long-term Ed25519 identity key and an X25519 signed
prekey, plus a batch of one-time prekeys and **ML-KEM-768** post-quantum
encapsulation keys. Sessions are established with a hybrid PQXDH-style handshake,
so an attacker who records traffic today and owns a quantum computer tomorrow
still gets nothing. Messages then flow through a Double Ratchet with encrypted
headers, giving forward secrecy and post-compromise security. Group messages use
per-sender ratchets with server-blind fanout. The server never sees plaintext, and
with sealed sender it doesn't see who sent a message either — only which mailbox
to drop the envelope into. It stores that envelope until the recipient picks it
up, then deletes it.

Full details: [`docs/PROTOCOL.md`](docs/PROTOCOL.md) ·
Threat model and explicit non-goals: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

> [!IMPORTANT]
> Tildra is pre-alpha and has **not** been independently audited. Do not use it
> yet for anything where being wrong has consequences. We'll say clearly, here,
> when that changes.

## Repository layout

```
tildra/
├── server/     Go — API, key directory, WebSocket gateway, sealed-sender relay
├── mobile/     React Native (Expo) + TypeScript — iOS & Android client
├── docs/       Protocol spec, threat model, self-hosting guide
└── .github/    CI
```

## Quick start

**Server** (Go 1.24+, Postgres 16+):

```bash
cd server
cp .env.example .env
make dev          # runs migrations + starts on :8080
make test
```

**Mobile** (Node 20+):

```bash
cd mobile
npm install
npm start         # Expo — press i for iOS, a for Android
```

## Contributing

Cryptographic changes need a written rationale in the PR and a matching update to
`docs/PROTOCOL.md`. Everything else: normal PRs welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Found a vulnerability? Please don't open a public issue —
[SECURITY.md](SECURITY.md) has the disclosure process.

## License

Server: [AGPL-3.0](LICENSE) — if you run a modified Tildra server for others, they
get the source. Client: GPL-3.0. The protocol spec is CC BY 4.0, so anyone can
implement it.
