# Where the work stands

Written 2026-07-30. Update this when it stops being true.

## Done and verified

Everything below has tests, and the ones that span the client and the server are
tested by running the real Go server and pushing real traffic through it.

| Area | State |
|---|---|
| Go server: accounts, auth, prekeys, sealed-sender relay, WebSocket gateway | done |
| Postgres store + in-memory store behind one conformance suite | done |
| Client crypto: PQXDH (X25519 + ML-KEM-768), Double Ratchet with header encryption | done |
| Sealed sender, rotating mailboxes, contact inbox for first contact | done |
| Encrypted local storage: keystore master key + vault-encrypted SQLite | done |
| Session manager: fanout per device, identity-change blocking, prekey top-up | done |
| Screens: onboarding, chat list, conversation, safety number, profile, device link (both halves) | done |
| Encrypted groups: sender keys, signed messages, rotation on removal | done |
| Encrypted profiles (name, photo, about), mutual introduction on first contact | done |
| Encrypted attachments; photo and voice messages with waveforms | done |
| Push notifications with a content-free payload | done |
| Key transparency: Merkle log, inclusion + consistency proofs verified by the client | done |
| Gossip between contacts for split-view detection | done |
| `tildra-auditor`: standalone log watcher, publishable checkpoints | done |
| Device linking, both halves: the new device shows a QR, the signed-in device scans it, six-digit pairing code compared on both screens | done |
| QR scanning and display for device links and safety numbers, with a hardened parser for what comes off the camera | done |
| Call signalling: SDP hardening, DTLS fingerprint bound to the identity key, ICE address policy, call state machine | done |
| Call signalling carried end to end through `SessionManager`: ring all devices, first answer wins, busy, hangup | done |
| Reproducible builds for the Go server and `tildra-auditor`, checked in CI | done |
| TURN relay credentials: `GET /v1/turn`, unlinkable to an account, and an ICE configuration that will not downgrade a relay-only phase | done |

Counts at time of writing: 354 client tests, Go suite clean under `-race`, both
store implementations passing the same conformance suite, Metro bundle builds.

The screens themselves have no tests — this project has no React Native test
renderer. What stands behind them is typecheck plus the Metro bundle, and the
logic they call is tested directly. That is weaker than it sounds and is worth
knowing before trusting a UI change.

## Not done

- **Voice and video calls — the media half.** The part that decides whether a
  call is private is done and tested. `mobile/src/crypto/calling.ts` parses and
  hardens the SDP, binds the DTLS fingerprint to the sender's identity key with
  a role- and peer-bound signature, holds an unanswered incoming call to
  relay-only candidates so it cannot be used to find out where you are, and
  refuses every out-of-order signal. `SessionManager` carries those signals
  over the pairwise ratchet: it rings every device, gives the call to the first
  that answers, replies busy to a second caller, and **does not ring at all
  when the fingerprint does not verify** — tested against a real Go server with
  a hand-forged offer. See `docs/PROTOCOL.md` §10.

  What does not exist: `react-native-webrtc` (so a dev build, not Expo Go) and
  a call UI — nothing calls `placeCall` yet. The relay side is ready on the
  server (`GET /v1/turn`, see `docs/PROTOCOL.md` §10) but no coturn is
  deployed. **No media has ever flowed.** The signalling is testable headlessly and is
  tested; the media path is not, and nothing here should be read as "calls
  work".
- **An independent security audit.** Not something that can be done from inside
  the repo. The crypto uses standard primitives and is heavily tested, but it has
  not been reviewed by anyone outside this work, and nothing should carry real
  traffic until it has.
- **A public auditor instance.** The tool ships; nobody operates one.
- **Reproducible builds for the mobile app.** The Go server and
  `tildra-auditor` now build reproducibly and CI checks it on every push, host
  target and cross-compiled. The app does not: Expo release builds pull in the
  Android SDK/NDK, Gradle and Hermes, and making that byte-identical is
  unstarted work. This is the half that matters for most users. See
  `docs/REPRODUCIBLE_BUILDS.md`.

## Needs a human, not code

- A domain. `tildra.chat` and `tildra.dev` were both free when the name was
  chosen; neither is registered.
- A server deployment. The app defaults to `https://api.tildra.chat`, which does
  not exist. Point it elsewhere with `EXPO_PUBLIC_TILDRA_SERVER`.
- Apple and Google developer accounts for store builds.
- Someone to run `tildra-auditor` who is not the operator.

## Things worth knowing before changing anything

- **The store conformance suite fails rather than skips in CI.** If you add a
  method to `store.Store`, add it to the suite too, or Postgres and memory are
  free to drift.
- **The client tests build and run the actual Go server.** Twice now, unit tests
  on both sides passed while real delivery was completely broken. Anything that
  claims two components agree is tested by making them agree.
- **`expo-file-system`'s top-level read/write functions throw at runtime.** All
  media modules use `expo-file-system/legacy`. Typecheck does not catch this
  because the deprecated stubs are still declared.
- **Go and TypeScript both implement the Merkle log.** They are kept honest by a
  cross-language test where Go produces proofs and TypeScript verifies them, not
  by reading both files.
- **Run the Go suite with `-race`.** A data race in a test double slipped through
  once because it was run without.
- **`docs/THREAT_MODEL.md` lists what Tildra does not defend against.** If a
  change would move something off that list, or onto it, the doc changes in the
  same commit.
- **A protocol that supports something is not a feature.** This table said
  device linking was done while the only screen was the *approving* half —
  there was nothing in the app that could produce a code for it to approve. The
  same mistake had already been made once with "multi-device". Before writing
  "done", find the entry point a user would actually press.
- **The camera is an input the attacker controls.** Everything scanned goes
  through `crypto/scan.ts`, which decides what kind of code it is, refuses the
  wrong kind by name, and validates the server address inside a link code
  before anything can act on it.
