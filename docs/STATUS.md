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
| `tildra-auditor`: standalone log watcher, signed publishable checkpoints | done |
| Clients verify and cross-check pinned auditors' signed checkpoints, distinguishing a split view from a bad publisher from an unreachable one | done |
| Device linking, both halves: the new device shows a QR, the signed-in device scans it, six-digit pairing code compared on both screens | done |
| QR scanning and display for device links and safety numbers, with a hardened parser for what comes off the camera | done |
| Call signalling: SDP hardening, DTLS fingerprint bound to the identity key, ICE address policy, call state machine | done |
| Call signalling carried end to end through `SessionManager`: ring all devices, first answer wins, busy, hangup | done |
| Reproducible builds for the Go server and `tildra-auditor`, checked in CI | done |
| Reproducible app JavaScript bundle including Hermes bytecode, iOS and Android, checked in CI | done |
| TURN relay credentials: `GET /v1/turn`, unlinkable to an account, and an ICE configuration that will not downgrade a relay-only phase | done |
| Call driver: peer-connection sequencing and the ICE ordering hazards, tested against a fake peer connection | done |

Counts at time of writing: 385 client tests, Go suite clean under `-race`, both
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

  `session/call-driver.ts` sequences the peer-connection operations and
  handles the ordering hazards — remote candidates that arrive before the
  description they belong to, local candidates gathered before the call has an
  id, and widening the address policy on the live connection when the user
  accepts. It runs against an interface, so it is tested against a fake peer
  connection rather than not at all.

  What does not exist: **`react-native-webrtc` and the adapter that would
  implement `PeerConnection` against it**, a call UI, and a deployed coturn.
  Nothing calls `CallDriver.place` yet.

  This one is blocked on something outside the repo, not deferred:
  `@config-plugins/react-native-webrtc` is at 15.0.1 and still declares
  `expo: ^56`, with no SDK 57 release. `react-native-webrtc` itself has no Expo
  constraint, but without the config plugin the native side — iOS deployment
  target, camera and microphone entitlements, Gradle wiring — is unconfigured,
  so adding the dependency would produce something that typechecks and bundles
  and does not run. That is the exact failure mode this project has been bitten
  by before. **No media has ever flowed** — every
  test in this area drives a double. Nothing here should be read as "calls
  work".

  One thing for whoever writes the adapter: `setConfiguration` must trigger an
  ICE restart when the policy widens from `relay` to `all`.
  `RTCPeerConnection.setConfiguration` alone does not go back for the host
  candidates it skipped while relay-only, so an answered call would sit on the
  relay forever with nothing indicating anything was wrong.
- **An independent security audit.** Not something that can be done from inside
  the repo. The crypto uses standard primitives and is heavily tested, but it has
  not been reviewed by anyone outside this work, and nothing should carry real
  traffic until it has.
- **A public auditor instance.** The tool ships, it signs what it publishes,
  and clients can now verify and cross-check a pinned auditor — that consumer
  did not exist before and is most of why running one had no obvious point.
  What is still missing is somebody actually operating one, and therefore an
  auditor for a client to pin. No client ships with a pinned auditor today.
- **Reproducible builds for the app's native shell.** The server, the auditor
  and the app's JavaScript bundle — Hermes bytecode included — all reproduce,
  checked in CI. The `.ipa` and `.aab` do not: that is Xcode and Gradle with
  the Android SDK/NDK involved, and it is unstarted. See
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
