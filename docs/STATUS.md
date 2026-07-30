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
| Session manager: fanout per device, identity-change blocking, prekey top-up, self-repair when a peer's session is gone | done |
| Account recovery: a 24-word phrase derives the identity, the blob is published under a lookup id derived from the same phrase, and both screens exist | done |
| Signed prekey rotation every 48h, with the replaced pair honoured for one more window, and every change to the secrets written to disk | done |
| Screens: onboarding, chat list, conversation, safety number, profile, device link (both halves) | done |
| Encrypted groups: sender keys, signed messages, rotation on removal, and screens to create one, talk in it and change who is in it | done |
| Encrypted profiles (name, photo, about), mutual introduction on first contact | done |
| Encrypted attachments; photo and voice messages with waveforms | done |
| Push notifications with a content-free payload | done |
| Key transparency: Merkle log, inclusion + consistency proofs verified by the client | done |
| Gossip between contacts for split-view detection | done |
| `tildra-auditor`: standalone log watcher, signed publishable checkpoints | done |
| Clients verify and cross-check pinned auditors' signed checkpoints, distinguishing a split view from a bad publisher from an unreachable one | done |
| The app configures auditors, checks them at startup and every six hours, and shows a split view as a persistent alarm | done |
| Device linking, both halves: the new device shows a QR, the signed-in device scans it, six-digit pairing code compared on both screens | done |
| QR scanning and display for device links and safety numbers, with a hardened parser for what comes off the camera | done |
| Call signalling: SDP hardening, DTLS fingerprint bound to the identity key, ICE address policy, call state machine | done |
| Call signalling carried end to end through `SessionManager`: ring all devices, first answer wins, busy, hangup | done |
| Reproducible builds for the Go server and `tildra-auditor`, checked in CI | done |
| Reproducible app JavaScript bundle including Hermes bytecode, iOS and Android, checked in CI | done |
| Native iOS and Android projects generate identically from the same source, checked in CI | done |
| `react-native-webrtc` and its config plugin, with the generated native permissions and usage strings asserted in CI | done |
| Call UI: place, ring, answer, decline, mute, hang up, and the peer's identity state shown on the call itself | done |
| Renegotiation, with the DTLS fingerprint pinned for the life of the call | done |
| TURN relay credentials: `GET /v1/turn`, unlinkable to an account, and an ICE configuration that will not downgrade a relay-only phase | done |
| Call driver: peer-connection sequencing and the ICE ordering hazards, tested against a fake peer connection | done |

Counts at time of writing: 468 client tests, Go suite clean under `-race`, both
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

  `session/webrtc-peer.ts` implements `PeerConnection` against
  `react-native-webrtc`. The plugin blocker turned out to be a stale
  declaration rather than a real incompatibility:
  `@config-plugins/react-native-webrtc@15.0.1` says `expo: ^56` and has no SDK
  57 release, but it uses only long-standing `expo/config-plugins` helpers.
  It is installed with an npm `overrides` entry so `npm ci` needs no flags,
  and — the part that makes this a decision rather than a hope —
  `scripts/check-native-config.sh` runs `expo prebuild` in CI and asserts every
  Android permission and both iOS usage strings are actually in the generated
  project. Verified it bites by removing the plugin and watching four
  permissions disappear.

  There is now a call UI: a phone button in the conversation header, a ring
  screen above everything else, answer and decline, mute, hang up, and — since
  Tildra deliberately has no spoken verification code — the peer's identity
  state stated in words on the call itself, because that is the moment somebody
  is most likely to act on believing they know who they are talking to. The
  adapter is loaded lazily, so only calls need a development build; messaging
  still runs in Expo Go.

  What does not exist:

  - **A deployed coturn.**

  Renegotiation now exists, so widening the address policy on answer actually
  takes effect: accepting a call re-offers with an ICE restart. The rule that
  makes it safe is that **a renegotiation may change the ICE credentials and
  may not change the DTLS fingerprint** — a peer's own key signs a re-offer
  perfectly well, so the signature cannot catch a mid-call substitution and
  only comparing against what the call was pinned to can. A re-offer that
  changes it ends the call.

  **No media has ever flowed, and nothing here has run on a phone.** Every
  test in this area drives a double; the media adapter and the call screen are
  covered by typecheck, the Metro bundle and the native-config check, and by
  nothing else. The first person to run this on two devices should expect to
  find things. Nothing here should be read as "calls work".

  One thing for whoever writes the adapter: `setConfiguration` must trigger an
  ICE restart when the policy widens from `relay` to `all`.
  `RTCPeerConnection.setConfiguration` alone does not go back for the host
  candidates it skipped while relay-only, so an answered call would sit on the
  relay forever with nothing indicating anything was wrong.
- **An independent security audit.** Not something that can be done from inside
  the repo. The crypto uses standard primitives and is heavily tested, but it has
  not been reviewed by anyone outside this work, and nothing should carry real
  traffic until it has.
- **A public auditor instance.** Everything around it now exists: the tool
  signs what it publishes, a build pins auditors through
  `EXPO_PUBLIC_TILDRA_AUDITORS`, the app asks them at startup and every six
  hours, and a disagreement is a persistent alarm on the chat list. What is
  missing is somebody actually operating one, so the default configuration is
  empty and the machinery runs against nobody.
- **Reproducible compilation of the app.** What now reproduces: the server,
  the auditor, the app's JavaScript bundle with its Hermes bytecode, and the
  Xcode and Gradle projects `expo prebuild` generates. What does not: running
  Xcode and Gradle over them to get an `.ipa` and an `.aab`. That needs the
  toolchains and has not been started. See `docs/REPRODUCIBLE_BUILDS.md`.

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
- **Published key material must reach disk before it is published.** The
  top-up generated a hundred one-time secrets, published their public halves,
  and stored nothing; after a restart the server handed out keys the device no
  longer held. Anything that changes `PreKeySecrets` goes through
  `onPreKeysChanged`. The serialisation lives in `storage/prekeys.ts` rather
  than in `state/app.ts` so it can be tested at all.
- **A test that holds a live object is not testing persistence.** The first
  version of the test above kept a reference to the secrets and passed with the
  persistence call deleted, because the top-up mutates the same maps in place.
  It serialises on the way in now. Run the negative control.
- **An undecryptable message must be acknowledged, not retried.** Throwing
  from `receiveEnvelope` leaves the envelope unacked so the server redelivers
  it, which is right for a transient failure and an infinite loop for a
  message encrypted to a ratchet that no longer exists. The rule: throw when
  retrying could work, acknowledge and repair when it cannot.
- **The recovery phrase is the account.** Registration derives the identity
  key from it rather than from the CSPRNG, so losing a device is survivable —
  and anyone holding the phrase is the account. The phrase-shown screen says
  that in those words instead of calling it a backup code, and the phrase is
  never persisted, which is why there is no "show it again" button.
- **The store conformance suite earns its place regularly.** Adding
  `PutRecoveryBlob` to it immediately caught the memory store accepting an
  unknown account where Postgres refuses it on a foreign key — a drift that
  would have surfaced only in production.
- **Group membership changes are in units of people, not devices.** The
  manager distributes a sender key per device, so `removeGroupMember` takes
  one. Removing a person with two phones by calling it twice rotates after the
  first and redistributes to whoever is left — which still includes their
  second phone, so they are handed the new key on the way out and keep
  reading. `removeGroupAccount` and `addGroupAccount` are the primitives the
  UI uses.
- **A group is a conversation whose account id is `group:<id>`.** That prefix
  is not a valid account id — those are Crockford base32 — so a group can never
  collide with a person, and the chat list, unread counts and message list work
  for one without a second implementation.
- **Two storage designs where one is unreachable is worse than one.** The
  database had a `prekeys` table with per-key rows and a comment saying a
  one-time secret is destroyed "after a session is established" — which never
  happened, because nothing called it and prekeys live in a `meta` blob. Both
  the table and its accessors are gone.
- **`npm run check:reachable` looks for the recurring bug in this project.**
  Something that works, is tested, and cannot be reached from the app has
  shipped four times: device linking with only its approving half,
  `safetyQrPayload` with no renderer, `checkAuditors` with no caller, and a
  split-view alarm written to a field the app never displays. The check
  reports exported functions and classes whose only callers are tests, with an
  allowlist where every entry carries a reason somebody can check. It reads
  public methods too, since a class the app holds a reference to is reachable
  while any number of its methods are not. It has found: a ringing timeout
  that never fired, signed prekeys that never rotated, one-time secrets that
  were published and never stored, groups with no screens, and a recovery flow
  that exists only in the protocol document.
- **A protocol that supports something is not a feature.** This table said
  device linking was done while the only screen was the *approving* half —
  there was nothing in the app that could produce a code for it to approve. The
  same mistake had already been made once with "multi-device", and again with
  the split-view alarm, which was written into the general `error` field that
  is only rendered while the app is failing to start, so it was never shown at
  all. Before writing "done", find the entry point a user would actually press
  and the pixel they would actually see.
- **A dependency that typechecks and bundles can still be unconfigured
  natively.** `expo prebuild` is cheap to run and its output can be asserted,
  which is the difference between adding a native module on faith and adding
  one with a regression test. `scripts/check-native-config.sh` is that test.
- **The camera is an input the attacker controls.** Everything scanned goes
  through `crypto/scan.ts`, which decides what kind of code it is, refuses the
  wrong kind by name, and validates the server address inside a link code
  before anything can act on it.
