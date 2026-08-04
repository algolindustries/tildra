# Where the work stands

Written 2026-07-30, revised 2026-08-05. Update this when it stops being true.

Three rows in the table below said **done** for a property that was not
delivered, and an audit pass found each of them. They are corrected in place
rather than quietly rewritten, because a status file that has been wrong before
is more useful than one that looks as though it never was.

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
| Session manager: fanout per device, identity-change blocking, prekey top-up, self-repair when a peer's session is gone | done — **the block did not cover calls** until 2026-08-04. Text and attachments read the flag; placing and answering did not, and the key comparison that looks like it covers the case does not, because flagging adopts the new key |
| Account recovery: a 24-word phrase derives the identity, the blob is published under a lookup id derived from the same phrase, and both screens exist | done |
| Signed prekey rotation every 48h, with the replaced pair honoured for one more window, and every change to the secrets written to disk | done |
| Screens: onboarding, chat list, conversation, safety number, profile, device link (both halves) | done |
| Encrypted groups: sender keys, signed messages, rotation on removal, and screens to create one, talk in it and change who is in it | done — **"rotation on removal" was half of one** until 2026-08-04. Only the member who performed the removal rotated: the removal never propagated, so everyone else kept the removed member on their fanout list and kept the chain that member already held. A membership epoch carries it now, and removing somebody forgets their chain rather than the whole group's |
| Encrypted profiles (name, photo, about), mutual introduction on first contact | done |
| Encrypted attachments; photo and voice messages with waveforms | done |
| Push notifications with a content-free payload, pinned by a test against the bytes actually sent | done |
| Key transparency: Merkle log, inclusion + consistency proofs verified by the client | done |
| Gossip between contacts for split-view detection | done — **it ran once per contact** until 2026-08-04, inside the first-contact branch, which compares two views at the moment there is least to disagree about. Sent now whenever our view of the log moves |
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
| Socket lifecycle: close, reconnect, backoff, subscription replay and ack durability, against a fake WebSocket | done |
| Text the server chooses is attributed, stripped of reordering characters and bounded before it reaches a banner | done |
| The error funnel: every failure's user-facing sentence, over both locales, with the identity codec's length check | done |
| Startup: the offline paths of `bootstrap`, including damaged storage and an unavailable keystore | done |
| The local database against real SQLite: blind indexes, encryption of every row, ordering, paging, cascade, erase | done |
| Session and group-key rows: a ratchet that has been through storage still decrypts, including skipped and post-step messages | done |
| Media adapter logic: ICE restart on widening, candidate filtering, connection-state mapping, teardown order — against a double of `react-native-webrtc`, not a device | done |
| Push registration and, more to the point, what a sign-out leaves on the device | done |
| The platform keystore: key persistence across runs, the accessibility option on every call, and erasing under a keychain that refuses | done |
| Voice recording: the duration cap against the audio it actually produces, and the plaintext capture removed on every path out | done |
| Photo and avatar picking: scaling, the budget walk against the platform, and no encode left in the cache directory on any path | done |
| Locales: the guard against every inherited property, tag resolution, and both tables complete, non-empty and actually translated | done |
| Startup against the real server: account creation, a cold restart onto the same account, and a device with no network at all | done |
| Voice playback: the decrypted audio removed on every path out — finished, stopped, unmounted, and a player that would not open | done |
| Two devices through the real server, driven entirely through the store: delivery, the reply, the shared safety number, and the handle path with its downgrade refusal | done |
| Server authentication: the registration proof, challenge single-use and device binding, domain separation on both signature contexts, token storage by hash, and the middleware | done |
| The WebSocket hub: backlog drain, live delivery, a closed socket leaving the listener set, and refusing both a subscribe and an ack for a mailbox the connection does not own | done |
| Identifier generation: the Crockford alphabet, hand-computed encoder vectors, every input bit reaching the output, and confusable glyphs mapped where a human types them | done |
| Configuration: defaults, every variable read, malformed values named, and a bound of zero or less refused rather than silently inverting the limit | done |
| The conformance suite covers every `store.Store` method, enforced by a test rather than by a rule in this file, with the provisioning channel included | done |
| `PROTOCOL.md` §9 checked against the code: no primitive named without an implementation, none implemented without a row, and the Argon2id costs pinned to the constants | done |
| Safety numbers: the construction pinned by a recorded vector, symmetry, and every byte of both identity keys reaching the digits | done |
| Every KDF label in `src/crypto` documented in `PROTOCOL.md` and vice versa, enforced by a test | done |
| The transparency log's own code (`internal/transparency/log.go`): the leaf encoding as a recorded vector, the tree-head signature checked against bytes the test assembles, and a lookup's head and proofs proved to come from one snapshot | done |
| `PROTOCOL.md` §8 enforced: the schema's columns are held against what the table says the operator can see, and a column named for something §8 says is not collected fails | done |
| The recovery phrase pinned to a recorded vector — a fixed phrase and the four values it must keep deriving, plus the same derivation rebuilt from the document's own literals | done |
| §6's padding buckets parsed out of the document and checked against the code that rounds to them | done |
| A server address that is not `https` refused unless it is loopback, on the client and the socket both | done |

Counts at time of writing: **756 client tests across 33 files**, twelve Go
packages clean under `-race`, both store implementations passing the same
conformance suite, Metro bundle builds.

The screens themselves have no tests — this project has no React Native test
renderer. What stands behind them is typecheck plus the Metro bundle, and the
logic they call is tested directly. That is weaker than it sounds and is worth
knowing before trusting a UI change.

It is also where bugs have hidden, so the answer when a component turns out to
own something that matters is to move it out rather than to shrug: `state/errors.ts`,
`storage/prekeys.ts` and now `media/playback.ts` all exist because logic that
could not be tested inside a screen could be tested a file away. If a component
holds an invariant, that is the signal.

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
  `scripts/check-native-config.sh` runs `expo prebuild` in CI and asserts the
  permissions the media stack needs and all three iOS usage strings are
  actually in the generated project. Verified it bites by removing the plugin
  and watching four permissions disappear.

  Two corrections to what that sentence used to claim, both measured rather
  than reasoned. It said "every Android permission", and it is not: Android
  merges every library's manifest at build time, so `POST_NOTIFICATIONS`
  arrives from `expo-notifications`' own manifest and is not in what prebuild
  writes — asserting it here would fail against a project that is correct. And
  it said "both iOS usage strings" when the app depends on three: the photo
  library one was unasserted while "send a photo" shipped. On iOS a usage
  string cannot arrive from a library, so what prebuild produces is what ships,
  and an absent key denies the picker at runtime with a crash log that says
  nothing useful — which is the exact failure this script exists to catch.

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
  test in this area drives a double. The first person to run this on two
  devices should expect to find things. Nothing here should be read as "calls
  work".

  The adapter's own logic is now tested — `webrtc-peer.test.ts` runs it
  against a double of `react-native-webrtc` and pins the rules that a phone
  would otherwise report as something vague: tracks are added before any SDP
  is built, the end-of-gathering marker is not forwarded as a candidate,
  `disconnected` does not end a call and nothing is reported after close,
  widening from `relay` to `all` triggers exactly one ICE restart and
  narrowing triggers none, and hanging up stops the tracks *before* closing
  the connection. Each of those was checked by breaking it and watching the
  test go red. What it cannot check is the library or the media: if
  `react-native-webrtc` disagrees with the double, these tests pass and the
  call still fails. The call screen is still covered by typecheck, the Metro
  bundle and the native-config check, and by nothing else.

  The ICE-restart rule is the one worth restating, because getting it wrong is
  invisible. `RTCPeerConnection.setConfiguration` does not go back for the
  host candidates it skipped while relay-only, so without the restart an
  answered call sits on the relay forever with nothing indicating anything is
  wrong.
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

- **The reproducibility checks run on a developer machine, not only in CI.**
  All four — both binaries, the app bundle, the generated native projects and
  the native config — were run on macOS on 2026-08-05 and pass, in a few
  minutes, needing Go and npm and nothing else. `scripts/check.sh --full` is all
  of them. The belief that they needed a toolchain this machine does not have
  was about *compiling* an `.ipa` and an `.aab`, which is a different thing and
  is still not started.
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
- **A claim lives in more than one file, and correcting it in one is how it
  survives.** Three times in two days: the sender-side of sealed sender was
  corrected in `PROTOCOL.md` and the threat model and stayed wrong in the
  README, which is the file most people read; the social-graph row was
  corrected in A1's table while the bullet above it still listed it under *what
  we defend against*; and certificate pinning was removed from A2 one commit
  before §6 was found still promising it "with a documented rotation
  procedure". When a claim changes, grep the other four documents for it before
  committing. `README.md`, `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`,
  `SECURITY.md` and this file are the set.

  This is not tidying. `SECURITY.md` sets the bar at "anything that lets the
  server learn more than §8 says it can — if you can determine who is talking
  to whom from server-side state, that is a vulnerability, not a design
  limitation, **unless it is already listed** under known limitations". Until
  those corrections landed it was not listed, so by this project's own
  definition the gap between the documents was the vulnerability.
- **A claim strong enough to matter should be pinned to code.** The ones that
  are: §9's primitives, every `Tildra_*` label, §6's padding buckets, §8's
  schema, the recovery derivation, and A1's both-ends-of-a-delivery. The ones
  that cannot be — there is no pinning, and the server terminates no TLS —
  say so in the document rather than describing an intention in the present
  tense.
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
- **The unlinkability claim now has tests, and it is a claim about the
  derivation.** `deriveMailboxSecret` and `contactInbox` carry what
  `docs/PROTOCOL.md` §5.1 promises about the *values* — that the contact inbox
  is a one-event leak per conversation and that nothing in one mailbox id
  relates it to another. That is not a claim about the operator, who does not
  have to correlate addresses it was handed: a device registers its mailboxes
  over an authenticated request, so `mailboxes` maps every one of them to an
  account. §5.1 said "nothing the server can correlate" until 2026-08-04.
- **The integration suites take a port from the OS.** They used fixed ones,
  and a killed run leaves `tildrad` behind — `afterAll` does not run when
  vitest is killed — so the orphan held the port and the next run's tests
  quietly talked to a stale server. Asking the OS removes the failure mode
  instead of documenting it.
- **`waitFor` throws on timeout, and says what it was waiting for.** It used
  to return silently, which is the worst of both worlds: a test whose
  assertion happened to hold anyway passed while measuring nothing, and one
  whose assertion then failed reported a value mismatch that reads as a logic
  bug rather than "the reply never came". Making it throw immediately
  revealed three call tests that had been passing on a wait that never
  completed.
- **§3 specified a message-key expansion Tildra has never used.** It said
  message keys are `HKDF(MK, info="Tildra_MsgKey_v1")` expanded to an 88-byte
  block, `32 enc ‖ 32 auth ‖ 24 nonce`. The code expands 56 bytes as
  `32 key ‖ 24 nonce`, and there is no separate authentication key because
  XChaCha20-Poly1305 is an AEAD and derives its own Poly1305 key. The document
  described an encrypt-then-MAC construction that does not exist here, and an
  implementer following it would have produced ciphertexts this client cannot
  read.

- **Six protocol-level derivations were in the code and nowhere in the
  document.** `Tildra_RootKey_v1` (the DH ratchet step, 96 bytes into root ‖
  chain ‖ next header key), `Tildra_HeaderKeys_v1`, `Tildra_GroupSenderKey_v1`,
  `Tildra_GroupMsg_v1` (the signature transcript), `Tildra_SealedSender_v1` and
  `Tildra_Provisioning_v1`. §§3–5 could not have been implemented from the
  document as written — which is the document's whole job.

  All six are written up now, each with its ikm, salt, info and output split,
  taken from the call sites rather than from memory. The `Tildra_Vault_*`
  domains and the blind index are deliberately still absent: they encrypt the
  local database and have no place in a document about what goes over the wire.

  `protocol-doc.test.ts` enforces both directions now. Every `Tildra_*` label
  under `src/crypto` must appear in `PROTOCOL.md`, and every label the document
  names must exist in the code — the second being how "blind-signed delivery
  token" became a guarantee in the threat model. Removing a label from the
  document, inventing one in the document, and adding one to the code each turn
  a different assertion red.

- **The safety number's comment described a construction the code does not
  have.** It said each group takes "20 bits of digest" and quoted the modulo
  bias for `2^20`. The code reads 24 bits at a two-byte stride, so consecutive
  groups overlap by a byte and only the first 25 of the 30 digest bytes are read
  at all. The digest length is the tell: twelve disjoint 20-bit fields is
  exactly 30 bytes, which is what somebody sized it for.

  Left as it is, and the comment now says why. Changing the extraction changes
  every safety number anyone has compared and written down, and this app's own
  words for a number that no longer matches are "this is what a key
  substitution looks like" — a real alarm raised by a cosmetic edit. There is
  nothing to gain: 25 bytes is 200 bits reaching a 60-digit output that can
  express about 199, so the comparison is as strong as its length allows
  whichever way the bits are cut.

  `crypto/safety.ts` had no test file of its own — five assertions in
  `crypto.test.ts` covered symmetry, the group count and that different peers
  differ, and nothing pinned the construction. It has eleven now, including a
  recorded vector, so the extraction cannot drift by accident. The vector is a
  characterisation and the test says so: it was produced by running this code,
  which locks the behaviour in place and is not evidence that the behaviour is
  what §7 intended.

  The assertion that earns its place is the exhaustive one: flipping any single
  byte of *either* identity key must change the number, over all sixty-four
  positions. A construction that dropped part of its input would let a
  substituted key produce the same digits for the bytes it still read, and two
  people comparing them would confirm an imposter. Dropping the second key from
  the derivation turns that test red along with two others.

  Checked and found faithful on the way past, since §5.1 writes them literally:
  the mailbox derivations match the document byte for byte — the `/` separator
  between owner account and device, the `mb_` prefix, the `:day` suffix on the
  label, sixteen bytes of hex. So do all twelve KDF labels the document names.

- **The threat model promised something the code does not do.** Its table of
  what the server learns had a row reading "Who sent a message — **Nothing.**
  Sealed sender puts the sender identity inside the ciphertext." The first half
  is true and the conclusion is not: `POST /v1/messages` sits behind the bearer
  token, so the server learns exactly which account delivered each envelope. It
  does not learn the sender *from the payload*; it learns them *from the
  request*.

  The claim traced back to one unbuilt mechanism. `PROTOCOL.md` §5 described the
  sender proving they are a real account with a **blind-signed delivery token**,
  and §9's primitives table listed "RSA-PSS blind signatures (RFC 9474)".
  Neither exists — no blind signature, no delivery token, nothing in the client
  or the server. A primitive named in a table had propagated into the guarantee
  a user is told to read, which is the most consequential direction a
  documentation error can travel.

  All three are corrected: §5 says what actually stops an open relay and that
  unlinkable delivery is designed and not built, §9 loses the row, and §11 gains
  the limitation. The threat-model row now says what the server learns and why
  it used to say otherwise. §11's line about there being "no
  `react-native-webrtc` integration" was stale too and is fixed in the same
  pass — the adapter exists and is tested against a double; what is missing is
  a TURN deployment and a device.

  `crypto/__tests__/protocol-doc.test.ts` is the guard. It parses §9 and fails
  on a primitive with no implementing symbol under `src/crypto`, on a primitive
  that is implemented but no longer documented, and on Argon2id parameters that
  disagree with the constants in `recovery.ts` — the row most likely to drift
  quietly, since its numbers are what a reviewer would use to judge whether a
  stolen phrase is worth grinding. Restoring the blind-signature row turns it
  red, which is to say the guard would have caught this.

  What it proves is narrow and worth stating: that every primitive named is used
  somewhere, not that it is used correctly. The rest of `crypto/` is for that.

- **The CI workflow was audited against what this file claims, and holds.**
  Every "checked in CI" row maps to a step: `reproduce.sh` covers both
  `tildrad` and `tildra-auditor`, the app bundle is built twice for iOS and
  Android, the native projects are regenerated and compared, the Postgres
  conformance suite has a service container and a URL so it fails rather than
  skips, and the client job installs Go because its integration suites build
  the real server. `gofmt`, `go vet`, `staticcheck`, `-race`, typecheck,
  `check:reachable`, the bundle and the crypto vectors are all there.

  One gap, in the native check rather than the workflow: it asserted two of the
  three iOS usage strings the app depends on. It asserts the photo library one
  now, and the negative control — pointing the assertion at a key the project
  genuinely does not have — exits 1 rather than printing "ok".

  Everything else in this audit was verified and found correct, including the
  one that looked like a defect on the way past: the generated Android manifest
  has no `POST_NOTIFICATIONS`, which would break every notification on Android
  13 and later. It arrives from `expo-notifications`' library manifest at
  Gradle merge time. Generated both projects and read them rather than
  reasoning about it.

- **The conformance suite had a hole exactly where it says it must not.** This
  file already carries the rule — "If you add a method to `store.Store`, add it
  to the suite too, or Postgres and memory are free to drift" — and nothing
  enforced it. Four of the thirty-nine methods had never been in the suite, and
  they were the whole device-linking provisioning channel:
  `CreateProvisioning`, `GetProvisioning`, `SetProvisioningApproval`,
  `DeleteProvisioning`. That is the one operation where a difference between
  the two implementations hands somebody else a seat at the table.

  They are covered now, including the invariant the in-memory store spells out
  in a comment: one approval per channel, because a second "would let a server
  that captured the first replace it after the user had already compared
  codes". Both implementations do enforce it — checked before writing anything,
  and the Postgres side does it in the `WHERE` clause so two concurrent
  approvals cannot both land. No drift, this time.

  The rule is enforced mechanically now. `storetest_test.go` reflects over
  `store.Store` and fails on any method the suite does not call, with an
  allowlist that requires a written reason — `Close` is on it, because both
  factories close in `t.Cleanup` and asserting it here as well would close the
  pgx pool twice. A second test catches the other way to have coverage on
  paper: a case defined but never registered in `Run`, which the scan would
  otherwise be satisfied by while it never executed.

  One trap worth recording: Postgres coalesces a null approval to an empty
  slice and the in-memory store leaves it nil. The assertion is on length, not
  on nil, or the suite would report a difference that is not one.

- **A configured bound of zero turned the server into one that destroys mail.**
  `config.Load` parsed every duration and size and accepted whatever came back.
  Each one is enforced by comparing against it, so zero does not mean "no
  limit", it means the opposite — silently:

  - `TILDRA_ENVELOPE_TTL=0s` puts the sweep's cutoff at `now`, so every
    undelivered message is destroyed on the next pass, ten minutes later.
  - `TILDRA_MAX_ENVELOPE_BYTES=0` rejects every message as too large.
  - `TILDRA_ATTACHMENT_TTL=0s` stores blobs that have already expired.
  - `TILDRA_TURN_TTL=0s` issues relay credentials that are dead on arrival.

  Negatives parse too, and are worse. None of it failed at startup; the
  operator would find out from a user.

  The file already argues the other side of this for the relay — "half a
  configuration is worse than none, ... the operator would find out when a call
  failed to connect for one user in ten" — and then did not apply it to the
  bounds. It does now: every duration and size must be positive, and the error
  names the variable.

  Found by writing the first tests for `internal/config`. Ten of the suite's
  cases failed on the first run; the rest passed, including the relay pairing
  and a list of separators not counting as configured URLs.

- **An account ID read aloud over the phone could not be typed back in.** The
  ID alphabet excludes I, L, O and U so that the glyphs people confuse can be
  mapped back rather than guessed at — `internal/id`'s doc comment says the
  point of the whole scheme is that an ID is "readable aloud over a phone call
  without a spelling alphabet". The server has carried that mapping in
  `id.Normalize` since the beginning and calls it from **nowhere**, because the
  place a human types an ID is the client. And `parseContactInput` did not map
  anything.

  So an ID read out and typed with an O for a zero, or a lowercase l for a one,
  failed the length-and-alphabet test and fell through to a handle lookup —
  and the user was told the person does not exist. The one property the
  alphabet is chosen for was not delivered anywhere.

  The mapping is in `parseContactInput` now, on the account-ID candidate only,
  so a handle called "olivia" does not become "0livia". U is not remapped: it
  is excluded outright rather than confusable with anything, so a string
  carrying one is not an ID and still falls through. `id.Normalize` and
  `id.ErrInvalid` are deleted — unreachable behaviour is deleted or wired up,
  and it cannot be wired up on a server that never sees user-typed IDs.

  Found by writing the first tests for `internal/id`, which is also now covered
  for the two things a round trip cannot show, since there is no decoder: that
  the alphabet is the one the design names, and that **every one of the 128
  input bits reaches the output** — checked over all 128 positions rather than
  a few samples, because an encoder that drops the tail loses entropy while
  every ID it produces still looks exactly right. The negative control that
  removes the tail turns four tests red.

- **`internal/gateway` had no tests either, only whatever the client suites
  happened to drive through it.** It has ten now, over a real WebSocket against
  an `httptest` server and the real in-memory store. `Conn` is built inside
  `Serve` and closes the socket on the slow-consumer path, so a nil double
  would only have proved that a nil pointer panics.

  Two of the hub's rules are written into the code as warnings about what
  happens without them, and both are one authenticated account reaching
  another's mail. A subscribe is resolved against the store rather than
  believed from the client — "ownership comes from the store, never from the
  client's claim". And an ack is refused for a mailbox the connection does not
  own, because "without this check, any authenticated account could delete
  anyone else's undelivered mail". Both are asserted now, and the ack one
  checks the other device's queue is still full afterwards.

  Nothing was wrong. The first version of the suite was, though, in a way worth
  keeping: `connect` returns when the client has dialled, which is not when the
  server has registered, so every negative assertion was also what an
  unfinished connection looks like. Each one now follows an observed positive —
  and for the two subscribe refusals, a second *owned* mailbox is subscribed
  after the refused one, so delivery working there proves the refused frame was
  already processed. The read loop takes frames in order; that is the
  happens-after.

- **The hub registers a connection before it drains the backlog, and that is
  not a bug.** `Serve` calls `register` and then `drain`, so an envelope
  arriving in between reaches the socket ahead of older queued ones — which the
  code's own comment says must not happen. Followed through rather than
  reported: `Dequeue` is a read and deletion happens on ack, so the system is
  at-least-once by construction; the client's message insert is `ON
  CONFLICT(id) DO UPDATE`, and the ratchet has tested handling for messages
  arriving out of order. The consequence is a duplicate and a skipped-key walk,
  both of which the design already carries. Written down so the next reader
  does not have to re-derive it.

- **`internal/auth` had no tests, and it is the only thing between a bearer
  token and every mailbox on the server.** It has nineteen now. Nothing was
  wrong, which is worth recording rather than dressing up.

  Almost all of the package's behaviour is what it refuses, so almost all of
  the suite is refusals: another key's signature, a proof whose timestamp
  drifts in either direction, an identity key of the wrong length, a challenge
  redeemed twice, a challenge redeemed for a different device or account, an
  unknown challenge, an unknown token, and — the two that matter most —
  signatures that skip the domain-separating context prefix, in both the
  registration and the challenge direction. Any signature Tildra asks a key to
  make carries a distinct prefix so that one protocol's signature is never
  valid in another; nothing had checked that.

  Two claims in the package's own doc comment are now assertions rather than
  prose. The server stores only SHA-256 of a token, so a database leak does not
  hand an attacker live sessions: the test looks the raw token up in the store
  and requires it to miss. And a failed redemption spends the challenge either
  way, which is the difference between one attempt at forging a signature and
  two minutes of them.

  Five negative controls: deleting the context prefix, not consuming the
  challenge on failure, storing the raw token, dropping the device binding, and
  dropping the timestamp window each go red.

  The store is the real in-memory implementation rather than a double — the
  conformance suite already holds it to the same contract as Postgres, and
  token expiry is enforced there rather than in `auth`, which is a thing to
  exercise rather than assume. Checked before writing any of this: both stores
  do filter on `expires_at`, so `TokenTTL` is real.

- **Calls now have a store-level test, and the last uncovered path in `app.ts`
  is closed.** `call-driver.test.ts` drives the peer-connection sequencing
  against a double and `manager.test.ts` carries the signalling end to end
  through a real server. Neither touches the store: what `placeCall` leaves in
  `call` and `callBusy`, whether a second press is ignored, whether a media
  stack that will not come up leaves the app stuck busy, and whether `endCall`
  takes the screen down when the hangup cannot be sent.

  That last one is written into the code as a comment — "a hangup that fails to
  send must still take the call screen down, or the user is looking at a call
  that is over and cannot leave it" — and had nothing checking it. It does now,
  and the negative control puts the clear back after the await and goes red.

  Two devices ring each other through the real server, with only
  `session/webrtc-peer` doubled, so the incoming side is observed rather than
  assumed. One pair is shared across the block: signing up costs a recovery
  phrase derivation and a prekey batch, and four tests needed the same two
  devices.

  Two things went wrong writing it, both caught by controls rather than by
  reading:

  - The callee was a `registerContact` at first — an account registered
    straight through the client. It cannot receive anything: mailboxes are
    registered by `publishMailboxes` at startSession, which a raw client never
    runs, so every send came back "unknown mailbox". The helper says so now.
  - The failing-hangup test spied on `SessionManager.prototype.endCall` from
    the *wrong module graph*. Every `boot()` resets the registry, so the class
    imported after the last boot is a different object from the one the first
    device's store uses. The spy patched nothing and the test passed against a
    build with the bug put back. `signedUp` returns the class from its own
    graph now, the way it already did for the client.

- **Attachments now cross two devices in a test, and nothing was wrong.**
  `sendPhoto` and `loadAttachment` were the last two network paths in `app.ts`
  with no coverage. A photo goes from one store to the other through the real
  server — encrypted, uploaded, referenced in the message, downloaded and
  decrypted — and the bytes come back identical. The dimensions travel in the
  message rather than the blob, so the bubble can lay out before anything is
  fetched; that is asserted on both ends.

  No defect. Worth recording as such: the value of the turn was the coverage,
  and reaching for a finding where there is none is how a test suite fills up
  with assertions nobody believes.

  The picker is mocked at the module boundary `photo.test.ts` already owns, so
  this does not re-test the shrink-and-compress pipeline — only everything
  after it.

  The cancellation case needed a second assertion to be worth anything.
  "Cancelling adds no message" passes with the early return deleted, because
  the throw that follows is caught and leaves the message list alone. It now
  also captures `error` before the action and requires it unchanged — a
  comparison rather than `toBeNull()`, since that field collects whatever else
  the store is doing.

- **A group you had just made could not be opened, used or seen.**
  `SessionManager.createGroup` saved the group, made a sender key and
  distributed it — and did not create the conversation row the messages live
  in. `ensureGroupConversation` exists for exactly that and was only reached
  from sending and receiving.

  So `App.tsx` created a group, called `openConversation` on it, and
  `openConversation` found no row and returned early. `activeAccountId` stayed
  null, which makes `send` a silent no-op; `activeGroup` stayed null, which
  makes the members screen unable to add or remove anyone; and
  `listConversations` reads the conversations table, so the group was not in
  the chat list either. A group was unusable and invisible until somebody
  *else* wrote to it.

  Found by writing the first store-level group test. One line fixed the whole
  flow.

  The test's own claim needed correcting twice, and both corrections came from
  the negative controls. It began as "a removed member cannot read", which it
  does not check: taking the sender-key rotation out of `removeGroupAccount`
  leaves it green, because the next message only goes to the mailboxes of the
  members who remain. What it checks is delivery — the removed member is no
  longer addressed. The cryptographic lock-out is `group.test.ts`'s "locks a
  removed member out once the group rotates", and the two are now named apart.

  The second correction is one this file already records and I made anyway:
  asserting `error === null` to mean the removal worked. That field collects
  anything from a prekey rotation to a socket blip and is never cleared until
  the next action sets it, so a run with nothing wrong failed. The assertion is
  on the member list now, which is what `removeFromGroup` actually changes.

- **Device linking now has a test where the two halves meet.**
  `linking.test.ts` drives the provisioning exchange at the manager level.
  Nothing drove it through the store, which is where the halves are wired to
  each other — the new device shows a payload and polls in the background, the
  signed-in device approves it and is handed six digits, and the entire security
  of the pairing is that both screens show the *same* six.

  The test asserts exactly that, and the negative control for it perturbs one
  side's derivation so the two codes diverge: `449979` against `095624`. Without
  that control the assertion could have been comparing a value with itself.

  It also asserts the new device ends up on the same account with its *own*
  master key and credentials in its own keychain — linking joins an account, it
  does not clone a phone.

  This closes the gap the previous entry named and left open: `confirmLink` was
  the third site with the publish-before-persist order and the only one fixed
  without a test. It has one now, by the same fault injection — the disk refuses
  the prekey write, and nothing is published.

- **The safety number was computed for contacts whose key we do not have.**
  `recoverAccount` restores contacts from the backup blob with an empty
  identity key on purpose — restoring one would let a stolen phrase pin a
  contact to a key of the thief's choosing, so it is trust on first use again
  and the safety number is what closes it.

  Two of the three paths that meet that empty key already refused:
  `safetyQrFor` returns null, `matchesSafetyCode` returns false. The third
  hashed it anyway. `safetyNumber(ourKey, empty)` is a perfectly well-formed
  sixty digits that depends on our own key alone — so every restored contact
  showed the *same* number, none of them matched what the other side computed,
  and `SafetyNumberScreen` enables "mark verified" whenever the number is
  non-null. A verification aid that verifies nothing, on the one screen in the
  app whose entire job is to require a human decision.

  The same shape as the HTTP-but-not-socket fix and the recording-but-not-
  playback one: a rule applied on two paths out of three. It returns null now,
  which the screen already handled, because groups have no safety number
  either.

- **Prekeys were published before the secrets reached the disk.** `docs/STATUS.md`
  has carried the rule since the top-up path broke it: published key material
  must reach disk first, or the server hands out keys the device cannot use.
  Both account paths did it in the wrong order — `publishKeys` ran, and the
  secrets were persisted on the next line.

  Three paths, not two: `createAccount`, `recoverAccount` and `confirmLink`.
  All three had it backwards, and the last two carried a comment saying the
  persist came first while the publish sat above it.

  In `createAccount` the blast radius is small: a failure in between orphans an
  account nobody has heard of. In the other two it is not. Both join an account
  that already exists and that people are already talking to, so a failure
  between the publish and the write leaves the server handing out prekeys
  nobody holds, and every contact who opens a session with one produces
  messages that device can never read.

  Fault injection covers all three — the disk refuses the prekey write, and the
  test asserts nothing was published. `confirmLink`'s was written one commit
  later, along with the store-level linking test it needed.

- **The two-device harness had never isolated anything.** Written last turn,
  it captured each device's keychain and database file inside the `vi.mock`
  factories, on the theory that a factory runs once per module graph. It does
  not — `vi.resetModules()` does not re-run a mock factory, so every graph in
  the file shared the first device's storage.

  The tests passed anyway, for a reason worth writing down: each store keeps
  its vault, identity and manager in memory after `createAccount`, so nobody
  ever re-read the disk they were all trampling. Real accounts, real delivery,
  real assertions — over a fiction. What caught it was adding a device that had
  to boot to `onboarding`, which is the one assertion that has to read the disk
  to pass.

  The lookup is per call now, against a pointer `boot()` sets; the database is
  still bound once at `openDatabaseAsync`, which is the part that has to
  survive two sockets interleaving. Three assertions guard it: two accounts
  that differ, and two keychains each holding their own distinct master key.

  The file also signs each booted store out at the end. Nothing in the app
  closes a socket except `signOut`, so eleven devices were left reconnecting to
  a server `afterAll` had killed — for the rest of the run, through every file
  after this one. `fileParallelism` is off precisely so files do not fight for
  the CPU.

- **Two real stores now talk to each other through the real server.** The
  online suite drove one device; the half it could not reach is the one where
  two devices have to agree. `integration.test.ts` already proves a sealed
  message survives the round trip, but it drives the crypto directly — nothing
  had ever driven `startConversation`, `send` and the socket's delivery path
  through the store the screens actually call, which is where two components
  can each be right while nothing arrives.

  Both mock factories now capture the keychain and the database file when the
  module graph is created rather than reading a global at call time, which is
  what lets two devices exist in one process without reaching into each
  other's storage once their sockets start interleaving.

  Three properties, none of which had a test above the crypto layer: a message
  arrives in a store that had never heard of the sender; the *reply* arrives,
  which runs different code because that side accepted the session rather than
  initiating it, and a messenger that works one way is exactly what unit tests
  on both halves will let through; and both ends derive the same safety number,
  without which every verification in the product is theatre.

  A fourth covers the handle path end to end: claim a handle, follow it, verify
  the inclusion and consistency proofs, write the checkpoint down — and then
  refuse the same lookup when the server stops answering with proofs, which is
  the downgrade that would make a later key swap invisible.

  Two things went wrong writing it, and the code was right both times. The
  downgrade test first failed because the test server ran with no
  `TILDRA_TRANSPARENCY_KEY`, so there was no log and every lookup came back
  unproven — the client cannot refuse a downgrade it has never seen an upgrade
  from, and the server warns about exactly this at startup. And the assertion
  that the send worked was `error === null`, which is not the same claim: that
  field collects anything from a prekey rotation to a socket blip, and a run
  where one of those fired failed a test that was about the send. It asserts
  the message's own state now — the row alone proves nothing, because `send`
  leaves a failed message on disk on purpose so the user can see what did not
  go out.

- **"Does not linger on disk after playback" was true of one path out of four.**
  `expo-audio` plays from a uri, so a received voice note is decrypted and
  written to the cache directory before it can be heard. `VoiceBubble` deleted
  that file when playback reached its own end — and only then. Pressing stop
  removed the player and returned, keeping the file *and* leaving the position
  poll running for the life of the app. Leaving the conversation removed the
  player and kept the file. A player that failed to open kept it too, because
  the audio is written before the player exists.

  So the fourth disk finding in a row, and the first one where the code had a
  comment claiming otherwise. `db.ts` proves by dumping every row that a
  forensic image finds nothing legible; a stopped voice note sat next to it in
  the clear.

  The lifecycle moved to `media/playback.ts`, which is the point as much as the
  fix. A screen cannot be tested here — there is no React Native test renderer,
  and STATUS has said so for a long time — but this was never screen logic. It
  is a lifecycle with one invariant, and out of the component it has twelve
  tests. Cleanup is one idempotent `stop()` because three things call it: the
  poll noticing the end, the user pressing stop, and the unmount, and two of
  those can land in the same tick.

  The player double throws on a second `remove()`, the way the real one does,
  and reports `playing: false` before the first frame as well as after the last
  — which is why the end condition needs `currentTime > 0` and why deleting on
  `!playing` alone would take the audio out from under a note that had not
  started yet. Five negative controls, all red.

- **The app would not start without a network.** Everything in `startSession`
  that touches the server is deliberately non-blocking, and each one says why
  in a comment: the socket reconnects on its own, push registration is best
  effort, the auditor check "must not hold up the app starting". One call was
  awaited anyway — `publishMailboxes` — and it took the whole startup down with
  it. A plane, a tunnel or an hour of server downtime looked exactly like a
  broken install: `bootstrap` threw, the phase went to `error`, and the user
  could not read messages already sitting decryptable on their own device.

  It is fired rather than awaited now, and reported rather than thrown. It
  still has to happen or nobody can reach this device, so a failure is retried
  when the socket reports it is open — the app's existing signal that the
  network came back. It also moved to after the socket is constructed, so the
  subscribe that follows a successful publish reaches a socket that can
  remember it; it used to run against `socket` still undefined.

  Found by writing the suite `bootstrap.test.ts` says it is deliberately not:
  "a device with credentials goes on to open a socket and publish mailboxes,
  which belongs in the integration suite that already runs a real server".
  `state/__tests__/online.test.ts` is that suite, and it was the last item on
  the list of code with no tests. Real registration against the real Go server,
  a real vault, a real socket; `expo-secure-store` is a map and `expo-sqlite` is
  `node:sqlite` over a file, so a cold start is a fresh module graph opening the
  database the last one wrote.

  Three of the seven tests exist because a negative control said the version
  before them proved nothing:

  - "says it is not reachable" passed against the *broken* build, because a
    bootstrap that throws sets an error too — it just sets `phase: 'error'`
    with it. It asserts the app is still usable while it says so.
  - Removing the publish's error reporting entirely changed nothing
    observable, because with a dead server the socket reports the outage
    itself. So there is now a test for a server that answers, opens the socket
    and *then* refuses the registration — the one case where nothing else is
    watching and the device is silently unreachable.
  - The retry test went through two wrong shapes before it was a test. First
    it started a *second* server on the port the app was pointed at, which
    cannot work: `tildrad` keeps its state in memory here, so a second process
    has never heard of the account and answers 401. Then it forwarded to the
    same server through a TCP proxy opened late — the honest shape of "the
    network came back", and still not a test, because it depends on the
    socket's reconnect backoff escalating to 20- and 30-second delays. It
    passed locally and timed out in CI. The failure is injected now: the first
    registration is refused and the rest are real, against a server that is up
    the whole time. Same wiring, about a second, nothing racing.

- **A type guard that answered true for `constructor`.**
  `isSupportedLocale` was `value in LOCALES`, and `in` walks the prototype
  chain. `constructor`, `toString`, `hasOwnProperty` and `__proto__` all passed
  it. Because it is a *type guard*, TypeScript then narrowed those strings to
  `Locale`, and `strings` handed back a function or `Object.prototype` instead
  of a table — every label in the interface rendering as `undefined`, with the
  compiler satisfied the whole way down and nothing raised anywhere.

  Honestly: not reachable today. The only caller is `resolveLocale`, and the
  only tag comes from `Localization.getLocales()`, which returns real BCP-47.
  What is wrong is that an exported guard lies, so anyone who later points it
  at a stored preference, a language picker or a deep link inherits a blank
  app that typechecks. Own keys only now.

  The first fix for the second half was wrong, and the test said so before the
  commit did: `strings` fell back with `?? en`, which never fired, because
  `LOCALES['constructor']` is the `Object` function and perfectly truthy. It
  goes through the same guard now — one definition of "is a locale", used by
  both.

  The guard is checked against every name on `Object.prototype` rather than the
  three anyone would think to write down, which is the same reason the Merkle
  verifier is checked over every index rather than a handful.

  Two more things the compiler cannot see are now tested. `const tr: Strings`
  guarantees the Turkish table has every key; it does not guarantee any of them
  is non-empty, and `welcomeTitle: ''` typechecks and renders a blank screen.
  And a new key added to both tables with the English text pasted into the
  Turkish one reads as finished work — the only string deliberately shared is
  the brand name, and the test says so by name.

- **So was every photo, five times over.** `saveAsync` writes each encode to
  the cache directory and returns a uri. `compressToBudget` calls the encoder
  once per quality step, and nothing deleted any of them — so sending one photo
  left up to five unencrypted copies of it in app storage, and setting an
  avatar left five more. The worst case was the failure path, where no quality
  fit: every step ran, and every file stayed.

  The cache directory is not a wipe. The OS may reclaim it or may not, and it
  was the one place a plaintext copy of a message the user sent survived
  everything the vault does.

  The encode is one shared function now — `renderJpegBytes` — rather than the
  same fifteen lines in `photo.ts` and `avatar.ts`. That is the point as much
  as the delete is: a fix applied to one path and not its twin is this
  project's most repeated mistake, and these two were already a copy of each
  other. A test asserts both pickers come out with nothing on disk, and the
  negative control for it splits them apart again to prove it would notice.

  Found by writing the first tests `media/photo.ts` has ever had.
  `avatar.test.ts` covered `compressToBudget`, the arithmetic; the platform
  half of both pickers was untested, and that is where the bug was.

- **Every voice message ever recorded was still on the disk, unencrypted.**
  The platform writes the microphone capture to app storage as a plain .m4a.
  `stop()` read it, encrypted the bytes, sent them — and left the file. So did
  `cancel()`, which is worse: the user slid to cancel and the audio stayed
  anyway. Nothing anywhere deleted it.

  `db.ts` goes to real lengths to make sure a forensic image of this device
  finds nothing legible, and there is a test that dumps every row to prove it.
  This walked around all of it. `VoiceBubble` already deletes the file it
  writes to play a *received* note, with the comment "the plaintext audio does
  not linger on disk after playback" — recording was the other half of that
  sentence and nobody wrote it.

  Deleted now on every path out: sent, cancelled, mis-tapped, and in a
  `finally` so a read that throws does not leave it behind either. A file that
  will not delete does not turn a sent message into a failed one.

- **The five-minute cap only shortened the number, not the recording.** At the
  cap the metering interval cleared itself and the recorder kept running. The
  duration was clamped with `Math.min`, so a twenty-minute hold produced
  twenty minutes of audio labelled `5:00`, under a waveform drawn from the
  first five.

  That duration is not cosmetic: it travels in the message rather than the
  blob, and it is what `VoiceBubble` renders and what `playbackProgress` uses
  — so the receiver saw a note that kept playing long past the end of its own
  progress bar. The validation in `attachment.ts` did not catch it either,
  because its ceiling is an hour and the sender was reporting five minutes.

  The cap stops the recorder now. Stopping is memoised as a promise rather
  than a boolean, because the cap and the user releasing the button can both
  reach it, and `recorder.uri` is only trustworthy once the recorder has
  actually finished — a flag would let the second caller past mid-flush.

  Both found by writing the first tests `media/voice.ts` has ever had.
  `waveform.ts`, the arithmetic, was already covered; what was not was the
  part that touches the microphone, the clock and the file. Two of those three
  were wrong. The recorder double throws when stopped twice, the way a real
  one does, so "stopped once" is observed rather than assumed.

- **The wipe gave up halfway, twice, on the same two lines.** `eraseKeystore`
  was two bare awaits in a row — delete the master key, then delete the
  credentials. A keychain that refused the first call meant the second never
  ran, so the credentials stayed: a live server session, on a device the user
  had just asked to wipe. That is the same shape as the `eraseAll` bug below,
  one level further down, and the earlier fix did not look inside.

  Both items are attempted independently now, credentials first — the master
  key only opens local data the database wipe has already removed, while the
  credentials are something whoever ends up holding the phone could resume. It
  still throws when either did not go, because a wipe that only partly
  happened must not be reported as one that did.

  And the caller had the same defect for the same reason. `signOut` awaited
  `eraseKeystore()` unguarded, so a throw stopped everything below it:
  `runtime = null` and the state reset never ran, leaving a live runtime and a
  signed-in screen for an account whose database had just been erased. Guarded
  now, with the failure folded into the one the user is already shown.

  Found by writing the first tests `storage/keystore.ts` has ever had. One of
  them was too weak and the negative control said so: asserting the error
  mentioned "credentials" passed against the old code too, because the
  platform's own exception names the item it refused.

  Two of those thirteen tests are not about erasing at all and matter as much.
  A second run must return the *same* master key — a `loadOrCreate` that
  quietly creates a second one turns every byte on the device into noise, with
  no error where it happens. And `keychainAccessible:
  WHEN_UNLOCKED_THIS_DEVICE_ONLY` must be on every call: that option is the
  entire basis for the claim that the key never reaches iCloud Keychain or an
  encrypted backup, and until now it lived only in a comment. Dropping it from
  one call site changes no type and broke no test.

- **The wipe did not reach the lock screen.** `presentLocalNotification` puts
  the contact's name in the title and the decrypted message in the body — on
  purpose, because the device knows both and the push service must not. That
  is the right trade while the account exists and the wrong thing to leave
  behind once it does not.

  `signOut` deleted the push token server-side, erased the database and
  dropped the master key. Nothing dismissed the notifications already on the
  device. So a user could delete their account, hand the phone over, and the
  lock screen would still be showing a contact's name and the plaintext of the
  last message — the exact data the entire stack exists to protect, sitting in
  the one place the wipe never looked.

  The only dismissal function that existed, `dismissWakeNotifications`, is not
  a wipe and cannot become one by accident: it matches `data.type === 'wake'`,
  and the named notifications are posted with `data: { accountId }`, so they
  were never in scope. A test asserts that the message body survives that call,
  so anyone who reaches for it on the sign-out path is told why it is not
  enough.

  `unregisterForPush` now clears the shade before it touches the network, is
  called unconditionally rather than only when a client exists — a device
  whose bootstrap never finished has no client and can still be holding
  notifications — and guards each step separately, so a notification centre
  that will not enumerate does not also cost the server-side revocation.

  Same family as the `eraseAll` bug below, found the same way: by writing the
  first tests `push/register.ts` has ever had.

- **A stored ratchet is only correct if it still decrypts.** The session and
  group-key rows carry the most consequential state on the device, and the
  useful assertion about them is not that the fields match after a round trip
  — a serializer that drops a chain key passes that by inspection and wedges
  the session on the next message.

  So the tests run the real thing. Alice encrypts, Bob's ratchet goes through
  the vault and SQLite, comes back, and has to open the message: fresh,
  mid-conversation, with a message that arrived out of order and sits in the
  skipped-key cache, and across a DH ratchet step where a message overtaken
  before the step still has to open afterwards. Group sender and receiver
  chains the same way, including that a restored sending chain advances
  rather than rewinding — a repeated iteration number in a group chain is key
  reuse.

  Six deliberate breakages of the database paths and three of
  `serializeRatchet`. The one that stayed green was the previous chain
  length, because none of the tests crossed a ratchet step with storage in
  the middle; the test that covers it exists because the control found that,
  not because I thought of it.

- **"Delete my account" left the account on the device.** `Database.eraseAll`
  is the local half of it — the header says "pairs with `eraseKeystore()` for
  a full account deletion" — and its statement list named a `prekeys` table
  the schema does not have. Prekeys live in `meta`. SQLite stops at the
  offending statement, so messages and sessions went and the contact list,
  group membership, group keys and `meta` stayed.

  Then it threw, and `signOut` called it on the line before `eraseKeystore()`
  with nothing catching anything. So the master key was never erased either:
  a user who asked to delete their account kept the data *and* the key that
  opens it, on a device they had been told was wiped, and the app stayed
  signed in.

  Both are fixed. The keystore is now erased even when the wipe fails —
  data without its key is unreadable, which is closer to what was asked for
  than keeping both — and the failure is reported after the wipe rather than
  instead of it. The test asserts the whole database is empty rather than
  listing the tables it remembers, so the next table added to the schema and
  forgotten here fails it.

  Found by writing the first tests `storage/db.ts` has ever had. 624 lines,
  every message, session and group on the device, and nothing had run against
  it — the earlier sweep for untested modules missed it because a test
  imported one of its *types*.

- **What a forensic image would see is now a test, not a claim.** `db.ts`
  says every column that would say who this device talks to is encrypted or
  reduced to a blind index. That is checked by writing a contact, a message,
  a group and a meta row, dumping every row of every table, and asserting
  that no account id, handle, display name, message body or group name
  appears anywhere in them. A column added later without encryption fails it
  without anyone remembering to update the test.

  The blind index is also checked for the property that makes it one: the
  same contact keys differently under a different master key, so a stolen
  database cannot be used to confirm a guess about who a row belongs to.

  Real SQLite, through `node:sqlite` rather than `expo-sqlite` — a different
  binding to the same engine, so every statement, index and constraint runs
  for real. What it does not exercise is Expo's binding.

- **`ON DELETE CASCADE` on `messages` has no caller.** Nothing deletes a
  single conversation; the only deletion paths are `deleteMessagesOlderThan`
  and `eraseAll`. Not a bug, but the schema implies a feature that does not
  exist.

- **`state/app.ts` is testable after all, and the reason it looked otherwise
  was two imports.** It reaches `react-native` transitively, which vitest
  cannot parse — but only through `expo-secure-store` and `expo-sqlite`, and
  nothing else in its graph is native. Replacing those two is enough to import
  the store and drive it.

  So `bootstrap` now has tests, which matters because the file's own header
  says the ordering is not incidental. Eleven of them, over the paths that do
  not reach the network: a fresh device stopping at onboarding with the vault
  and database it will need seconds later, credentials without an identity,
  an identity blob of the wrong length, an identity that will not decrypt,
  missing prekeys, a keystore that throws, a device with no secure storage at
  all, and the locale being applied before the first thing that can fail —
  because the error a failed startup shows has to be in the user's language.

  The worst outcome for startup is not an error screen, it is a spinner:
  nothing times out a bootstrap, so a phase left at `starting` is permanent.
  Two tests exist for that alone.

  Everything except the database is real — a real vault, a real master key, a
  real identity, real decryption. Seven deliberate breakages; the one that
  stayed green was mine, not the code's: "keeps what onboarding will need"
  asserted that a runtime object existed and nothing about what was in it, so
  nulling the database sailed through. It checks the vault and the database
  by capability now.

  Still untested: everything in that file that reaches the network, which is
  most of it.

- **The fix for that was incomplete, and the audit caught it rather than a
  user.** `ApiError.detail` was attributed; the socket's error frame was not.
  `frame.error` is also the server's text, and it was wrapped in a plain
  `Error`, which the funnel rendered as-is. So the HTTP path was closed and
  the WebSocket path stayed open, which is the usual shape of a half-fix.

  It now arrives as `ServerFrameError` — a distinct type because the
  destination has to be able to tell — and goes through `serverText` like the
  other one. The test that catches this class of thing is not a case, it is a
  property: every error type carrying words the server picked must come back
  attributed, asserted over both locales.

  `describeError` moved to `state/errors.ts` to be testable at all. `app.ts`
  reaches `react-native` transitively, so nothing in it can be imported by a
  test, and the single function deciding what every failure says should not
  be untestable because of what its neighbours import. The identity codec
  moved to `storage/identity.ts` for the same reason, and gained the length
  check it never had: a truncated vault entry used to decode into a key pair
  of the wrong size, whose first symptom was a signature failing somewhere
  far from the cause.

- **The server got to choose words the user reads.** `ApiError.detail` is
  whatever the server puts in its `error` field, and `describeError` returned
  it directly — so it became the body of a banner the app itself titled. Every
  screen renders it that way.

  This is not a cosmetic problem. The threat model's answer to a swapped key
  is that the user sees a warning and acts on it, so a server that can write a
  calm, plausible sentence into that banner is attacking the control the whole
  design leans on. "Your contact's new key was verified by Tildra" costs the
  server nothing.

  `serverText` attributes it, flattens it and bounds it. Flattening matters
  more than it looks: a newline lets the server lay out what reads as a second
  element of the interface, and a right-to-left override (U+202E) displays a
  different sentence from the one stored. Found by reading `describeError`
  while looking for something else, which is the usual way.

- **Two bugs were hiding behind `socket.ts` having no unit tests.** It was
  covered only by the integration suite, which drives it against a real
  server and can therefore only reach the states that happen when things go
  right. Both bugs live in the states that happen when they do not.

  A socket kept delivering after it was no longer the live one. `close()`
  returns before the WebSocket has finished closing, and `onmessage` checked
  nothing, so an envelope already in flight at logout still advanced a
  ratchet, wrote session state and surfaced as a message in an app that had
  torn that session down. The same hole let a socket a reconnect had already
  replaced deliver into the session that replaced it. Dropping those costs
  nothing, because the ack is only sent after the handler succeeds: an
  envelope that was never handled is still queued on the server.

  Acks were not durable, despite a comment saying they were. `pendingAcks`
  was documented as holding envelopes "so a drop mid-ack does not lose them",
  and `ack()` removed the entry *before* trying to send — so when the socket
  died in between, the record was gone and the reconnect had nothing to
  replay. The server then redelivered a message the client had already
  stored. Entries are now cleared only on a send that actually went out, and
  nothing is recorded until the handler has returned, so a replayed ack can
  never ack an envelope that was still being handled.

  Nineteen tests, against a fake WebSocket, and nine deliberate breakages to
  check they bite. One of those breakages did not go red, which is how the
  twentieth test got written: closing during a backoff wait was not covered.

- **A test that asserts an absence needs a moment it can prove has passed.**
  `TestNoPushWithoutARegisteredToken` sent a message to a device with no push
  token, slept 300 milliseconds, and checked that no notification had gone
  out. The wake runs detached from the request, so on a machine slow enough
  that it had not run yet, "nothing was sent" was true because nothing had
  happened at all — the test passed while measuring nothing.

  `Server.WaitForWakes` is the synchronisation point it was missing. The
  counter is raised inside `wake`, synchronously, before the request that
  triggered it is answered, so a caller holding a response has already seen it
  rise and there is no window where the wait returns early. The positive test
  uses it too, and no longer polls a three-second deadline.

  Demonstrated rather than argued: with the server broken to notify a device
  that has no token *and* the wake delayed by a second and a half, the old
  sleeping test passes and the waiting one fails.

- **A test fixture shortened a product timer, and it broke fifteen other
  tests.** `SessionManager` gives up on a call nobody answers after
  `CALL_RINGING_TIMEOUT_MS`, 45 seconds. One test asserts that, and rather
  than wait three quarters of a minute the fixture built *every* device in
  `manager.test.ts` with `ringingTimeoutMs: 700`. So every call test required
  a full round trip through a real Go server — register, ring, answer, deliver
  — to complete inside 700 milliseconds, or the manager correctly gave up and
  the call ended underneath the test.

  This is the failure I chased for four commits and diagnosed wrong three
  times. It presented as undelivered envelopes, because that is what it looks
  like from the outside: the answer never arrives, neither side reports an
  error, and every structural probe comes back clean — the addressing agrees
  byte for byte, both sockets are open, the envelope is enqueued before live
  delivery is attempted, and `Serve` drains every registered mailbox on
  connect. All of that was true. Nothing was lost. The call had been
  cancelled, by design, before the answer could matter.

  What identified it was the shape of a failing run rather than another probe:
  six tests failed and seventy-eight passed, and all six were call tests. A
  slow machine does not sort its victims by feature.

  The fixture now defaults to 30 seconds and the two tests that are about the
  timeout ask for a short one. Confirmed both ways under an artificial load
  average of 15 to 27, far worse than the conditions that produced the
  original failures: with the fix all six pass, and with 700ms put back a
  failure reappears.

  The lesson worth keeping is not about calls. A test fixture that overrides a
  production constant is applying that override to every test that shares the
  fixture, including the ones written later by someone who never read it. The
  override belongs at the test that needs it.
- **A bound with no test is a number in a file.** `MAX_SKIP`,
  `MAX_SKIPPED_KEYS` and `SKIPPED_KEY_TTL_MS` had been there from the start,
  are quoted in `docs/PROTOCOL.md` §3 as what bounds a device compromise, and
  nothing exercised any of them.
- **Test the thing that crosses the wire, not the helper.** `bucketSize` and
  `pad` were well tested and nothing checked an actual envelope. Writing that
  test found the claim was true and my expectation of it was wrong — the
  observable size is the bucket plus a constant header, not the bucket — which
  is the kind of thing worth knowing before reading a packet capture.
- **The log is a place things leak into.** The middleware was careful never
  to record the client IP and recorded `r.URL.Path` instead — and the paths
  here carry account ids, device ids, handles, mailbox ids and the lookup id
  that addresses a recovery blob. It logs a route label from an allowlist now,
  and three tests hold it there.
- **A privacy claim with no test is a comment.** The push payload has always
  been content-free and the `Notifier` interface takes only a token, so the
  server cannot pass content even by mistake — but nothing checked the bytes
  that go to Expo, and one well-meant "New message from Ayşe" would have
  broken a claim in the README and the threat model with nothing noticing.
  `internal/push` now asserts the exact payload. The same question is worth
  asking of every other claim in the table above.
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
