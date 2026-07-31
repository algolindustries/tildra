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
| Push notifications with a content-free payload, pinned by a test against the bytes actually sent | done |
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

Counts at time of writing: 656 client tests, Go suite clean under `-race`, both
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
- **The unlinkability claim now has tests.** `deriveMailboxSecret` and
  `contactInbox` carry what `docs/PROTOCOL.md` §5.1 promises — that the
  contact inbox is a one-event leak per conversation and everything after it
  is unlinkable — and neither had a test.
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
