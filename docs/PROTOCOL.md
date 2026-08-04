# The Tildra Protocol

Version 0.1 (draft). This document is normative for implementations. Where it
disagrees with the code, the document is right and the code is a bug.

## 0. Notation

| Symbol | Meaning |
|---|---|
| `IK` | Long-term identity key pair (Ed25519 for signing, X25519 for DH via birational map) |
| `SPK` | Signed prekey (X25519), rotated every 48h |
| `OPK` | One-time prekey (X25519), consumed on use |
| `PQSPK` | Signed post-quantum prekey (ML-KEM-768), rotated every 48h |
| `PQOPK` | One-time post-quantum prekey (ML-KEM-768), consumed on use |
| `EK` | Ephemeral key pair, generated per handshake |
| `DH(a, B)` | X25519 scalar multiplication |
| `KEM.Enc(pk)` | ML-KEM-768 encapsulation → `(ct, ss)` |
| `‖` | Concatenation |

All hashing is SHA-256. All KDFs are HKDF-SHA256. All AEAD is
XChaCha20-Poly1305 (24-byte nonces, so random nonces are safe).

**Signed prekey rotation.** A signed prekey serves every sender who fetches a
bundle, so its security argument is a bounded lifetime: replaced every 48
hours, checked at startup and once a day.

Rotation is not instantaneous from outside. Somebody may have fetched the old
bundle a minute before it was replaced and be about to send with it, so the
outgoing pair is retained for one more window and `acceptSession` will complete
a handshake against either. Exactly one generation — two would double the
window in which a stolen prekey is still useful, which is what rotation exists
to shrink.

One-time prekeys are not touched by a rotation. They are consumed individually
and topped up on their own schedule, and discarding a hundred unused ones every
two days would push every handshake in between onto the signed prekey and cost
them their replay resistance.

Whatever changes the secrets — a rotation or a top-up — has to reach disk
before the public halves are useful. Publishing a key whose private half is
lost on the next restart looks, to every sender who draws it, exactly like the
recipient no longer exists.

## 1. Identity

A Tildra account is a **key**, not a phone number.

Registration produces:

1. A device identity key pair `IK`.
2. A random 128-bit account ID, displayed to humans as a 26-character
   Crockford-base32 string.
3. An optional, user-chosen **handle** (`@ayse`), which is a mutable pointer in a
   public directory. Handles are convenience, never authority — the identity key
   is the identity.

The server stores: account ID, public identity keys, prekey bundles, and an opaque
push token. It does not require or store a phone number or an email address.

### 1.1 Account recovery

There is no server-side password reset, because the server has nothing to reset.

**The phrase is the account.** A 24-word BIP-39 phrase is generated at
registration and everything else follows from it:

```
seed       = Argon2id(phrase, salt = "Tildra_Recovery_v1", m = 64 MiB, t = 3, p = 4)
IK         = Ed25519 from HKDF(seed, info = "Tildra_RecoveryIdentity_v1")
backup key = HKDF(seed, info = "Tildra_RecoveryBackup_v1")
```

An earlier draft of this section had the blob carry a "device-provisioning
secret" and left the identity unrecoverable. That is not recovery. An account
is a key, so restoring everything *except* the key gives the user their contact
list back under a new identity — and every contact sees a key change, which is
indistinguishable from the attack this whole design exists to make visible.
Recovery that fires the alarm is not a feature. The alternative also needed the
server to let a device join an account without an existing device approving it,
which is a second way into an account, and a second way in is a second thing to
attack.

**The cost is that anyone holding the phrase is you.** It is exactly as
powerful as an unlocked device. The onboarding screen has to say that in those
words rather than calling it a backup.

Two derivations from one seed, so handing the backup key to something does not
hand it the identity. The blob carries the contact list and group memberships —
**not messages**: a blob on a server that holds what was said is the thing this
design is arranged to avoid. A server that serves the wrong blob fails to
decrypt rather than restoring somebody else's contacts — under the backup key,
for the reason two paragraphs below. This said "encrypted with the account id
as associated data" until 2026-08-04, which is the abandoned design and is
contradicted further down the same section; nothing in the code has ever bound
it, and binding it is what the paragraph below explains cannot work.

**Every value here is pinned to a recorded vector.** A recovery phrase is
written on paper, so a change to the salt, a label, an output length or what
normalisation does to the words locks out every phrase already written down —
permanently, silently, and with a suite that generates its own phrase every run
staying green throughout. `crypto/__tests__/recovery.test.ts` holds a fixed
phrase and the four values it has to keep producing.

Argon2id is not load-bearing for a 24-word phrase, which already carries 256
bits. The parameters are chosen for the weaker inputs a later version might
allow — and for the user who writes down twelve words instead of twenty-four.

**Where the blob lives.** Recovery needs the account id to log in, and the
account id was on the device that is gone — so the blob cannot be addressed by
account. A third derivation gives it an address:

```
lookup id = hex(HKDF(seed, info = "Tildra_RecoveryLookup_v1")[0..16])
```

`PUT /v1/recovery/{lookupId}` is authenticated, because an account publishes
its own. `GET` is **not**, and has to not be: the caller has nothing to
authenticate with yet. What protects the blob is that the id is 128 bits only
the phrase produces and the contents are encrypted under a different
derivation of it, so guessing an id yields ciphertext. The first account to
claim an id keeps it, which closes the case where an id leaks later.

The unauthenticated read is a scraping surface and this deployment has no rate
limiting. The blob is bounded at 256 KiB so it stays cheap to serve; the
missing limiter is in `docs/THREAT_MODEL.md`.

**The blob is not bound to the account id.** Binding it as associated data is
the obvious thing to do and makes recovery impossible: the account id is
exactly what the recovering device does not have, so it cannot supply it in
order to decrypt the thing that would tell it. The account and device ids are
*inside* the ciphertext instead — not beside it, so guessing a lookup id
teaches nobody an account id. What stands in for the binding is the key: a blob
that opens under this phrase's backup key was written by somebody holding this
phrase.

**Contacts come back without their keys.** A restored conversation is trust on
first use again, and the safety number closes that. Restoring an identity key
out of the blob would mean a stolen phrase could pin a contact to a key of the
thief's choosing, which is worse than asking the user to verify again.

The blob is republished when what it holds changes — a new contact, a new
group — rather than on a timer. A stale blob recovers somebody into an empty
app.

**What recovery does not bring back, and what that costs.**

A recovered device has the account and the contact list. It has no session
state: no ratchets, no per-session mailboxes, no sender keys. Three
consequences, all of them visible rather than silent:

- *Sending works.* No session means the next message establishes one from a
  fresh bundle, which is the ordinary first-contact path.
- *One message from a contact with a live session is lost, and then it
  repairs itself.* Mailbox registration lives on the server, so their address
  is still valid and their send succeeds — the message arrives at a device
  that cannot decrypt it. The recovered device acknowledges it (redelivering
  an undecryptable message forever helps nobody), reports it, and handshakes
  back. That init replaces the dead session on their side, and both directions
  work from their next message. The repair is the ordinary first-contact path
  and runs only for a sender whose identity key is already the one this device
  had stored, so it is not a new signal for anybody to forge.
- *Groups come back as membership, not as keys.* Sender keys belong to an
  epoch that ended with the device. A restored group is one you can send to,
  which distributes a fresh chain, and one you can read from once each member
  next distributes theirs.

There is deliberately no "my session is gone" message. The situation is
already unambiguous from a message that decrypts to nothing, and a message
that means "throw away our session" would be one more thing worth forging.

## 2. Session establishment — PQXDH-hybrid

Alice wants to message Bob. She fetches a prekey bundle for each of Bob's devices:

```
bundle = (IK_B, SPK_B, Sig(IK_B, SPK_B), PQSPK_B, Sig(IK_B, PQSPK_B),
          [OPK_B], [PQOPK_B])
```

The client **must** verify both signatures before proceeding. A bundle with an
invalid signature is a hard failure, not a warning.

Alice generates `EK_A` and computes:

```
DH1 = DH(IK_A,  SPK_B)
DH2 = DH(EK_A,  IK_B)
DH3 = DH(EK_A,  SPK_B)
DH4 = DH(EK_A,  OPK_B)        // omitted if no one-time prekey is available
(ct, SS) = KEM.Enc(PQOPK_B ?? PQSPK_B)

SK = HKDF(
  ikm  = 0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS,
  salt = 0,
  info = "Tildra_PQXDH_v1_25519_MLKEM768"
)
```

`AD = IK_A ‖ IK_B` is used as associated data for the initial message, binding the
handshake to both identities.

The KEM ciphertext `ct`, `EK_A`, `IK_A`, and the prekey IDs travel in the initial
message header. Alice deletes `EK_A` immediately after deriving `SK`.

**Why hybrid:** an adversary who breaks X25519 (quantum) still faces ML-KEM-768;
an adversary who breaks ML-KEM (cryptanalysis — it is young) still faces X25519.
Both must fall for the session to fall.

## 3. Message encryption — Double Ratchet

Standard Signal Double Ratchet, with two deliberate choices:

- **Header encryption is mandatory.** Message headers (ratchet public key,
  counters) are encrypted with a separate header key chain. A passive observer
  cannot correlate messages into conversations by watching ratchet keys.
- **Chain keys advance with a domain-separated KDF:**
  `CK' = HMAC(CK, 0x02)`, `MK = HMAC(CK, 0x01)`, and message keys are
  `HKDF(MK, info="Tildra_MsgKey_v1")` expanded to a 56-byte
  (32 key ‖ 24 nonce) block. There is no separate authentication key:
  XChaCha20-Poly1305 is an AEAD and derives its own Poly1305 key from the
  encryption key. This paragraph said 88 bytes as `32 enc ‖ 32 auth ‖ 24 nonce`
  until 2026-07-31, which describes an encrypt-then-MAC construction Tildra has
  never used — an implementer following it would have produced ciphertexts this
  client cannot read.

The two derivations either side of that one, which this section did not state
at all:

- **The DH ratchet step**, run whenever the conversation changes direction:
  ```
  HKDF(ikm = DH(our ratchet secret, their ratchet public),
       salt = current root key,
       info = "Tildra_RootKey_v1") → 96 bytes
     = root key' ‖ chain key ‖ next header key
  ```
- **The initial header keys**, from the PQXDH shared secret:
  ```
  HKDF(ikm = SK, salt = none, info = "Tildra_HeaderKeys_v1") → 64 bytes
     = initiator header key ‖ responder next header key
  ```

Skipped message keys are cached for at most 1000 messages / 7 days per session,
then dropped. This bounds the damage of a device compromise.

The age bound is enforced on activity, not by a timer: every message sent or
received on a session expires whatever has aged out of its cache. A session
with no traffic at all keeps what it holds until it next sees any — which is
the residue, and it is stated here rather than left to be discovered.

### 3.1 Post-compromise security

Every DH ratchet step (i.e. every time the conversation changes direction) heals
the session. An attacker who steals a device's state at time T loses the ability
to read messages after the next ratchet step they don't observe.

## 4. Groups

Telegram has no E2EE groups. This is the design that fixes that.

Tildra groups use **sender keys over pairwise sessions**:

1. Each member generates a per-group **sender chain** (a symmetric ratchet).
2. The sender chain key is distributed to every other member over their
   pairwise Double Ratchet session — so joining a group costs O(n) handshakes
   once, not per message.
3. Messages are encrypted once with the sender's chain key and fanned out by the
   server, which sees only opaque bytes and a group ID.
4. **Membership changes force a rotation.** When a member leaves or is removed,
   every remaining member generates a fresh sender chain. A removed member cannot
   read anything sent after their removal.

Point 4 is the one with a moving part, because membership is client-side: a
removal is a claim one device makes to the others, not a fact the server
enforces. So the group carries an **epoch**, and a removal bumps it. A
distribution arrives with the sender's list and the epoch it belongs to:

| Their epoch | What the receiver does |
|---|---|
| Newer than ours | Their list is the answer. Anyone it drops is removed here too: forget their chain, rotate ours, redistribute at the new epoch. |
| Equal to ours | Union. A member must not be able to drop somebody from everyone else's view of the group inside a routine rekey. |
| Older than ours | Ignore the list. A device that was offline for the removal cannot put the removed member back. |

That is what makes "every remaining member" true rather than "whoever pressed
the button". Without it a removal reaches only the remover: everyone else keeps
the removed member on the list they fan out to, and keeps the sender chain that
member already holds — so the removed member goes on reading everything except
the remover's own messages.

The cost, stated plainly: any member can remove any member. That is the same
authority every member already has to *add* one, and it is what client-side
membership means. Server-enforced admin roles would need the server to know the
member list, which is the thing §4 exists to avoid.

**A removed member is not told.** There is no "you are out" signal, because
there is none that somebody else could not also send — the same reason the
member list is not something the server can vouch for. So they go on writing
into a group that has rotated away from them, and every device still in it
receives a message it has no chain for.

That case is answered by dropping it. An undecryptable group message is
normally worth retrying, because a distribution can arrive after a message it
was needed for — the two ride different paths, one inside the pairwise ratchet
and one outside it, so either order is possible. But a sender who is not on the
member list of a group we do know is not late, they are gone, and retrying
means holding the envelope for its full lifetime and trying again on every
reconnect, for every message they send. The cost of dropping is a message they
genuinely sent before the removal that is only now being redelivered.

Removing somebody forgets **their** chain, not the whole group's. Forgetting
every chain takes the staying members' with it, and nothing prompts them to
send another distribution, so the group falls silent for whoever did the
removal — and each of their later messages becomes an envelope that cannot be
decrypted and so is never acknowledged, which the server then redelivers
forever.

A group message key is expanded exactly as a pairwise one is, under its own
label, and every message carries a signature over a domain-separated
transcript so one member cannot forge another's:

```
HKDF(ikm = group message key, salt = none,
     info = "Tildra_GroupSenderKey_v1") → 56 bytes = key ‖ nonce

signed bytes = "Tildra_GroupMsg_v1:" ‖ group_id ‖ u32(iteration) ‖ ciphertext
```

Group membership is stored client-side and mirrored on the server as an encrypted
blob. The server knows a group exists and how many mailboxes to fan out to. It
does not know the member list.

> Roadmap: migrate to full **MLS (RFC 9420)** once the ecosystem's Go and RN
> implementations are mature. The sender-key design above is a deliberate,
> documented interim — it has weaker post-compromise security for large groups
> than MLS's tree-based rekeying.

## 5. Sealed sender

A message envelope the server sees:

```
{
  to:        mailbox_id,        // recipient's rotating mailbox identifier
  ciphertext: bytes,            // sender identity is INSIDE this
  ts:        server_timestamp
}
```

The sender's identity is encrypted to the recipient's identity key, not attached
to the envelope. What stops this from being an open relay is ordinary
authentication: `POST /v1/messages` sits behind the bearer token, so the server
knows the request came from a real account.

That is weaker than sealed sender is usually taken to mean, and saying so is
the point of this paragraph. The envelope does not name the sender; **the
request does**. A server that wanted to could link every delivery to the
account that made it. Unlinkable delivery — a blind-signed token that proves an
account without naming one — would close that, and is **not implemented**. It
was described here as though it were, which is the kind of claim this document
exists to avoid; see §11.

The envelope itself is sealed to the recipient's identity key under an
ephemeral X25519 key, with both public keys bound into the salt so a captured
shared secret cannot be replayed against a different pair:

```
HKDF(ikm = DH(ephemeral secret, recipient DH public),
     salt = ephemeral public ‖ recipient DH public,
     info = "Tildra_SealedSender_v1") → 32 bytes
```

### 5.1 Mailbox addressing

A device listens on two kinds of address.

**Per-session mailboxes**, derived from the session secret and rotated daily:

```
session_secret = HKDF(SK, info = "Tildra_SessionSecret_v1")
mailbox_secret = HKDF(session_secret ‖ owner_account ‖ "/" ‖ owner_device,
                      info = "Tildra_Mailbox_v1")
mailbox        = "mb_" ‖ hex(HKDF(mailbox_secret,
                                  info = "Tildra_Mailbox_v1:" ‖ day_number)[0..16])
```

Both parties can derive both directions, so the sender knows where to deliver
and the recipient knows where to listen. These addresses are unlinkable across
days and across contacts — two conversations of the same user share nothing the
server can correlate.

Devices publish yesterday's, today's and tomorrow's mailbox. Clocks drift, and
a message sent at 23:59:58 must not land somewhere nobody is watching.

**A contact inbox**, stable and derived from the identity key:

```
contact_inbox = "mb_" ‖ hex(HKDF(identity_key, info = "Tildra_ContactInbox_v1")[0..16])
```

This exists because per-session addressing has a bootstrapping problem that no
amount of key rotation fixes: to deliver the *first* message, the sender needs
an address the recipient is already watching — but the per-session mailbox
derives from a secret the recipient cannot compute until that first message
arrives.

The cost is stated plainly: anyone holding a device's public identity key can
compute its contact inbox, and the server holds every identity key because it
publishes bundles. So **the server can see that someone opened a conversation
with a given device, and when**. It cannot see who. From the first reply
onwards the conversation moves to per-session mailboxes and that visibility
ends. This is listed under known limitations in `docs/THREAT_MODEL.md`.

### 5.2 Live subscription

Mailboxes come into existence as conversations do. A device that has been
connected for hours must be able to start listening on an address created a
second ago, so the delivery socket accepts a `subscribe` frame. The server
verifies ownership against its own mailbox table — a client's claim to own an
address is never taken at face value — and then drains anything already queued
there.

### 5.3 Profiles

A profile — display name, photo, and a short about — is **not** a server-side
record. It is a typed message (`ContentType.Profile`) sent to each contact over
their pairwise Double Ratchet session, encrypted exactly like chat text.

```
profile = frame(display_name, about, updated_at_seconds, avatar_bytes)
```

Consequences that are the point of doing it this way:

- The server has no profile endpoint and stores no name or picture. It cannot
  answer "who is account X" for anyone, including itself.
- A profile is sent automatically just before the first message to a new
  contact, and receiving one from a new contact sends ours back — so an
  introduction is mutual without a round trip the user has to think about.
- `updated_at` lets a receiver ignore a stale profile. Multi-device fanout plus
  redelivery means an older update can arrive after a newer one.
- Received names are sanitized: C0/C1 controls become spaces, and zero-width
  and bidirectional formatting characters are stripped. A display name renders
  next to a stranger's messages, so an RTL override there is impersonation.
- Avatars are capped at 96 KiB and bounded again on receipt, because the bytes
  came from someone else.

This is what makes Tildra non-anonymous without being non-private: the people
you talk to know exactly who you are, and the operator does not.

### 5.4 Attachments

A file gets its own key, generated per attachment and never reused:

```
padded      = plaintext ‖ random_padding   (to the next size bucket)
ciphertext  = XChaCha20-Poly1305(key, nonce, padded, ad = "Tildra_Attachment_v1")
digest      = SHA-256(ciphertext)
```

The ciphertext is uploaded and the server returns an ID. The reference —
`{id, key, nonce, digest, size, mimeType, ...}` — travels inside the message
that mentions the file, encrypted with everything else. So the server holds a
blob it cannot decrypt, and holding every blob it ever received gains it
nothing.

- The digest is over the **ciphertext**, so a substituted or corrupted download
  is rejected before its bytes reach the cipher.
- Padding is applied before encryption, because encrypted length is plaintext
  length otherwise, and file size alone identifies a great deal — a specific
  photo, or whether a voice note was two seconds or two minutes.
- No uploader is recorded. An account-to-blob mapping would recreate precisely
  the metadata sealed sender exists to remove, so the attachments table has no
  owner column.
- Blobs expire after 7 days. An attachment nobody fetched in a week is one
  nobody is going to.

**Voice notes** are attachments with two extra fields in the reference: a
duration and a 48-byte waveform, one bar per byte, 4 bits of loudness each — a
bar is 0–15. Both ride in the message rather than inside the blob, so a bubble
shows its shape and length the moment it arrives — needing a download to learn
whether a note is three seconds or three minutes makes the feature feel broken.

Both are bounded on receipt as well as on send, because they come from the
sender and are rendered directly. That means the waveform's **values** as well
as its length: a bar becomes a fraction of the bubble's height, so a byte above
15 is a bar taller than the bubble, drawn by whoever sent the message. The
renderer clamps too. Either check alone would do; a rule about untrusted input
that is enforced in exactly one place is one refactor from not being enforced
at all.

### 5.5 Linking a device

An account may hold several devices, each with its own identity key and its own
ratchet per contact. Adding one has to work without trusting the server, since
the provisioning channel *is* the server.

1. The new device generates its identity key and an ephemeral X25519 key, opens
   a channel, and displays `tildra://link?id=…&key=…&commit=…&server=…` where
   `commit = SHA-256(new identity public key)`.
2. An existing, signed-in device reads the channel, and checks **both** keys the
   server hands over against what it scanned: the identity key against `commit`,
   and the ephemeral key against `key`. **Both travelled over a camera, not the
   network**, so a substituted key fails here rather than later. The approval is
   sealed to the scanned ephemeral key, not the fetched one — otherwise the
   check is advisory and the server's copy is still the one in use.
The approval is sealed under its own label, with both ephemeral public keys
bound into the salt in the order the sealer computes them:

```
HKDF(ikm = DH(sealer ephemeral secret, new device ephemeral public),
     salt = sealer ephemeral public ‖ new device ephemeral public,
     info = "Tildra_Provisioning_v1") → 32 bytes
```

3. The existing device registers the new one and seals an approval to the
   ephemeral key: `{accountId, deviceId, approvedBy, signature}` over a
   transcript binding all three.
4. Both devices derive a six-digit pairing code:

   ```
   code = HKDF(shared ‖ account_id ‖ new_identity_key,
               info = "Tildra_PairingCode_v1") mod 10^6
   ```

   The user compares them. A server that aimed the device at a different
   account changes the transcript, so the two screens disagree.

   The code is the backstop, not the first line. An ephemeral key the server
   swapped is refused at step 2 without anyone having to compare anything; that
   swap used to reach this step, which meant a cryptographic guarantee was
   resting on whether a person actually reads six digits off two screens.

Channels expire in 5 minutes and accept exactly one approval: a second would
let a server that captured the first replace it after the codes had already been
compared. Accounts are capped at 8 devices, because every device multiplies the
fanout of every message the account receives.

Once linked, the new device is visible in the account's device list, so contacts
fan out to it automatically. It does **not** receive past messages: the ratchets
that could decrypt them exist only on the original device, and the server has no
key that would let it re-key anyone into their own history.

## 6. Transport

- TLS 1.3 only. No downgrade, no TLS 1.2.
- Certificate pinning in the mobile client, with a documented rotation procedure.
- WebSocket for real-time delivery; the socket carries an authenticated, but
  identity-blinded, session.
- **Padding:** all envelopes are padded to bucketed sizes (256 B, 1 KiB, 4 KiB,
  16 KiB, 64 KiB, then 64 KiB increments) so ciphertext length leaks little.

  What an observer measures is `bucket + a fixed header` — the ephemeral key,
  the nonce and the tag — the same constant for every envelope, revealing
  nothing. Four hundred distinct message lengths collapse into three
  observable sizes, and the gap between any two of them is a bucket boundary
  rather than a byte of message. Worth knowing before reading a packet
  capture and concluding the padding is missing.

## 7. Key verification

Two users verify each other by comparing a **safety number**: a 60-digit code
derived from both identity keys, `HKDF(sort(IK_A, IK_B), info="Tildra_SafetyNumber_v1")`.
The client shows a QR code for in-person verification.

If a contact's identity key changes, the conversation is **blocked from sending**
until the user acknowledges the change. Silent key changes are how server-side
MITM attacks succeed; we refuse to make that quiet.

Everything the user originates is covered, calls included: placing one and
answering one both sign something under an identity key and open a channel to
whoever holds the other end. An incoming call still rings — knowing somebody
tried to reach you is not the dangerous part — and the call screen labels the
peer as *changed*, but answering is refused until the change is acknowledged.

Note what does the blocking. Flagging a change **adopts** the new key: it is
written into the conversation so the safety number the user is asked to compare
is the one that is actually in use. From that moment the key comparison made on
every send passes, because it is comparing the new key against itself. The flag
is the only thing that still refuses, so a path that originates traffic and
does not read it is not blocked at all, however many key checks it runs.

### 7.1 Key transparency

Safety numbers only work if two people actually compare them. Key transparency
is the half that works without asking anyone to do anything.

Every binding of a handle to an identity key is appended to a Merkle log
(RFC 6962 hashing, including its leaf/node domain separation). The log signs a
tree head:

```
STH = (size, root_hash, timestamp,
       Sig(log_key, "tildra-sth-v1:" ‖ size ‖ root_hash ‖ timestamp))
```

Both sides re-derive these bytes from what the other sends, so the encodings
are part of the protocol and not an implementation detail:

```
leaf = SHA-256(0x00 ‖ u32(len(handle))       ‖ handle
                    ‖ u32(len(account_id))   ‖ account_id
                    ‖ u32(len(identity_key)) ‖ identity_key
                    ‖ u64(recorded_at))
node = SHA-256(0x01 ‖ left ‖ right)

size, recorded_at, timestamp: 64-bit big-endian; times in whole seconds.
Field lengths: 32-bit big-endian.
```

Length-prefixed rather than delimited, so that no two different bindings can
encode identically. The leaf does not commit to the entry's index: the index is
its position in the tree, which the inclusion proof already establishes, and
committing to it would mean a client could not re-derive the leaf from what a
lookup returns.

A handle lookup returns the binding, an **inclusion proof** against the current
head, and a **consistency proof** from the last head the client verified. The
client checks all three and stores the new head.

The binding, both proofs and the head must describe **one** snapshot of the
tree. A server that reads its head separately from the proofs it sends beside
it will, whenever a registration lands in between, hand a client a proof that
does not reproduce the signed root — indistinguishable, from the client's side,
from the log having been rewritten. Routine traffic must not be able to raise
this alarm, or nobody will believe it when it is real.

That leaves a server two options if it wants to substitute a key:

1. **Append it.** The substitution is then a permanent, public entry that any
   auditor — or the victim's own next lookup — can see.
2. **Fork the log**, showing one tree to the victim and another to everyone
   else. This breaks the consistency proof the moment those two views meet.

A client that has verified a log once will not accept a later response with no
proof at all. Dropping the mechanism silently would undo every check made
before it.

### 7.2 Gossip

Inclusion and consistency proofs stop a server rewriting history for *one*
client. They do nothing about a server that keeps two internally consistent
logs and shows a different one to each person. Catching that requires two
clients to compare what they were told.

Tildra uses the messages people already exchange as the transport. A device
that has verified a tree head attaches it to a message
(`ContentType.TransparencyGossip`); the recipient verifies the signature under
the log key it already trusts, and then asks the server to prove the two heads
are on the same log:

```
GET /v1/transparency/consistency?first=<smaller size>&second=<larger size>
```

Whichever head is smaller must be a prefix of the larger. Three outcomes are
treated as evidence of a split view:

1. Same size, different roots — no proof can reconcile those.
2. A consistency proof that does not verify.
3. The server declining to link two heads it signed itself.

A gossiped head whose *signature* does not verify is explicitly **not** a split
view. That is a broken or malicious contact, not the operator; conflating the
two would make the alarm trivially forgeable and therefore worthless.

Anyone can also read the log directly:

```
GET /v1/transparency/entries?from=<index>&to=<index>
```

### 7.3 Auditors

Gossip only helps between people who message each other. An auditor has no
account and no stake in any conversation, so it notices a fork whether or not
the people inside it ever talk.

`tildra-auditor` reads the whole log and checks three things a client cannot:

1. Every tree head is consistent with every head it has previously seen.
2. The entries the server actually serves hash to the roots it signs. A
   consistency proof says the tree grew; only re-deriving the root says the
   tree is made of the entries anyone can read.
3. Handles that were rebound to a different key — reported, not judged, because
   a reinstall and a substitution look identical from outside.

```
tildra-auditor -server https://api.tildra.chat -state ./auditor.json -watch 5m
```

The checkpoint file is meant to be **published**. An auditor keeping its view
private proves only that the log it personally saw was internally consistent;
two auditors comparing published checkpoints is what establishes they were
shown the same log:

```
tildra-auditor -server https://api.tildra.chat -compare ./other-auditor.json
```

An auditor never advances its checkpoint past a critical finding. Recording a
head it does not believe would make the next run compare against a lie.

#### Signed checkpoints, and who reads them

Two operators who know each other can exchange files by hand and compare them.
The case that protects a *user* is different: a phone fetching a checkpoint
over the network. There an unsigned JSON document is worth nothing, because
whoever serves it — including the operator being audited — can write whatever
makes the two views agree.

So an auditor has its own Ed25519 key, publishes the public half once, and
signs every checkpoint:

```
tildra-auditor -genkey                       # print a seed and a public key
tildra-auditor -server … -key ./auditor.key -publish ./checkpoint.json
```

The signature covers

```
"tildra-auditor-checkpoint-v1:" ‖ frame(size, root_hash, log_key, checked_at)
```

— a length-framed encoding, not the JSON. JSON has no canonical form, so
signing the serialised bytes would mean an equivalent document re-serialised by
a different encoder stops verifying, and that two different documents could
share one signature. `checked_at` is truncated to seconds for the same reason:
a timestamp whose precision changes between encoders is a signature that fails
for no reason. The context prefix means an auditor's signature can never pass
for a signed tree head.

Publishing without `-key` is refused rather than warned about. A document that
looks like an attestation and is not one is worse than no document.

**The client reads these.** A device holds a list of pinned auditors — a URL
and a public key each, configured out of band, which is the same act as
deciding to trust an auditor at all — fetches their checkpoints, verifies the
signature against the pinned key, and cross-checks each against the head it was
shown itself. Same comparison as gossip: equal sizes must have equal roots,
different sizes must be linked by a consistency proof the server can produce.

Three outcomes, deliberately distinct:

| What happened | What the client does |
|---|---|
| The auditor saw a log that cannot be reconciled with ours | Split-view alarm |
| The checkpoint does not verify against the pinned key | An error about *that publisher* — not an alarm about the log |
| The auditor could not be reached, or its checkpoint is stale | An error, no alarm |

Conflating the second with the first would make the alarm forgeable by anyone
who can serve a file. Conflating the third with the first would let the
operator raise the alarm by dropping a request, which teaches people to dismiss
it. A checkpoint older than 48 hours is treated as stale: an auditor that
stopped running last month cannot testify about today's log, and the way a fork
survives is the operator making the auditor's fetches fail and waiting.

A build pins auditors through `EXPO_PUBLIC_TILDRA_AUDITORS`, a JSON array of
`{name, url, publicKey}`. A malformed entry fails the whole list rather than
being skipped: an operator who mistypes one key and gets a shorter list
believes their users are checking an auditor that is not being checked, and
nothing anywhere says otherwise. The app asks at startup and every six hours —
a fork is a state the operator has to keep up, not a moment, so checking a few
times a day catches one without becoming a beacon.

**What is still missing.** Nobody is obliged to run an auditor, and Tildra
operates none as a public service, so the default configuration is empty. The
mechanism now runs end to end — an auditor can publish, a build can pin one,
the app checks it, and a disagreement is an alarm the user actually sees — but
a mechanism with nobody on the other end still catches nothing.

The log key must be held outside the database. A signing key sitting next to
the log it signs can be used to rewrite the whole thing.

## 8. What the server stores

| Data | Stored | Notes |
|---|---|---|
| Account ID + public keys | yes | required to route |
| Phone number / email | **no** | never collected |
| Message plaintext | **no** | impossible — no keys |
| Message ciphertext | temporarily | deleted on delivery; hard TTL 30 days |
| Sender of a message | **no** | sealed sender |
| Social graph / contact list | **no** | client-side; encrypted backup blob only |
| Group membership | **no** | distributed inside pairwise ciphertext |
| Display name, photo, about | **no** | sent to contacts, never uploaded |
| Attachment contents | **no** | per-file key, held only in the message |
| Handle→key bindings | **yes, on purpose** | public append-only log; that is the point |
| Who uploaded an attachment | **no** | no owner column, by design |
| IP addresses | in memory only | never written to disk or logs |
| Request URLs | not logged | the log records a route label — `/v1/keys/{}/{}` — never the identifiers in the path |

## 9. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Signatures | Ed25519 |
| Key agreement (classical) | X25519 |
| Key agreement (post-quantum) | ML-KEM-768 (FIPS 203) |
| AEAD | XChaCha20-Poly1305 |
| Hash | SHA-256 |
| KDF | HKDF-SHA256 |
| Password/phrase stretching | Argon2id (64 MiB, t=3, p=4) |

No primitive here is novel. That is the point.

## 9.1 Scanned codes

Two flows put a value on one screen and a camera on another: device linking
(§1 of `docs/STATUS.md`, protocol in the provisioning module) and safety-number
verification (§7). Both are `tildra:`-scheme payloads and both are read by the
same parser, which applies three rules.

**Every code declares its kind, and every caller declares what it wants.** The
link screen refuses a safety code and the verification screen refuses a link
code, each by name. Two flows that both accept "whatever was scanned" is how
somebody gets talked into pointing their camera at the wrong square.

**The server address inside a link code is hostile input.** It must be HTTPS,
or HTTP only on loopback; embedded credentials and query strings are refused.
The approving device does not use the field at all — it talks to the server it
is already authenticated against — but a field parsed and returned unchecked is
a trap for the next caller.

**A scanner fires repeatedly.** `onBarcodeScanned` delivers the same code many
times a second for as long as it is in frame. Repeats of the same value are
suppressed and a different value is let through immediately; once a scan has
been acted on, the gate closes entirely. Without that, one poster held in frame
for two seconds adds fifty devices to an account.

A scanned safety code is *evidence*, not a decision: a match is shown to the
user and the conversation is still only marked verified when they press the
button that says the numbers match.

## 10. Calls

Media is WebRTC: DTLS-SRTP between the two endpoints, with a TURN server for
the cases where a direct path cannot be found.

**The problem DTLS-SRTP does not solve.** The DTLS handshake authenticates with
a self-signed certificate that neither party has seen before. On its own it
proves the two endpoints share a key, not who they are — so a server that
relays signalling can hand each side its own certificate, terminate both DTLS
sessions, and listen to the call. The `a=fingerprint` line in the SDP is what
names the certificate; it is only meaningful if it arrives over a channel the
peer's identity key vouches for.

**The binding.** Every offer and answer carries an Ed25519 signature by the
sender's identity key over a length-framed transcript:

```
"tildra-call-fingerprint-v1:" ‖ frame(call_id, role, from_account,
                                      to_account, fingerprint, timestamp)
```

`role` is `caller` or `callee`, so an offer signature cannot be replayed as an
answer. The account ids bind the call to two specific people, so a captured
offer cannot be used to ring a third party. The transcript is length-framed
rather than delimiter-joined: with delimiters, an identifier containing the
delimiter could shift a field boundary and make one signature verify for a
different call.

**The verifier does not read a claimed fingerprint.** It parses the fingerprint
out of the SDP it is about to hand to the peer connection and checks the
signature over *that* value. There is no separate "claimed fingerprint" field,
because a signature over a fingerprint that is not the one in use is
decoration.

**SDP hardening.** An SDP is rejected if it carries no fingerprint, more than
one distinct fingerprint (legal in RFC 8842 — each media section may run its
own DTLS association — and exactly how a second certificate gets past a check
that reads only the first line), a fingerprint hashed with anything weaker than
SHA-256, a fingerprint whose length disagrees with its hash, an `a=crypto:`
SDES line, or a media section whose transport is not DTLS-based. Signalling
rides the pairwise Double Ratchet as content type 6, so the server sees two
people exchanging a few small messages and not that a call took place.

**Timestamps.** Offers and answers are valid for 120 seconds, with 60 seconds
of clock-skew tolerance. Without a freshness bound, a captured offer can be
replayed later to make a phone ring.

**ICE and addresses.** A host or server-reflexive candidate is the device's IP
address. An incoming call is held to relay-only candidates until it is
answered, so a call you never picked up reveals your TURN server and nothing
else — someone who only wanted your network location and hangs up before you
answer gets nothing. After the call is accepted, direct paths are allowed.
Candidates that do not parse are dropped rather than forwarded: an unclassified
candidate might be a host candidate, and a leaked address cannot be taken back.

The same policy governs what is *accepted*, not only what is sent. Adding a
caller's host candidate while the phone is still ringing makes the callee's ICE
agent send binding requests to an address the caller chose, which tells the
caller where the callee is — the same leak arriving from the other direction.

**Ringing, and which device.** An offer is signed once and delivered to every
device on the account through its own pairwise session, so the same fingerprint
is covered everywhere and there is nothing per-device to get wrong. The first
device to answer wins: it becomes the only device whose signals count for that
call, and the others are told to stop ringing. A second incoming call while one
is live is answered with `Busy` and never rings — one call at a time is a
property of a phone, and it also means a peer cannot flood the call UI.

**The relay.** A direct path is not always available, so a deployment can run
a TURN server and `GET /v1/turn` hands clients a short-lived credential for it
(coturn's `use-auth-secret` convention: `username = <expiry>:<name>`,
`credential = base64(HMAC-SHA1(secret, username))`). Two details are not
incidental:

- **The name is random, never an account id.** Every deployment guide fills
  that field with a user identifier, which would put an account in the TURN
  server's logs for every call — when it happened and for how long — next to a
  messenger built so the server cannot know that. The relay only checks the
  MAC; it has no use for the name.
- **A relay-only phase with no relay gathers nothing, and never falls back.**
  A missing or expired credential produces an empty ICE server list with the
  policy still set to `relay`, plus a flag saying the relay is unavailable. The
  alternative — quietly using direct paths because there is nowhere to relay
  through — would hand the callee's address to anyone who can make their phone
  ring. No STUN server is offered during that phase either: a binding request
  is itself a disclosure, and a reflexive candidate is the address.

A server with no relay configured answers `503` rather than an empty
credential, because a client that cannot tell "no relay" from "relay with no
servers" cannot tell a safe call from a broken one.

**Ordering.** Signalling and gathering race each other, and getting that
wrong is silent rather than loud — the call still connects, over the relay,
when a direct path existed. Two buffers are therefore part of the design and
not an implementation detail: remote candidates that arrive before the
description they belong to are held until it is installed, and local
candidates gathered before the call has an id are held until it does. When the
user accepts an incoming call the widened policy has to be applied to the
*live* connection with an ICE restart; setting the configuration alone does
not go back for the candidates that were skipped while relay-only.

**Renegotiation.** Widening the policy on a live connection needs an ICE
restart, and an ICE restart changes the ICE ufrag and pwd, which is a fresh
offer/answer exchange. Those travel as two more signal kinds, `Renegotiate`
and `RenegotiateAnswer`, signed exactly like the original pair but with their
own role strings — `reoffer` and `reanswer` — so a signature made for one
exchange can never be replayed as another. All four roles are distinct, and
there is a test that tries every pair.

The rule that makes renegotiation safe is separate from the signature: **a
renegotiation may change the ICE credentials and may not change the DTLS
fingerprint.** The peer's own identity key signs a re-offer perfectly well, so
a signature cannot distinguish "restarting ICE" from "becoming somebody else
halfway through". Only comparing against the fingerprint the call was pinned to
can, and that is what makes "this call is with the key you checked" true for
the whole call rather than for its first second. A re-offer that changes it, or
that fails verification, ends the call rather than being ignored — carrying on
would mean media continuing under terms the device has refused.

A renegotiation before the call is answered is refused too: nothing is pinned
yet, so there would be nothing to compare against.

**Calls are not persisted.** A call that outlives the process is not a call; it
is a row that would ring a phone about something that stopped happening when
the app was killed.

**There is no spoken verification code, deliberately.** ZRTP-style short
authentication strings exist because ZRTP has no long-term identity to sign
with. Tildra does. An attacker who substitutes the fingerprint cannot produce
the signature and is rejected without asking the user anything; an attacker who
substitutes the *identity key* is what the safety number in §7 is for. A short
code read out during a call would be grindable — the attacker chooses both
forged fingerprints offline and needs only a collision between the two sides'
codes, which is birthday-cheap at any length a person will say out loud. A
check that looks like a check but is not one is worse than none.

## 11. Known limitations

Stated up front, because a protocol document that only lists strengths is
marketing:

- Sender keys give weaker post-compromise security in large groups than MLS.
- Sealed sender hides the sender from the *envelope*, not from the *request*.
  Delivery is authenticated with the sender's own bearer token, so the server
  can link a sender to the mailbox they deliver to. §5 described a blind-signed
  delivery token that would remove that link; it is designed and not built.
- Sealed sender does not hide traffic *timing* either. A global passive
  adversary correlating timing across the network can still infer who talks to
  whom.
- Push notifications route through APNs/FCM, which leaks delivery timing to
  Apple/Google. Payloads carry no content, only a wake signal.
- The call *media path* above is specified, its signalling logic is implemented
  and tested, and `session/webrtc-peer.ts` now adapts it to
  `react-native-webrtc` — but no media has ever flowed. There is no TURN
  deployment and nothing has run on a device; the adapter is tested against a
  double. Nothing in §10 should be read as "calls work".
- Not yet audited.
