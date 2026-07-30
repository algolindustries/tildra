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
Recovery is a 24-word BIP-39-style **recovery phrase** that seeds a
recovery key pair. The client encrypts a backup blob (contact list, group
memberships, and a device-provisioning secret) under a key derived from the
phrase with Argon2id (m=64 MiB, t=3, p=4) and uploads the ciphertext. The server
stores bytes it cannot read.

Losing the phrase means losing the account. This is stated plainly during
onboarding, twice, and the phrase must be re-entered to continue.

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
  `HKDF(MK, info="Tildra_MsgKey_v1")` expanded to an 88-byte
  (32 enc ‖ 32 auth ‖ 24 nonce) block.

Skipped message keys are cached for at most 1000 messages / 7 days per session,
then dropped. This bounds the damage of a device compromise.

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
to the envelope. To stop this from becoming an open spam relay, the sender proves
they're a real account with a **blind-signed delivery token**: the server issues
tokens via a blind RSA signature, so it can verify a token is valid without
linking it to who it was issued to.

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
duration and a 48-byte waveform, 4 bits of loudness per bar. Both ride in the
message rather than inside the blob, so a bubble shows its shape and length
the moment it arrives — needing a download to learn whether a note is three
seconds or three minutes makes the feature feel broken. Both are bounded on
receipt as well as on send, because they come from the sender and are rendered
directly.

### 5.5 Linking a device

An account may hold several devices, each with its own identity key and its own
ratchet per contact. Adding one has to work without trusting the server, since
the provisioning channel *is* the server.

1. The new device generates its identity key and an ephemeral X25519 key, opens
   a channel, and displays `tildra://link?id=…&key=…&commit=…&server=…` where
   `commit = SHA-256(new identity public key)`.
2. An existing, signed-in device reads the channel, and checks the identity key
   the server handed over against `commit`. **The commitment travelled over a
   camera, not the network**, so a substituted key fails here.
3. The existing device registers the new one and seals an approval to the
   ephemeral key: `{accountId, deviceId, approvedBy, signature}` over a
   transcript binding all three.
4. Both devices derive a six-digit pairing code:

   ```
   code = HKDF(shared ‖ account_id ‖ new_identity_key,
               info = "Tildra_PairingCode_v1") mod 10^6
   ```

   The user compares them. A server that swapped the ephemeral key to read the
   channel, or aimed the device at a different account, changes the transcript —
   so the two screens disagree.

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

## 7. Key verification

Two users verify each other by comparing a **safety number**: a 60-digit code
derived from both identity keys, `HKDF(sort(IK_A, IK_B), info="Tildra_SafetyNumber_v1")`.
The client shows a QR code for in-person verification.

If a contact's identity key changes, the conversation is **blocked from sending**
until the user acknowledges the change. Silent key changes are how server-side
MITM attacks succeed; we refuse to make that quiet.

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

A handle lookup returns the binding, an **inclusion proof** against the current
head, and a **consistency proof** from the last head the client verified. The
client checks all three and stores the new head.

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

**What is still missing.** Nobody is obliged to run an auditor, and Tildra
operates none as a public service. The mechanism means a fork *can* be caught
by any third party who looks; it does not guarantee that someone is looking.

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
| Blind signatures (delivery tokens) | RSA-PSS blind signatures (RFC 9474) |

No primitive here is novel. That is the point.

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
- Sealed sender does not hide traffic *timing*. A global passive adversary
  correlating timing across the network can still infer who talks to whom.
- Push notifications route through APNs/FCM, which leaks delivery timing to
  Apple/Google. Payloads carry no content, only a wake signal.
- The call *media path* above is specified and its signalling logic is
  implemented and tested, but no media has ever flowed: there is no
  `react-native-webrtc` integration and no TURN deployment yet. Nothing in §10
  should be read as "calls work".
- Not yet audited.
