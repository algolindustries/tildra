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

## 8. What the server stores

| Data | Stored | Notes |
|---|---|---|
| Account ID + public keys | yes | required to route |
| Phone number / email | **no** | never collected |
| Message plaintext | **no** | impossible — no keys |
| Message ciphertext | temporarily | deleted on delivery; hard TTL 30 days |
| Sender of a message | **no** | sealed sender |
| Social graph / contact list | **no** | client-side; encrypted backup blob only |
| Group membership | **no** | encrypted blob |
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

## 10. Known limitations

Stated up front, because a protocol document that only lists strengths is
marketing:

- Sender keys give weaker post-compromise security in large groups than MLS.
- Sealed sender does not hide traffic *timing*. A global passive adversary
  correlating timing across the network can still infer who talks to whom.
- The handle directory is a trusted-ish component; key transparency
  (CONIKS-style, with an auditable append-only log) is planned but not yet built.
- Push notifications route through APNs/FCM, which leaks delivery timing to
  Apple/Google. Payloads carry no content, only a wake signal.
- Not yet audited.
