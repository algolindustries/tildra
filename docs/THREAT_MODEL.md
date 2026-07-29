# Threat model

A security claim without a threat model is a slogan. This document says who we
defend against, who we don't, and what we would lose in each case.

## Adversaries

### A1 — The Tildra server operator (including us)

**Assume the server is hostile.** This is the primary adversary, because it is
the one every centralised messenger asks you to ignore.

| The operator wants | They get |
|---|---|
| Message content | Nothing. No key material capable of decryption exists server-side. |
| Who sent a message | Nothing. Sealed sender puts the sender identity inside the ciphertext. |
| Who received a message | A mailbox ID, which rotates daily and is not linkable to an account without the recipient's cooperation. |
| The social graph | Nothing durable. Contact lists live on the client; the backup blob is opaque. |
| Group membership | Group size (fanout count) and nothing else. |
| Message timing | **Yes.** See "What we don't defend against". |
| Message size | Bucketed. Padding hides exact length, not order of magnitude. |
| Your phone number | It was never collected. |

**Active attack:** a hostile server can hand Alice a key bundle it controls
instead of Bob's. This is the classic MITM, and the only real defence is out-of-band
verification. Tildra's mitigation is that identity-key changes **block sending**
until acknowledged, so the attack cannot be silent — Alice sees a state change
she has to dismiss, and the safety-number comparison catches it.

We consider undetectable MITM the most serious possible failure, so there are
now two defences rather than one.

The manual one: an identity-key change blocks sending until acknowledged.

The structural one: **key transparency**. Every handle→key binding is appended
to a signed, append-only Merkle log, and every lookup carries an inclusion
proof plus a consistency proof from the last tree head the client verified. A
server that swaps a key must either publish that swap where anyone can see it,
or fork the log — which fails consistency as soon as the two views meet. See
`docs/PROTOCOL.md` §7.1.

**What is still missing**: split-view detection needs clients to gossip tree
heads with each other or with independent auditors. Without that, a server
willing to maintain a permanent, consistent fork aimed at one specific person
is not caught by the log alone — only by that person comparing safety numbers.
That is the remaining work, and until it lands the log raises the cost of an
attack rather than closing it.

### A2 — A network observer (ISP, coffee-shop Wi-Fi, national firewall)

Sees: that you connect to a Tildra server, when, and roughly how much data
moves. TLS 1.3 with certificate pinning protects everything else.

Does not see: content, recipients, or which conversation traffic belongs to
(header encryption prevents correlating messages by ratchet key).

### A3 — Someone with your unlocked phone

Gets everything on it: your messages, your contacts, your sessions. No messenger
defends against this, and any that claims to is lying about disk encryption.

What we do bound: skipped message keys are cached for at most 1000 messages or
7 days, so an attacker cannot walk backwards indefinitely through old sessions.
Post-compromise security means that once they lose access, the next ratchet step
locks them out of future messages.

### A4 — Someone with your locked phone, later

Key material lives in the platform keystore (iOS Keychain with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, Android Keystore hardware-backed
where available), so it is bound to the device and unavailable while locked.

### A5 — A malicious contact

Can screenshot everything you send them, and always could. E2EE is about the
channel, not about the person at the other end. Disappearing messages are a
courtesy feature, not a security control, and we describe them that way in the UI.

### A6 — A global passive adversary

Sees timing across the whole network and can correlate "Alice's device sent
1 KiB at 14:02:07" with "a mailbox received 1 KiB at 14:02:07". This defeats
sealed sender.

We do not defend against this. Doing so requires mixnet-grade cover traffic with
latency and battery costs that make a mainstream messenger unusable. Anyone
whose threat model includes a global passive adversary should be looking at a
different tool, and we would rather say so than imply protection we don't provide.

## What we defend against

- Server-side reading of messages — **structurally impossible**, not policy.
- Server-side reconstruction of the social graph.
- Retroactive decryption of recorded traffic, including by a future quantum
  adversary (hybrid X25519 + ML-KEM-768).
- Compromise of past messages after a device is stolen (forward secrecy).
- Compromise of future messages after an attacker loses access (post-compromise
  security).
- Silent key substitution by the server (detected, blocks sending).
- Reading group messages after being removed from the group (forced rotation).
- Requiring a phone number to have an account (never collected).

## What we don't defend against

Stated plainly, because the alternative is letting users infer protection that
isn't there:

- **Traffic analysis by a global passive adversary.** See A6.
- **A compromised endpoint.** Malware with your device's key material reads your
  messages. Nothing in a protocol fixes this.
- **Push notification metadata.** APNs and FCM learn that a device received a
  wake signal and when. The payload carries no sender, no preview and no
  conversation — the client decrypts locally and replaces the placeholder with
  a real notification — so what leaks is timing, not who is talking to whom.

  The push token itself is a second cost, and a real one: it is a stable
  identifier issued by Apple or Google, so the operator holds a value those
  companies can link to a device. It is the only durable device-linked datum
  the server keeps beyond routing. Deployments can run with
  `TILDRA_PUSH_PROVIDER=none`, in which case no token is ever collected and
  clients receive on reconnect; users who decline the permission are in the
  same position individually.
- **First-contact timing.** A device's contact inbox is derived from its public
  identity key, which the server holds. So the server can observe that someone
  started a conversation with a given device, and when — though not who. Every
  message after the first moves to per-session mailboxes that rotate daily and
  are unlinkable across contacts, so this is a one-event leak per conversation,
  not an ongoing one. Closing it entirely needs private information retrieval
  or cover traffic; see `docs/PROTOCOL.md` §5.1 for why the simpler fixes do
  not work.

- **A targeted split view of the transparency log.** The log catches a server
  that rewrites history or that substitutes a key for everyone. It does not yet
  catch one that maintains a separate, internally consistent log for a single
  target, because clients do not gossip tree heads. Verify safety numbers with
  people who matter to you.
- **Malicious client builds.** Reproducible builds are a project goal, tracked in
  CI, not yet achieved. Until then, "open source" means auditable source, not
  verified binaries.
- **Legal compulsion of the operator.** We defend by not having the data — but a
  compelled operator can still be forced to log connection timing going forward,
  or to serve a modified client. This is a structural limit of any centralised
  service and an argument for self-hosting.

## Design consequences

The threat model above is why certain conveniences are absent:

- **No server-side message search.** It would require plaintext.
- **No cloud chat history across devices without the recovery phrase.** The
  server cannot re-key you into your own history.
- **No "last seen" on other people's devices.** It is a behavioural fingerprint
  and a stalking aid, and we do not expose it in the API.
- **No read receipts by default.** They confirm a device is awake and attended at
  a specific moment.
- **No phone-number contact discovery.** Every implementation of it leaks the
  social graph to the server, including the ones using bloom filters and
  hardware enclaves.

If a feature request in this repo is declined, it is usually because of something
on this list, and the response should link here rather than being restated.
