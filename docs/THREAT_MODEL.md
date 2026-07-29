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

We consider undetectable MITM the most serious possible failure. Key
transparency (an auditable append-only log of the handle directory) is the
planned structural fix; today the defence is user-visible and manual.

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
  wake signal and when. Payloads carry no content, but delivery timing leaks to
  Apple and Google. Self-hosted deployments can use a WebSocket-only mode.
- **The handle directory being trusted.** Until key transparency ships, a
  hostile server can lie about which account ID a handle maps to. Verify safety
  numbers with people who matter to you.
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
