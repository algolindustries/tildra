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

Clients also **gossip**: a device attaches a tree head it has verified to the
messages it already sends, and the recipient checks that head and its own are
on the same log. A server running a split view is then caught as soon as two
of its targets talk to each other. See `docs/PROTOCOL.md` §7.2.

Third parties can also **audit**: `tildra-auditor` reads the whole log,
re-derives every root from the entries the server serves, and publishes a
checkpoint. Two auditors comparing checkpoints catch a fork without either of
them having an account. See `docs/PROTOCOL.md` §7.3.

**What is still missing**: nobody is obliged to run an auditor, and we operate
none as a public service. A fork *can* now be caught by any third party who
looks — that is a real change from before — but nothing guarantees someone is
looking.

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
- A server inserting itself into the media path of a call, by binding the DTLS
  fingerprint to the identity key — see `docs/PROTOCOL.md` §10. The signalling
  logic is implemented and tested; no media has flowed yet, so this is a
  designed defence, not an operating one.

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

- **A split view nobody happens to be watching.** Gossip catches a forked log
  when two targets exchange messages, and an auditor catches it without
  needing an account — but only if someone is actually running one. We ship the
  tool and operate no public instance, so this is a "can be detected", not a
  "will be". Verify safety numbers with people who matter to you.
- **That a call happened, to whoever runs the TURN relay.** A relayed call
  goes through the operator's server, which sees two endpoints exchanging
  media and how long for. The credential carries a random name rather than an
  account id, so the relay's logs cannot say *whose* call it was — but a
  deployment running both the relay and the message server can correlate by
  timing, and self-hosting is the only real answer to that. A call that finds
  a direct path does not touch the relay at all.
- **Your IP address, once you answer a call.** WebRTC finds the shortest path
  between two endpoints, and the shortest path is a direct one — which means
  each side learns the other's address. An unanswered incoming call leaks
  nothing (candidates are held to relay-only until you accept), and a
  deployment can force relay for the whole call at the cost of routing all
  media through its TURN server, but the default after you pick up is that the
  person you are talking to can see where you are.
- **Malicious client builds.** The Go server, `tildra-auditor` and the app's
  **JavaScript bundle** all build reproducibly, and CI proves it on every push.
  That covers every line of cryptography Tildra runs. What it does not cover is
  the **native shell** — the `.ipa` and `.aab` that Xcode and Gradle produce —
  so an *installed* app is still something you trust the publisher for, even
  though you can now check the JavaScript inside it against this source. A
  narrowing, not a fix. See
  [`docs/REPRODUCIBLE_BUILDS.md`](REPRODUCIBLE_BUILDS.md).
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
