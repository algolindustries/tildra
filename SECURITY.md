# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security bug.

Use GitHub's private reporting: **Security → Report a vulnerability** on
[github.com/algolindustries/tildra](https://github.com/algolindustries/tildra/security/advisories/new).

The repository has been private since 2026-08-05, so that form is reachable only
with access to it. Nothing else here changes: the scope below, the bar for what
counts as a vulnerability, and the response times are what they were. Going
private narrows who can report, which is a reason to take the reports that do
arrive more seriously rather than fewer.

What helps most, in order:

1. What breaks, and what an attacker gains.
2. Reproduction steps or a proof of concept.
3. Which component and commit.

We will acknowledge within 72 hours and aim to have a fix or a concrete plan
within 14 days. We'll credit you in the advisory unless you'd rather we didn't.

## Scope

In scope:

- The protocol as specified in [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — including
  the spec itself. A flaw in the design is more valuable than a flaw in the code.
- `server/` — authentication, key distribution, message routing, any path where
  the server learns more than the threat model says it can.
- `mobile/` — key handling, storage, session state, anything that would expose
  plaintext or key material.

Out of scope:

- Denial of service via raw traffic volume.
- Social engineering of maintainers or users.
- Vulnerabilities in Expo, React Native, Go, or their dependencies — report those
  upstream (but do tell us if we're using them wrongly).
- Missing hardening headers on endpoints that return no sensitive data.

## What we consider a vulnerability

Because the whole product is a claim about what the server *cannot* do, the bar
is: **anything that lets the server, or someone who has compromised it, learn
more than [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §8 says it can.** That includes
metadata. If you can determine who is talking to whom from server-side state,
that is a vulnerability, not a design limitation — unless it is already listed
under "Known limitations" in the protocol doc.

## Current status

Tildra is pre-alpha and **has not been independently audited**. Assume bugs. We
would rather hear about them early than ship a version people trust prematurely.
