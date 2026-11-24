# Security policy — Soty relay host

[Русский](SECURITY.md) · **English**

`dtm_host` stores only encrypted envelopes and answers peer-discovery requests. It must never see plaintext or private keys, so a flaw here can still break availability, isolation between clients, or metadata hygiene.

## Supported versions

Only the latest release in [Releases](https://github.com/slavabars/soty/releases) is supported. Operators should run the current `dtm_host.bin`; installers update it without touching `host.db`.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Preferred: GitHub private vulnerability reporting: <https://github.com/slavabars/soty-relay/security/advisories/new>

Alternative: email **security@soty.su**.

Please include the relay version (`hostVersion` in `/status`), the protocol message or request involved, the impact, and reproduction steps.

## What is in scope

- reading, modifying or deleting another client's envelopes;
- bypassing signature/id/replay checks before an envelope is stored or relayed;
- federation abuse: an impostor host learning envelopes or forging an identity;
- unbounded allocation from untrusted frames, headers, lists or subscriptions;
- crashes or data loss caused by malformed input;
- leaking `host_state.ed_seed` or any client key material.

## Out of scope

- metadata a relay inherently observes (IPs, connection times, envelope sizes);
- denial of service against a relay you operate yourself;
- a host whose `host.db` was already stolen by someone with filesystem access;
- unofficial binaries.

## Response

- acknowledgement within 7 days;
- an assessment within 14 days;
- a patched release, and a deploy note for operators, for confirmed issues.

Please give operators time to update before publishing details.
