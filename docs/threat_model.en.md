# Threat model — relay host

[Русский](threat_model.md) · **English**

`dtm_host` is deliberately dumb: it moves opaque envelopes and answers peer discovery. This file states what it must and must not be trusted with.

## Assets

- envelope contents — **not** readable by the host (ciphertext only);
- client identity keys — never sent to the host;
- `host_state.ed_seed` — the host's own Ed25519 identity, used to sign pruned batch roots and to prove identity during federation;
- client pins — each client remembers the host's Ed25519 key, so a changed identity must be treated as an attack;
- subscriber routing keys (X25519) — needed to deliver, never sufficient to decrypt.

## Adversaries

1. **Any connected client** — can send malformed frames, flood subscriptions, forge envelopes, or probe other clients' keys.
2. **A federated host** — may lie, replay, withhold data or impersonate.
3. **An on-path attacker** — can drop or replay traffic between host and client.
4. **Someone with filesystem access** — can read `host.db`.

## Security goals

- **No plaintext, ever.** The host never decrypts; it has no keys that can.
- **Delivery isolation.** A subscriber receives only envelopes addressed to its X25519 key.
- **Verification before storage.** Clock skew → signature → envelope id → dedup, in that order; a failed envelope is never stored or relayed.
- **Bounded resources.** Frame size, connection count, subscription count, gossip lists and windows are capped before allocation.
- **Federation identity.** A host proves its Ed25519 identity; an impostor gets no envelopes.
- **Durability of identity.** `host.db` is never deleted on upgrade, so client pins stay valid.

## Non-goals

- **Hiding metadata from the operator.** The operator sees IPs, connection times, envelope sizes and routing keys. That is inherent to relaying.
- **Protecting a client from its own device.** End-to-end encryption is the client's job.
- **Availability under a targeted flood.** Limits bound the damage but a determined attacker can still saturate a small relay.
- **Trusting the operator.** Clients pin the identity, but a malicious operator can withhold or drop envelopes. Soty tolerates relays, it does not trust them.

## Trust boundaries

| Boundary | Rule |
| --- | --- |
| socket → frame decoder | max frame size enforced before allocation |
| frame → envelope | strict parsing; malformed input closes the connection |
| envelope → database | only after skew, signature and id checks |
| database → subscriber | entitlement by X25519 key, never by connection order |
| host ↔ host | identity proof + announce address; unknown hosts get nothing |

## Operational invariants

- never delete or commit `host.db`;
- never log envelope contents, keys or seeds;
- TLS terminates in front of the relay in production; the unit carries `--announce`;
- the relay runs with the smallest useful privileges (user unit or shell supervisor, no root after setup).

Exploitable details and their fixes are tracked in the private audit log.
