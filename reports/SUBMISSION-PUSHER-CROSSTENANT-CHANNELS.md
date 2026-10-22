# [Amplitude] Orbit PusherAuth signs arbitrary channel names with no channel↔org binding — VIEWER subscribes to foreign-org private & presence channels (presence payload injection)

- **Asset:** app.amplitude.com `/o/graphql` (Orbit lens) — `pusherAuth(socketId, channelName)`; delivery socket `wss://ws-us3.pusher.com/app/4295069416aecca99ee6` (cluster us3)
- **Program:** Amplitude private bug bounty (Bugcrowd)
- **Severity:** Low/Medium — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N = **4.3** (P4→P3 boundary; presence-integrity term only — see Ceiling)
- **Date:** 2026-10-17 · **Tenant:** researcher org 464637 (foreign control: org 464504) · Role used: VIEWER (orgRole 1)
- **Classification:** CWE-862 missing authorization (channel-name↔tenant binding absent at the signing oracle); CWE-345 insufficient verification of data authenticity downstream

---

## Summary

The Orbit realtime plane authorizes WebSocket subscriptions solely by **asking Amplitude to sign whatever channel name the client supplies**. `POST https://app.amplitude.com/o/graphql?q=PusherAuth` with a plain VIEWER session returns a valid HMAC auth for **every** attacker-chosen name — own-org ids, **foreign-org ids (464504)**, bogus ids, and arbitrary strings — with no check that the channel belongs to the caller's org/app. Pusher's signature validation is the only gate, and the signature comes from the application itself. Consequently a low-privileged session **successfully subscribes** (`pusher_internal:subscription_succeeded`) to another customer org's `private-*` and `presence-*` channels, and a presence subscription publishes an attacker-chosen `user_id` payload into the foreign channel's roster.

## Repro (measured 2026-10-17)

1. **Signing oracle:** `POST /o/graphql?q=PusherAuth` (VIEWER C cookies) with
   `{"query":"query PusherAuth($socketId:String!,$channelName:String!){pusherAuth(socketId:$socketId,channelName:$channelName){auth channelData}}","variables":{"socketId":"<real-socket-id>","channelName":"private-ws-464504"}}`
   → `200` + valid `auth` for ALL of: `private-ws-464637` (own), **`private-ws-464504` (foreign)**, `private-ws-999999`, `private-branch-anything`, `private-app-862908`, `private-notifications-464637`, `presence-ws-464637`, **`presence-ws-464504`**. ORG_ADMIN baseline identical (no role check for anyone — the oracle never had a binding to check).
2. **Live join:** connect `wss://ws-us3.pusher.com/app/4295069416aecca99ee6?client=js&version=8.4.0&protocol=6` → take `socket_id` → subscribe with protocol-6 frame `{"event":"pusher:subscribe","data":{"auth":"<verbatim from PusherAuth>","channel":"private-ws-464504","channel_data":"<verbatim, when returned>"}}`
   → **`pusher_internal:subscription_succeeded` on all six tested channels, including both foreign-org channels.**
   (Protocol note: protocol-6 requires `channel` inside `data` and both `auth` and `channel_data` forwarded **verbatim**; a reshaped subscribe is correctly rejected `pusher:error Invalid signature` — that rejection is Pusher validating the application's signature, i.e. the signature is the *only* control.)
3. **Presence injection:** `presence-ws-464504` join delivers the channel's presence roster including **C's own `user_id` payload** (injected by Amplitude's signing from the session, not derived from any org membership of the channel).
4. **Controls:** fabricated 40-hex auth → `pusher:error` (Pusher enforces the signature); no channel-existence differential between signed names (all join identically) → the oracle leaks no channel-inventory information.

## Impact

- **Cross-tenant channel subscription primitive:** any authenticated user of any role joins any named private/presence channel of **any customer org** by id.
- **Presence-roster poisoning:** the presence payload of the attacker's choosing (their own `user_id`, but bound into someone else's channel) appears in a foreign org's live presence list — corrupts collaboration presence UIs and any server-side logic consuming presence counts.
- **Forward-compat risk:** today's channels are idle (see Ceiling); any future private event on `private-ws-<org>` / `private-app-<app>` / `private-branch-*` style channels is delivered to an unauthorized cross-tenant subscriber by default.

## Ceiling (honest bounds)

- **No data leak demonstrated:** a 35-second idle listen on the two foreign channels produced only `subscription_succeeded` (no data frames) — the observed channels carry no at-rest data to a listener. The 4.3 score reflects the presence-integrity term only; a future eventful channel would make this a confidentiality finding.
- Channel enumeration oracle: **negative** (uniform join success leaks no existence signal).
- Pusher-side validation of signatures works; the defect is that Amplitude signs unbound names.

## Suggested remediation

Parse the channel name at `pusherAuth` and verify the org/app/branch id segment against the session's memberships before signing (reject foreign ids with the same generic error as malformed names).

## Evidence

- Join/listen raw logs + harness: `hunt2610/wave3-pusher/evidence/{join_log_raw.txt, join_results.txt, listen_log_raw.txt, listen_results.txt}`, harness `pusher_join.py`; verdict matrix `hunt2610/wave3-pusher/FINDINGS.md`.
- Signing-oracle raws (first run, prior wave): `hunt2610/wave2-mcp/evidence/h3_*`.
