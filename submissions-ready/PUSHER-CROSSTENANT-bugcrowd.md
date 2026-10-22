# [Amplitude] Orbit PusherAuth signs arbitrary channel names with no channel↔org binding — VIEWER subscribes to foreign-org private & presence channels (presence payload injection)

**Target Location:** `https://app.amplitude.com/o/graphql` (Orbit lens) — `pusherAuth(socketId, channelName)`; delivery socket `wss://ws-us3.pusher.com/app/4295069416aecca99ee6` (cluster us3)
**Target category:** Web App
**VRT (suggested):** Broken Access Control > Missing Authorization (CWE-862) · downstream CWE-345
**CVSS 3.1 (suggested):** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = **4.3 (Medium)** — presence-integrity term only

---

**Affected Asset:** `app.amplitude.com` `/o/graphql` — the `pusherAuth(socketId, channelName)` signing resolver that authorizes subscriptions to the Orbit realtime plane (Pusher, app key `4295069416aecca99ee6`, cluster us3).

**Summary:** The Orbit realtime plane authorizes WebSocket subscriptions solely by **asking Amplitude to sign whatever channel name the client supplies**. `POST https://app.amplitude.com/o/graphql?q=PusherAuth` with a plain VIEWER session returns a valid HMAC auth for **every** attacker-chosen name — own-org ids, **foreign-org ids (464504)**, bogus ids, and arbitrary strings — with no check that the channel belongs to the caller's org/app. Pusher's signature validation is the only gate, and the signature comes from the application itself. Consequently a low-privileged session **successfully subscribes** (`pusher_internal:subscription_succeeded`) to another customer org's `private-*` and `presence-*` channels, and a presence subscription publishes an attacker-chosen `user_id` payload into the foreign channel's roster.

**Honest ceiling, front and center:** **no data leak was demonstrated.** A 35-second idle listen on both foreign channels produced zero data frames — the observed channels are idle, so the measured impact is **presence-integrity injection only** (the attacker's `user_id` appearing in a foreign org's presence roster). The `C:N` term in the score reflects that. The forward-compat risk is real and stated: any future private event on `private-ws-<org>` / `private-app-<app>` / `private-branch-*` style channels would be delivered to an unauthorized cross-tenant subscriber by default, at which point this becomes a confidentiality finding.

**Steps to Reproduce:**

All measured 2026-10-17 against researcher org **464637** (foreign control org: **464504**), role VIEWER (orgRole 1). Everything reverted after testing.

**Step 1 — the signing oracle signs arbitrary names.** `POST /o/graphql?q=PusherAuth` with VIEWER session cookies:
```
POST /o/graphql?q=PusherAuth HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER SESSION>
Content-Type: application/json

{"query":"query PusherAuth($socketId:String!,$channelName:String!){pusherAuth(socketId:$socketId,channelName:$channelName){auth channelData}}",
 "variables":{"socketId":"<real-socket-id>","channelName":"private-ws-464504"}}
```
→ `200` + valid `auth` for ALL of: `private-ws-464637` (own), **`private-ws-464504` (foreign)**, `private-ws-999999` (bogus), `private-branch-anything` (arbitrary), `private-app-862908`, `private-notifications-464637`, `presence-ws-464637`, **`presence-ws-464504` (foreign)**. An ORG_ADMIN baseline was identical — no role check for anyone; the oracle never had a channel↔org binding to check.

**Step 2 — live cross-tenant join.** Connect `wss://ws-us3.pusher.com/app/4295069416aecca99ee6?client=js&version=8.4.0&protocol=6`, take the `socket_id`, and subscribe with the protocol-6 frame (note: `channel` must be INSIDE `data`, and `auth` + `channel_data` must be forwarded **verbatim**):
```
{"event":"pusher:subscribe",
 "data":{"auth":"<verbatim from PusherAuth>",
         "channel":"private-ws-464504",
         "channel_data":"<verbatim, when returned>"}}
```
→ **`pusher_internal:subscription_succeeded` on all six tested channels, including both foreign-org channels:**

| channel | org | result |
|---|---|---|
| private-ws-464637 | own | subscription_succeeded |
| private-ws-464504 | FOREIGN | subscription_succeeded |
| presence-ws-464504 | FOREIGN | subscription_succeeded, presence {count:1, ids:[C's user_id]} |
| presence-ws-464637 | own | subscription_succeeded |
| private-ws-999999 | bogus | subscription_succeeded |
| private-branch-anything | arbitrary | subscription_succeeded |

(Protocol note: a reshaped subscribe — `channel` outside `data`, or `auth`/`channel_data` not forwarded verbatim — is correctly rejected with `pusher:error Invalid signature`. That rejection is Pusher validating the *application's* signature, i.e. it confirms the signature is the only control on this plane.)

**Step 3 — presence payload injection.** The `presence-ws-464504` join delivers the channel's presence roster **including our own `user_id` payload** — injected by Amplitude's signing from the session, not derived from any org membership of the channel. A VIEWER of org 464637 appears in org 464504's live presence list.

**Step 4 — fabricated-auth control.** A fabricated 40-hex auth string → `pusher:error Invalid signature: Expected HMAC SHA256 hex digest of <sock>:<channel>` — Pusher enforces the signature; the defect is that Amplitude signs unbound names. No channel-existence differential exists between signed names (all join identically), so the oracle leaks no channel-inventory information.

**Step 5 — the ceiling measurement.** A 35-second idle listen on `private-ws-464504` + `presence-ws-464504` produced only `subscription_succeeded` — **zero data frames** (channels empty). No at-rest data reached the listener.

**Impact:**

- **Cross-tenant channel-subscription primitive:** any authenticated user of any role joins any *named* private/presence channel of **any customer org** by id.
- **Presence-roster poisoning (the measured impact):** the attacker's chosen `user_id` (bound from their session by Amplitude's signing) appears in a foreign org's live presence list — corrupts collaboration presence UIs and any server-side logic consuming presence counts.
- **Forward-compat risk (stated, not demonstrated):** today's channels are idle; any future private event on `private-ws-<org>` / `private-app-<app>` / `private-branch-*` channels is delivered to an unauthorized cross-tenant subscriber by default.

**Controls (what bounds this):**

- **No data leak demonstrated:** the 35-second idle listen produced zero data frames on both foreign channels. The 4.3 score carries `C:N` for exactly this reason — a future eventful channel would change the picture.
- **Channel enumeration oracle: negative** — uniform join success leaks no existence signal.
- **Pusher-side signature validation works** (fabricated auth → `pusher:error`); the defect is entirely in Amplitude's signing of unbound names.
- Requires an authenticated session (PR:L) — no unauthenticated path was found or claimed.

**Why this is not a duplicate of the already-filed reports:**

No other filed report touches the WebSocket plane — this is the only submission concerning the Orbit/Pusher realtime subscription path, the `pusherAuth` signing oracle, or cross-tenant channel membership. All other filed submissions concern HTTP surfaces and their own object families, and are disjoint from this mechanism.

**Remediation:**

Parse the channel name at `pusherAuth` and verify the org/app/branch id segment against the session's memberships **before signing** (reject foreign ids with the same generic error as malformed names). The signature should never be issued for a name whose tenant segment the session is not a member of.

**Evidence to attach:**

- `hunt2610/wave3-pusher/evidence/join_log_raw.txt`, `join_results.txt` — the six-channel join matrix with verbatim protocol-6 frames and `subscription_succeeded` receipts.
- `hunt2610/wave3-pusher/evidence/listen_log_raw.txt`, `listen_results.txt` — the 35-second idle listen (zero data frames; the ceiling measurement).
- Harness: `hunt2610/pusher_join.py`. Verdict matrix: `hunt2610/wave3-pusher/FINDINGS.md`.
- Signing-oracle raws (first run, prior wave): `hunt2610/wave2-mcp/evidence/h3_*`.
