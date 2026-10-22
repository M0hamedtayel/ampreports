# FULL PROGRAM RETEST REPORT — Amplitude ×3 + Statsig
**Date:** 2026-10-17 · **Method:** from-zero retest, 3 waves (R1×4 + R2×4 + R3×2 agents), ~750 requests total, all on self-owned tenants
**Comparison baseline:** September 2026 full hunt (FINDINGS/LEDGER.md)

---

## Executive summary

| Metric | Count |
|---|---|
| Surfaces retested | 38 task-groups across auth, GraphQL, REST, Statsig console, OAuth/MCP, SSRF/files, XSS/JS, races, SSO/SCIM, G&S/SDK, cross-tenant |
| **Still vulnerable (September findings holding)** | 7 (incl. 1 expanded) |
| **NEW confirmed this engagement** | 2 (MCP viewer-all:write 7.6 · PusherAuth cross-tenant 4.3) |
| **Fixed by vendor since September** | 3 (GS-AUTHZ viewer writes · ingestion SSRF · SSO metadataUrl field) |
| **Partially fixed / downgraded** | 1 (XLIFF amplification 6.5→~4.3 Low residual) |
| **Tightened (improved posture)** | 3 (signup throttle pooled · role-assign concurrency guard · login email-trigger no-send) |
| New low/info items | 4 (no-RL member-directory reads, archiveSharedLink 5-arg 500, /t path-less demo-org resolution, trace-header leak change) |
| Hard contradictions between waves | 0 (consistency check passed; 2 actionable notes) |

---

## 1. The surface matrix (September → October)

### Amplitude — app.amplitude.com
| Surface | Sept | Oct verdict |
|---|---|---|
| GraphQL /t admin mutations viewer-gating | gated OK | **HOLDS** (RBAC clean set re-confirmed) |
| NEW custom-RBAC plane (rbac*) | n/a | **CLEAN** (4/4 correctly gated; custom roles feature-off org-wide) |
| NEW-OP viewer sweep (~45 ops) | n/a | **CLEAN** — all admin/secret/audit/provisioning 403; lows: usersForApp, searchUsers, usersRequestingOrgAccess (via /fed only) |
| S6 notebook IDOR (notebooks/notebookItems/chartEdit) | CONFIRMED Medium | **STILL LIVE** (re-proven AM; control intact PM) |
| TAXONOMY-SHIM viewer writes (7.1) | CONFIRMED High | **STILL LIVE** (AM full chain; premise re-verified PM: C secretKey null) |
| AGENT-IDOR (7 resolvers) | CONFIRMED High | **STILL LIVE** (AM re-proven) |
| G&S viewer writes (themes/collections/G&S/h.syncs) | CONFIRMED Medium | **FIXED** (all 403; 8 bypass shapes closed) |
| G&S viewer reads | parity | **PARITY** (unchanged — still viewer-readable) |
| GS content-reach SDK delivery | proven (viewer-authored) | **HOLDS — now requires ADMIN authorship** (nudge 107566 delivered in seconds, deleted clean) |
| RC-SSRF (website source, viewer trigger) | CONFIRMED Low 2.9 | **STILL LIVE** (AM: egress + viewer trigger re-proven) |
| XLIFF amplification | CONFIRMED Medium 6.5 | **PARTIALLY FIXED** (1339× capped → ~7× residual, Low) |
| SAML ACS parser gate | XXE ruled out | **HOLDS** (uniform 302 not-configured) |
| SSO metadataUrl save-time SSRF candidate | open_proof_gap (plan-gated) | **MOOT/CLOSED — field removed from IdpSettingsInput** |
| SCIM / core.amplitude.com boundary | separate credentials | **HOLDS** (sessions give zero reach) |
| Cross-tenant matrix (/a /h /d /t /fed) | uniform fail-closed | **HOLDS** (final matrix re-run) |
| REST API v2 tenancy (project= ignored) | fail-closed | **HOLDS**; DSAR org-credential boundary holds; L7 usersearch = same-project only |
| Magic-link validation rate limit | absent | **STILL ABSENT** (10/10 @2s, no 429) |
| org-access-request (unauth, no captcha) | absent wall | **STILL ABSENT** (5/5 plus-addresses; decline route documented + cleaned) |
| login-info org oracle (L1) | CONFIRMED Low | **STILL PRESENT** |
| invite-token auth-state echo | info | **STILL PRESENT** |
| login email-trigger | mail sent unauth | **CHANGED — accept-but-no-send** (impact reduced) |
| Signup captcha-free channel | ruled out | **HOLDS ruled out** (shape gate) |
| Device flow | new | **CLEAN** (no unauth poll/leak; 11 paths) |
| Cookie posture (JS-set session tokens) | known design | **UNCHANGED** |
| Stored-XSS sinks (org/profile/notebook/share) | all escaped | **ALL STILL ESCAPED** (re-stored canaries + anon share) |
| NEW render surfaces (agents/AI/cursor) | n/a | **CLEAN** (client-rendered, no SSR interpolation) |
| DOM-XSS static (183 chunks) | n/a | **CLEAN** (no tainted sink chains; postMessage gated) |
| CSP L10 | present | **STILL PRESENT** (unsafe-inline; XFO/COOP absent) |
| MCP token survives logout | LOW (Sept) | **STILL VULNERABLE — full 86400s window confirmed** (signout+logout ≥4min no revocation) |

### mcp.amplitude.com
| Surface | Sept | Oct verdict |
|---|---|---|
| DCR arbitrary redirect_uri (HIGH#1 filed) | CONFIRMED High | **STILL UNFIXED** (fresh client minted; unthrottled) |
| MCP scopes | mcp:read/write | **BROADENED to all:read/all:write** (amplifies filed chain) |
| VIEWER token all:write + no call-time check | companion Medium | **CONFIRMED 7.6 High — NEW REPORT** (13 write tools, admin-identical) |
| Service accounts / custom-MCP-server | n/a (flags) | **NO API SURFACE** (flag-gated, unreachable as viewer or admin) |

### console.statsig.com / statsigapi.net
| Surface | Sept | Oct verdict |
|---|---|---|
| Plaintext key reads (3 persisted ops) | CONFIRMED High (filed e103ef0a) | **STILL LIVE — ALL TIERS** (raw captures for triage; omni_read_write company key → Member plaintext) |
| Member→Admin REST write (class-key rule) | CONFIRMED 8.8 | **STILL LIVE** (201 + roster read-back; reverted) |
| Review-commit bypass (gates/dynamic_configs) | CONFIRMED 6.5 | **STILL LIVE + EXPANDED — autotunes confirmed → 5/5 commit routes** |
| UpdateSDKKeyScopes / Deactivate (no admin gate) | CONFIRMED High-companion | **STILL LIVE** |
| Signup-state enumeration | CONFIRMED Low 3.7 | **STILL LIVE — throttle TIGHTENED** (pooled ~3 mails/5min/session) |
| Role-assign concurrency | authz-pre-mutation | **+ optimistic-concurrency guard now visible** (3×201+3×409, single state) |
| org webhooks precommit (L6) | owner-tier still present | **UNCHANGED** (owner accepts 169.254; member now role-blocked) |
| Wrong-tier key echo (L5) | STILL-PRESENT | **RE-CAPTURED TODAY** (full credential in 403 body) |
| Ingestion SSRF (databricks) | CONFIRMED 4.6 | **FIXED** (IP-literal refused; egress dead) |
| WHN /wh_connections plan-gate | open gap | **UNCHANGED open gap** (400 not-WHN) |
| NEW org-roles/permissions RBAC | n/a | **CLEAN** (member write 400 'Must be admin'; owner executes) |
| NEW agents/ai_traces/fabric/entity_properties | n/a | **NO DIFFERENTIAL** (company-scoped parity reads; fabric has no REST plane) |
| Integrations/connection-setup | n/a | **NO DIFFERENTIAL** (nothing configured; B=A identical) |
| Session posture | healthy | **HEALTHY** (HttpOnly/Secure/SameSite=Lax; double-submit stable) |

---

## 2. The filing pack (final state after full retest)

| # | Report | CVSS | Retest status |
|---|---|---|---|
| 1 | SUBMISSION-MCP-VIEWER-ALLWRITE (NEW) | 7.6 | CONFIRMED (chain executed; token-outlives-logout strengthens it) |
| 2 | SUBMISSION-PUSHER-CROSSTENANT-CHANNELS (NEW) | 4.3 | CONFIRMED (join proven; no data leak on idle channels) |
| 3 | SUBMISSION-STATSIG-MEMBER-TO-ADMIN | 8.8 | re-verified live |
| 4 | SUBMISSION-TAXONOMY-SHIM | 7.1 | re-verified live |
| 5 | SUBMISSION-AGENT-IDOR | 7.1 | re-verified live |
| 6 | SUBMISSION-STATSIG-REVIEW-BYPASS | 6.5 | re-verified + **expanded to 5/5 commit routes** (update before filing) |
| 7 | SUBMISSION-RC-SSRF | 2.9 | re-verified live |
| 8 | S3 plaintext keys (companion to filed e103ef0a) | — | all tiers live; raw captures delivered for triage |
| 9 | REPLY-e103ef0a-TRIAGE-RESPONSE | — | ready (permission matrix + escalation proof included) |
| — | SUBMISSION-GS-AUTHZ | — | **DO NOT FILE** (fixed) — also its PATCH repro shape went stale |
| — | SUBMISSION-STATSIG-INGESTION-SSRF | — | **DO NOT FILE** (fixed) |
| — | SUBMISSION-XLIFF-DOS | — | downgrade to ~4.3 Low or fold into a Lows bundle |
| — | Hygiene Lows L1/L2/L4/L6/L10/L11 (+L5 echo) | — | all still present → one merged Low report still viable |

## 3. Actionable notes from the consistency check
1. **archiveSharedLink near-miss**: r2-xss could not archive a B link (insufficient permissions) while r2-races archived 3 B links {ok:true} — per-link state difference unresolved; do not cite archive behavior in any report until root-caused.
2. **GS-AUTHZ repro stale**: PATCH minimal-body shape now 500 for everyone (full-object body required). Irrelevant for filing (finding fixed) but the draft must not be reused as-is.
3. **GS content-reach authorship**: viewer-authored delivery no longer reproducible (writes fixed) — pending GS reports must state admin authorship required.
4. Ops: /t/graphql path-less resolves demo org 3149; Statsig persisted-op registry rotated (old pids 400); curl_cffi chrome124 triggers CF err-1016 on /t/rest/* (artifact); taxonomy REST = FORM-encoded; archiveSharedLink legacy 1-arg only.

## 4. Evidence index
- R1: hunt2610/retest/r1-{auth,gql,rest,statsig}/evidence/
- R2: hunt2610/retest/r2-{oauth,ssrf,xss,races}/evidence/
- R3: hunt2610/retest/r3-{sso,gs}/evidence/
- Ledger: FINDINGS/LEDGER.md (dated 2026-10-17 sections per wave) · Plan: hunt2610/retest/RETEST-PLAN.md
