# [Amplitude] MCP OAuth consent mints a global all:read all:write bearer for any role — mint-time scope is never bound to the requesting user's RBAC capabilities

- **Asset:** mcp.amplitude.com (OAuth grant plane + `/mcp` tool layer)
- **Program:** Amplitude private bug bounty (Bugcrowd)
- **Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:L = **7.6**
  *(calibration note: a triager accepting component separation between the MCP grant plane and the analytics data plane may read S:C → 8.9; not claimed here)*
- **Date:** 2026-10-17 · **Tenant:** researcher-owned org (org 464637, app 862908) · Roles used: ORG_ADMIN (control) + VIEWER (subject)
- **Classification:** CWE-862 (missing authorization at token issuance — granted scope not intersected with the principal's permission set) · CWE-1220-ish weak binding between consent artifact and enforcement layer

---

## Summary

The MCP OAuth layer issues 24-hour bearer tokens whose scope (`all:read all:write`) is **not derived from, nor checked against, the authenticating user's role**. A VIEWER — the lowest analytics role, whose `USE_MCP_WRITE` action is explicitly `false` in the org's own RBAC (`rbacBatchCheckPermissions`) — completes the consent screen, receives a token with `scp:["all:read","all:write"]`, and the `/mcp` tool layer then executes write-class tools for that token **with byte-identical success responses to an ORG_ADMIN's** (no differential = no call-time role check either). 13 of the 48 advertised tools are write-class, including destructive ones (`delete_event_properties` with `confirmed:true` executed "plan-wide removed").

The consent screen renders `all:read all:write offline_access` to the human with **no role/capability caveat** — a viewer silently approves global write. Since the September disclosure, the vendor also broadened the advertised scopes from `mcp:read mcp:write` to `all:read all:write` (`/.well-known/oauth-protected-resource`), which amplifies every downstream consumer of this grant class, including the token-theft chain already filed.

## Why this is not a duplicate of the September companion finding

The September report (token-theft chain, Bugcrowd `f354f04c-7a27-4649-a5e1-b848e410f961`) carried a companion: *an `mcp:read` token executed a write tool (create_properties) — call-time scope enforcement missing*. Separation test:

- **Fix the call-time half only** (tools check role/scopes per call) → this finding's mint-time half survives: the consent artifact itself promises `all:write` to a principal RBAC denies; the grant is a durable, revocation-tardy misrepresentation (24h, offline_access refresh).
- **Fix the mint-time half only** (issued scope = role capability intersection) → the call-time absence survives for stolen/company-scoped credentials.
- The September companion demonstrated (b) with a read-scoped token of an admin-plane user; **this finding demonstrates (a)+(b) with a VIEWER and the new `all:*` scope semantics** — the vendor's own scope vocabulary changed since the filed report, which neither fix was scoped against.

Fixing one root cause leaves the other exploitable ⇒ standalone report, cross-referenced as an escalation comment on the filed chain.

**Also distinct from the session-plane taxonomy finding** (`/o/taxonomy-api-shim`, filed separately): that defect is a wrong permission *computation* on an internal REST resolver reached with a browser **session cookie**; this one is the **OAuth issuance layer** binding scope to nobody. The vendor's "Use MCP (write) / Update Tracking Plan" documentation line is quoted in both reports only because the vendor states the intended policy once for both planes — the routes, credentials, resolvers, and fixes share nothing.

## Repro (measured 2026-10-17, researcher-owned tenant)

1. **Baseline (subject is write-denied):**
   `POST https://app.amplitude.com/t/graphql/org/464637?q=rbacBatchCheckPermissions` with the VIEWER session →
   `{"USE_MCP_READ": true, "USE_MCP_WRITE": false, "AI_CREATE_GLOBAL_AGENT": true, "CHANGE_ORG_ADMINS": false, "FULL_ADMIN_ACCESS": false}`
2. **Anonymous DCR** (no auth, unthrottled — already reported, unchanged):
   `POST https://mcp.amplitude.com/register` with `{"client_name":"[MCP] wave2-h1-probe","redirect_uris":["https://<attacker-sink>/cb"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"all:read all:write offline_access"}` → `200` + `client_id`.
3. **Full OAuth chain with the VIEWER session** (cookies of the viewer account): proxy 302 → Hydra login → accept-login → consent screen renders *"[MCP] wave2-h1-probe requesting all:read all:write offline_access"* for org agentmail-602393 → approve → `303` with `?code=` at the sink → `POST /token` (PKCE) → `200` bearer, `expires_in 86400`.
   Decoded token: `scp:["all:read","all:write"], sub:<viewer email>, ext.org_id:"464637", aud:[]`.
4. **Tool layer with the VIEWER token:**
   - `initialize` → `200`; `tools/list` → `200`, 48 tools, 13 write-class (`create_properties`, `update_properties`, `delete_event_properties`, `delete_user_properties`, `manage_amp_events/taxonomy`, `rename_chart`, `save_chart_edits`, `share_amp_entities`, `restore_*` …).
   - `create_properties` on app 862908 → **`200 {"success":true,"message":"Processed 1 event property(ies): 1 created."}`**; re-invoking the same create returns "already exists" (creation independently proven).
   - `delete_event_properties` `{"confirmed":true}` → **`200 {"success":true,…,"1 plan-wide removed"}`**.
5. **Admin control (the differential that proves "no check" rather than "weaker check"):** the same tools with an ORG_ADMIN's token on the same project return byte-equivalent success shapes. The tool layer resolves no role predicate for anyone.
6. **RBAC-layer contrast (intent):** in the console, the viewer role's action map denies `USE_MCP_WRITE` (the bundle's own permission matrix and the live `rbacBatchCheckPermissions` both say so) — the vendor's stated policy is that a viewer must not write; the OAuth layer hands it over anyway.

## Impact

- **Role-boundary break, mint-time:** the lowest privileged role can self-service a 24h global write bearer (and request `offline_access`) through a consent screen that never discloses what "all:write" bypasses. Every internal "read-only stakeholder" in a customer org holds this capability.
- **Tool-layer reach:** write-class tools cover taxonomy/event-property plan mutation (public-facing instrumented-property semantics), chart mutation, sharing primitives, and destructive plan-wide deletes — from a token any phish, XSS, or log-leak can capture, and which survives app logout within its 24h window (September measurement).
- **Amplification of the filed theft chain:** scopes moved from `mcp:read|mcp:write` to `all:read|all:write` — a stolen token (the filed HIGH#1 chain still reproduces today: anonymous DCR still accepts arbitrary `redirect_uri`, re-verified 2026-10-17) is now a global-write credential instead of a product-scoped one.

## Ceiling (honest bounds)

- All testing on the researcher's own org/app; no third-party data touched. `org_id` is embedded in the token (`ext.org_id`), so cross-org reach was **not** claimed and not tested — the finding is intra-org privilege escalation, not cross-tenant.
- Token revocation works (`/revoke` → 200; revoked tokens then `401 invalid_token`) — containment exists once misuse is detected.
- `delete_event_properties` was exercised only on a probe property the researcher created.

## Suggested remediation

1. At `/token`, intersect the consented scope with the authenticating principal's RBAC capabilities (a viewer cannot consent to any write scope).
2. Enforce `USE_MCP_WRITE` (and per-tool action mappings) at tool-call time against the token's linked user, not just the token's scope string.
3. Render per-scope role implications on the consent screen ("this grants write access to [org] — your role: Viewer").

## Evidence

- Raw chain captures + tool responses: `hunt2610/wave2-mcp/evidence/` (numbered; ~50 files), verdict matrix `hunt2610/wave2-mcp/FINDINGS.md`.
- Consent screen + token claims: `hunt2610/wave2-mcp/evidence/h1_*` (token values masked `first8…last4`; all 6 test tokens revoked and verified `401` post-revoke).
- Cross-refs: `rbacBatchCheckPermissions` baselines in `hunt2610/fresh-surface/evidence/`; September filed chain `f354f04c-7a27-4649-a5e1-b848e410f961`.
