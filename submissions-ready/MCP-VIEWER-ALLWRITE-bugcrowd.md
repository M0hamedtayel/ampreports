# Amplitude MCP — OAuth consent mints a global `all:read all:write` bearer for a VIEWER: granted scope is never bound to the requesting user's RBAC capabilities, at mint or at tool call

**Target Location:** Amplitude MCP
**Target category:** API Testing
**VRT (suggested):** Broken Access Control (BAC) > Privilege Escalation — CVSS 3.1 `AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:L` = **7.6 (High)** *(calibration note: a triager accepting component separation between the MCP grant plane and the analytics data plane may read S:C → 8.9; that reading is offered for calibration only and is not the claim — this report claims S:U intra-org escalation.)*

---

**Affected Asset:** `https://mcp.amplitude.com` (OAuth grant plane: `/register`, `/authorize`, `/token`, `/revoke`; advertised scopes at `/.well-known/oauth-protected-resource`) + the `/mcp` tool layer (48 tools, 13 write-class).

**Summary:**

The Amplitude MCP OAuth layer issues 24-hour bearer tokens whose scope — now `all:read all:write` — is **not derived from, nor checked against, the authenticating user's role**, at token mint or at tool call. A VIEWER — the lowest analytics role, whose `USE_MCP_WRITE` action is explicitly `false` in the org's own RBAC (live `rbacBatchCheckPermissions` response, re-measured 2026-10-17: `USE_MCP_READ: true, USE_MCP_WRITE: false, FULL_ADMIN_ACCESS: false`) — completes the consent screen, receives a token with `scp:["all:read","all:write"]`, and the `/mcp` tool layer then executes write-class tools for that token **with byte-identical success responses to an ORG_ADMIN's**. No differential on the wire means there is no call-time role check either: the tool layer never consults `USE_MCP_WRITE` (or any role action) for anyone. 13 of the 48 advertised tools are write-class, including destructive ones (`delete_event_properties` with `confirmed:true` executed `"1 plan-wide removed"`).

The consent screen renders `all:read all:write offline_access` to the human with **no role/capability caveat** — a viewer silently approves global write and gets it. Since September, the vendor has also broadened the advertised scopes from `mcp:read mcp:write` to `all:read all:write` (`/.well-known/oauth-protected-resource`), which amplifies every downstream consumer of this grant class.

Token lifecycle was measured 2026-10-17: a minted token **survives `/signout` and `/logout`** — full 86400s lifetime with no revocation trigger on session end — while `/revoke` propagation is instant (revoked tokens immediately `401 invalid_token`), so containment exists only if misuse is independently detected within 24 hours.

All testing was on the researcher-owned org (org `464637`, app `862908`) with ORG_ADMIN as the control role and VIEWER as the subject role. All 6 test tokens minted during the run were revoked and verified `401`; both probe properties were deleted and verified gone.

**Steps to Reproduce:** *(measured 2026-10-17, performed on my own tenant — org 464637, app 862908; all tokens revoked and verified 401 afterwards, probe properties deleted and verified gone)*

1. **Baseline — the subject is write-denied in RBAC:**
   ```
   POST https://app.amplitude.com/t/graphql/org/464637?q=rbacBatchCheckPermissions
   Cookie: <VIEWER SESSION>
   ```
   ```
   HTTP/1.1 200 OK
   {"USE_MCP_READ": true, "USE_MCP_WRITE": false, "AI_CREATE_GLOBAL_AGENT": true,
    "CHANGE_ORG_ADMINS": false, "FULL_ADMIN_ACCESS": false}
   ```
2. **Client registration:** `POST https://mcp.amplitude.com/register` (this endpoint's open-registration behaviour is separately reported and is *not* this finding) → `200` + `client_id`.
3. **Full OAuth chain with the VIEWER session** (`mohamed-9499-2+member@agentmail.to`, orgRole 1): proxy `302` → Hydra login → accept-login → **consent screen renders *"[MCP] wave2-h1-probe requesting all:read all:write offline_access"* for org agentmail-602393 — no mention that the approver is a VIEWER, no per-scope role gating** → approve → `303` with `?code=` at the sink → `POST /token` (PKCE) → `200` bearer, `expires_in 86400`. Decoded token: `scp:["all:read","all:write"]`, `sub:<viewer email>`, `ext.org_id:"464637"`, `aud:[]`.
4. **Tool layer with the VIEWER token:**
   - `initialize` → `200`; `tools/list` → `200`, **48 tools, 13 write-class** (`create_properties`, `update_properties`, `delete_event_properties`, `delete_user_properties`, `manage_amp_entities`/`manage_amp_events`/`manage_amp_taxonomy`, `rename_chart`, `save_chart_edits`, `share_amp_entities`, `restore_*`, …).
   - `create_properties` on app 862908 → **`200 {"success":true,"message":"Processed 1 event property(ies): 1 created."}`**; re-invoking returns "already exists" (creation independently proven).
   - `delete_event_properties` `{"confirmed":true}` → **`200 {"success":true,…,"1 plan-wide removed"}`**.
5. **Admin control (proves "no check", not "weaker check"):** the same tools with an ORG_ADMIN's token on the same project return **byte-equivalent success shapes**. The tool layer resolves no role predicate for anyone.
6. **Token lifecycle:** the VIEWER token kept working after `/signout` and `/logout` (full 86400s, measured 2026-10-17); `POST /revoke` → `200`, and the very next call with the revoked token → `401 invalid_token` (instant propagation).
7. **Cleanup:** all 6 tokens (5 VIEWER + 1 ORG_ADMIN control) revoked at `/revoke` → `200` ×6, each verified `401` post-revoke; probe property `wave2_h1_viewer_probe` deleted via confirmed delete and verified gone by create-collision check; admin probe `wave2_h1_admin_probe` deleted in the same ORG_ADMIN call (`"Deleted 2 … plan-wide removed"`).

**Impact:**

* **Role-boundary break at mint time:** the lowest privileged role can self-service a 24h global `all:read all:write` bearer (plus `offline_access`) through a consent screen that never discloses what "all:write" bypasses. Every "read-only stakeholder" in a customer org holds this capability — **no token theft required**: the account owner's own legitimate consent mints the write credential.
* **Tool-layer reach:** write-class tools cover event-property/taxonomy plan mutation, chart mutation, sharing primitives, and destructive plan-wide deletes — from a token any phish, XSS, or log leak can capture, and which survives app logout for its full 24h window (measured 2026-10-17; no revocation trigger on session end).
* **Scope amplification:** advertised scopes moved from `mcp:read mcp:write` to `all:read all:write` since September — any token of this grant class (including theft-vector ones from the separately-filed chain, which still reproduces: anonymous DCR with arbitrary `redirect_uri` re-verified 2026-10-17) is now a global-write credential instead of a product-scoped one.

**Controls (what bounds this):**

* All testing on the researcher's own org/app; `org_id` is embedded in the token (`ext.org_id`), so **cross-org reach was not claimed and not tested** — the finding is intra-org privilege escalation, not cross-tenant.
* **Revocation works:** `/revoke` → `200` with instant propagation (`401 invalid_token` on next use) — containment exists once misuse is detected within the 24h window. The bound is detection, not containment mechanics.
* `delete_event_properties` was exercised only on a probe property the researcher created.
* Self-building-taxonomy write surfaces (`agentListSelfBuildingTaxonomyRuns` et al.) are feature-gated off for the whole org (`auto_taxonomy_alpha_off`) — identical 403-shape for VIEWER and ORG_ADMIN, so no differential observable there; not claimed.

**Why this is not a duplicate of the already-filed reports:**

* **vs the April 2026 report "Unauthenticated OAuth Client Registration on mcp.amplitude.com Enables Consent-Phishing Account Takeover and Cross-Customer Workspace Data Access" (GET-Based, P2, VRT) — the report `f354f04c` was just marked duplicate of:** that report's subject is the **registration/redirect surface and the consent-phishing vector** — anonymous client registration with arbitrary `redirect_uri` enabling a *stolen*-token chain (phish the code, take the account). This finding is about **what ANY token of this grant plane carries, independent of how it was obtained** — including one obtained with **full, legitimate consent from the account owner himself** (steps 3–4 above: the viewer's own session, his own approval, no theft, no phishing, no third party). The two failure modes are orthogonal, and the remediations do not overlap:
  - **Fixing DCR entirely — the April report's remediation (authenticated/throttled registration, strict redirect_uri allow-listing) — leaves this finding fully exploitable with zero change.** Any future *legitimate* integration consented by a viewer still mints `all:read all:write`, still executes write tools with byte-identical responses to an admin's, and still bypasses `USE_MCP_WRITE=false`. The April report's fix hardens how tokens are obtained; it does nothing about what they carry.
  - Separation test on objects: April covers `/register` (anonymous DCR), `redirect_uri` validation, and the phishing UX. This report covers **`/token` scope issuance** (granted scope ≠ issuer RBAC) and **`/mcp` tool-call authorization** (`USE_MCP_WRITE` never consulted — admin control byte-identical, step 5). Zero shared routes, zero shared checks, zero shared fix.
  - The registration surface appears in this report's step 2 only as an inert enabler of the test harness (registering the test client), and the consent screen appears only as the UI the legitimate owner himself approves — neither is the defect demonstrated.
* **vs `f354f04c` (the September token-theft chain, filed by this researcher) and its companion:** `f354f04c` is the theft vector (DCR → consent-phishing → token capture). Its companion demonstrated a *read-scoped* token executing a write tool (call-time scope enforcement missing) on the old `mcp:read mcp:write` vocabulary. Separation test: fixing the call-time half only (per-call role/scope checks) leaves this finding's mint-time half alive — the consent artifact itself promises `all:write` to a principal RBAC denies; fixing the mint-time half only leaves the call-time absence alive for stolen/company-scoped credentials. Neither filed fix was scoped against the new `all:*` semantics; the September companion used an admin-plane user's read token, this report uses a **VIEWER** and the broadened scopes.
* **vs the session-plane taxonomy finding** (`/o/taxonomy-api-shim`, filed separately): that defect is a wrong permission *computation* on an internal REST resolver reached with a browser **session cookie**; this one is the **OAuth issuance layer** binding scope to nobody. The vendor's "Use MCP (write)" documentation line is quoted in both only because the vendor states the intended policy once for both planes — routes, credentials, resolvers and fixes share nothing.

**Remediation:**

1. At `/token`, **intersect the consented scope with the authenticating principal's RBAC capabilities** — a viewer cannot consent to (or be issued) any write scope, regardless of what the client requested.
2. **Enforce `USE_MCP_WRITE` (and per-tool action mappings) at tool-call time** against the token's linked user, not just the token's scope string — today the admin control proves no role predicate resolves for anyone.
3. **Render per-scope role implications on the consent screen** ("this grants write access to [org] — your role: Viewer"), so the human approving `all:write` knows what it bypasses.
4. **Bind token lifetime to session policy:** add a revocation trigger on `/signout`/`/logout` (or shorten the 86400s window), so a compromised consented token does not outlive the session that minted it by up to 24 hours.
5. **Re-scope the grant vocabulary:** `all:read all:write` is broader than any MCP consumer needs; return to product-scoped grants (or an explicit per-tool allow-list at consent) so the blast radius of any single token matches its function.

**Evidence to attach:**

* `hunt2610/wave2-mcp/FINDINGS.md` — verdict matrix (H1 CONFIRMED), token/consent facts, cleanup record.
* `hunt2610/wave2-mcp/evidence/` — ~50 numbered raw files: full OAuth chain captures, consent screen, decoded token claims (`first8…last4` masked), `tools/list` output (48 tools), `create_properties` / `delete_event_properties` raw 200 responses for both VIEWER and ORG_ADMIN tokens, RBAC baselines.
* `hunt2610/fresh-surface/evidence/` — `rbacBatchCheckPermissions` baselines (`USE_MCP_WRITE:false` for viewer, re-measured 2026-10-17).
* Cross-ref: September filed chain `f354f04c-7a27-4649-a5e1-b848e410f961`.
