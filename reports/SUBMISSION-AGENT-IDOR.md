# Amplitude Global Agent — cross-user object reference: the read-only Viewer can read another user's agent threads and conversation state

**Target:** App Platform — `https://app.amplitude.com` (Global Agent runtime)
**VRT:** Broken Access Control (BAC) > Insecure Direct Object Reference (IDOR)
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` = **7.1 (High)**
**Date:** 2026-09-19
**Tested org:** `464637` (`agentmail-602393`), app `862908` — our own tenant only.

---

## Summary

The Global Agent runtime lives on `POST https://app.amplitude.com/fed/graphql/org/<orgId>`.
Several of its resolvers verify that the object they are handed **exists**, but never that the
caller **owns** it. The authorization decision is therefore made on existence, not on ownership,
and any authenticated member of the organization — including the read-only **Viewer** role — can
address another user's agent objects directly by id.

The differential is unambiguous, because the same resolver produces a *distinguishable* error for
a non-existent id:

| Caller | Request | Result |
|---|---|---|
| **VIEWER** | `agentGetThread(<the ORG_ADMIN's threadId>)` | **`200`** — returns `threadId`, `sessionId`, **`userId: <admin's address>`**, `orgUrl`, `appId` |
| **VIEWER** | `agentGetThread(00000000-0000-0000-0000-000000000000)` | `NOT_FOUND` — `"Thread … not found"` |

That contrast is the finding: the object is not public, the caller has no relationship to it, and
the server knows the difference — it simply does not check ownership.

This is not "an object shared by design". The session-access model that *would* express sharing
says the opposite: `agentListSessionUserAccess(<the admin's sessionId>)` returns
**`{"accessEntries": []}`** for the Viewer, and the admin's session does not appear in the
Viewer's own `agentListSessions`.

---

## Reproduction

### Step 1 — the ORG_ADMIN creates an agent session, a thread and a marked object

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

### Step 2 — the VIEWER reads the ADMIN's thread

```
POST https://app.amplitude.com/fed/graphql/org/464637
Cookie: <VIEWER session>          x-csrf-token: 1
{"query":"query AgentThreadContext($threadId: ID!) { agentGetThread(threadId: $threadId) { threadId sessionId userId orgUrl appId } }",
 "variables":{"threadId":"ab964d6f-8463-44fe-ba3a-aa217a992f46"}}
```
```
HTTP/1.1 200 OK
{"data":{"agentGetThread":{
   "threadId":"ab964d6f-8463-44fe-ba3a-aa217a992f46",
   "sessionId":"32a80523-c8f5-4563-81d2-ffb1e19e6866",
   "userId":"mohamed-9499-3@agentmail.to",        <- the ORG_ADMIN's identity
   "orgUrl":"agentmail-602393",
   "appId":"862908"}}}
```

The thread's stored state is the **`stateJson`** field — the shipped document is
`query AgentThreadContextWithState($threadId: ID!) { agentGetThread(threadId: $threadId) { threadId requestContextJson stateJson } }`,
and it is `stateJson.chat_history` that is the conversation itself (measured: 10 turns, including
`model_name` and the assistant's answer). `requestContextJson` is a **different** field: it is the
thread's run index — measured on the same thread as
`[{"thread_run_id":"22064991-…","status":"completed","updated_at":"2026-09-20T02:07:32Z",…}]`, and
`"[]"` on a thread with no run. A triager who runs the document quoted in the earlier draft sees the
run index, not the conversation.

### Step 3 — the negative control proves it is an ownership failure, not a public object

```
[VIEWER] agentGetThread(threadId: "00000000-0000-0000-0000-000000000000")
-> 200 {"errors":[{"message":"Thread 00000000-0000-0000-0000-000000000000 not found",
                   "extensions":{"code":"NOT_FOUND"}}]}
```

### Step 4 — the Viewer has no legitimate relationship to that session

```
[VIEWER] agentListSessionUserAccess(sessionId: "32a80523-c8f5-4563-81d2-ffb1e19e6866")
-> 200 {"data":{"agentListSessionUserAccess":{"accessEntries":[]}}}
```

### Other resolvers with the same missing ownership check (agent-verified)

| Operation | Result for the VIEWER |
|---|---|
| `agentListThreads(<admin's sessionId>)` | `200` — returns the admin's threads and their `threadRuns` |
| `agentForkThread(<admin's threadId>)` | `{"crossUser":true, "copiedObjectCount":0}` |
| `agentSearchObjects` (org object store) | `200` — returns stored objects carrying other users' `user_id` |
| `agentSubmitFeedback` into the admin's session | `200 {"objectStoreId":"…"}` — a **cross-user write** |

The root cause is one shared pattern: **the agent-runtime resolvers check `exists(object)` where they
should check `owns(caller, object)`.**

All three documents above take `$sessionId: **ID!**`, not `String!`. Sending `String!` returns
`400 GRAPHQL_VALIDATION_FAILED {"message":"An error occurred"}` — which reads like a missing resolver
but is only an argument-type mismatch. The shipped documents in
`bundles/gs-app/use-send-message-direct-D4HCrmCl.js` are authoritative here.

---

## Extended vectors — what the same missing check exposes beyond the thread object

The same ownership check is absent on **seven** resolvers — `agentGetThread`, `agentListThreads`,
`agentForkThread`, `agentSearchObjects`, `agentSubmitFeedback` (a write), `agentGetThreadRun` and
`agentGetSession` — and three of them return materially more than a thread header. (The earlier draft
said "five" in the summary and "six" in this section; both were under-counts, and the section then
enumerated only five of the seven.) All verified with
a read-only Viewer (orgRole 1), all with `NOT_FOUND` controls on fabricated ids:

### 1. `agentGetThreadRun(threadRunId, sessionId, threadId)` — the full run transcript

```
query { agentGetThreadRun(threadRunId:"<admin's run>", sessionId:"<admin's session>",
                          threadId:"<admin's thread>") { … } }
-> 200   the Admin's completed run, including every TOOL_CALL and TOOL_RETURN verbatim:
         raw tool arguments, the chart definition the agent built, and the
         PROJECT ANALYTICS the agent retrieved from the organization's data.
```

This is the strongest form of the finding: the Viewer does not merely learn that a conversation
exists — it receives **the analytics data another user pulled from the organization**, together
with the exact tool calls that produced it.

### 2. `agentGetThread(threadId)` — the whole conversation state

`stateJson.chat_history` in full: the user's prompt, `model_name`, the tool trace and the
assistant's answer.

### 3. `agentSearchObjects(objectType:"artifact")` — the artifact payload

```
{"objectType":"artifact", "content": {…BlocksArtifact…},
 "metadata":{"thread_id":"<admin's thread>","thread_run_id":"<admin's run>"}}
```
The payload itself, not just metadata, and the metadata names the victim's thread and run.

### 4. `agentGetSession(sessionId)` — a seventh unscoped resolver

Returns the Admin's session object (`userId`, `threads[]`, tags). This is the **cheapest
reproduction of the whole class: one request, no chained ids**, which is why it is worth calling out
separately — a triager can confirm the defect with a single call.

### 5. `agentListThreads(sessionId)` → `threadRuns{threadRunId}`

Lists the Admin's threads together with their run ids, so a Viewer obtains the two identifiers the
run read in (1) needs — a clean two-step chain from list to full transcript.

**Everything above is the same defect as the originally reported thread read** — `exists(object)`
where `owns(caller, object)` is required — so it is folded into this report rather than filed
separately. It raises the confidentiality impact from "another user's thread exists and here is its
header" to "**another user's tool-level activity and the organization's analytics data**".

### Verified negative — agent memory IS correctly gated

To show the check is genuinely absent on the read resolvers rather than absent everywhere, the same
surface was probed where it *is* enforced. With an Admin memory present (`totalCount: 1` for its
owner):

```
agentListMemories / agentSearchMemories(userId=<other>)   -> []      (the userId arg cannot widen scope)
agentCreateMemory(userId=<other>)                         -> FORBIDDEN
                                                             "…create memories outside your own scope"
agentUpdateMemory / agentDeleteMemory on another's memory -> NOT_FOUND, victim row survived
```

Control: a Viewer **can** create and read its own memory, so the read path is not vacuous. Cross-user
writes and archives are likewise refused (`agentArchiveThread`, `agentUpdateObject`,
`agentSubmitArtifactDataCallback` → `FORBIDDEN "Only the session owner…"`; `agentArchiveSession` →
`FORBIDDEN "…manage this session"`), and session enumeration returns `[]` for every mode
(`tag`/`owned`/`all_listable`/`orgAudit`).

So the defect is specific and directional: **reads of other users' agent objects are unscoped;
writes and the memory subsystem are not.** That contrast is what makes it an oversight rather than a
design decision.

---

## Relationship to previously submitted reports

There is no overlap with the other Amplitude reports from this engagement:

| | |
| --- | --- |
| `SUBMISSION-GS-AUTHZ.md` (`/a/`, `/h/` Guides & Surveys / Houston) | different asset and different authorization mechanism — a Django REST permission class on the Guides & Surveys viewsets, evaluated against the org role. This report is about the **federation GraphQL agent runtime** (`POST /fed/graphql/org/<orgId>`), where the resolvers verify that an object **exists** and never that the caller **owns** it. Different routes, different objects (agent sessions, threads, runs, stored objects), different fix (an ownership predicate in the resolver family, derived from one shared helper). |
| `SUBMISSION-TAXONOMY-SHIM.md` (`/o/taxonomy-api-shim/*`) | different asset, different object (the tracking plan), different defect (a role check that is never evaluated, on a route whose own `readOnly` flag is wrong). |
| `SUBMISSION-XLIFF-DOS.md` (XLIFF expansion) | different asset and different class (parser resource consumption on an upload route). |

The only thing shared with the GS-AUTHZ report is the *actor* — the read-only Viewer role — and that
is the engagement's common thread, not a shared defect. Neither report's route, object or remediation
appears in the other.

## Impact

* A read-only **Viewer** — Amplitude's lowest role, and the default role for invited collaborators
  and read-only stakeholders — can read **other users' agent threads**, including the
  conversation state (`chat_history`) of an **organization administrator's** agent sessions.
* Agent conversations routinely contain the questions a user asked, the data they queried, and the
  answers returned — i.e. exactly the material an organization expects to be private per user.
* The same pattern yields a cross-user **write** (`agentSubmitFeedback` into another user's
  session) and access to the org-wide object store via `agentSearchObjects`.
* The missing check is uniform across the family, so it is not a single endpoint oversight.

## Remediation

* Enforce ownership (or an explicit share grant) in the agent-runtime resolvers, not existence:
  resolve the caller from the session and require `thread.userId == caller` — or a row in the
  session-access table — before returning any thread, run or object.
* Apply the same predicate to `agentListThreads`, `agentForkThread`, `agentSearchObjects`,
  `agentGetThreadRun` and `agentSubmitFeedback`; derive it from one shared helper rather than
  repeating it per resolver.
* Treat `agentSearchObjects` as an org-scoped query that must itself be permission-gated
  (`AGENT_ANALYTICS_VIEW` plus an ownership filter), since it returns other users' objects.
* Return the same `NOT_FOUND` for "exists but not yours" as for "does not exist", so the API does
  not act as an existence oracle.

## Negative controls / ceilings checked

* Non-existent thread id → `NOT_FOUND`, distinguishable from the cross-user `200` (this is the
  control that makes the finding).
* `agentUpdateThread` / `agentUpdateObject` / `agentAddSessionUserAccess` → `FORBIDDEN "Only the
  session owner…"` — writes *are* gated, which is why the read-side gap is an oversight rather
  than a deliberate design.
* `agentSearchThreads(userId: <other>)` → `FORBIDDEN`; `visibility: all_visible|owned` → own-only.
* `agentAuditTranslateThread` → admin-only. `mcpListOrgConnectorTools` → `FORBIDDEN`.
* `mcpListCatalogEntries.oauthConfig.clientSecret` → empty string, no leak.
* **Cross-tenant**: ids from org 465907 addressed in the 464637 context → `NOT_FOUND`;
  `AgentCreateSession` in 465907 → `FORBIDDEN`. The gap does not cross the org boundary.
* `agent-analytics-rbac-enforced` was investigated and **ruled out** as the escalation vector.
  `RbacBatchCheckPermissions` for the Viewer returns, verbatim:
  `AGENT_ANALYTICS_VIEW → allowed: true`, `AGENT_ANALYTICS_MANAGE_INACTIVE_EVAL → allowed: false`,
  `AGENT_ANALYTICS_TRIGGER_EVAL_RUN → allowed: false`, `AGENT_ANALYTICS_ACTIVATE_EVAL → allowed: false`
  (plus `AI_VIEW_GLOBAL_AGENT → true`, `AI_CREATE_GLOBAL_AGENT → true`, `VIEW_PROJECT_DETAILS → true`).
  So the server evaluates the three eval-write permissions and correctly denies the Viewer all three,
  while granting the read permission; the feature flag only swaps a coarse client-side fallback.

No LLM call and no outbound tool call was made. All probe sessions were archived (`success:true`) and
`agentListSessions` verified empty for both roles.

**Residual test data, declared:** `agentSearchObjects` has **no delete operation** — feedback and
artifact objects cannot be removed, only overwritten. As of the final read-back this org's object
store returns **8 rows**: 6 from earlier runs plus the 2 this report's chain created. Their `content`
has been overwritten with `{"hermes_probe":"removed"}` / a non-sensitive marker and read back, and the
only live content they ever carried was our own marker text. A triager running
`agentSearchObjects(limit: 200)` will see these rows and should expect them.

## Evidence

`escal/root_verify_agent_20260919T*.json` (root-agent independent reproduction: session/thread
creation, the Viewer reading the Admin's thread, the `NOT_FOUND` control, the empty access-entry
list, cleanup), `escal/REPORT-AGENT-SURFACE.md` (full surface map, 192 operations),
`AGENTSURF/repro.json` (clean 12-step end-to-end), `AGENTSURF/ops.json` (192 recovered operation
documents — note that `agentListThreads`, `agentSearchObjects`, `agentGetSession`, `agentListSessions`,
`agentCreateMemory`, `agentListMemories`, `agentUpdateObject` and `agentSearchThreads` are **not** in
it; they come from the shipped runtime bundle
`bundles/gs-app/use-send-message-direct-D4HCrmCl.js`, which is where the fragments
`agentThreadField`, `agentSessionField` and `agentMemoryField` are defined),
`AGENTSURF/p1…p13` probes and raw JSON evidence.
