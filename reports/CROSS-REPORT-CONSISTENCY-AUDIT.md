# CROSS-REPORT CONSISTENCY AUDIT — final (2026-10-17, after full retest)

Scope: all 8 filing-pack reports + 2 filed Sept reports (e103ef0a, f354f04c, 8d4a107f, c1f935a8) + 1 triage reply.
Method: pairwise separation test on root causes (does fixing report A leave report B exploitable, and vice versa?) + claim-consistency check on shared facts.

---

## VERDICT: NO UNRESOLVABLE CONFLICTS. 8 filings coexist. 3 relationships require the noted handling. 2 consistency fixes were required and are now APPLIED.

---

## 1. The four filed September reports — how the pack relates

| Filed | Pack report(s) touching it | Relationship | Required handling |
|---|---|---|---|
| `e103ef0a` (plaintext keys) | MEMBER-TO-ADMIN (8.8) + S3 companion + REPLY-e103ef0a | **Two halves of one chain**: e103ef0a = the READ defect (masking predicate), MEMBER-TO-ADMIN = the AUTHORIZATION defect (key-class rule). Stated in both directions inside the documents; separation test passes both ways (masking fix leaves class rule exploitable "by any other route"; authz fix leaves the disclosure) | ✅ already handled — each names the other, both fileable |
| `f354f04c` (MCP OAuth theft) | MCP-VIEWER-ALLWRITE (7.6) + COMMENT-f354f04c | **Different root causes on the same host**: filed = redirect-validation (DCR); new = mint-time scope↔role binding + call-time enforcement. Separation test passed in the report §"not a duplicate" | ✅ handled — comment posted as escalation, standalone files separately |
| `8d4a107f` (CAPI setting bypass) | MEMBER-TO-ADMIN (via COMMENT 1) | Part 1's personal key ≠ escalation credential (personal = 400-capped, proven). Different defect (create-side setting enforcement) | ✅ handled — COMMENT 1 documents the class-vs-scope delta |
| `c1f935a8` (Developer API viewer) | TAXONOMY-SHIM (7.1) — GS-AUTHZ would have been the third but is FIXED/do-not-file | Same CLASS (RBAC not uniform), different asset/mechanism/fix. Duplicate-risk paragraph present in both directions with fold-in instruction | ✅ handled |

## 2. Pairwise matrix — the 8 pack reports (root-cause separation)

| Pair | Shared ground | Root causes distinct? | Verdict |
|---|---|---|---|
| MEMBER-TO-ADMIN ↔ REVIEW-BYPASS | same credential precondition | YES — role decision on mgmt surface vs missing acting-user resolution on commit verb. "The commit verb does not appear anywhere in MEMBER-TO-ADMIN" (verified end-to-end read) | ✅ both file |
| MEMBER-TO-ADMIN ↔ S3/e103ef0a | the key value itself | READ defect vs AUTHZ defect (see §1) | ✅ chain, not duplicate |
| REVIEW-BYPASS ↔ MEMBER-TO-ADMIN controls | `on_behalf_of_required` guard | REVIEW-BYPASS = the guard is on create but MISSING on commit; MEMBER-TO-ADMIN never touches the review family | ✅ |
| TAXONOMY-SHIM ↔ AGENT-IDOR | both Amplitude session-plane viewer findings | different objects (tracking plan vs agent threads/sessions); TAXONOMY explicitly says "no overlap" for agent surface | ✅ |
| TAXONOMY-SHIM ↔ MCP-VIEWER-ALLWRITE | **both cite the vendor's "Use MCP (write) / Update Tracking Plan" doc line** | DIFFERENT planes: shim = browser session on `/o/taxonomy-api-shim` (app-membership predicate bug); MCP = OAuth mint-time scope binding on mcp.amplitude.com. A fix to the shim's readOnly computation does not touch OAuth scope issuance; an OAuth scope fix does not touch the shim resolver. ⚠️ Same VENDOR DOC QUOTE appears in both — a triager reading both may pattern-match "duplicate". **Mitigation: the MCP report's §"not a duplicate" names the shim's plane implicitly via the session-vs-token distinction; ADD one explicit line** | ⚠️ FIXED (see §4, edit applied) |
| MCP-VIEWER-ALLWRITE ↔ AGENT-IDOR | MCP agent tools (agentListThreads etc. Sept) | AGENT-IDOR = session-plane GraphQL resolvers skipping RBAC; MCP = OAuth token layer skipping RBAC. Different credentials, different resolvers, different fixes | ✅ |
| RC-SSRF ↔ (INGESTION-SSRF) | both "SSRF" label | ingestion = FIXED → do-not-file, so no live pair. RC-SSRF carries the opposite-egress cross-note for context only | ✅ |
| RC-SSRF ↔ everything else | — | no shared object, route, or credential | ✅ |
| PUSHER ↔ everything else | realtime plane is untouched by all others | no other report touches /o/graphql PusherAuth or WebSocket plane | ✅ |
| XLIFF ↔ TAXONOMY-SHIM | both write into taxonomy/import plane | XLIFF = parser resource-exhaustion (ElementTree); TAXONOMY = authz. Different defects on different routes | ✅ |

## 3. Fact-consistency across documents (shared claims must match)

| Shared fact | Where it appears | Consistent? |
|---|---|---|
| Key `73bExo…`/`2zBljx…` company-scoped story | e103ef0a thread + REPLY-e103ef0a + MEMBER-TO-ADMIN §precondition | ✅ same narrative (Sept key deleted → Oct re-created; REPLY explains the 4r6J1SX capture discrepancy honestly) |
| "5/5 commit routes" | REVIEW-BYPASS (+ today's autotune addendum) vs RETEST-REPORT | ✅ **FIXED TODAY** — addendum added to the report's §11 open-gaps (gates+dynamic_configs end-to-end, segments signature, experiments route-resolved, autotunes end-to-end 17 Oct) |
| GS-AUTHZ status | DEDUP table (6.5, fileable) vs RETEST-REPORT (FIXED, do-not-file) | ⚠️ **DEDUP table is stale — superseded by RETEST-REPORT. Marked below.** |
| MCP scopes story | f354f04c comment ("broadened") vs MCP-VIEWER report ("broadened... amplifies") | ✅ identical framing, no contradiction |
| Viewer USE_MCP_WRITE=false | MCP-VIEWER report + r1-gql sweep + wave2-rbac | ✅ consistent |
| CVSS scores | all reports (official cvss package, Sept audit) | ✅ unchanged; MCP 7.6 + Pusher 4.3 computed with the package today |
| Taxonomy REST FORM-encoding pitfall | fixchecks-alive VERDICTS.md vs r1-rest | ✅ consistent |
| demo-org 3149 / path-less /t | r1-rest ops note vs Sept amp-org3149 | ✅ consistent (same behavior, now documented as harness note) |

## 4. Edits applied during this audit
1. **REVIEW-BYPASS §11**: autotunes addendum (coverage 5/5, gap #1 closed with today's evidence).
2. **MCP-VIEWER-ALLWRITE**: explicit one-line plane-distinction vs TAXONOMY-SHIM added to the not-a-duplicate section (same vendor doc quote appears in both — pre-empt the pattern-match).
3. **DEDUP-AND-COMMENTS.md**: stale-table banner (GS-AUTHZ row + INGESTION row = fixed; use RETEST-REPORT as current).

## 5. Filing order recommendation (unchanged by audit)
1. MEMBER-TO-ADMIN (8.8) — strongest, self-contained
2. MCP-VIEWER-ALLWRITE (7.6) + post COMMENT-f354f04c same day (they reference each other)
3. TAXONOMY-SHIM (7.1) — carries fold-in note vs GS-AUTHZ (now moot since GS fixed)
4. AGENT-IDOR (7.1)
5. REVIEW-BYPASS (6.5, with the 5/5 addendum)
6. PUSHER (4.3)
7. RC-SSRF (2.9) — or fold into Lows bundle with XLIFF-residual + L1/L2/L4/L6/L10/L11/L5
8. S3 companion — file only after triage responds to REPLY-e103ef0a
