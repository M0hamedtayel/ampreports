# Amplitude Guides & Surveys — unbounded XML entity expansion in the XLIFF localization import (CWE-776 / CWE-400), reachable by the read-only Viewer role

**Severity:** CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = **6.5 (Medium)**
**Tenant:** org `464637` (`agentmail-602393`), app `862908` — our own tenant only. Accounts: a VIEWER (`orgRole 1`) browser session for `upload-xliff`, plus the project Basic credential for the documented `import` route.

## Summary

Both XLIFF import entry points parse the uploaded document with Python's `xml.etree.ElementTree` (pyexpat) — **not `defusedxml`** — and impose **no limit on entity expansion**. A ~1.4 KB request whose DTD defines a few nested internal entities is expanded in the worker before any validation, and the expanded material is then serialised back into the response.

The parser is **fingerprintable** from its error strings, which reproduce byte-for-byte on a local CPython 3.11 `ElementTree.fromstring`, and the expansion is **observable in-band** — the response grows. The decisive measured pair:

```
[VIEWER] req=1416 B -> HTTP 200, resp=10166 B, 1.7 s      (control with no entity: 167 B)
```

Two things make it practical rather than cosmetic. It is **reachable by the read-only role**: a `Viewer` (`orgRole 1`) — Amplitude's lowest role, which is not supposed to be able to change anything — can drive it through `upload-xliff` with nothing but a browser session; no project credentials are required for that path. And the service is **multi-tenant**: Amplitude's Guides & Surveys backend serves every customer, so the memory a worker materialises is not contained to the attacker's own organization.

**Scope note, stated up front:** I deliberately did **not** send a payload large enough to actually exhaust a worker. The extrapolated figures below are arithmetic, not measurements, and are labelled as such.

## Repro

1. The endpoint accepts an XLIFF upload from a Viewer session.

```
POST /a/guides-surveys/<nudge_id>/upload-xliff/?org_id=464637&app_id=862908&variant_id=<variant>
Cookie: <VIEWER session>
Content-Type: multipart/form-data; boundary=...

----<boundary>
Content-Disposition: form-data; name="file"; filename="x.xliff"
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<xliff version="1.2" xmlns="urn:oasis:names:tc:xliff:document:1.2">
  <file original="amp-probe" datatype="plaintext" source-language="en" target-language="de">
    <body><trans-unit id="step_1_title"><source>a</source><target>b</target></trans-unit></body>
  </file>
</xliff>
----<boundary>--
```
```
HTTP/1.1 200 OK
{"de":{"state":"COMPLETE","message":"Updated 1 translation units.",
       "data":{"timestamp":"...","step_1_title":{"source":"a","target":"b"}}}}
```

2. Nested internal entities are expanded, and the expansion is echoed back. `a1` = 1 000 chars; `a(n)` = `a(n-1)` repeated 10×; the reference sits in the `target` the endpoint echoes.

```
<!DOCTYPE xliff [
  <!ENTITY e1 "AAAA…(1000 chars)…">
  <!ENTITY e2 "&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;">
]>
…
    <body><trans-unit id="step_1_title"><source>a</source><target>&e2;</target></trans-unit></body>
```
```
[VIEWER] req=1416 B -> HTTP 200, resp=10166 B, 1.7 s      (control with no entity: 167 B)
```

The response body grows from **167 B to 10 166 B** — the server resolved the entity tree and serialised the expanded value back to the caller. That is the in-band proof that expansion happens server-side; it is not a parser that merely rejects or drops the reference.

3. The same parser is on the documented import route. The file's `original="&e;"` attribute is echoed verbatim into the JSON response key, which is where the largest measured amplification was observed.

```
POST /a/guides-surveys/api/v1/localization/import/?org_id=464637&app_id=862908
Authorization: Basic <api_k…key>
Content-Type: application/xml; charset=utf-8
```

**Amplification measured (bounded — the large payloads were deliberately not sent):**

| Payload | Request bytes | Response bytes | Server time | Amplification |
|---|---|---|---|---|
| flat `<!ENTITY e "A"×1000>` | 1 329 | 2 090 | 3.8 s | 1.6× |
| 2 levels (10 × 10 KB base) | 1 439 | 200 090 | 10.3 s | 139× |
| **3 levels (10³ × 1 KB)** | **1 494** | **2 000 090** | **75.1 s** | **1 339×** |
| quadratic (2 000 refs × 1 KB) | ~2 200 | >4 MB (client cut at 40 s) | >40 s | >1 800× |
| `upload-xliff`, 2 levels, in `target` | 1 416 | 10 166 | 1.7 s | 7.2× |

The base entity differs between rows and is stated above: row 1 and row 3 use a **1 KB** base, row 2 uses a **10 KB** base (the capture is tagged `C2-10KB` in `xxe_entity_evidence.json`). Read as "10^N × 1 KB" the label is arithmetically right for the measured totals but makes the two rows look inconsistent by a factor of ten.

**Arithmetic extrapolation of the same 10×-per-level geometry:** 4 levels → 10 MB, 5 → 100 MB, 6 → 1 GB, 7 → 10 GB, 8 → 100 GB of string materialised per ~1.6 KB request. *These are extrapolations, not measurements* — no payload of that size was sent, on purpose.

**Controls**

- Classic XXE is correctly refused — so this is expansion, not external resolution:

```
<!DOCTYPE xliff [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>   … &xxe; …
→ HTTP 400, no file content in the response
```
External entities are rejected (`undefined entity &e;`), parameter entities are ignored, a remote external DTD is not fetched, and `xi:include` is not executed. **There is no XXE here.**
- A webhook.site listener we own recorded **0** callbacks across the whole test (covers parameter entities and the remote external DTD).
- Cross-tenant IDOR on `upload-xliff` / `import` (foreign `org_id`/`app_id`) → 404 / 403; read-back confirmed no cross-tenant write.
- The DOCX importer (`/a/guides-surveys-imports/`, `method=walkme_docx`) resolved **no** entity in our tests: an external `file:///` entity in `word/document.xml` produced a failed job with an empty extracted title, an OOB parameter entity produced a completed job and **0** listener hits, and a bounded billion-laughs produced a failed job with an empty title. This is a **behavioural negative**, not a claim about the library's configuration — `python-docx`'s own parser is constructed as `etree.XMLParser(remove_blank_text=True)` and does not pass `resolve_entities=False`.
- Only bounded payloads were sent; no payload capable of exhausting a worker was used.
- All test nudges were deleted (`204`) and `GET /a/guides-surveys/` verified back to `[]`.

## Impact

- A **~1.6 KB request** can make the Guides & Surveys worker materialise tens of megabytes of string before any application-level validation runs. Repeated, that is a memory/CPU exhaustion vector against shared multi-tenant infrastructure.
- **No cap and no rate limit were observed** on the parser or the endpoint.
- **Reachable by the read-only `Viewer` role** through `upload-xliff` with only a browser session — the same role the separately reported broken-authorization finding shows can already create nudges. No project credentials are needed for that path.
- Amplitude's own docs point integrators at this API, so it is a supported, documented surface.

**Ceiling:** the attacker does **not** read files or reach the network — external entities, parameter entities, remote DTDs and `xi:include` all fail (measured `400`, no file content; 0 listener callbacks), so no data-disclosure or SSRF primitive is claimed. No payload capable of actually exhausting a worker was sent, so worker exhaustion is an arithmetic extrapolation from the measured 10×-per-level geometry, not an observed outage. Impact is availability only.

**CVSS terms and the measured fact behind each:**

- `A:H` — measured: a 1 494 B request produced a 2 000 090 B response in 75.1 s (**1 339×**), and `>1 800×` was observed on the quadratic row before the client cut the connection at 40 s. The `A:H` rating rests on that measured amplification plus the multi-tenant blast radius; **the exhaustion itself is an inference from the geometry, not a measurement.**
- `PR:L` — measured: the `upload-xliff` path accepts a `Viewer` (`orgRole 1`) session and returns `200`.
- `AC:L` — measured: a single request reproduces the amplification; the geometry is 10× per nesting level.
- `C:N`/`I:N` — measured: no file content and no cross-tenant write in any control; the defect is resource consumption, not disclosure.
- `AV:N`, `UI:N`, `S:U` — the route is a plain internet-facing HTTP call by an authenticated tenant user with no victim interaction; no scope change is claimed, because the impact is confined to the component doing the parsing.

**Dedup note.** `SUBMISSION-GS-AUTHZ.md` is the same backend but a **different defect**: it is about *who may write* (a Viewer accepted on `POST /a/themes/`, `/a/collections/`, `/a/guides-surveys/`, `/h/syncs/`); this report is about *what the parser does with a body it is already allowed to send* — the expansion reproduces for an Org Admin as well and is therefore not an authorization defect. The routes overlap (`upload-xliff` lives in the `/a/guides-surveys/` family) but the broken thing does not: the fix here is `defusedxml` / an expansion ceiling, the fix there is a permission class. `SUBMISSION-TAXONOMY-SHIM.md` (`/o/taxonomy-api-shim/*`) and `SUBMISSION-AGENT-IDOR.md` (`/fed/graphql`) share no route. The earlier `REPORT-XXE.md` XXE sweep is the same run with superseded scope: the XXE hypothesis was ruled out and this is the remaining finding from that sweep — expansion, not external resolution.

## Remediation

- Parse untrusted XML with `defusedxml` (or `lxml` with `resolve_entities=False` and `no_network=True`), which rejects DTDs and entity definitions outright.
- If DTDs must be supported, cap total expansion: reject any document whose DTD contains entity definitions, limit entity nesting depth and total expanded size, and enforce a hard request-body ceiling before parsing.
- Never serialise the parsed/expanded document back to the caller (the `original` echo is what turns a parser quirk into an amplification primitive).
- Add a per-organization rate limit on the localization import/upload routes.
- Regression test: POST the two-level payload above as a Viewer and assert the response body does not grow beyond the source string — i.e. `resp` stays near the 167 B no-entity control instead of 10 166 B, and a DTD-bearing document is rejected outright.

---
Evidence: `escal/root_verify_xxe_dos_20260919T130412Z.json` (root-agent independent reproduction: control 167 B vs 2-level 10 166 B, external-entity 400 — the two earlier files in that series record `resp: 0` because the verifier's own multipart body was malformed), `escal/REPORT-XXE.md` (full audit), `xxe_entity_evidence.json` (raw amplification table — **workspace root**, not `escal/`), `xxe_uploadxliff_evidence.json`, `xxe_cleanup.json` (**workspace root**), and the re-measurement of 2026-09-23: `escal/ampaudit/x_*.json` (upload-xliff control 178 B vs 2-level 10 173 B; import route 207 with 1393 B → 20 090 B; external entity `400 … undefined entity &e;: line 1, column 297`).
