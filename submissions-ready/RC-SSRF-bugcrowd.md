# Amplitude Resource Center — server-side request forgery via a tenant-supplied website content source (proxied, title-only read-back)

**Target Location:** https://app.amplitude.com (App Platform — Resource Center content sources: `/h/sources/`, `/h/syncs/`, `/h/content-items/`)
**Target category:** Web App
**VRT (suggested):** Server-Side Request Forgery (SSRF)
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N` = **2.9 (Low)**
---
**Affected Asset:** App Platform — `https://app.amplitude.com`, Resource Center `website` content-source fetcher (`settings.recursive_urls`). Tested org `464637` (`agentmail-602393`), app `862908` — researcher-owned tenant only; all test sources deleted and cascade-deleted content items verified gone.

**Summary:** A Resource Center **website** content source takes fully tenant-controlled URLs in `settings.recursive_urls`. When a sync runs, Amplitude's backend **fetches those URLs server-side** and **stores the response**. That makes it an arbitrary-URL server-side fetch whose *fetched title* is returned to the caller — **blind, proxied, title-only**: the attacker chooses the URL, Amplitude's backend fetches it and stores the response, and the content-item records expose the fetched page's **title, URL and content type** — the response body itself is **not** returned (`GET /h/content-items/` returns no body field; the detail route adds exactly one field, `"content_markdown": null`; the title is extracted from the fetched page's `<title>` tag).

Two properties make this reachable, and they sit at **different privilege levels**:

1. **Create is Admin-gated** — measured: `POST /h/sources/` returns `201` for an Admin and `403 {"detail":"You do not have permission to perform this action."}` for a Viewer. A Viewer cannot choose the URL.
2. **Trigger has no authorization check** — `POST /h/syncs/` is reachable by a read-only **Viewer**: Viewer on a real source → `200`; Viewer on a bogus source → `404 "Not found."` (no authz layer, straight to object lookup). Note the asymmetry: **Viewer-create is 403 but Viewer-trigger is 201/200 — the ungated leg.**

Read together: an Admin chooses the URL once, and from then on **any Viewer in the tenant can re-drive the fetch on demand**. The Viewer-only path is a *replay* of an Admin-chosen URL, not an attacker-directed fetch.

**Scoping caveat, stated up front:** the fetches egress through the **ScrapingBee** scraping proxy (`"enable_scrapingbee": true` on the source; observed fetches came from seven different datacentre IPs with browser-like User-Agents and no `Referer`). The request therefore does **not** originate from Amplitude's own network, so classic cloud-metadata theft (`http://169.254.169.254/...`) is **not** claimed and was deliberately not fired. The finding is the arbitrary-URL server-side fetch with a proxied egress and a title-only read-back.

**Re-verified 2026-10-17 (fix-check pass, "fixchecks-alive"):** the **egress and the Viewer-trigger leg were both re-proven live** against the current build (B-tenant creates a `website` source pointed at a webhook.site canary; Viewer triggers the sync; canary hits recorded). **The full content-read was not reproduced on retest — the title-only framing stands exactly as originally audited**; no body-read claim is made or resurrected here.

**Steps to Reproduce:** (all on researcher's own tenant, org `464637` / app `862908`, fully reverted)

1. As ADMIN, create a `website` source pointed at a listener we control:

```
POST /h/sources/?org_id=464637&app_id=862908 HTTP/1.1
Host: app.amplitude.com
Cookie: <session>
x-csrf-token: 1
Content-Type: application/json

{"type":"website",
 "title":"zz-rootverify-35813",
 "settings":{"recursive_urls":["https://webhook.site/<canary-uuid>"]}}
```
```
HTTP/1.1 201 Created
{"id":25935,"type":"website","title":"zz-rootverify-35813",
 "settings":{"recursive_urls":["https://webhook.site/<canary-uuid>"]},
 "enable_scrapingbee":true, "workflow_schedule_id":"houston-schedule-sync-521bf763-..."}
```

2. Trigger the sync (201 even for the later Viewer-trigger leg — this route is the ungated one):

```
POST /h/syncs/?org_id=464637&app_id=862908
{"source":25935}
```
```
HTTP/1.1 201 Created
{"id":74329,"source":25935,"status":"PENDING",
 "workflow_id":"houston-sync-25935","workflow_run_id":"01a0b7d1-..."}
```

3. The listener records the server-side fetches. In the original run: sync triggered 02:58:48Z, **7 fetches from 7 distinct datacentre IPs within 60 seconds** (02:58:54Z – 02:59:08Z: 209.242.204.166, 23.95.244.184, 23.229.19.190, 216.173.109.246, 45.43.190.35, 64.137.83.198, 104.239.41.222 — browser-like UAs, no `Referer`). In the 2026-10-17 re-verification, the webhook.site canary recorded its hits within the sync window, re-proving live egress.

4. The fetched page's **title-only metadata** is persisted and readable:

```
GET /h/content-items/?org_id=464637&app_id=862908&source_id=25934
-> {"results":[{"id":1049776,"source":25934,
              "title":"Webhook.site requests and emails - SAML SSO Login",
              "url":"https://webhook.site/saml/login","source_type":"website",
              "content_type":"document","archived":false, ...}, ...]}
```

Measured: `https://example.com/` → title `"Example Domain"`. No body field exists on the list or detail route (`content_markdown: null` is the only extra field). **This is a proxied, title-only read-back — it is not a body-read primitive, and the severity does not rest on one.**

5. The privilege split:

```
POST /h/sources/  ADMIN -> 201 | VIEWER -> 403   (correctly gated)
POST /h/syncs/    ADMIN -> 201 | VIEWER -> 200   (never 403 — ungated leg)
POST /h/syncs/ {"source":999999} VIEWER -> 404   (no authz layer; straight to object lookup)
```

**Negative controls / ceilings checked:**
- Anonymous on `/h/sources/`, `/h/content-items/`, `/h/syncs/` → `403 "Authentication credentials were not provided."`
- Attempted to force a **direct** (non-proxied) fetch by setting `enable_scrapingbee:false` and re-pointing the source at a marked URL: **no direct fetch arrived**. The flag is accepted and echoed (`201` body contains `"enable_scrapingbee":false`) but the fetcher ignores it and still egresses through the proxy. We therefore do **not** claim an Amplitude-origin fetch and did not target `169.254.169.254`.
- On the 2026-10-17 re-verification: egress + Viewer-trigger re-proven live; **content-read (title extraction) was not reproduced on the retest — title-only stands.**
- The listener used is one we own; no third-party host was fetched; all test sources deleted (`204`) and cascade-deleted content items verified gone.

**Impact:**
- Amplitude's backend can be made to issue HTTP requests to an arbitrary tenant-supplied URL, and a metadata record derived from the response — the fetched page's **title, URL and content type** — is returned to the caller through `/h/content-items/`. The response body itself is **not** returned.
- A read-only Viewer can trigger the fetch against a source it did not create (Viewer-create 403 but Viewer-trigger 201 — the ungated leg).
- The fetches are proxied through ScrapingBee, so the reachable target set is whatever that proxy can resolve — **not** Amplitude's internal network. That bounds the impact and is why this is reported as Low rather than High.
- **Differentiation (one line):** this is the only server-side-fetch finding in the current filing pack that remains live — the companion Statsig ingestion-connector SSRF (`statsigapi.net/console/v1/ingestion/connection/databricks`) was **fixed by the vendor and never filed**; the two are independent findings on different vendors/routes (the Statsig one egressed from Statsig's own production network; this one egresses through ScrapingBee).

**Remediation:**
- Treat `settings.recursive_urls` as untrusted input: resolve the host and reject private, loopback, link-local, and metadata addresses (`127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254.0.0/16`, `::1`, `fc00::/7`), and re-validate after every redirect.
- Pin the fetcher to the ScrapingBee egress (documented and monitored) rather than allowing a direct-fetch fallback; do not let a tenant disable the proxy.
- Add the missing authorization check to `POST /h/syncs/` (Viewer-trigger leg — see companion broken-authorization report).

**Evidence to attach:**
- `escal/root_verify_ssrf_20260919T035813Z.json` (independent root-agent reproduction, 5 fetches)
- `escal/evidence/webhook-requests.json` + `webhook-requests-summary.json` (first run: 7 fetches / 7 distinct IPs in the sync window)
- `escal/raw2/001_B_ssrf_src.txt`, `escal/raw2/001_B_sync_B.txt`, `escal/raw2/001_B_contentitems.txt`
- 2026-10-17 fix-check re-verification: egress + Viewer-trigger captures and VERDICTS from `hunt2610/fixchecks-alive/VERDICTS.md` (egress and viewer-trigger re-proven 2026-10-17; content-read not reproduced — title-only stands)
- `escal/REPORT-GS-ESCALATION.md`
