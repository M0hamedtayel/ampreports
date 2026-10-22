# Hygiene bundle — six re-verified low-severity hardening findings across Amplitude and Statsig (merged)

**Target Location:** app.amplitude.com, mcp.amplitude.com, console.statsig.com, statsigapi.net
**Target category:** Web App
**VRT (suggested):** Server Security Misconfiguration (bundle)
**CVSS 3.1 (suggested):** Low — individual items range ~2.0–3.7; each item's severity is stated per sub-section below

---
**Affected Asset:** Amplitude App Platform (`app.amplitude.com`), Amplitude MCP OAuth surface (`mcp.amplitude.com`), Statsig Console (`console.statsig.com`), Statsig API (`statsigapi.net`). All testing performed on researcher-owned tenants (Amplitude org `464637` / app `862908`; Statsig self-owned projects) and fully reverted.

**Summary:** This is ONE merged submission covering seven re-verified low-severity / informational hygiene findings that individually fall below the filing bar but collectively describe a consistent hardening gap pattern (missing rate limits, missing input validation, credential-bearing error bodies, permissive CSP, missing dedupe) across both Amplitude and Statsig surfaces. Every item was re-verified against the live builds during the full program retest of 2026-10-17 (from-zero retest, 3 waves, ~750 requests, all on self-owned tenants); the re-verification date is stated per item. Items are numbered L1–L11 matching the internal finding ledger. None of these items overlaps a separately filed report except where explicitly noted (L4).

**Steps to Reproduce:** (each sub-section is self-contained; all testing on researcher-owned tenants, everything reverted)

---

### L1 — Unauthenticated organization-enumeration oracle at `GET /d/config/login-info/{orgUrl}` (Amplitude)

**Re-verified 2026-10-17** (retest wave R1-auth): still present.

`GET https://app.amplitude.com/d/config/login-info/{orgUrl}` requires no authentication, no captcha, and no rate limit. For ANY organization slug it returns HTTP 200 (existing org) vs 404 (non-existent org), and on 200 the body discloses `org_id`, `org_name`, plan tier, and SSO-configuration flags.

1. From an unauthenticated client, request `GET /d/config/login-info/{any-known-org-slug}` → 200 with org_id, org_name, plan, SSO flags.
2. Request `GET /d/config/login-info/{random-nonexistent-slug}` → 404.
3. Repeat at a polite cadence with a list of candidate slugs → the 200/404 split cleanly enumerates which org slugs exist, with no 429 observed.

**Impact (one line):** Unauthenticated attackers can enumerate valid Amplitude organization slugs and pre-attack reconnaissance each org's plan and SSO posture (SSO-enabled orgs are Steal-Login-Slack targets; non-SSO orgs are phishing targets).

---

### L2 — Statsig signup-state enumeration via anonymous persisted ops — STILL PRESENT, throttle tightened (Statsig)

**Re-verified 2026-10-17** (retest wave R2-races): **still present, but the throttle has been TIGHTENED since the September hunt to a pooled ~3 emails per 5 minutes per session.** The finding survives; the practical list-scale ceiling is now materially lower and we state that honestly.

Anonymous (pre-auth) GraphQL persisted operations `register_email` (`6e09c800…`) and `finish_registration` (`1cdaa814…`) return **distinct, lifecycle-specific error strings** that split (a) never-registered, (b) pending-signup (email issued but not confirmed), and (c) fully confirmed accounts, for any submitted email address.

1. From an unauthenticated session, invoke the persisted op `register_email 6e09c800…` with a candidate address.
2. Compare the distinct lifecycle error returned (never-registered vs pending vs confirmed) against a control address of known state.
3. Repeat across candidate addresses. As of 2026-10-17 the response throttle is pooled at approximately 3 emails / 5 minutes per session (previously effectively unthrottled at polite cadence — 18/18 distinct emails answered cleanly in September).

**Impact (one line):** An unauthenticated party can determine the registration state (exists / pending / confirmed) of arbitrary email addresses against Statsig, useful for account-takeover targeting and list vetting; the tightened ~3-per-5-minute pooled throttle now bounds practical list-scale abuse.

---

### L4 — MCP DCR scheme-acceptance + CORS reflection (mcp.amplitude.com) — hardening only; DCR-arbitrary-redirect overlap acknowledged

**Re-verified 2026-10-17.** **Scoping note:** the DCR arbitrary-redirect_uri issue itself is ALREADY COVERED by the April master report (our related DCR finding `f354f04c` was duped against it). This item is therefore scoped STRICTLY to two residual hardening observations not covered there: (1) scheme acceptance and (2) CORS reflection.

1. `POST /register` (RFC 7591 dynamic client registration, anonymous) accepts a registration body with `redirect_uris: null` and registers the client successfully.
2. The same endpoint accepts `redirect_uris` entries using dangerous schemes — `javascript:` and `file:` URIs — at registration time, in addition to arbitrary https hosts.
3. On `mcp.amplitude.com`, the CORS middleware reflects an arbitrary attacker-supplied `Origin` header together with `Access-Control-Allow-Credentials: true`, allowing any origin to make credentialed cross-origin requests to the MCP API.

**Impact (one line):** Defense-in-depth gap: a registered client may carry non-https/non-web scheme callbacks (`javascript:`, `file:`, null) and any origin may read credentialed MCP responses; exploitable only in combination with the already-reported DCR redirect issue, so this is filed as hardening.

---

### L5 — `statsigapi.net` wrong-tier key echo: 403 error bodies echo the caller's FULL plaintext key (Statsig)

**Re-verified 2026-10-17** (wave3-pusher; fresh captures): still present.

When a caller presents a key of the wrong class to `https://statsigapi.net/console/v1/*`, the 403 error body **echoes the caller's full plaintext key back verbatim**:

```
HTTP/1.1 403
"...but a CLIENT key was sent. Key: client-<51 chars>"
```

1. Call any `statsigapi.net/console/v1/*` endpoint with a CLIENT key where a SERVER key (or vice versa) is expected.
2. Observe the 403 response body contains the complete plaintext key, character-for-character (51-char client key / full secret key in the server-key direction).

**Impact (one line):** Plaintext API credentials are persisted into WAF logs, SIEM ingestion pipelines, and error-tracker captures wherever the 403 body is logged — converting a low-impact misuse error into durable credential leakage across the logging stack.

---

### L6 — Statsig pre-commit webhook URL field accepts metadata/RFC1918/loopback/encoded targets at SAVE-TIME (Statsig)

**Re-verified 2026-10-17** (retest R1-statsig): owner tier still accepts; member tier is now role-blocked (improvement noted).

The org pre-commit webhook URL field (owner tier) accepts, at SAVE-TIME and persisting verbatim, URLs targeting: `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`, `168.63.129.16`, RFC1918/CGNAT ranges, loopback in 6 encodings including `[::ffff:169.254.169.254]`, nip.io/sslip rebinding hosts, `file://`, and `gopher://`. (Contrast: Ory Hydra rejects all of these.)

1. As org OWNER on a self-owned Statsig org, set the pre-commit webhook URL to `http://169.254.169.254/latest/meta-data/` (and each encoded variant above) → SAVE accepts and persists verbatim.
2. As MEMBER, the same field is now role-blocked (role check present as of 2026-10-17).
3. Runtime egress was NOT proven (the feature is org-gated off in our tenant; 0 webhook.site hits) — this is an input-validation hardening finding, not a proven SSRF.

**Impact (one line):** Missing save-time input validation on a URL field that accepts cloud-metadata, internal-range, loopback (including IPv4-mapped-IPv6-encoded), rebinding-alias, and non-http scheme targets; should the gate ever be enabled, this becomes a first-class SSRF primitive.

---

### L10 — `app.amplitude.com` CSP uses `script-src 'unsafe-inline'`, no `img-src`, no `frame-ancestors` (Amplitude)

**Re-verified 2026-10-17**: still present.

1. Request any `app.amplitude.com` page and inspect response headers.
2. `Content-Security-Policy` carries `script-src` including `'unsafe-inline'`; no `img-src` directive; no `frame-ancestors` (and X-Frame-Options / COOP absent) — observed again on the current build.

**Impact (one line):** The escaping layer is the ONLY barrier against stored-XSS on the platform (all sinks currently render escaped, re-confirmed), and the missing `frame-ancestors`/`X-Frame-Options` leaves the app frameable; CSP here provides no effective script protection.

---

### L11 — `CreateSharedLink` has no dedupe and no per-notebook cap (Amplitude)

**Re-verified 2026-10-17, concurrent execution** (retest wave R2-races): still present.

1. On a self-owned notebook, issue 3 **concurrent** `CreateSharedLink` calls.
2. All 3 succeed and produce **3 DISTINCT live, anonymous-viewable share links** for the same notebook (September run showed 8 concurrent → 8 distinct links; the concurrent 2026-10-17 re-run reproduces with 3).
3. Each link is independently viewable anonymously and must be taken down link-by-link by an admin.

**Impact (one line):** Unbounded anonymous-viewable link multiplication per notebook (share-spam, per-link takedown burden, no audit consolidation).

---

### L12 (NEW informational) — Amplitude member-directory read endpoints answer with no rate limit (Amplitude)

**Re-verified 2026-10-17** (retest wave R2-races, task T5): present, informational.

1. As an authenticated **Viewer** on a self-owned org, call `usersForApp`, `searchUsers`, and `rbacAppsLookup` at a steady 2 Hz.
2. 24/24 requests succeed with **zero 429 responses** across all three endpoints.

**Scope note:** own-org member directory only (viewer-authorized reads, no cross-tenant reach — cross-tenant matrix re-confirmed fail-closed on 2026-10-17). Informational rate-limit hardening.

**Impact (one line):** Intra-org member-directory enumeration is unthrottled for the lowest role; no data exposure beyond the caller's own org, hence informational.

---

**Impact:** Individually each item is Low or informational; together they describe a consistent hardening gap pattern (unauthenticated or unthrottled oracles, missing save-time input validation, credentials in error bodies, ineffective CSP, missing dedupe) across two vendors' platforms. We request they be assessed as one merged Low submission rather than seven separate Below-Threshold closures.

**Remediation:**
- L1: rate-limit and/or captcha-gate `/d/config/login-info/*`; return a uniform response that does not distinguish existing vs non-existent orgs to unauthenticated callers.
- L2: return a single uniform "check your email" response regardless of registration state; retain the tightened pooled throttle.
- L4: reject `javascript:`/`file:`/null `redirect_uris` at DCR save-time; do not reflect arbitrary `Origin` with `Allow-Credentials: true`.
- L5: never echo key material in error bodies — reference a key prefix/ID at most.
- L6: validate webhook URLs at save-time: https-only, resolve-and-reject private/loopback/link-local/metadata ranges (incl. IPv4-mapped-IPv6 encodings), reject non-http schemes and rebinding aliases.
- L10: drop `'unsafe-inline'` from `script-src` via nonce/hash; add `img-src`, `frame-ancestors 'self'` (or X-Frame-Options: DENY) and COOP.
- L11/L12: dedupe or cap share links per notebook; apply modest rate limits to member-directory read endpoints.

**Evidence to attach:**
- L1: unauth 200/404 request/response pairs (retest R1-auth, 2026-10-17) — dir `%LOCALAPPDATA%/Temp/amplitude/hunt2610/retest/r1-auth/` (verified present) plus original recon-app/raw captures; verdict also grounded in RETEST-REPORT-2026-10-17.md §1 "login-info org oracle (L1) STILL PRESENT".
- L2: persisted-op register_email lifecycle-error captures + tightened-throttle timings (retest R2, 2026-10-17) — dir `%LOCALAPPDATA%/Temp/amplitude/hunt2610/retest/r2-races/` (verified present, 14 files); verdict grounded in RETEST-REPORT-2026-10-17.md ("STILL LIVE — throttle TIGHTENED (pooled ~3 mails/5min/session)") and FINDINGS/statsig-signup-state-enumeration.md.
- L4: DCR `/register` scheme-acceptance matrix + CORS Origin-reflection request/response pairs.
- L5: fresh 2026-10-17 captures `%LOCALAPPDATA%/Temp/amplitude/hunt2610/wave3-pusher/evidence/statsig_wrongtier_{CLIENT,SERVER}.json` (verified present); verdict grounded in RETEST-REPORT-2026-10-17.md ("Wrong-tier key echo (L5) RE-CAPTURED TODAY (full credential in 403 body)") and FINDINGS/LEDGER.md #6.
- L6: `statsig-ssrf/precommit_validation_matrix.json` (save-time acceptance matrix, all targets).
- L10: response-header captures showing `script-src 'unsafe-inline'`, absent `img-src`/`frame-ancestors` (2026-10-17).
- L11: concurrent CreateSharedLink captures (3 concurrent → 3 distinct live anon links, 2026-10-17; September 8× run in `races/evidence/`).
- L12: 24/24 @ 2Hz zero-429 request logs (retest r2-races T5, 2026-10-17).
