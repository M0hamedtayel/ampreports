Hi theartisan,

Thanks for the careful review and for confirming the persisted op IDs and the fabricated-key controls from your side. All four requested items are below. To make validation self-contained, I also re-ran the entire leak **fresh today (17 Oct 2026)** on my current test tenant with a newly created key — so every capture is from one continuous session, exactly as requested.

---

## 1. Raw capture of the company-scoped `omni_read_write` row (fresh, today)

You were right about the 17 Sep Burp capture — the node visible in that screenshot was `4r6J1SX…` (my Member's own personal key), and it does **not** carry the claim. The `73bExo…` row existed only as pasted text. To fix the evidence gap, today I re-ran the full chain on my current tenant `4n6HCY59mDqwX1iSZQtNvx`:

- The project **Owner (mohamed-9499-2@agentmail.to)** created a **company-scoped CONSOLE key**: `{"type":"CONSOLE","scopes":["omni_read_write"],"owner_id":null,"description":"e103ef0a-triage-repro"}` → record id **`2zBljx822Kbq7SdFaBPVv7`**, `owner: null`, 51-char `console-…` value. (The original `73bExo…` key was deleted during September remediation of my own test artifacts, which is why I re-created the identical shape.)
- The **Member (mohamed-9499-3@agentmail.to)** then sent, in the **same session**, the exact requests below. Raw request+response captures (DevTools-export format, full body, key redacted here but present in the attached originals) are attached:

**Request 1 — `ApiKeysBoxQuery` (d6fcaacb…), keyType:ALL:**
```
POST /api/graphql?company_id=4n6HCY59mDqwX1iSZQtNvx HTTP/1.1
Host: console.statsig.com
Content-Type: application/json
x-csrf-token: 1
Origin: https://console.statsig.com
Referer: https://console.statsig.com/4n6HCY59mDqwX1iSZQtNvx/api_keys
Cookie: <member session — same session as Request 2 and 3>

{"id":"d6fcaacbc921668f7e7aa576b9d2ca1e","operationName":null,"variables":{"first":50,"keyType":"ALL"}}
```
Response body (`HTTP/1.1 200`, `"count":3`) — the relevant node:
```json
{"id":"2zBljx822Kbq7SdFaBPVv7","value":"console-H1pV…0C48","scopes":["omni_read_write"],"owner":null,"type":"CONSOLE","is_active":true,"description":"e103ef0a-triage-repro"}
```
The response contains the full 51-char plaintext `console-…` value in `keys_connection.nodes[0].value` (count: 3 = CONSOLE company-scoped + SERVER + CLIENT, all owner-null, all plaintext to this Member session).

**Request 2 — `PersonalCAPITokenSectionQuery` (0799d4b7…), variables {}:** returns the **same** company-scoped key id `2zBljx…` with its full plaintext value again (`console_api_keys[0]`, 51 chars) — the second independent resolver, same session.

**Request 3 — `useLoadOnboardingServerKeyQuery` (63df72f6…), variables {}:** returns the SERVER key `secret-…` (50 chars) plaintext, same session — confirming the original report's operation is still live as well.

Attached (fresh, today): `raw_02_keybox_ALL_leak.txt`, `raw_03_capi_section_leak.txt`, `raw_04_onboarding_serverkey.txt` — each contains the full request (headers + cookie + body) and the full response body.

## 2. Member role confirmation (same session, same tenant)

**Request 4 — `CompanyMembersTabV2Query` (839712b2…), variables {}:** sent as the **same session immediately before the key queries** (raw capture: `raw_01_members_role.txt`). Response:

- `mohamed-9499-3@agentmail.to` → `roleName: "Member"` (the session that read the keys)
- `mohamed-9499-2@agentmail.to` → `roleName: "Owner"` (the account that created the key)
- third account → `"Member"` (my second member, used in September's member-to-member test)

**How the account was added:** the Owner invited it from the members page via the standard invite flow; it holds the **standard Member role only** — no custom roles (the tenant has none; custom role management is not enabled org-wide), no additional roles, no beta access or feature flags were requested or granted. The key was created by the Owner minutes before the capture.

## 3. Plan tier

The tenant `4n6HCY59mDqwX1iSZQtNvx` is on the **Free plan**. Evidence in the same capture set: the leaked key drives `GET https://statsigapi.net/console/v1/company` → `200` with `"isWarehouseNative":false` and **no organization attached** (`orgID: null`), and `GET /console/v1/users` → `200` (roster of 3) — the behaviour your note flagged as plan-sensitive was reproduced on this tier (raw captures: `raw_05_rest_company.txt`, `raw_06_rest_users.txt`). The September tenant `66BuQS9…` (also Free, now de-provisioned) is where the original `73bExo…` capture was taken.

## 4. Note on the severity framing

Understood on the program's severity model — the same-organization framing and the per-project SERVER/CLIENT exclusion. The claim this report should be assessed on is the company-scoped CONSOLE key row above (the credential that drives the whole `/console/v1` management surface, including user roster and audit trail, none of which the Member can see in the console UI), which is exactly the evidence now supplied as raw captures. The original `73bExo…` row no longer exists (deleted in my September cleanup), so today's `2zBljx…` capture is the operative evidence — created by the Owner, read in plaintext by a standard Member, and proven live against the management API, all in one session.

All test artifacts from today's run were deleted after capture (the key record `2zBljx…` is deleted; final CONSOLE box = empty, verified by read-back).

Happy to provide anything else that would speed validation — and if it helps, my tenant's Owner/Member/Read-Only accounts are all mine, so if your own provisioned project becomes available, the identical sequence (Owner creates company-scoped CONSOLE key → Member reads ApiKeysBoxQuery keyType:ALL) should reproduce there directly.

Best regards,
m0hamedtayel
