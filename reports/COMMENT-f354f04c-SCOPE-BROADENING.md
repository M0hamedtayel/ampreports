# Escalation comment — scope broadening on the already-filed MCP token-theft chain

**Re: `f354f04c-7a27-4649-a5e1-b848e410f961`** (mcp.amplitude.com — anonymous DCR accepts arbitrary redirect_uri → consent → code to attacker sink → 24h token)

Posted as an update comment on the filed report, not a new submission. Two measured changes on the current build (2026-10-17) **increase** the impact of this chain:

## 1. The stolen token is now a global-write credential

`/.well-known/oauth-protected-resource` on mcp.amplitude.com now advertises:

```
"scopes_supported": ["all:read", "all:write"]      (was: ["mcp:read", "mcp:write"])
```

A token captured through this report's redirect chain (re-verified still reproducible today: anonymous `POST /register` still accepts an arbitrary `https://` `redirect_uri` and issues a `client_id`; full consent→code→exchange completed again on the researcher's own account) now carries `scp:["all:read","all:write"]` — product-global read/write rather than the product-scoped pair the report was triaged against.

## 2. Write executes with no call-time capability check

With a token minted from our own **VIEWER**-role account (`USE_MCP_WRITE=false` per the console's `rbacBatchCheckPermissions`), the `/mcp` tool layer executed write-class tools successfully:

- `tools/list` → 48 tools, 13 write-class.
- `create_properties` on our app → `200 {"success":true,"message":"Processed 1 event property(ies): 1 created."}`
- `delete_event_properties {"confirmed":true}` → `200 … "1 plan-wide removed"`
- ORG_ADMIN control with the same tools → byte-identical success shapes (no differential ⇒ no role check at call time).

All test artifacts were cleaned up (probe properties deleted + verified; all 6 test tokens revoked at `/revoke`, revocation verified).

**Requested:** re-score the exposure of a token captured via this chain in light of the `all:write` capability set (the detailed standalone analysis of the scope/role binding gap is being filed separately as its own report, since its root cause — mint-time scope-to-role binding — is distinct from this report's redirect-validation defect).
