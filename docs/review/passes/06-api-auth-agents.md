# Pass 06: API, authentication, agents (MCP)

**Output:** `docs/review/v0.2.0/06-api-auth-agents.md` (+ `patches/06-*`)

## Scope
The management surface: the REST API, sign-in (local users, TOTP, OIDC), tokens and roles,
the audit log, configuration changes made through the API, and AI-agent access over MCP
with plans and approvals.

- `crates/telltale-api/` (`lib.rs` router, `auth/`, `mcp.rs`, `plans.rs`, `config_api.rs`,
  `problem.rs`, `vqlog.rs` API, `ui.rs` static UI serving)
- `crates/telltale/src/`: `api_backend.rs` (the backend the API calls), `auth_setup.rs`,
  `mcp_stdio.rs`, `ctl.rs`, `checks.rs`, `managed.rs` (UI-made config overrides)
- `docs/api/openapi.json`, `docs/api/mcp-tools.json` (generated; tests check they match)

## Read first
1. `spec/07-api-and-ui.md`, `spec/13-agent-api-and-mcp.md`, `spec/08` §5 (security);
   ADR-028 to ADR-030, ADR-033, ADR-034, ADR-040, ADR-064, ADR-065, ADR-069 to ADR-071.
2. `crates/telltale-api/src/lib.rs` (routes and middleware) → `auth/` → `mcp.rs` + `plans.rs`.

## Look for
- **Authentication and sessions:** password hashing parameters, lockout, TOTP replay,
  session fixation and expiry, cookie flags, CSRF on state-changing routes, OIDC
  (state/nonce/PKCE, issuer and audience checks, group-to-role mapping, account linking).
- **Authorization:** every route's required role or scope; agent tokens' deny-by-default
  scopes; group-restricted agents; can a viewer reach a write through any path (MCP, plans,
  forwarded writes, config overrides)?
- **Plans and approvals:** a plan applied later than approved (If-Match), plans from one
  node applied on another, the audit chain (ADR-033) and what it actually proves.
- **Input handling:** request size limits, JSON depth, query parameters, vqlog cost limits
  (a cheap query that scans everything), problem responses not leaking internals.
- **The UI server:** security headers, CSP, caching, path traversal in embedded assets.

## Threat surface
The API listens on 8053 (on the homelab behind an ingress with trusted proxies). Untrusted
callers, stolen tokens, a compromised agent, prompt-injected agents trying to escalate
through MCP tools.

## Useful
```sh
cargo test -p telltale-api
bash deploy/agent-e2e.sh; bash deploy/mcp-e2e.sh             # if prerequisites are present
UPDATE_OPENAPI=1 cargo test -p telltale-api api_001_committed_openapi   # regenerate only if you change the API
```
