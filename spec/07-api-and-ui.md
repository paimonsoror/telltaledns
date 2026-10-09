# 07 — API and UI

## 1. API conventions (API-001, API-002)
- Base path `/api/v1`. JSON (camelCase). Errors use RFC 9457 `application/problem+json` with a stable `code`.
- OpenAPI 3.1 is generated from handler types (`utoipa`), served at `/api/v1/openapi.json`, and a CI test fails if the committed spec drifts.
- Every list endpoint has cursor pagination (`?cursor=&limit=`). Every analytics endpoint accepts `scope=cluster|site:<s>|node:<id>` (default `cluster`, see `12 §6`) and `from`/`to` (RFC 3339 or relative `-24h`). Federated responses include `meta.missingNodes`.
- Mutations accept `If-Match: <config-version>` for optimistic concurrency (`412` on conflict) and return the new version. Mutations on a replica are transparently forwarded to the primary. When no primary is reachable, they return `503 no_primary` with a `promote` hint.
- Auth: session cookie (UI) or `Authorization: Bearer <token>`.

## 2. Resource map
| Area | Endpoints (abridged) |
|---|---|
| Auth | `POST /auth/login`, `POST /auth/logout`, `POST /auth/totp/verify`, `GET /auth/oidc/*`, `GET/POST/DELETE /tokens` |
| Users/RBAC | `/users`, `/users/{id}/roles` |
| Dashboard | `GET /stats/summary`, `/stats/timeseries?metric=&step=`, `/stats/top?kind=domains\|blocked\|clients\|nxdomain&limit=`, `/stats/latency?by=upstream\|client\|qtype\|stage` (percentiles), `/stats/slo` (objectives, error budgets, burn rates; OBS-016) |
| Query log | `GET /queries` (filters: client, group, qname (substring/glob/regex), status[], qtype[], rcode[], upstream, node, minLatencyMs, cursor), `GET /queries/stream` (SSE), `GET /queries/export` |
| Explain | `GET /explain?name=&client=&qtype=` |
| Clients | `/clients` (CRUD; merge identities), `/clients/{id}/profile` (analytics), `/clients/discovered` |
| Groups | `/groups` CRUD, `/groups/{id}/pause` (POST `{minutes}`), `/groups/{id}/schedules` |
| Lists | `/lists` CRUD, `POST /lists/refresh`, `/lists/{id}/stats`, `/lists/overlap` |
| Rules | `/rules` (manual allow/deny, regex), bulk import/export |
| Upstreams | `/upstreams`, `/upstream-groups`, `/routes`, `/upstreams/presets`, `/upstreams/{id}/health`, `POST /upstreams/test` (run a query through a candidate upstream) |
| Local DNS | `/records`, `/zones`, `/rewrites`, `/safesearch`, `/services` |
| Cache | `GET /cache/stats`, `POST /cache/flush` (`{name?, subtree?}`) |
| Blocking | `POST /blocking/pause`, `POST /blocking/resume` (global) |
| Settings | `GET/PATCH /config` (whole document, JSON-Patch), `GET /config/schema`, `POST /config/validate` |
| Cluster | `GET /cluster` (members, roles, versions, lag, epochs), `POST /cluster/tokens`, `POST /cluster/promote`, `DELETE /cluster/nodes/{id}`, `GET /cluster/conflicts`, `POST /cluster/conflicts/{id}/reapply` |
| Analytics | `/analytics/new-domains`, `/analytics/suspicious`, `/analytics/anomalies` (every node's, `acknowledged=false`), `POST /analytics/anomalies/acknowledge` and `/unacknowledge` (`{ids, note?}`, OBS-014), `/analytics/lists/effectiveness`, `/analytics/cache` |
| Alerts | `/alerts/rules`, `/alerts/destinations`, `/alerts/history` |
| Ops | `/backup`, `/restore`, `/import/pihole`, `/import/technitium`, `/audit`, `/system/info`, `/system/health` (healthy, degraded, or severe, and why; OBS-015), `/healthz`, `/readyz`, `/livez`, `/metrics` |

## 3. UI scope (API-005)
Tech: Svelte 5 + Vite + TypeScript, uPlot for charts (fast, tiny), no CSS framework (design tokens + CSS variables), embedded in the binary. Budget: ≤ 400 KiB gzipped total and first paint < 1 s on a Pi-served LAN. Responsive down to 360 px (phone use is common for "pause blocking").

| Page | Must show |
|---|---|
| **Dashboard** | KPI tiles (queries, blocked %, cache hit %, p95 latency, active clients, nodes up); queries-over-time stacked by status; latency percentiles over time; "where time goes" stage breakdown; top domains/blocked/clients; upstream share + health; scope selector (cluster/site/node) |
| **Query log** | Virtualized table; live-tail toggle; a filter bar with chips; per-row stage-timing bar; "Why?" (explain) drawer; quick actions (allow/block domain for this client's group) |
| **Clients** | Discovered vs. named; merge identities (IP + MAC + client ID → one device); per-client profile page (traffic, top domains, new domains, latency, groups, protocols) |
| **Groups** | Lists, rules, upstream group, block mode, schedules (weekly grid editor), safe search, services, pause |
| **Lists** | Add by URL/preset; stats, overlap, dead-list hints; refresh |
| **Upstreams** | Presets gallery; groups + strategy; routes; live health (sparklines, breaker state); "test" button |
| **Local DNS** | Records, zones, rewrites |
| **Cluster** | Topology view (sites → nodes), versions, lag, roles, epoch, heartbeat age; join-token wizard; promote; conflicts |
| **Analytics** | New domains, suspicious (DGA/NXDOMAIN storms), anomalies, list effectiveness, cache efficiency |
| **Settings** | Listeners/TLS, DNSSEC, cache, privacy level, telemetry/exporters, alerts, users/2FA/OIDC, backup/import, audit log |

UX rules:
- A banner shows cluster state: read-only (no primary), GitOps-managed, client IPs masked, or a node lagging.
- Every chart has a table view.
- The UI requires JavaScript and is not prerendered.
