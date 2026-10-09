# 13 — Agent Interface: Agent-Ready API and MCP Server

## 1. Why
The owner expects AI agents to manage the platform and run analytics:
- "Why is the TV slow?"
- "Block whatever the new IoT camera keeps calling home to."
- "Weekly report of new domains per kid's device."
- "Fail over to the Pi and promote it."

Neither Pi-hole nor Technitium is designed for this. TelltaleDNS treats agents as a first-class client type with the same security model as humans: **least privilege, preview before change, full audit.**

## 2. Requirements
| ID | Pri | Requirement |
|---|---|---|
| AGT-001 | P0 | **Agent-ready REST API:** every operation in OpenAPI has a summary, a description, examples, and enum docs written for LLM consumption. Responses include units in field names (`latencyMs`, `ttlSeconds`). Errors are problem+json with actionable `hint`s. |
| AGT-002 | P0 | **Dry-run on every mutation:** `?dryRun=true` returns the computed config diff, a validation result, and an *impact estimate* (e.g., "would block 1,243 queries/day from 3 clients, based on the last 7 days"), without applying. |
| AGT-003 | P0 | **Idempotency:** `Idempotency-Key` header on all POST/PATCH/DELETE; replays return the original result for 24 h. |
| AGT-004 | P0 | **Agent principals:** API tokens with `kind=agent`, a human owner, scopes (`analytics:read`, `querylog:read`, `config:read`, `config:write:<area>`, `ops:pause`, `ops:cache`, `cluster:admin`), an optional group restriction, rate limits, and expiry. Default scope set is read-only. |
| AGT-005 | P0 | **Audit attribution:** audit entries record `actor = agent:<token-name> (owner: <user>)`, the MCP client name/version when present, and the agent-supplied `reason` string (required on writes). |
| AGT-006 | P0 | **Built-in MCP server, read-only tools** (§3.1) over Streamable HTTP at `/mcp`, plus `telltale mcp --stdio` (a local stdio bridge that authenticates to a node with a token). |
| AGT-007 | P1 | **MCP write tools with plan/apply** (§3.2): a write tool returns a plan + `planId`. `apply_plan(planId)` executes it only if the config version hasn't changed and the plan hasn't expired (10 min). Optionally, a policy requires human approval: the plan appears in the UI "Pending agent changes" inbox (and via alert destinations) before apply succeeds. |
| AGT-008 | P0 | **MCP auth:** Bearer agent tokens. The OAuth 2.1 flow per the MCP authorization spec (protected-resource metadata at `/.well-known/oauth-protected-resource`) uses the configured OIDC provider as the authorization server (P1), so a user can connect an agent with SSO and consent to scopes. |
| AGT-009 | P0 | **Guardrails:** result-size caps with pagination cursors (default 200 rows / 32 KiB per tool result), privacy level enforcement identical to the UI, per-token rate limits, and a cluster-wide kill switch (`agents.enabled=false`). Tool descriptions state side effects explicitly. |
| AGT-010 | P1 | **MCP resources and prompts:** resources for cluster status, config (redacted), and the daily summary report; prompts for "investigate device", "weekly network report", "tune blocklists", and "upstream health review". |
| AGT-011 | P1 | **Scope-aware federation:** every analytics tool accepts `scope` (cluster/site/node) and reports `missingNodes`, matching `12 §6`. |
| AGT-012 | P2 | **Agent-friendly analytics query language:** a constrained, safe query DSL (`vqlog`) over the query log and rollups (filter, group by, top-K, percentiles, time bucket), with a cost estimate, exposed as one tool. This avoids dozens of narrow tools and never allows arbitrary SQL. |

## 3. MCP tool catalog
Implement with the official Rust MCP SDK (`rmcp`) or a minimal compliant implementation (tools/resources/prompts + Streamable HTTP; spec revision pinned in `Cargo.toml` and documented). **Tools are thin wrappers over the REST API handlers. No separate business logic.**

### 3.1 Read-only (P0)
| Tool | Purpose |
|---|---|
| `get_overview` | KPIs for a window: queries, blocked %, cache hit %, latency p50/p95/p99, active clients, node health |
| `top_items` | Top domains / blocked domains / clients / NXDOMAIN / upstreams for a window, optionally per client or group |
| `search_queries` | Query-log search (client, group, qname pattern, status, qtype, rcode, upstream, min latency, node, time range), paginated |
| `explain_decision` | `explain` for name + client + qtype: rules matched, winner, upstream route |
| `get_client_profile` | Device profile: identity, groups, traffic, top/new domains, latency, protocols |
| `latency_breakdown` | Percentiles by stage / upstream / client / qtype |
| `upstream_health` | Per-upstream health, breaker history, latency percentiles |
| `list_effectiveness` | Hits, unique contribution, overlap, dead lists |
| `find_anomalies` | New domains, NXDOMAIN storms, DGA-suspicious names, rate anomalies, per-domain volume anomalies, behavior drift, beaconing (OBS-013), with evidence, over a window; every node's, each with its ID and acknowledgement (OBS-014), optionally only unacknowledged |
| `health` | One level for the deployment (healthy, degraded, severe) and every reason with its node and where to look (OBS-015) |
| `upstream_checks` | Per node and upstream: DNSSEC verdicts, EDE codes returned, second-opinion outcomes, and the latest disagreements with both answers (OBS-019) |
| `probe_status` | Every node's synthetic probes of its own listeners (and extra targets): answering, latency, failures in a row, certificate days left (OBS-020) |
| `cache_advice` | Per node: hit rate, memory, the estimated extra hits a 25/50/100% larger cache would serve, peak use, and grow/shrink/ok advice (OBS-021) |
| `slo_status` | The service-level objectives: target, SLI and error budget left over the window, burn rates over 5m–3d, and whether the budget burns fast enough to warn (OBS-016) |
| `cluster_status` | Members, roles, epochs, lag, versions, primary reachability |
| `get_config` | Config section (secrets redacted) + current version |
| `test_resolution` | Resolve a name through a given upstream/group *without* caching or logging, to diagnose |

### 3.2 Write (P1, plan/apply)
`plan_block_domain`, `plan_allow_domain`, `plan_add_list`, `plan_update_group`, `plan_assign_client`, `plan_rename_client` (API-010), `plan_update_upstreams`, `plan_set_schedule` → `apply_plan`, `discard_plan`.
Immediate low-risk ops (scope-gated, still audited, no plan): `pause_blocking` (max 60 min for agents), `resume_blocking`, `flush_cache`, `acknowledge_anomalies` (`ops:anomalies`; `undo` takes it back; OBS-014). Pre-save checks (T9.12; change nothing, need the entry's write scope): `check_upstream`, `check_list`.
`cluster_promote` is excluded from agents unless `cluster:admin` scope **and** human approval are both configured.

### 3.3 Example interaction
> **User → agent:** "Why is the living-room TV slow tonight?"
> **Agent:** `get_client_profile(client="living-room-tv", window="-6h")` → p95 latency 840 ms (normally 30 ms), 92% of misses go to the `quad9-doh` upstream
> → `upstream_health(window="-6h")` → `quad9-doh` breaker flapping since 19:40
> → `plan_update_upstreams(group="default", strategy="fastest", reason="quad9 degraded")` → plan shows the diff + impact
> → the user approves in the UI → `apply_plan`.

## 4. Implementation notes
- Crate: `telltale-mcp` (depends on `telltale-api` service layer). It is mounted in the same axum router on every node, so any node is an MCP entry point (single management plane).
- Tool JSON Schemas are generated from the same Rust types as the OpenAPI document (`schemars`), so they cannot drift. A CI test diffs the tool catalog against a committed snapshot.
- Tests:
  - an MCP conformance test with the reference inspector/client in CI;
  - golden transcripts for §3.3-style flows using a scripted fake agent;
  - authorization tests proving each tool honors scopes and privacy levels.
- Footprint: the MCP layer is a feature flag (`mcp`, default **on**) adding ≤ 1 MiB to the binary.
