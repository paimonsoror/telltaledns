# 01 — Requirements (the contract)

Every requirement has a stable ID. Code, tests, and PRs **must** reference IDs (e.g., `// REQ: FLT-004`, test name `flt_004_wildcard_suffix_block`). Priority: **P0** = v1.0 must ship; **P1** = v1.x; **P2** = later / stretch.

Detailed behavior lives in the referenced spec section. If this table and a section disagree, the section wins, and fix the table.

## DNS core (DNS) — see `03`
| ID | Pri | Requirement |
|---|---|---|
| DNS-001 | P0 | Serve DNS over UDP and TCP (RFC 1035, RFC 7766) on configurable addresses/ports, IPv4 and IPv6. |
| DNS-002 | P0 | Serve DoT (RFC 7858) with configurable cert/key, plus ACME (via cert files that cert-manager mounts in k8s). |
| DNS-003 | P0 | Serve DoH (RFC 8484) over HTTP/2 with GET and POST on `/dns-query` and `/dns-query/{client-id}`. |
| DNS-004 | P1 | Serve DoH over HTTP/3 and DoQ (RFC 9250). |
| DNS-005 | P0 | EDNS(0) (RFC 6891), with a configurable advertised UDP payload size (default 1232) and TC-bit truncation. |
| DNS-006 | P0 | Sharded in-memory cache that stores wire-format responses and rewrites ID and TTLs on hit; honors min/max TTL clamps; negative caching (RFC 2308). |
| DNS-007 | P0 | Serve-stale (RFC 8767), with configurable max stale age and client-response timeout. |
| DNS-008 | P1 | Prefetch: hot entries refresh asynchronously when remaining TTL < 10% (configurable). |
| DNS-009 | P1 | Cache persistence: an optional dump on shutdown and load on startup. |
| DNS-010 | P0 | Local records: A, AAAA, CNAME, PTR (auto-generated from A/AAAA), TXT, SRV, MX; wildcard local records; hosts-file import. |
| DNS-011 | P0 | DNSSEC validation (RFC 4033–4035) for forwarded and recursive answers. Bogus → SERVFAIL with EDE 6. Configurable negative trust anchors. |
| DNS-012 | P1 | Full recursive resolution from root hints, with QNAME minimization (RFC 9156) and aggressive NSEC caching (RFC 8198). |
| DNS-013 | P0 | Extended DNS Errors (RFC 8914) on blocked, stale, and failed answers. |
| DNS-014 | P0 | Per-client rate limiting (token bucket; default 1000 q/60 s like Pi-hole), with REFUSED or drop as the action and an allowlist exemption. |
| DNS-015 | P1 | ECS (RFC 7871): strip, pass through, or substitute per upstream; never leak ECS by default. |
| DNS-016 | P1 | DNS64 (RFC 6147) per group. |
| DNS-017 | P0 | Conditional forwarding / per-domain upstream routing, including reverse zones (Pi-hole `rev-server` parity). |
| DNS-018 | P1 | Local zones: a small authoritative zone loaded from an RFC 1035 zone file or config (split-horizon views per group). |
| DNS-019 | P0 | Refuse ANY queries (RFC 8482 minimal response) and drop malformed packets cheaply. |
| DNS-020 | P1 | PROXY protocol v2 on TCP/DoT/DoH listeners, to preserve client IPs behind load balancers. |
| DNS-021 | P2 | NSID (RFC 5001), off by default: a query that asks for it gets the answering node's name, so a client can tell which node or pod answered behind a shared address (owner request 2026-10-09, from Technitium #1932). |

## Upstreams (UPS) — see `04`
| ID | Pri | Requirement |
|---|---|---|
| UPS-001 | P0 | Upstream protocols: UDP, TCP, DoT, DoH (HTTP/2). |
| UPS-002 | P1 | Upstream protocols: DoH over HTTP/3 and DoQ. |
| UPS-003 | P1 | Upstream DNSCrypt v2 (to cover what Pi-hole users run via dnscrypt-proxy). |
| UPS-004 | P0 | A built-in preset catalog covering every Pi-hole preset (Google, OpenDNS, Level3, Comodo, Quad9 filtered/unfiltered/ECS, Cloudflare) and the common Technitium forwarder presets (Cloudflare, Google, Quad9, AdGuard, NextDNS, Mullvad, ControlD), each in all protocols it offers. |
| UPS-005 | P0 | Selection strategies: `failover`, `round_robin`, `weighted`, `fastest` (EWMA latency), `parallel` (race N, first valid answer wins). |
| UPS-006 | P0 | Active and passive health checks; a circuit breaker per upstream; failover within one query (retry next upstream before the client timeout). |
| UPS-007 | P0 | Upstream groups referenced by name; routing by domain suffix, client group, and qtype. |
| UPS-008 | P0 | Connection reuse/pipelining for TCP/DoT/DoH (HTTP/2 multiplexing); configurable pool size; idle timeouts. |
| UPS-009 | P0 | Bootstrap resolution for hostname upstreams (pinned IPs or dedicated bootstrap servers; never resolve through ourselves). |
| UPS-010 | P1 | SOCKS5 and HTTP CONNECT proxy per upstream (Tor parity with Technitium). |
| UPS-011 | P1 | **Custom upstreams:** (a) arbitrary endpoint parameters (custom DoH path/headers/method, SNI override, client certificate mTLS, TLS pinning); (b) an *exec/socket plugin* that speaks DNS wire format over a Unix socket or localhost; (c) a WASM upstream plugin ABI (P2). |
| UPS-012 | P1 | `recursive` as an upstream type (uses DNS-012), so it can sit in any upstream group. |

## Filtering (FLT) — see `05`
| ID | Pri | Requirement |
|---|---|---|
| FLT-001 | P0 | List formats: hosts files, plain domain lists, wildcard (`*.example.com`), AdBlock/AdGuard DNS syntax (`||domain^`, `@@`, `$important`, `$badfilter`, `$client`, `$dnstype`, `$denyallow`), Pi-hole regex (with `;querytype=`, `;invert`). |
| FLT-002 | P0 | Domain rules match the domain and all subdomains by default (Technitium semantics), with an exact-match opt-in (Pi-hole "exact" parity). |
| FLT-003 | P0 | Compiled filter snapshot: an FST for domain sets plus a compiled multi-pattern DFA for regexes. Lookup cost is independent of the number of rules. |
| FLT-004 | P0 | Background list download (ETag/If-Modified-Since), compile, and atomic swap with no query pause; the last-good snapshot is kept on failure. |
| FLT-005 | P0 | Groups (Pi-hole model): clients → groups → {lists, allow/deny rules, upstream group, schedules, response policy}. A default group exists. |
| FLT-006 | P0 | Client identification by IP/CIDR, MAC (ARP/NDP neighbor table), hostname (DHCP lease / reverse lookup), client ID (DoH path, DoT/DoQ SNI prefix), and EDNS MAC option (dnsmasq `add-mac` format). |
| FLT-007 | P0 | CNAME deep inspection: block if any CNAME target in the answer chain is blocked for that client. |
| FLT-008 | P0 | Block response modes: NXDOMAIN, NODATA, null IP (0.0.0.0/::), custom IPs, REFUSED; always with EDE 15 (Blocked) or 17 (Filtered) plus the rule attribution text (configurable). |
| FLT-009 | P0 | Global and per-group pause (disable blocking for N minutes), with auto-resume. |
| FLT-010 | P1 | Schedules: per-group weekly time windows that enable extra lists or block all ("bedtime"). |
| FLT-011 | P1 | Safe-search enforcement (Google, Bing, DuckDuckGo, YouTube restricted, Pixabay…) via CNAME/A rewrites per group. |
| FLT-012 | P1 | Blocked-services presets (one-click service bundles: TikTok, Facebook, gaming, etc.), shipped as data files. |
| FLT-013 | P0 | Rule attribution: every block or allow decision records list ID + rule ID, and the API can explain "why was X blocked for client Y". |
| FLT-014 | P1 | Rewrites (`$dnsrewrite`-like): map a domain to an answer per group. |
| FLT-015 | P1 | Response IP filtering: block answers whose A/AAAA falls in a configured CIDR (DNS rebinding protection; private IPs from public names). |
| FLT-016 | P2 | Per-group AAAA filtering: a group's AAAA questions get no data (devices fall back to IPv4 on a network with broken IPv6); local data still answers, blocks still win, not combined with DNS64 (owner request 2026-10-09, from Pi-hole's feature requests). |

## Observability (OBS) — see `06`
| ID | Pri | Requirement |
|---|---|---|
| OBS-001 | P0 | Every transaction emits a QueryEvent (full schema in `06`), including a per-stage timing breakdown. |
| OBS-002 | P0 | The hot path never blocks on telemetry: per-worker lock-free ring buffers; overflow increments a drop counter that is itself exported. |
| OBS-003 | P0 | Embedded query-log store: segmented, columnar, compressed, and indexed; retention by age and size. |
| OBS-004 | P0 | Real-time rollups: counts by status/qtype/rcode/upstream/client/group; top-K domains/clients/blocked (Space-Saving); latency histograms (HDR) per upstream, client, qtype, and stage. |
| OBS-005 | P0 | Prometheus `/metrics` endpoint (low-cardinality by default; per-client series opt-in with a cap). |
| OBS-006 | P1 | OpenTelemetry OTLP export (metrics; optional logs for QueryEvents). |
| OBS-007 | P1 | dnstap output (Frame Streams over Unix socket or TCP). |
| OBS-008 | P0 | Live query tail over WebSocket/SSE with server-side filters. |
| OBS-009 | P1 | Analytics: first-seen domains per client, NXDOMAIN-storm detection, high-entropy/DGA-likelihood scoring, query-rate anomaly per client, list effectiveness (hits per list, dead lists, overlap). |
| OBS-013 | P1 | Per-device behavior baselines and anomaly alerts, deterministic and explainable: query-rate spikes per client, abnormal volume to one domain from one client, drift from a device's learned domain set (e.g. an IoT device contacting many new domains), and periodic phone-home/beaconing. Alert-only by default; never blocks on its own (`06` §7.1, ADR-019). |
| OBS-014 | P1 | Acknowledging anomaly findings: each finding has a stable ID (the same on every node); an operator (or an agent with `ops:anomalies`) acknowledges findings or takes it back, audited; acknowledged findings stop counting as new (badge, `acknowledged=false`, anomaly alerts) on every cluster node, including nodes that were down when it happened. The Anomalies view covers every node's findings. Not a configuration change: allowed in a GitOps-managed cluster (ADR-103). |
| OBS-015 | P1 | One health level for the whole deployment, `healthy`/`degraded`/`severe`, with its reasons (node, summary, where to look), in the API, MCP, and an icon in the UI's navigation. Severe: an upstream group with no upstream answering, no node serving, SERVFAIL ≥ 25%. Degraded: one upstream down, a node unreachable/not serving/behind, a list failing, devices rate-limited, SERVFAIL ≥ 5%, a data disk > 90% full. Device anomalies don't count (ADR-104). |
| OBS-016 | P1 | Service-level objectives (owner request, 2026-10-08): availability (answers that aren't SERVFAIL) and latency (answers within a threshold that is a `/metrics` bucket bound), each with an error budget over a window and burn rates over 5m–3d; multi-window burn-rate warnings (fast 14.4× over 1h+5m, slow 6× over 6h+30m) degrade the health level and fire `slo_burn` alerts; API, MCP, a dashboard card; Prometheus recording rules and alerts with the same definitions (`06` §8.2, ADR-105). |
| OBS-017 | P1 | Exemplars and traces (owner request, 2026-10-08): the latency histograms on `/metrics` carry OpenMetrics exemplars naming a recent query in each bucket (a trace ID the query log can find); optionally, sampled and slow queries are exported as OTLP traces whose spans are built from the query event off the query path (`06` §5.1). |
| OBS-018 | P1 | Shadow lists and over-blocking suspects (owner request, 2026-10-08): a list in `shadow` mode is compiled but never blocks; what it would have blocked is counted per list (names, devices, top names) so it can be judged before it's enforced. Blocked names that devices keep retrying, or that are allowed right after being blocked, are listed as likely over-blocking, with the deciding list (`06` §7.2). |
| OBS-019 | P1 | Upstream truth checks (owner request, 2026-10-08): a sampled share of forwarded questions (off by default) is asked again of a second upstream off the query path and the answers compared (same, different addresses, different response code, filtered/sinkholed); per-upstream counts of DNSSEC verdicts and of the EDE codes upstreams return (`04` §9). |
| OBS-020 | P1 | Synthetic probes (owner request, 2026-10-08): every DNS listener (UDP, TCP, DoT, DoH, DoQ) is asked a question through its own protocol on a schedule, plus optional extra targets (a load balancer's address); success, latency, and each TLS listener's certificate expiry are exported, degrade the health level when failing or near expiry, and can alert (`06` §9). |
| OBS-021 | P1 | Cache sizing advice (owner request, 2026-10-08): a sampled ghost list of evicted keys estimates the extra hits a 1.25×, 1.5×, and 2× cache would have served, and the peak use says whether the cache could shrink; shown on the Cache page, in the API and MCP, and as metrics (`03` §4.1). |
| OBS-022 | P1 | Exclusions (owner request 2026-10-09): names (with their subdomains) and clients (addresses, networks) kept out of the query log, live view, analytics, anomalies, and exports while still answered and counted in metrics; an on/off toggle; editable in the UI (checked, applied, reverted) and in the config files / Git; shared by the cluster (`06` §4.1). |
| OBS-023 | P1 | Stale lists (owner request 2026-10-09): a URL list whose content hasn't changed in `stale_after_days` (default 30, per list too) is reported on the Lists page and in the API, degrades the health level (`list_stale`), and can alert (`05` §3.5). |
| OBS-010 | P1 | Event sinks: JSON-lines file, syslog (RFC 5424), HTTP webhook (batched), and alert rules (threshold → webhook/ntfy/email). |
| OBS-011 | P0 | Upstream health dashboard data: per-upstream p50/p95/p99 latency, error/timeout rates, breaker state, share of traffic. |
| OBS-012 | P0 | Cluster-wide (federated) analytics: every dashboard and query-log search can scope to one node, a set of nodes, or the whole cluster (see `12`). |

## Clustering and HA (CLU) — see `12`
| ID | Pri | Requirement |
|---|---|---|
| CLU-001 | P0 | Nodes join a cluster with a join token; mTLS between nodes uses certificates issued by the cluster CA. Works across sites and deployment types (bare-metal Pi ↔ Kubernetes pods). |
| CLU-002 | P0 | Single management plane: the UI/API on *any* node shows and manages the whole cluster; writes are forwarded to the primary. |
| CLU-003 | P0 | Config replication: a versioned, signed snapshot log; replicas converge to the primary's version automatically, including after long partitions. |
| CLU-004 | P0 | DNS independence: a node answers queries from its last applied snapshot regardless of primary/controller reachability. |
| CLU-005 | P0 | Failover: a manual `promote` in two-node clusters; automatic promotion when ≥ 3 voters exist or a witness is configured; epoch-based fencing prevents split-brain writes. |
| CLU-006 | P0 | Per-node overrides: listen addresses, local-only records, cache size, and storage retention can differ per node without forking the shared config. |
| CLU-007 | P0 | Telemetry federation: scatter-gather query-log search and rollup aggregation across nodes. Optional ship-to-controller mode with local store-and-forward buffering (for SD-card nodes). |
| CLU-008 | P0 | Cluster health view: membership, versions, snapshot lag, last heartbeat, per-node qps/latency. An alert fires when a node lags or disappears. |
| CLU-009 | P1 | Ephemeral members (Kubernetes pods) auto-register and are garbage-collected after a TTL; they are grouped under a "site" for display. |
| CLU-010 | P1 | Rolling-upgrade compatibility: N and N-1 versions interoperate in a cluster (protocol + snapshot schema versioning). |
| CLU-011 | P2 | Cache-warm hints: replicas exchange top-N hot names so a newly started node prefetches them. |

## API and UI (API) — see `07`
| ID | Pri | Requirement |
|---|---|---|
| API-001 | P0 | REST JSON API, versioned (`/api/v1`) and described by an OpenAPI 3.1 document generated from code. |
| API-002 | P0 | **API parity:** everything the UI does is possible via the API, and everything in config can be changed via the API. |
| API-003 | P0 | **Basic auth:** local users with username/password (Argon2id), UI session login, optional HTTP Basic on the API for scripts/dashboards/scrapers (off by default; TLS required unless explicitly overridden), scoped API tokens, TOTP 2FA, RBAC roles (admin, operator, viewer). |
| API-004 | P0 | **OIDC SSO** (Authorization Code + PKCE) with group/claim → role mapping, JIT user provisioning, multiple providers (Authentik, Authelia, Keycloak, Entra ID, Google, Pocket ID tested); a local break-glass admin always remains. |
| API-009 | — | **Non-goal:** LDAP/AD bind authentication is explicitly out of scope (use an OIDC bridge such as Authentik/Keycloak if needed). |
| API-005 | P0 | Embedded web UI: dashboard, query log, clients, groups, lists, rules, upstreams, local DNS, cluster, settings, audit log. |
| API-006 | P0 | Audit log of every config change (who, when, diff), replicated cluster-wide. |
| API-007 | P0 | Backup/restore (Teleporter parity): a single archive with config + local data, and an option to include query history. Import from a Pi-hole Teleporter archive and from a Technitium backup (P1 for Technitium). |
| API-008 | P1 | CLI (`telltale ctl ...`) that wraps the API. |
| API-010 | P0 | **Inline device naming** (owner request, 2026-10-02): wherever a client IP (or MAC) appears — top clients, top blocked, query log, live tail, client detail, charts — it opens a menu with "Name this device…", "Add to group…", and "Show queries". Naming creates or updates a client object (IP, and the MAC when known from the neighbor table/EDNS) so every view and the API show the alias instead of the address. Names are resolved at read time, so renaming also relabels historical data. Suggestions are pre-filled from DHCP leases, reverse DNS, and mDNS when available. Also available as an API mutation (with dry-run, AGT-002) and the MCP write tool `plan_rename_client` (`13` §3.2). Replicated cluster-wide like other config (CLU-003). |
| API-011 | P0 | **Guided UI, for novices and experts alike** (owner request, 2026-10-04): features are named by what they do, with the DNS term as a subtitle ("Names on my network" — *local zone*; "Send a domain to another server" — *conditional forwarding*). Every setting has a "?" that opens a slide-out help panel (what it does, when to use it, a home-network example, what goes wrong if misused, the technical term, a docs link) with a **small diagram of what the option does**, filled in with the user's own values. Pages have Simple and Advanced views (remembered per user); expert fields and record types sit under Advanced with safe defaults. Every change shows a plain-language preview (with the same diagram) before it is applied, and each rule has a "Test a name" action (explain). Help text lives in one glossary that the UI, docs, and site share. Expert depth stays fully available in the config, API, and CLI. |

## Agent interface (AGT) — see `13`
AGT-001..012 are defined in `13 §2`. Summary: agent-ready OpenAPI (P0); dry-run + impact estimates on every mutation (P0); idempotency keys (P0); scoped agent tokens + audit attribution (P0); built-in MCP server with read-only analytics tools (P0) and plan/apply write tools with optional human approval (P1); OAuth via the configured OIDC provider (P1); guardrails and a kill switch (P0); safe analytics query DSL (P2).

## Deployment and operations (OPS) — see `08`
| ID | Pri | Requirement |
|---|---|---|
| OPS-001 | P0 | Multi-arch OCI image (linux/amd64, linux/arm64, linux/arm/v7) built `FROM scratch`/distroless with a static musl binary; runs as non-root. |
| OPS-002 | P0 | Helm chart: resolver Deployment/DaemonSet, controller StatefulSet (or all-in-one), Services (UDP+TCP), PDB, HPA, ServiceMonitor, NetworkPolicy, probes, cert-manager integration. |
| OPS-003 | P0 | Client-IP preservation guidance and defaults (externalTrafficPolicy: Local, hostNetwork option, PROXY protocol). The chart validates and warns when client IPs would be masked. |
| OPS-004 | P0 | Raspberry Pi / Linux: the same image via Docker/Podman Compose (primary path); a static binary + systemd unit + install script (secondary path). |
| OPS-005 | P0 | Declarative config file (TOML) + env overrides; config can be seeded from a ConfigMap; GitOps mode (config file is the source of truth, API writes are rejected or written back as a PR-able diff). |
| OPS-006 | P0 | Health endpoints: `/healthz` (process), `/readyz` (snapshot loaded and listeners bound), `/livez`. |
| OPS-007 | P0 | Graceful shutdown: drain TCP/DoH connections, flush telemetry, persist the cache (if enabled). |
| OPS-008 | — | ~~Optional DHCPv4 server (Linux/Pi installs only), with leases feeding client naming.~~ **Descoped** (owner, 2026-10-06; ADR-091): routers hand out addresses; their DHCP clients still name devices (`[[router]]`, API-010). |
| OPS-009 | P0 | Config hot-reload without dropping queries (SIGHUP, API, or snapshot from the primary). |

## Project site and documentation (DOC) — see `11` ADR-012
Requested by the owner on 2026-10-02. A GitHub Pages site that introduces the project to two audiences. Guiding rule: **visual first**. Every page leads with a diagram, screenshot, or animation, and prose stays short.
| ID | Pri | Requirement |
|---|---|---|
| DOC-001 | P0 | Project site on GitHub Pages, deployed from `main` by CI. Static HTML/CSS with inline SVG; works without JavaScript (JS only enhances); light/dark themes; mobile-friendly. |
| DOC-002 | P0 | **"Start here" track (non-technical):** what TelltaleDNS is, what it focuses on, and credit to the projects that inspired it (Pi-hole, Technitium; no competitive comparison, owner direction 2026-10-05), a 3-step quick start per platform (Raspberry Pi, Docker, Kubernetes), and what you'll see (dashboard screenshots once the UI exists). No jargon without a tooltip or glossary link. |
| DOC-003 | P0 | **Technical track:** architecture (data/control plane, threading, query pipeline with per-stage timing), clustering/HA topology and failover, performance methodology with published harness numbers only (`09 §3` rule), configuration reference (from the JSON Schema), API/MCP overview. |
| DOC-004 | P0 | **Standards page:** every RFC TelltaleDNS implements, each with its support status (supported / partial / planned, tied to requirement IDs), a one-line summary, and a diagram of the behavior it adds (e.g., packet layout for EDNS/EDE, sequence diagrams for TCP pipelining, serve-stale, DNSSEC chain of trust). Status comes from one data file so the page can't drift from the code. |
| DOC-005 | P1 | Site quality gates in CI: HTML validation, broken-link check, accessibility (WCAG 2.1 AA via axe), page weight ≤ 500 KiB per page excluding screenshots. |
| DOC-006 | P1 | Each task that changes user-visible behavior updates the relevant site page in the same PR (extends AGENTS.md "Done means"). |

## Non-functional (NFR)
| ID | Pri | Requirement |
|---|---|---|
| NFR-001 | P0 | Performance targets in `00 §5` are release gates, measured by `09`. |
| NFR-002 | P0 | No heap allocation on the steady-state cache-hit and blocked-answer paths (verified by an allocation-counting test harness). |
| NFR-003 | P0 | Memory safety: `#![forbid(unsafe_code)]` in all crates except an audited `telltale-net` crate (recvmmsg/sendmmsg, socket options). Each `unsafe` block carries a `// SAFETY:` comment. |
| NFR-004 | P0 | Fuzzing: cargo-fuzz targets for the wire parser, list parsers, rule compiler, and API JSON inputs; run in CI nightly. |
| NFR-005 | P0 | Supply chain: `cargo-deny` (licenses, advisories), `cargo-auditable`, SBOM (CycloneDX), cosign-signed images, reproducible builds. |
| NFR-006 | P0 | Clean-room implementation: **no code copied** from Pi-hole (EUPL-1.2) or Technitium (GPL-3.0). Specs and RFCs only. Project license: Apache-2.0 OR MIT (owner may change). |
| NFR-007 | P0 | Observability of the observability: exported metrics for telemetry drops, store write latency, segment counts, and snapshot versions. |
| NFR-008 | P1 | Accessibility: the UI meets WCAG 2.1 AA; dark/light themes. |
