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
| OPS-008 | P1 | Optional DHCPv4 server (Linux/Pi installs only), with leases feeding client naming. |
| OPS-009 | P0 | Config hot-reload without dropping queries (SIGHUP, API, or snapshot from the primary). |

## Project site and documentation (DOC) — see `11` ADR-012
Requested by the owner on 2026-10-02. A GitHub Pages site that introduces the project to two audiences. Guiding rule: **visual first**. Every page leads with a diagram, screenshot, or animation, and prose stays short.
| ID | Pri | Requirement |
|---|---|---|
| DOC-001 | P0 | Project site on GitHub Pages, deployed from `main` by CI. Static HTML/CSS with inline SVG; works without JavaScript (JS only enhances); light/dark themes; mobile-friendly. |
| DOC-002 | P0 | **"Start here" track (non-technical):** what TelltaleDNS is and why it beats Pi-hole/Technitium (visual comparison), a 3-step quick start per platform (Raspberry Pi, Docker, Kubernetes), and what you'll see (dashboard screenshots once the UI exists). No jargon without a tooltip or glossary link. |
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
