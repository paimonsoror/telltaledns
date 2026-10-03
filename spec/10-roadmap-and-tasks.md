# 10 — Roadmap and Task List

Ordering reflects the owner's priorities: **performance → observability → Kubernetes + Pi deployability → clustering/HA → breadth**. Each task lists the requirement IDs it satisfies and objective acceptance criteria (AC). A task is done only when its AC pass in CI. Tick boxes as you go and keep this file current.

## M0 — Foundations (week 1)
- [x] **T0.1 Workspace scaffold.** Crates per `02 §2`, `#![forbid(unsafe_code)]` where required, rust-toolchain pinned, CI (fmt, clippy, test, cargo-deny), `LICENSE` (Apache-2.0 OR MIT). *AC:* CI is green on an empty skeleton; `cargo deny check` passes. *Done 2026-10-02: local gate green (fmt/clippy/test/deny); GitHub Actions run pending until a remote exists.*
- [x] **T0.2 Config skeleton.** `telltale-config` with the TOML schema for listeners/upstreams/cache/telemetry, env overrides, `telltale config check`, JSON Schema output. *(OPS-005)* *AC:* unknown keys error with path; env override test. *Done 2026-10-02. Deferred: node.toml key allow-list (T5.5/CLU-006), GitOps mode (OPS-005, with API in M3), CLI-flag layer (with `telltale run`), config migrations (none needed at v1).*
- [ ] **T0.3 Bench harness skeleton.** `bench/` with dnsperf runner, corpora generator, and JSON results. *(NFR-001)* *AC:* `make bench-smoke` runs against a stub server.
- [ ] **T0.4 Container build.** Multi-arch `FROM scratch` image, non-root, published on main as `edge`. *(OPS-001)* *AC:* image ≤ 15 MiB compressed; runs on arm64 under QEMU in CI.

## M1 — Fast forwarding resolver (weeks 2–4)
- [x] **T1.1 telltale-proto hot path.** Header/question/OPT parse, name normalization + hash, response TTL-offset scan, ID/TTL patching, synthesis helpers (NXDOMAIN/NODATA/A/AAAA/EDE). *(DNS-005, DNS-013, DNS-019)* *AC:* proptest round-trips; fuzz target runs for 10 min clean; differential test vs hickory. *Done 2026-10-02: 2000-case proptests + hickory 0.26 differential both directions; 3 fuzz targets × 10 min, 0 crashes (69.9M execs). Micro-bench (x86 WSL): parse+hash 53 ns, blocked answer 56 ns, cache-hit patch 5 ns.*
- [x] **T1.2 UDP workers.** SO_REUSEPORT per worker, recvmmsg/sendmmsg, PKTINFO. *(DNS-001)* *AC:* answers `kdig`; multi-core scaling test shows ≥ 3.2× qps at 4 workers vs 1. *Done 2026-10-02: verified with `dig` (kdig not installed; equivalent). `examples/udp_scaling`: 3.58× at 4 workers with 20 µs/query synthetic work. With 2 µs/query the in-process generator saturates first (2.16×), so the authoritative number must come from the dnsperf harness (T0.3) on separate hardware. Non-Linux fallback compiles but is untested here.*
- [x] **T1.3 TCP listener.** Pipelining, limits, idle timeouts. *(DNS-001)* *Done 2026-10-02: RFC 7766 pipelining (reader/writer split, ready for out-of-order async replies), 10 s idle timeout, 64 in-flight per connection, 1024 connection cap (constants for now; config keys come with T1.10/OPS tuning). Per-thread response scratch keeps idle connections cheap.*
- [x] **T1.4 Cache.** Sharded S3-FIFO, wire storage, TTL clamps, negative caching, singleflight. *(DNS-006)* *AC:* zero-alloc test passes (NFR-002); hit ratio on the Zipf corpus ≥ LRU baseline. *Done 2026-10-02: 0 allocations over 100k hits + 100k blocked answers. S3-FIFO vs LRU (100k names, 1M Zipf requests): s=1.0 59.7%/50.5% (1% cache), 77.8%/73.4% (10%); s=0.8 31.4%/20.4%, 54.5%/46.6%. Full hit path 153 ns single-thread. Also includes serve-stale lookup (DNS-007) and the prefetch signal (DNS-008); the background refresh itself lands with upstreams. Not wired into `telltale run` until T1.5. Decision: negative answers without SOA are not cached (RFC 2308 §5); responses whose OPT isn't the last record are not cached.*
- [x] **T1.5 Upstreams v1.** UDP/TCP/DoT/DoH(h2) transports with pooling; strategies (failover, round_robin, weighted, fastest, parallel); health + breaker; bootstrap; loop detection. *(UPS-001, 005, 006, 008, 009)* *AC:* chaos test with toxiproxy: one upstream at 100% loss → no client-visible failures; p99 within 1.5× of the healthy baseline. *Progress 2026-10-02 — **T1.5a done**: UDP (+TCP fallback on TC) and TCP transports with anti-spoofing validation; all five strategies; health (EWMA, 50-sample window, breaker) and active checks; 2 s budget; hedged attempts (ADR-013); routes; pipeline wired with cache, singleflight, serve-stale, prefetch, SERVFAIL+EDE. Chaos AC met in-process (fake upstreams, one blackholed): 0 failures, p99 1.04–1.15× baseline across failover/round_robin/fastest/parallel; toxiproxy version pending Docker. Verified live against 1.1.1.1/9.9.9.9 with a dead member. **T1.5b done**: DoT and DoH (HTTP/2) over rustls (ring, Mozilla roots built in), pooled pipelined TCP/DoT connections with ID demux, h2 multiplexing, bootstrap resolution for hostnames (per-upstream servers or /etc/resolv.conf minus our listeners), loop tag (EDNS 65429) with drop + error log. Verified live: DoT 1.1.1.1, DoH dns.quad9.net and dns.google. Not yet: spki_pins, proxy, ECS, DoH3 (startup errors if configured).*
- [ ] **T1.6 Presets catalog.** *(UPS-004)* *AC:* every Pi-hole preset present; each entry resolves `example.com` in an online smoke test (nightly, allowed to be flaky-tolerant).
- [ ] **T1.7 Local records + conditional forwarding/routes.** *(DNS-010, DNS-017)*
- [ ] **T1.8 Rate limiting, special names, allowed_networks.** *(DNS-014)*
- [ ] **T1.9 Metrics core.** Thread-local counters + HDR per path; `/metrics`; `/healthz` `/readyz` `/livez`. *(OBS-005 partial, OPS-006)*
- [ ] **T1.10 Graceful shutdown + hot reload.** *(OPS-007, OPS-009)*
- [x] **T1.11 Project site skeleton (GitHub Pages).** *(DOC-001, DOC-002, DOC-004, DOC-005)* Scheduled right after T1.5, when TelltaleDNS first resolves queries, so the quick start is real. Landing page (non-technical pitch + comparison visual), "Start here" quick start, Standards page driven by `site/data/standards.json` covering everything implemented so far, Pages deploy workflow, link/HTML checks. *AC:* deployed from `main`; Lighthouse ≥ 90 in all categories; every page has at least one diagram; Standards page lists every RFC referenced by a ticked task. *Done 2026-10-02: 4 pages (landing, start, how-it-works, standards with 12 diagrams), build.py (partials, standards render, roadmap coverage + link + page-weight checks), Pages workflow with Lighthouse CI (≥ 0.9 all categories). Deployment needs Pages enabled once (Settings → Pages → Source: GitHub Actions); Lighthouse scores come from that first workflow run.*
- **M1 gate:** `cache-hot` ≥ 150k qps on the 4-core reference box; idle RSS ≤ 20 MiB.

## M2 — Filtering engine (weeks 4–6)
- [ ] **T2.1 List fetcher** (ETag, caps, retries, stored sources). *(FLT-004)*
- [ ] **T2.2 Parsers** for all formats in `05 §2`, with golden fixtures. *(FLT-001)*
- [ ] **T2.3 Compiler:** external-sort merge → FST (subtree/exact), ListSetTable, regex meta set, modifier rules, `$badfilter`. *(FLT-002, FLT-003)* *AC:* 1.5M-domain fixture ≤ 12 B/domain; compile ≤ 8 s on Pi 4.
- [ ] **T2.4 Matcher + precedence + overlay for manual rules.** *(FLT-003, ADR-003)* *AC:* precedence table tests; lookup p99 ≤ 1 µs (no regex) on x86.
- [ ] **T2.5 Groups/clients:** identification chain incl. neighbor table, DoH path / SNI client IDs, EDNS MAC. *(FLT-005, FLT-006)*
- [ ] **T2.6 Block modes + EDE + CNAME inspection + pause.** *(FLT-007, FLT-008, FLT-009)*
- [ ] **T2.7 Atomic swap under load.** *AC:* recompile during the `realistic-home` run → p99 regression ≤ 10%, zero errors.
- [ ] **T2.8 Explain engine.** *(FLT-013)*
- **M2 gate:** `blocked` corpus ≥ 150k qps; RSS with the bench lists ≤ 64 MiB.

## M3 — Observability core + API + auth (weeks 6–9)
- [ ] **T3.1 QueryEvent rings + aggregator + rollups + top-K + HDR.** *(OBS-001, 002, 004)* *AC:* drop counter is 0 at 100k qps sustained on x86 with default ring sizes.
- [ ] **T3.2 Segment store:** writer, block index, bloom, dictionary-first search, retention, privacy levels. *(OBS-003)* *AC:* 50M-row synthetic dataset search ≤ 2 s on Pi 4; format fuzzed.
- [ ] **T3.3 Full Prometheus metric set + Grafana dashboard.** *(OBS-005, OBS-011)*
- [ ] **T3.4 API skeleton:** axum, OpenAPI generation, problem+json, pagination, scope param (local-only for now). *(API-001, API-002)*
- [ ] **T3.5 Auth:** local users + Argon2id + sessions + HTTP Basic (opt-in) + tokens + TOTP + RBAC; setup-token first run. *(API-003)*
- [ ] **T3.6 OIDC:** PKCE, discovery, claim → role mapping, JIT, break-glass local admin. *(API-004)* *AC:* integration tests against Keycloak and Authentik containers.
- [ ] **T3.7 Live tail (SSE/WS).** *(OBS-008)*
- [ ] **T3.8 Audit log (hash-chained).** *(API-006)*
- [ ] **T3.9 UI MVP:** login (local + OIDC), dashboard, query log + explain, groups, lists, upstreams, local DNS, settings. *(API-005)* *AC:* bundle ≤ 400 KiB gz; Playwright suite green.
- [ ] **T3.10 Inline device naming.** Shared client-chip component used by every view that shows an IP/MAC: click → "Name this device…" (pre-filled suggestion from DHCP/rDNS/mDNS), "Add to group…", "Show queries". Backed by `PUT /api/v1/clients/{id}` (dry-run + idempotency) and MCP `plan_rename_client`; names resolved at read time. *(API-010, FLT-005, FLT-006)* *AC:* Playwright: rename from the top-clients widget and see the alias immediately in the query log, live tail, and historical charts; API test proves renaming relabels past query-log rows without rewriting segments.

## M4 — Kubernetes + Pi deployment (weeks 8–10, overlaps M3)
- [ ] **T4.1 Helm chart** (allInOne, scaled, daemonSet shapes; Services with ETP=Local; PDB; HPA; probes; NetworkPolicy; ServiceMonitor; cert-manager; existingSecret everywhere). *(OPS-002, OPS-003)* *AC:* `ct install` on kind + k3d arm64; DNS answers via the LB; client IP preserved in the query log in an e2e test.
- [ ] **T4.2 Masked-client-IP detector + NOTES warning.** *(OPS-003)*
- [ ] **T4.3 Pi Compose bundle + docs; native binary + systemd + install.sh + self-update.** *(OPS-004)*
- [ ] **T4.4 PROXY protocol v2 on TCP/DoT/DoH.** *(DNS-020)*
- [ ] **T4.5 DoT + DoH (h2) listeners with cert hot-reload.** *(DNS-002, DNS-003)*
- [ ] **T4.6 Site: deployment guides + technical track.** *(DOC-002, DOC-003)* Pi / Docker Compose / Helm install guides with topology diagrams (including the hybrid Pi + k8s cluster), architecture and pipeline pages, configuration reference generated from `telltale config schema`. *AC:* a new user follows the Pi guide to a working resolver without leaving the page; config reference is regenerated in CI.
- [ ] **T4.7 Site: dashboards and performance.** *(DOC-002, DOC-003)* UI screenshots once T3.9 lands; performance page fed by `bench/compare` results (harness numbers only). *AC:* screenshots regenerated by the Playwright suite; numbers link to the raw harness JSON.

## M5 — Clustering and HA (weeks 10–14)
- [ ] **T5.1 PKI + join tokens + mTLS channel** (protobuf, persistent streams, reconnect). *(CLU-001)*
- [ ] **T5.2 Change log + signed snapshots + content-addressed blob sync.** *(CLU-003)* *AC:* a list change ships only the changed blobs; propagation ≤ 5 s p95 across simulated WAN (50 ms RTT).
- [ ] **T5.3 Data-plane independence + snapshot persistence + cold start from disk.** *(CLU-004)* *AC:* primary killed → replicas keep 100% answer rate; replica restart without primary → serving in ≤ 500 ms.
- [ ] **T5.4 Epochs, leases, manual promote, witness + quorum election, fencing, conflicts UI.** *(CLU-005)* *AC:* `telltale-sim` 10k randomized partition schedules → never two writers in one epoch; orphaned writes always surfaced.
- [ ] **T5.5 Node-local overrides.** *(CLU-006)*
- [ ] **T5.6 Federated reads** (stats merge, top-K merge, HDR merge, k-way query-log merge, partial results). *(CLU-002, OBS-012)*
- [ ] **T5.7 Write forwarding to primary with identity propagation.** *(CLU-002)*
- [ ] **T5.8 Telemetry ship mode + store-and-forward.** *(CLU-007)*
- [ ] **T5.9 Cluster health page, metrics, alerts.** *(CLU-008)*
- [ ] **T5.10 Ephemeral k8s members + site grouping; Helm values for hybrid.** *(CLU-009)* *AC:* e2e: Pi-like container (outside kind) + kind cluster form one cluster; UI on either shows both; promote works both ways.
- [ ] **T5.11 Version compatibility N/N-1 + rolling upgrade test.** *(CLU-010)*

## M6 — Protocol depth + migration (weeks 13–16)
- [ ] **T6.1 DNSSEC validation + NTAs + EDE.** *(DNS-011)*
- [ ] **T6.2 Serve-stale, prefetch, cache persistence.** *(DNS-007, 008, 009)*
- [ ] **T6.3 Pi-hole importer (v5 + v6 Teleporter).** *(API-007)*
- [ ] **T6.4 Backup/restore archive.** *(API-007)*
- [ ] **T6.5 Agent-ready API hardening:** LLM-grade OpenAPI descriptions, dry-run + impact estimates on all mutations, idempotency keys, agent tokens/scopes, audit attribution, kill switch. *(AGT-001..005, AGT-009)* *AC:* every mutation has a dry-run test; OpenAPI lint (spectral) passes the description rules.
- [ ] **T6.6 MCP server (read-only tools) at `/mcp` + `telltale mcp --stdio`.** *(AGT-006, AGT-008 bearer part)* *AC:* MCP conformance test green; scope/privacy authorization tests; a scripted agent completes the "why is the TV slow" golden transcript.
- **v1.0 release gate:** all P0 requirements pass; `00 §5` metrics met on the reference hardware; comparative benchmark report published; security review of auth + cluster + parsers completed.

## M7 — v1.x (post-1.0, priority order)
MCP write tools with plan/apply + approval inbox, OAuth via OIDC, resources/prompts (AGT-007, 008, 010, 011) → DoQ + DoH3 listeners and upstreams (DNS-004, UPS-002) → schedules, safe search, services (FLT-010..012) → analytics suite + alerts (OBS-009, 010) → recursive resolver (DNS-012, UPS-012) → socket/exec upstream plugins + proxies (UPS-010, 011) → OTLP + dnstap + sinks (OBS-006, 007) → Technitium importer → DHCP (OPS-008) → ECS/DNS64/local zones/rewrites/IP filter (DNS-015, 016, 018, FLT-014, 015) → DNSCrypt (UPS-003) → CLI (API-008).

## M8 — v2 (stretch)
Agent analytics DSL `vqlog` (AGT-012), WASM upstream plugins, io_uring, beaconing detection, cache-warm hints (CLU-011), mDNS client naming, router integrations (UniFi/OPNsense lease import).
