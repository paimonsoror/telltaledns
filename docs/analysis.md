# Pi-hole vs Technitium DNS Server — Comparative Analysis

*Prepared 2026-10-02. Versions considered: Pi-hole Core v6.4.x / FTL v6.6–6.7 / Web v6.5–6.6 (2026), Technitium DNS Server v14 (Nov 2025) and v15 (Apr 2026).*

This analysis feeds the design of **TelltaleDNS**, our own filtering DNS resolver. Each finding ends in a *takeaway* that the spec in `/spec` turns into requirements.

---

## 1. Architecture at a glance

| Aspect | Pi-hole v6 | Technitium v15 |
|---|---|---|
| Language / runtime | C (FTL, an embedded dnsmasq fork) + Bash (core scripts) + JS/HTML (web) | C# on .NET 10 (managed, GC) |
| DNS engine | dnsmasq: a single-threaded `poll()` event loop, forwarder plus small cache | Purpose-built engine: multi-threaded, async, recursive and authoritative |
| Role | Filtering forwarder; DHCP; local records | Full DNS server: recursive resolver, authoritative zones, forwarder, filtering, DHCP |
| Web/API | Embedded CivetWeb in FTL (v6 removed lighttpd and PHP); REST API with session auth | Built-in Kestrel HTTP server; HTTP API with token auth; 2FA (v14), OIDC SSO (v15) |
| Config | `pihole.toml` (v6) plus SQLite `gravity.db` for lists, groups, and clients | Proprietary binary config files plus zone files; managed through UI or API |
| Blocklist storage | SQLite `gravity.db`. FTL queries it with prepared statements and caches the per-domain verdict | In-memory "Blocked zone" plus list-derived zones (object-heavy); the Advanced Blocking app adds regex and per-group lists |
| Query history | Shared memory holds about 24h; long-term data goes to SQLite `pihole-FTL.db` | Hourly and daily stat files for the dashboard; per-query logs need a logging App (SQLite/MySQL/Postgres/MSSQL) |
| Extensibility | None at runtime; shell scripts plus dnsmasq `misc.dnsmasq_lines` | **Apps** (plugin DLLs): Advanced Blocking, Split Horizon, Geo, Failover, DNS64, Log Exporter, Query Logs, … |
| Multi-node | None natively; community tools (nebula-sync, orbital-sync) sync through the API | **Clustering** (v14): syncs settings, lists, apps, and admin config; cache and logs stay per node |
| License | EUPL-1.2 | GPL-3.0 |

---

## 2. Pi-hole: deep dive

### 2.1 Design and code
- **FTL embeds dnsmasq.** Pi-hole inherits dnsmasq's maturity and tiny footprint. It also inherits dnsmasq's limits: a single-threaded event loop, a C codebase with a history of serious CVEs (e.g., DNSpooq, 2021), and a forwarding-only model. FTL hooks dnsmasq's callbacks to add filtering, statistics, and the API.
- **v6 was a big cleanup.** The PHP/lighttpd stack is gone. CivetWeb sits inside FTL, there is a proper REST API (`/api/...`) with sessions and app passwords, all config lives in one TOML file with env-var overrides (Docker-friendly), and Teleporter export/import is built in.
- **Gravity** is the list pipeline. `pihole -g` downloads every adlist, parses it, deduplicates, and rebuilds `gravity.db`, then FTL reloads. On low-end hardware with multi-million-entry lists, a rebuild takes minutes and heavy CPU and I/O. The DB grows to hundreds of MB.
- **Groups** are an elegant model and the best UX idea in the product. Clients (by IP, MAC, hostname, or interface) belong to groups, and groups pick which adlists and allow/deny entries apply.
- **Regex filtering** uses POSIX-style (TRE) regexes with Pi-hole extensions (`;querytype=`, `;invert`, `;reply=`). Every query is tested against every regex until one matches, so cost is **linear in the number of regexes**. The verdict cache softens this, but it is still the main filtering hot spot.
- **CNAME deep inspection** blocks a response if any name in the CNAME chain is blocked. This defeats CNAME cloaking.
- **Rate limiting** is per client (default 1000 queries / 60s).
- **Upstreams:** plain UDP/TCP to any IP:port, a preset list (Google, OpenDNS, Level3, Comodo, Quad9 variants, Cloudflare, …), custom servers, conditional forwarding (`rev-server`), and dnsmasq `server=/domain/ip` lines for per-domain routing. **There is no native DoH, DoT, or DoQ upstream.** Users run `cloudflared` or `dnscrypt-proxy` beside it, or `unbound` for recursion. DNSSEC validation comes from dnsmasq.
- **Serving:** plain DNS (UDP/TCP 53) only. No DoH, DoT, or DoQ for clients.

### 2.2 Observability
- **Strengths:** a good real-time dashboard (queries over time, per-client graph, top permitted/blocked domains, top clients, upstream distribution, query types). The query log can be filtered and has per-query reply time. Long-term SQLite storage is queryable with plain SQL.
- **Weaknesses:**
  - Recent data lives in shared memory and long-term data in SQLite, so long-range queries over the DB are slow on a Pi.
  - There is no native Prometheus/OpenTelemetry (community exporters scrape the API) and no dnstap.
  - Latency data is limited to reply time for forwarded queries. There is no per-stage breakdown (filter vs. cache vs. upstream) and no latency percentiles per upstream or client.
  - Client identity is IP/MAC (via the ARP table) or hostname. There is no client ID for encrypted transports, because Pi-hole has none.

### 2.3 Performance and footprint
- **Footprint is excellent.** It runs on a Pi Zero / 512 MB devices. FTL's RSS is tens of MB, scaling with list size and the in-memory query window.
- **Throughput** is bounded by dnsmasq's single thread. That is plenty for a home (homes see roughly 1–50 qps), but it cannot use multiple cores. Pi-hole's own docs and community benchmarks on low-end SoCs report hundreds to low thousands of qps once the logging/DB path is included. *(These are community numbers, not controlled benchmarks. See §5.)*
- **Big lists hurt.** Gravity builds are slow, the regex scan is linear, and SQLite I/O becomes the bottleneck on SD cards.

### 2.4 Pros / cons

**Pros**
1. Tiny footprint; runs on anything.
2. The group/client/list model is simple and powerful.
3. Excellent, approachable dashboard and query log; huge community; ecosystem of lists.
4. v6 brought a clean REST API, TOML config, env-var config, and Teleporter backup.
5. CNAME deep inspection; per-client rate limiting; regex with qtype/reply extensions.
6. dnsmasq's DHCP and local DNS are battle-tested.

**Cons**
1. No encrypted DNS in either direction (needs sidecars), and no built-in recursion (needs unbound).
2. Single-threaded DNS core; it cannot scale with cores.
3. Linear regex evaluation; slow gravity rebuilds; large on-disk DB.
4. Inherits dnsmasq's C attack surface; regular security advisories (six closed in FTL v6.7 alone, and several XSS/injection fixes in v6.6).
5. No HA or clustering; no native metrics export; limited latency analytics.
6. No plugin model. Customization means dnsmasq config lines.

---

## 3. Technitium: deep dive

### 3.1 Design and code
- **A full DNS server written from scratch in C#**: recursive resolver (with QNAME minimization, serve-stale, prefetch, and on-disk cache persistence), authoritative server (primary, secondary, stub, forwarder, and catalog zones; DNSSEC signing), DHCP, and filtering.
- **Protocols:** serves and forwards over UDP, TCP, **DoT, DoH (HTTP/1.1, 2, and 3), and DoQ**. Upstream forwarders can be reached through **SOCKS5/HTTP proxies (including Tor)**. It supports **concurrent forwarding** (query N forwarders and take the fastest), EDNS Client Subnet, DNS64, DNSSEC validation, and EDE.
- **Blocking:** a "Blocked zone" plus downloaded block lists, both held in memory. Blocking a domain implicitly blocks its subdomains. You choose the block response type (NXDOMAIN, custom IP, or "any address"). Regex filtering, ABP syntax, and per-client-group lists live in the **Advanced Blocking App**. Lists refresh on an interval.
- **Apps framework:** `IDnsApplication` plugin DLLs hook request handling, authoritative answers, blocking, and post-processing logging. It is powerful, but plugins run in-process with full trust.
- **Clustering (v14):** a single admin console for many nodes. Settings, allowed/blocked lists, apps, and admin config sync automatically, with aggregate dashboards and a Cluster Catalog zone. Cache and logs are per node.
- **Security posture:** 2FA (v14), OIDC SSO (v15), non-root service install (v15). Multiple vulnerabilities were fixed in v15 (several 2026 CVEs).
- **Config** is stored in a proprietary binary format, which makes GitOps and diffing hard. Everything goes through the UI/API.
- **Bus factor:** the project is driven predominantly by a single maintainer.

### 3.2 Observability
- **Strengths:** dashboard with total/blocked/cached/recursive/NXDOMAIN/SERVFAIL counts and top clients/domains/blocked domains over selectable windows. Query Logs apps write to real databases (SQLite/MySQL/Postgres/MSSQL). The Log Exporter app ships logs to HTTP, syslog, or file. Cluster-wide aggregate dashboards.
- **Weaknesses:**
  - Per-query logging is *opt-in via plugins*, and the core stats are coarse aggregates.
  - No native Prometheus or OpenTelemetry. No dnstap.
  - No per-stage latency breakdown and no latency percentiles per upstream or client.
  - The UI is functional but dense.

### 3.3 Performance and footprint
- **Throughput is high.** The vendor claims about 100k qps on gigabit-class hardware, and the multi-threaded async engine uses all cores.
- **Footprint is heavy for a homelab.** The .NET runtime is required (install footprint around 100 MB+). RSS is about 150 MB idle and about 200–300 MB with large blocklists (e.g., HaGeZi Pro, ~750k entries) according to community reports. GC pauses add tail latency. List entries are stored as managed objects, which costs on the order of hundreds of bytes per domain.
- **Major upgrades are heavy:** each requires a manual runtime upgrade (.NET 9 for v14, .NET 10 for v15).

### 3.4 Pros / cons

**Pros**
1. A complete DNS server: recursion, authoritative zones, DNSSEC validation and signing. It replaces Pi-hole, unbound, and BIND.
2. Every modern transport, inbound and outbound (DoT/DoH/DoH3/DoQ); proxy and Tor support; concurrent forwarding.
3. Serve-stale, prefetch, persistent cache, QNAME minimization, ECS, DNS64, EDE.
4. Plugin framework (Apps) and clustering.
5. Strong auth: 2FA and OIDC; non-root by default (v15).
6. Multi-core throughput.

**Cons**
1. Memory and disk footprint 5–10× Pi-hole's; runtime dependency; GC tail latency.
2. Per-query logging and advanced blocking are add-ons, not core.
3. Binary config, so it is not GitOps-friendly.
4. Plugins are in-process with full trust (a stability and security risk).
5. Coarse analytics: no percentiles, no stage timing, no standard telemetry export.
6. Concentrated maintainership; a complex UI for the casual user.

---

## 4. Prior art worth borrowing from (briefly)
- **AdGuard Home (Go):** client IDs carried in DoH paths and DoT/DoQ SNI. This lets you identify phones on encrypted DNS. It also has scheduled blocking per client, safe-search enforcement, blocked-services presets, and the AdGuard filter syntax (`$client`, `$dnstype`, `$dnsrewrite`, `$important`, `$badfilter`).
- **Blocky (Go):** stateless and config-file-driven; native Prometheus; per-group upstreams; a good model for GitOps.
- **dnsdist / Unbound:** SO_REUSEPORT multi-socket listeners, `recvmmsg`, packet caches that store wire format and patch IDs and TTLs in place, and dnstap.

---

## 5. A note on performance numbers
Published numbers are not comparable:
- Technitium's ~100k qps is a vendor claim for cache-hit traffic on capable hardware.
- Pi-hole's numbers come from community tests on low-end SoCs with logging enabled.
- Memory figures come from community reports with varying list sizes.

**Takeaway:** the spec requires a reproducible benchmark harness (`dnsperf`/`resperf` plus fixed query corpora) that runs TelltaleDNS, Pi-hole, and Technitium side by side on the same hardware and list set (see `spec/09-testing-and-benchmarks.md`). Performance claims in our README must come from that harness.

---

## 6. Synthesis: what TelltaleDNS keeps, fixes, and adds

| Keep from Pi-hole | Keep from Technitium | Fix (weak in both) | Add (new) |
|---|---|---|---|
| Group ↔ client ↔ list model | DoT/DoH/DoH3/DoQ, inbound and outbound | Linear regex scan → compiled multi-regex DFA | Per-stage latency tracing for every query |
| Tiny footprint, single binary | Recursive resolver + DNSSEC validation | Slow list rebuild → background compile + atomic swap, zero query impact | Native Prometheus, OpenTelemetry, dnstap |
| TOML config + env overrides | Serve-stale, prefetch, persistent cache | Heavy per-domain memory → FST-compressed (~5–10 B/domain) | Latency histograms (p50/p95/p99) per upstream, client, and qtype |
| CNAME deep inspection | Concurrent/fastest upstream strategies | Plugin trust → out-of-process / WASM sandboxed extensions | Client ID via DoH path / DoT SNI / EDNS MAC |
| Rate limiting, Teleporter-style backup | Clustering / config sync | Binary or ad-hoc config → declarative config with API parity | Anomaly detection (DGA, NXDOMAIN storms, new-domain alerts) |
| Approachable dashboard | 2FA / OIDC, non-root by default | No native metrics → first-class metrics | Scheduled per-group blocking, safe-search enforcement |
| Local DNS / CNAME records, DHCP (optional) | Split horizon, conditional forwarders, proxy/Tor upstream | Single-thread (Pi-hole) / GC (Technitium) → Rust, multi-core, no GC | Custom upstream plugins; per-domain + per-group routing |

### Sources
- Technitium v15 release notes: https://blog.technitium.com/2026/04/technitium-dns-server-v15-released.html
- Technitium v14 release notes: https://blog.technitium.com/2025/11/technitium-dns-server-v14-released.html
- Pi-hole FTL v6.6 / v6.6.1 / v6.7 announcements: https://discourse.pi-hole.net/t/pi-hole-ftl-v6-6-web-v6-5-and-core-v6-4-1-released/85626 , https://discourse.pi-hole.net/t/pi-hole-ftl-v6-6-1-and-core-v6-4-2-released/85843 , https://pi-hole.net/blog/2026/04/
- Pi-hole benchmark guide / community thread: https://docs.pi-hole.net/guides/misc/benchmark/ , https://discourse.pi-hole.net/t/benchmark-for-pihole-that-is-meaningful-on-pogoplugs-low-ram-rpis-lightweight-headless-servers/74554
- Community comparisons (memory / throughput reports): https://selfhosting.sh/compare/pi-hole-vs-technitium/ , https://korben.info/en/technitium-dns-server-replaces-pihole-unbound-bind.html
- Source repos: https://github.com/pi-hole/pi-hole , https://github.com/pi-hole/FTL , https://github.com/TechnitiumSoftware/DnsServer
