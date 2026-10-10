# Learning from Pi-hole and Technitium DNS Server — design notes

*Prepared 2026-10-02, revised 2026-10-05. Versions considered: Pi-hole Core v6.4.x / FTL v6.6–6.7 / Web v6.5–6.6 (2026), Technitium DNS Server v14 (Nov 2025) and v15 (Apr 2026).*

TelltaleDNS stands on the shoulders of these two projects. Both did the hard work of making self-hosted DNS something people actually run at home, and each made design choices that fit its goals well. These notes record what we learned from them while designing TelltaleDNS. Each section ends in what we took away; the spec in `/spec` turns those into requirements. We studied their public documentation and data formats, never their code (TelltaleDNS is a clean-room project under Apache-2.0 OR MIT). The MAC vendor table that ships with TelltaleDNS (`presets/oui.bin`, for device identification) is built by `presets/build-oui.py` from the IEEE Registration Authority's public MA-L and MA-M registry exports; no other project's vendor file is used.

---

## 1. Architecture at a glance

| Aspect | Pi-hole v6 | Technitium v15 |
|---|---|---|
| Language / runtime | C (FTL, built on dnsmasq) + Bash (core scripts) + JS/HTML (web) | C# on .NET 10 |
| DNS engine | dnsmasq's proven event loop: a forwarder with a small cache | A purpose-built multi-threaded async engine: recursive and authoritative |
| Role | Filtering forwarder; DHCP; local records | Full DNS server: recursive resolver, authoritative zones, forwarder, filtering, DHCP |
| Web/API | Embedded CivetWeb in FTL; REST API with sessions and app passwords | Built-in Kestrel HTTP server; HTTP API with token auth; 2FA (v14), OIDC SSO (v15) |
| Config | `pihole.toml` (v6) plus SQLite `gravity.db` for lists, groups, and clients | Config files plus zone files, managed through the UI or API |
| Blocklist storage | SQLite `gravity.db`, queried by FTL with a per-domain verdict cache | In-memory blocked zones; the Advanced Blocking app adds regex and per-group lists |
| Query history | Shared memory for recent data; long-term data in SQLite `pihole-FTL.db` | Hourly and daily stats for the dashboard; per-query logs through Query Logs apps (SQLite/MySQL/Postgres/MSSQL) |
| Extensibility | dnsmasq configuration lines | **Apps** (plugin DLLs): Advanced Blocking, Split Horizon, Geo, Failover, DNS64, Log Exporter, Query Logs, … |
| Multi-node | Community tools (nebula-sync, orbital-sync) sync through the API | **Clustering** (v14): settings, lists, apps, and admin config sync; cache and logs stay per node |
| License | EUPL-1.2 | GPL-3.0 |

---

## 2. Pi-hole

### 2.1 Design
- **FTL builds on dnsmasq**, inheriting its maturity, tiny footprint, and battle-tested DHCP and local DNS. FTL hooks dnsmasq's callbacks to add filtering, statistics, and the API.
- **v6 was a big modernization:** CivetWeb inside FTL replaced PHP and lighttpd, a REST API (`/api/...`) with sessions and app passwords arrived, all configuration moved into one TOML file with environment-variable overrides (Docker-friendly), and Teleporter export/import became built in.
- **Gravity** is the list pipeline: `pihole -g` downloads every adlist, parses and deduplicates it, and rebuilds `gravity.db`, then FTL reloads.
- **Groups** are the best UX idea in home DNS filtering. Clients (by IP, MAC, hostname, or interface) belong to groups, and groups pick which adlists and allow/deny entries apply.
- **Regex filtering** with Pi-hole extensions (`;querytype=`, `;invert`, `;reply=`), backed by a verdict cache.
- **CNAME deep inspection** blocks a response if any name in the CNAME chain is blocked, which defeats CNAME cloaking.
- **Per-client rate limiting** (default 1000 queries / 60 s).
- **Upstreams:** plain DNS to any server, a preset list, conditional forwarding, and per-domain routing. Encrypted upstreams and recursion are added with companion tools such as `cloudflared` or `unbound`, a composable approach the community documents well.

### 2.2 Observability
A clear real-time dashboard (queries over time, per-client graph, top permitted and blocked domains, top clients, upstream distribution, query types), a filterable query log with per-query reply time, and long-term SQLite storage anyone can query with plain SQL. Community exporters bring the data into Prometheus.

### 2.3 Footprint
Runs on a Pi Zero and other 512 MB devices; FTL's memory scales with list size and the in-memory query window. dnsmasq's single event loop is ample for a home, where traffic is typically 1–50 queries per second.

### 2.4 What we took away
1. A tiny footprint is a feature people love: TelltaleDNS gates on it (`spec/00 §5`).
2. The group ↔ client ↔ list model, nearly as is (FLT-005).
3. An approachable dashboard and query log come first; depth goes behind "Advanced".
4. TOML configuration with environment overrides, and a one-file backup.
5. CNAME deep inspection, per-client rate limiting, regex with query-type and reply extensions.
6. Its list formats and Teleporter export are a shared language: TelltaleDNS reads them as they are and imports a Teleporter file (ADR-061).

---

## 3. Technitium DNS Server

### 3.1 Design
- **A complete DNS server** written from scratch: a recursive resolver (with QNAME minimization, serve-stale, prefetch, and on-disk cache persistence), an authoritative server (primary, secondary, stub, forwarder, and catalog zones; DNSSEC signing), DHCP, and filtering.
- **Protocols:** serves and forwards over UDP, TCP, **DoT, DoH (HTTP/1.1, 2, and 3), and DoQ**. Forwarders can be reached through **SOCKS5/HTTP proxies, including Tor**. It supports **concurrent forwarding** (ask several forwarders and take the fastest), EDNS Client Subnet, DNS64, DNSSEC validation, and EDE.
- **Blocking:** a blocked zone plus downloaded block lists; blocking a domain blocks its subdomains; a choice of block responses. The **Advanced Blocking app** adds regex, ABP syntax, and per-group lists.
- **Apps framework:** `IDnsApplication` plugins hook request handling, authoritative answers, blocking, and logging, which makes the server very extensible.
- **Clustering (v14):** one admin console for many nodes, with settings, lists, apps, and admin config synced automatically, aggregate dashboards, and a Cluster Catalog zone.
- **Security:** 2FA (v14), OIDC SSO (v15), and a non-root service install (v15).

### 3.2 Observability
A dashboard with total, blocked, cached, recursive, NXDOMAIN, and SERVFAIL counts and top clients and domains over selectable windows; Query Logs apps that write to real databases; a Log Exporter app for HTTP, syslog, or files; and cluster-wide aggregate dashboards.

### 3.3 Performance
A multi-threaded async engine that uses every core; the project cites about 100k queries per second on capable hardware.

### 3.4 What we took away
1. The full transport set, inbound and outbound (DoT, DoH, and later DoQ and DoH3).
2. Serve-stale, prefetch, a persistent cache, EDE, and DNSSEC validation.
3. Fastest and parallel upstream strategies; proxy upstreams (planned).
4. Clustering with one management console, which TelltaleDNS extends across a Pi and Kubernetes.
5. Strong sign-in: 2FA, OIDC, non-root by default.
6. Its HTTP API made a faithful importer possible (ADR-062).

---

## 4. Other prior art
- **AdGuard Home (Go):** client IDs carried in DoH paths and DoT/DoQ SNI, so phones on encrypted DNS can be told apart; scheduled blocking per client; safe-search enforcement; blocked-services presets; and the AdGuard filter syntax (`$client`, `$dnstype`, `$dnsrewrite`, `$important`, `$badfilter`).
- **Blocky (Go):** stateless and config-file-driven; native Prometheus; per-group upstreams; a good model for GitOps.
- **dnsdist / Unbound:** SO_REUSEPORT multi-socket listeners, `recvmmsg`, packet caches that store wire format and patch IDs and TTLs in place, and dnstap.

---

## 5. A note on performance numbers
Published numbers from different projects are measured on different hardware, traffic, and list sets, so they aren't comparable. **Takeaway:** the spec requires a reproducible benchmark harness (`dnsperf`/`resperf` plus fixed query corpora, `spec/09-testing-and-benchmarks.md`), and TelltaleDNS publishes only numbers it measured itself, with the hardware and versions.

---

## 6. Where TelltaleDNS goes its own way
TelltaleDNS's goals (one cluster across a Pi and Kubernetes, per-query observability, and agent automation) led to its own design choices:

| Learned and kept | Our own choices for our goals |
|---|---|
| Groups ↔ clients ↔ lists; CNAME inspection; rate limiting (Pi-hole) | Rust with a per-core fast path and no garbage collector |
| Encrypted transports, serve-stale, prefetch, persistent cache (Technitium) | Blocklists compiled into FSTs plus one regex DFA, swapped atomically in the background |
| Fastest and parallel upstream strategies (Technitium) | Per-stage timing for every query; latency percentiles per upstream, device, and query type |
| A tiny footprint and a single binary (Pi-hole) | Prometheus built in (OpenTelemetry and dnstap planned) |
| TOML config with env overrides; one-file backup (Pi-hole) | Declarative config with API parity and a GitOps mode |
| Clustering with one console; 2FA and OIDC (Technitium) | A fenced primary/replica cluster spanning a Pi and Kubernetes |
| Client IDs from DoH paths and DoT SNI (AdGuard Home) | Device anomaly detection; scoped agent tokens and an MCP server |

### Sources
- Technitium v15 release notes: https://blog.technitium.com/2026/04/technitium-dns-server-v15-released.html
- Technitium v14 release notes: https://blog.technitium.com/2025/11/technitium-dns-server-v14-released.html
- Pi-hole FTL v6.6 / v6.6.1 / v6.7 announcements: https://discourse.pi-hole.net/t/pi-hole-ftl-v6-6-web-v6-5-and-core-v6-4-1-released/85626 , https://discourse.pi-hole.net/t/pi-hole-ftl-v6-6-1-and-core-v6-4-2-released/85843 , https://pi-hole.net/blog/2026/04/
- Pi-hole benchmark guide: https://docs.pi-hole.net/guides/misc/benchmark/
- Source repos: https://github.com/pi-hole/pi-hole , https://github.com/pi-hole/FTL , https://github.com/TechnitiumSoftware/DnsServer
