# 11 — Architecture Decision Records

Format: Context → Decision → Consequences. New ADRs append here (`ADR-0NN`). An agent must not contradict an accepted ADR without adding a superseding ADR and flagging it to the owner.

## ADR-001 — Language: Rust (Accepted)
**Context:** Performance and footprint are paramount. Technitium pays for the .NET runtime and GC (150–300 MB RSS, GC tail latency). Pi-hole inherits C memory-safety issues from dnsmasq. Go (AdGuard Home, Blocky, CoreDNS) is productive, but its GC and ~2× memory overhead fight our RSS targets.
**Decision:** Rust (stable, 2024 edition), tokio, rustls (ring or aws-lc-rs backend), quinn.
**Consequences:** No GC, static musl binaries, memory safety, and a mature DNS crate ecosystem (hickory). Compile times are slower and the contributor pool is smaller. `unsafe` is confined to `telltale-net`.

## ADR-002 — Custom hot-path wire handling; hickory for the long tail (Accepted)
**Context:** Full decode/encode per query costs allocations and µs. Cache hits only need the header, question, and TTL offsets.
**Decision:** `telltale-proto` handles the hot path zero-copy. `hickory-proto` is used for DNSSEC, zone files, and complex record handling.
**Consequences:** Two code paths, so cross-checking them against each other is part of fuzzing (differential fuzz: both parsers must agree on header, question, and EDNS).

## ADR-003 — FST + regex DFA snapshots, compiled off-path (Accepted)
**Context:** Pi-hole's SQLite lookups + linear regex scan, and Technitium's object-heavy in-memory zones, both scale poorly with list size.
**Decision:** Immutable, mmappable FST snapshots (reversed-label keys) + a multi-pattern lazy DFA, built in the background and swapped atomically.
**Consequences:** ~10× less memory per domain, O(|qname|) lookups, and instant reloads. Snapshots are immutable, so every edit triggers a recompile. To keep manual rule edits instant, a small **overlay** (a HashMap of manual rules) is consulted before the FST and folded into the next compile.

## ADR-004 — Container-first distribution, Kubernetes-first operations (Accepted)
**Context:** The owner prioritizes Kubernetes and also runs a Raspberry Pi. Native packaging per distro is costly (Pi-hole's installer complexity; Technitium's runtime upgrades).
**Decision:** Tier-1 artifacts are the multi-arch OCI image + Helm chart, and the same image runs on the Pi with host networking. The static binary + systemd unit is Tier 2.
**Consequences:** One artifact to test. The Pi needs Docker/Podman (~50 MB extra), which is acceptable on Pi 3+. A Pi Zero can use the native binary.

## ADR-005 — Clustering: fenced primary/replica with optional witness, not Raft-by-default (Accepted)
**Context:** The reference topology has exactly two nodes (Pi + k8s). Raft needs 3 voters to tolerate one failure. DNS must never depend on consensus.
**Decision:** A replicated, signed change log from a single primary. Epoch-based fencing. Promotion is manual (2 nodes), witness-assisted, or quorum (≥ 3). Data-plane independence (CLU-004).
**Consequences:**
- Config writes pause during a primary outage in manual mode (DNS is unaffected).
- Orphaned writes are possible and surfaced, never silently merged.
- Much simpler than embedding openraft, and correct for 2 nodes.
- Revisit (ADR-0NN) if multi-writer is ever needed.

## ADR-006 — Telemetry: custom columnar segments + SQLite rollups (Accepted)
**Context:** Pi-hole's SQLite query DB gets slow and large. Technitium depends on external DB apps. DuckDB/ClickHouse are too heavy for a Pi.
**Decision:** Hourly columnar segments with dictionary encoding, a block index + bloom filters, and zstd, plus SQLite rollups. Parquet export for external analysis.
**Consequences:** We own a storage format (versioned, fuzzed, with a migration tool). Search is fast via dictionary-first predicate evaluation. External SQL access goes through export or the API, not live SQL.

## ADR-007 — Plugins out-of-process (socket/exec) first, WASM later (Accepted)
**Context:** Technitium's in-process DLL apps have full trust. The owner needs custom upstreams.
**Decision:** DNS-wire-over-socket plugins for upstreams in v1, with WASM (wasmtime, feature-gated) in v2.
**Consequences:** Plugin crashes can't take down DNS, there is a small IPC latency cost (~20–50 µs), and plugins can be written in any language.

## ADR-008 — Auth: local users + OIDC; no LDAP (Accepted)
**Context:** The owner requires basic auth and OIDC, and explicitly skips LDAP.
**Decision:** Local Argon2id users (session login + opt-in HTTP Basic for API/scrapers + tokens + TOTP) and OIDC (PKCE) with claim → role mapping, both P0.
**Consequences:** Smaller attack surface. LDAP users bridge through an OIDC IdP.

## ADR-010 — Agents as first-class clients via built-in MCP (Accepted)
**Context:** The owner expects agents to manage the platform and run analytics.
**Decision:**
- MCP tools are thin wrappers over the REST service layer, so the tool and API schemas come from one source.
- Agents get dedicated, scoped, read-only-by-default tokens.
- Writes use plan/apply with optional human approval.
- Every node exposes `/mcp`, so agents get the single management plane too.

**Consequences:** No separate logic to keep in sync. Agent writes are always previewable and attributable. The plan store adds a small table replicated with config.

## ADR-009 — UI: Svelte + uPlot embedded (Accepted)
**Decision:** A small SPA compiled to static assets and embedded via `rust-embed`. No Node runtime in the product.
**Consequences:** One binary. The UI build is part of CI (Node only at build time).

## ADR-011 — Project name and identifiers: TelltaleDNS (Proposed)
**Context:** "Vigil" was a working name and collides with an existing Rust project (a status-page monitor). The owner chose **TelltaleDNS** on 2026-10-02. A telltale shows what the wind is doing; DNS shows what the network is doing, which matches the observability-first mission.
**Decision:** The brand is `TelltaleDNS`. Machine identifiers use the short form `telltale`:
- binary/CLI `telltale`, crate prefix `telltale-*`, env vars `TELLTALE_*`
- paths `/var/lib/telltale` and `/etc/telltale`, config file `telltale.toml`
- Helm chart and image `telltale`, metrics prefix `telltale_`, backup archives `.ttbk`

Workspace crates set `publish = false`, so the short prefix can't collide on crates.io.
**Consequences:** Short, typeable identifiers. If crates are ever published or the registry name is taken, switch the published names to `telltaledns-*` without renaming internal crates. *Owner to confirm:* short `telltale` form vs. `telltaledns` everywhere.

## ADR-012 — Project site: hand-written static HTML + inline SVG on GitHub Pages (Proposed)
**Context:** The owner wants a GitHub Pages site for two audiences (non-technical and deeply technical), visual-first, including a standards page with diagrams per RFC (DOC-001..006). The project values a lightweight footprint and minimal tooling.
**Decision:**
- A `site/` directory of plain HTML pages, one shared CSS file, and inline SVG diagrams (hand-authored, or exported from Mermaid/Excalidraw sources committed beside them). No site generator and no Node build.
- A tiny optional JS file only for the theme toggle and tabs; every page works without it.
- The Standards page table is generated from `site/data/standards.json` at deploy time by a small script in the Pages workflow, which also fails if a ticked roadmap task cites an RFC missing from the file.
- Deployed by a GitHub Actions Pages workflow on push to `main`.

**Consequences:** Zero build dependencies and fast pages. The shared header/footer is duplicated across pages (acceptable at ~10 pages; revisit with a minimal generator past ~20). Pages must be enabled once in the repo settings (source: GitHub Actions).

## ADR-013 — Hedged upstream attempts and a faster breaker trip (Proposed)
**Context:** `spec/04` §4–5 retries the next upstream only after an attempt fails or times out (up to 400 ms), and opens a breaker only after ≥ 10 samples with > 50% errors. With one dead upstream that makes the first ~10 queries, and every exploration or half-open probe, wait a full timeout. That breaks T1.5's chaos criterion (p99 within 1.5× of healthy).
**Decision:**
- **Hedging:** if an attempt hasn't answered within its upstream's hedge delay (≈ 3 × EWMA + 10 ms, bounded to [20 ms, attempt timeout]; 100 ms before there is data), the next member starts in parallel. The first good answer wins.
- **Must-hedge cases:** exploration picks (`fastest` ε), half-open probes, members whose last attempt failed, and last-resort unhealthy members all start immediately alongside the next member, so they never add client latency.
- **Losers finish in the background** (detached, not aborted), so their real outcome (often a timeout) reaches the health tracker.
- **Breaker:** 3 consecutive failures also open it (in addition to the window rule).

**Consequences:** Measured in-process (debug build), one blackholed upstream out of two: 0 failures and p99 1.04–1.15× of baseline for failover, round_robin, fastest, and parallel. The cost is a few extra upstream queries while a member is degraded, and detached attempts holding a socket for up to one attempt timeout.

## ADR-014 — Access, rate-limit, and special-name defaults (Proposed)
**Context:** DNS-014, DNS-019, `spec/03` §3 step 4, and `spec/08` §6 name these behaviors but leave several defaults open.
**Decision:**
- **Access:** queries from outside `[access] allowed_networks` get REFUSED + EDE 18. The default list is RFC 1918, 100.64/10 (CGNAT, Tailscale), 169.254/16, 127/8, fc00::/7, fe80::/10, and ::1. Pod/service CIDR auto-detection waits for the Helm work (T4.1). Allowing `0.0.0.0/0` triggers a startup warning.
- **Rate limit:** token bucket of 1000 queries per 60 s per client (Pi-hole parity), with REFUSED + EDE 18 by default (or drop). IPv4 clients are counted per /32, IPv6 per /64 (a device's rotating privacy addresses share a bucket). Loopback is exempt.
- **Special names:**
  - `localhost`/`*.localhost` → 127.0.0.1 / ::1, authoritative (RFC 6761 §6.3).
  - `*.invalid` → NXDOMAIN (RFC 6761 §6.4).
  - `use-application-dns.net` → NXDOMAIN (Firefox DoH canary).
  - All CHAOS-class queries → REFUSED.
  - Reverse lookups for private ranges → NXDOMAIN unless a local record or an explicit `[[route]]` covers them (RFC 6303; Pi-hole `bogus-priv`).
  - `.local` is **not** intercepted, because many AD domains use it; mDNS names never reach unicast DNS anyway.

**Consequences:** Safe by default on a home network. Users exposing TelltaleDNS beyond RFC 1918 must widen `allowed_networks` deliberately. Each special-name rule can be turned off under `[special]`.

## ADR-015 — Image build, allocator tuning, and port 53 for non-root host networking (Proposed)
**Context:** OPS-001 and `spec/08` §2 require a static musl image that runs as 65532. T0.4 turned up three things the spec leaves open:
1. Compiling arm64/armv7 under QEMU with fat LTO takes hours on CI runners.
2. musl's allocator roughly halved cache-hit throughput in the bench harness (≈100–125k vs ≈190–210k qps for glibc). With mimalloc, transparent huge pages (THP; `madvise` mode on WSL and many distros) raised idle RSS from ≈6 MiB to ≈22 MiB, over the 20 MiB gate.
3. Docker doesn't give added capabilities to a non-root user (no ambient capabilities). The `spec/08` §3 Pi compose example (`network_mode: host` + `user: 65532` + `cap_add: [NET_BIND_SERVICE]`) therefore gets `EACCES` binding :53. With bridge networking, Docker sets `net.ipv4.ip_unprivileged_port_start=0` inside the container, so :53 works there with every capability dropped. Kubernetes pods get the same with containerd ≥ 2.0, or with the safe sysctl `net.ipv4.ip_unprivileged_port_start` in the pod securityContext.

**Decision:**
- The build stage runs on `$BUILDPLATFORM` and cross-compiles with `cargo zigbuild` (pinned zig 0.15.2 and cargo-zigbuild 0.23.4, checksums verified). Only the smoke test runs under QEMU.
- `mimalloc` is the global allocator (as `02` §3 already says), built with `no_thp`.
- The image keeps `USER 65532:65532`, with no file capabilities: file caps break exec when the capability is dropped and are ignored under `no_new_privs` (`allowPrivilegeEscalation: false`). For host networking on a Pi, the docs recommend the host sysctl `net.ipv4.ip_unprivileged_port_start=53` (one line in `/etc/sysctl.d/`), which keeps the container non-root. The fallback is `user: "0:0"` with `cap_drop: [ALL]` + `cap_add: [NET_BIND_SERVICE]`. The Helm chart (T4.1) sets the pod sysctl.

**Consequences:** CI image builds take minutes, not hours. musl matches glibc throughput, and idle RSS stays ≈6 MiB. The `spec/08` §3 compose example must change before the compose bundle ships (T4.3); the owner chooses between the sysctl and the root-with-one-capability fallback as the documented default.

## ADR-016 — List fetcher behavior and configuration (Proposed)
**Context:** FLT-004 and `spec/05` §3.4 step 1 define the fetcher's duties (conditional GETs, size caps, retries, stored sources) but not its configuration, scheduling, name resolution, or edge cases. T2.1 needed answers.

**Decision:**
- **Config:** `[[list]]` entries with a stable `name` (`[a-z0-9_-]{1,64}`, used in file names, metrics, and the API) and exactly one source: `url` (https; http allowed with a warning), `path`, or inline `rules`. Plus `kind` (`block`/`allow`), `match` (`subtree`/`exact`, FLT-002), `enabled`, and per-list `refresh_secs`/`max_bytes`. `[filter]` holds the defaults: refresh 24 h (minimum 15 min), concurrency 4, 120 s per attempt, 3 retries, 64 MiB. At most 1024 lists (the `05` §3.1 bitset width).
- **Location:** the fetcher lives in `telltale-filter::fetch` and runs only on `all`/`controller` nodes, starting after the DNS listeners are bound. HTTP/1.1 over rustls with the built-in Mozilla roots, one connection per download, `Accept-Encoding: identity` so the size cap is exact.
- **Retries:** network errors, timeouts, 5xx, 408, and 429 are retried with 2 s × 4ⁿ backoff (±25% jitter, capped at 60 s); other 4xx, oversize bodies, and bad redirects are not. Between refreshes, a failing list is retried after 5 min, doubling to 1 h (never later than its normal refresh).
- **Sanity:** an empty body or an HTML page (`<!doctype html`/`<html` at the start) counts as a failure, so captive portals and error pages served with 200 never replace a good list. Identical content (same BLAKE3) is "unchanged" even without validators.
- **Storage:** `lists/<name>.src.zst` (zstd level 3) plus `<name>.meta.json`, each written to a temp file and renamed into place. Inline rules are stored too, so the compiler and explain treat every source the same. Lists removed from the config are deleted; disabled lists keep their files.
- **Name resolution:** the system resolvers minus our own listeners (as UPS-009), falling back to the OS resolver, which may be TelltaleDNS itself. A download is an HTTP client, not a forwarder, so this can't loop.
- **Change signal:** a `watch` counter bumps only when stored content changes or a list is removed. The compiler (T2.3) subscribes to it.

**Consequences:** One small request per list per day once lists are cached. A broken upstream list or a captive portal never empties a blocklist. Gzip transfer and per-list custom headers/auth are left for later (P1) if users need them.

## ADR-017 — List parsing rules and synthetic golden fixtures (Proposed)
**Context:** FLT-001 and `spec/05` §2 list the syntaxes, but not how to tell them apart line by line or what to do with near-misses. `spec/09` §1 asks for golden tests on vendored copies of StevenBlack, HaGeZi Pro, OISD small, an AdGuard DNS filter, and Pi-hole regex samples. Several of those are GPL-licensed data (HaGeZi, AdGuard), which shouldn't be committed into an Apache-2.0/MIT repository.

**Decision:**
- **Per-line detection,** in order: blank/comment → cosmetic/HTML (`##`, `#@#`, `#?#`, `#$#`, `#%#`, `$$`, unsupported) → hosts (first token is an IP, zone IDs allowed) → AdBlock (`@@`, `|`, `||`, `/regex/`, or `name^[$mods]`) → Pi-hole regex (any regex metacharacter, `;querytype=`, `;invert`) → `*.name`/`.name` → plain name. Inline ` # comments` are stripped outside AdBlock lines.
- **Semantics for open cases:** `name^` without `||` = `||name^` (subtree). Leading `.name` = subdomains only, like `*.name` (the narrower reading of AdBlock's suffix match). In an allow-kind list, every non-exception rule allows. Explicit AdBlock anchors (`||`, `|`) beat the list's `match` mode.
- **Unsupported, not invalid** (counted, skipped): cosmetic rules, URL paths and `/regex/` containing `/`, wildcards inside names, IP rules (`||192.0.2.1^`, which belong to the response IP filter, FLT-015), unknown modifiers, and Pi-hole `;reply=`. A rule with any unsupported modifier is skipped entirely, never applied without it.
- **Invalid:** malformed names (empty or long labels, characters outside `[a-z0-9_-]` after IDNA), unknown query types, empty `$client`, negated `$denyallow`, `$denyallow` on allow rules, regexes that `regex-syntax` rejects (including backreferences and lookaround), and regexes over 1024 characters. Hyphens at label edges are accepted (DNS allows them).
- **Fixtures:** the committed golden fixtures are synthetic files that reproduce each format's real shape (headers, boilerplate, modifiers, malformed lines). The real lists are exercised by an ignored, network-dependent test (`tests/lists_online.rs`) that requires < 0.1% invalid lines; it currently reports 0 invalid lines on StevenBlack, HaGeZi Pro (adblock, wildcard, domains), OISD (small, big) and the AdGuard DNS filter.

**Consequences:** Real lists parse without spurious errors, and browser-only rules never widen DNS blocking. The golden tests stay license-clean. Real-list drift is caught by the online test rather than by snapshot diffs.

## ADR-018 — Filter snapshot layout and compile scheduling (Proposed)
**Context:** `spec/05` §3 describes FSTs with list bitsets, and `spec/02` §5 names per-group blobs (`filter-<group>.fst`, `regex-<set>.dfa`, `rules.idx`). T2.3 needed a concrete on-disk layout, a way to handle `*.name` scope and the four precedence tiers, a rule for when to compile, and an answer for mmap, which needs `unsafe` that only `telltale-net` may contain.

**Decision:**
- **Layout** (`snapshots/<version>/`): `subtree-<n>.fst`, `exact-<n>.fst`, `subdomains-<n>.fst` (reversed-label keys → list-set index), with one shard per compile thread recorded as `fst_shards` in the manifest. A key's shard is FNV-1a of its first two reversed labels (`com.example.`), so every suffix of a query name with two or more labels is in one shard, and a lookup reads at most two shards per scope; `listsets.bin`, interned entries of four list bitsets each (important-allow, important-block, allow, block), so one lookup yields every tier's lists and a group check is a bitset AND (§3.1); `modrules.fst` + `modrules.json` (§3.3); `regex.json` (patterns + metadata); `manifest.json` with list IDs, list options, source hashes, and the BLAKE3 + size of every blob. Group selection happens at query time through the bitsets, so there are no per-group blobs: one snapshot serves every group.
- **Regex:** patterns are stored, not serialized DFAs, and compile-checked at compile time with the same engine settings the matcher uses (case-insensitive, linear time). Resolvers build the regex set when loading; whether that fits the 500 ms cold-start budget gets measured in T2.4/T5.3.
- **Loading:** `Snapshot::open` reads blobs into memory and verifies each against the manifest. An mmap loader (a small safe wrapper in `telltale-net`) can replace it in T2.4 if RSS with large lists needs it.
- **When to compile:** at startup, when stored list content changes, and on reload when the enabled lists or their `kind`/`match` change, debounced by 2 s. It's skipped when the newest manifest already matches the inputs, and when no list has been downloaded yet. A failed compile keeps the previous snapshot. The 3 newest snapshots are kept.
- **CPU and memory:** compile threads run at nice 10 (set through `telltale_net::lower_thread_priority`), on a dedicated thread rather than tokio's blocking pool. With more than one thread, large lists are cut into line-aligned chunks for parallel parsing, and each worker builds one FST shard. `[filter] compile_threads` defaults to `0` = half the cores, between 1 and 4 (2 on a Pi 4). **This changes `spec/05` §3.4's "default 1 on Pi"**, because one Pi core can't meet the `00` §5 gate. `compile_memory` (128 MiB) bounds the sort before spilling.

**Consequences:** One snapshot format for every group and node, and only content-changed blobs ship in cluster sync. Measured on the owner's **Raspberry Pi 4** (4 GB, Cortex-A72 1.5 GHz; production Technitium running alongside, compile at nice 10), names from HaGeZi TIF: 2M names in 11.6 s on 1 thread, **6.4 s on 2** (gate ≤ 8 s met), and 4.7 s on 3, at 8.2–9.1 B/name; 1.5M names in 8.6 / 6.2 / 3.7 s. Peak RSS while compiling was 136–204 MiB. Sharding costs about 0.5 B/name per extra thread (still ≤ 10 B/name at 4 threads), and one thread writes one FST per scope, so it loses nothing. Whether compiling on 2 threads at nice 10 disturbs query latency on a Pi is T2.7's acceptance test.

## ADR-019 — Deterministic device anomaly detection (Proposed)
**Context:** The owner wants TelltaleDNS to notice when a device behaves differently: abnormal traffic, many queries to one domain, or IoT/appliance phone-homes, in a safe and deterministic way. OBS-009 already lists per-client rate anomalies, first-seen domains, NXDOMAIN storms, DGA scoring, and beaconing (P2), but has no per-domain volume, no drift baseline, and no rules on determinism, explainability, or acting on findings.

**Decision:** Add OBS-013 (P1) and `06` §7.1. Detection uses fixed-math streaming statistics (EWMA, MAD, Space-Saving top-K, cuckoo filters, inter-arrival histograms), timed by event timestamps so replays are reproducible. Every finding carries its evidence. A device must pass a learning period before it can alert. State is bounded and lives in the aggregator, off the query path. Findings only inform: alerts, UI, and MCP. Any response, such as quarantining a device, is a separate explicit, audited action. Beaconing moves from P2 to P1, because periodic phone-home is the motivating IoT case. Scheduled as T3.11, after the aggregator (T3.1).

**Alternatives considered:** ML models (isolation forests, autoencoders) can catch subtler patterns but aren't deterministic across versions, are hard to explain, and need training data a home network doesn't have. Rejected for v1; the evidence-carrying finding format leaves room for an optional, clearly labeled model-based detector later. Automatic blocking on anomalies was rejected: false positives would break devices silently, against the "DNS never surprises you" principle.

**Consequences:** Owners get actionable, explainable alerts ("plug contacted 37 new domains; usual 0–1") with no black box, at bounded cost. Detection quality depends on baselines, so the first week after install (or after a device appears) is quiet by design.
