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

## ADR-020 — Query-time hash index over the snapshot FSTs (Proposed)
**Context:** T2.4 requires a filter lookup p99 ≤ 1 µs (no regex) on x86. Walking the snapshot FSTs byte by byte measured p50 0.65 µs and p99 1.65–1.8 µs on a native x86 machine (Ryzen 5 5500U) with 2.6M names. The walk is a chain of dependent compressed-node decodes, about 30 ns per byte, so tuning can't fix it. ADR-003 picked FSTs for size and O(|qname|) lookups; it didn't fix the query-time structure.

**Decision:** Keep FSTs as the snapshot and sync format (compact, content-addressed, ~9 B/name). Each resolver builds an in-memory index from them on load: one table per scope, in 64-byte buckets of 8 entries, each entry `48-bit fingerprint | 16-bit list-set ID`, with a seeded xxh3 hash (random seed per load) and a 75% load factor. A lookup is one probe per (scope, reversed suffix), almost always one cache line each, and the probes are independent memory reads. A false match needs a fingerprint collision inside one bucket: ~6e-14 per probe, about once per few thousand years of a busy resolver, and the seed changes on every load. Snapshots with more than 65,536 distinct list combinations use the FST walk. A new snapshot is served with the walk the moment it's loaded, and the indexed matcher is swapped in when ready (built at nice 10), so the index never delays a cold start or a list update.

**Consequences:** Measured with 2.6M real names and no regex: p50 0.32 µs and **p99 0.93–0.94 µs** on the Ryzen (0.61–0.64 µs on the i5 laptop), versus 1.65 µs for the walk. The cost is ~10 B/name of RAM on top of the FSTs (26.9 MiB for 2.6M names), built in ~0.9 s. At the `00` §5 RSS gate (1M names) that's ~10 MiB, within budget. Zero allocations per lookup in both modes (tested). The regex path adds ~0.2 µs with AdGuard's 29 regexes.

## ADR-021 — Groups, clients, and identification (Proposed)
**Context:** FLT-005/006 and `spec/03` §3 step 2 define groups and the identification chain, but not the configuration, the trust model for client-supplied identity, or how group lists meet the compiled snapshot.

**Decision:**
- **Config:** `[[group]] { name, lists?, priority }`, where omitted `lists` means every enabled list. A `default` group always exists; declaring one restricts what unknown devices get. `[[client]] { name, match = [IP | CIDR | MAC | "id:<client-id>"], groups = ["default"] }`, validated for unknown groups and lists and for a key that identifies two clients. `[clients] { neighbor_table = true, neighbor_refresh_secs = 60, trust_edns_mac_from = [] }`.
- **Chain:** client ID → EDNS MAC (only from `trust_edns_mac_from`: the option is client-supplied, so trusting it by default would let any device claim another's identity) → MAC from the kernel neighbor table (rtnetlink dump, IPv4 + IPv6, in `telltale-net`, refreshed only while some client is matched by MAC) → exact IP (IPv4-mapped IPv6 canonicalized) → most specific CIDR → `default`. Lookups are hash maps and a short sorted prefix list; a prefix trie can replace the list if CIDR counts grow.
- **Groups:** a device in several groups gets the union of their lists; other settings come from the highest-priority group. Per-client list masks are precomputed whenever the snapshot or the client config changes. The filter state records the client table it was built for, so a query racing a reload never pairs one table's identity with another's masks.
- **Routing:** client group names feed `[[route]] match_group`. Resolution now looks up the upstream group by the cache view chosen at selection time, rather than re-selecting without groups.
- **Deferred:** hostname-based matching (DHCP leases / rDNS, FLT-006), client IDs until the DoH/DoT listeners (T4.5), and per-group block mode, pause, and schedules (T2.6, FLT-009/010).

**Consequences:** Pi-hole-style per-device filtering, with MAC identification that survives DHCP and IPv6 privacy addresses on host-networked installs. Identification costs a few hash lookups per query and allocates nothing.

## ADR-022 — Block answers, CNAME inspection, and pause semantics (Proposed)
**Context:** FLT-007/008/009 list the block modes, CNAME deep inspection, and pause, but not the default mode, the TTL, how CNAME inspection meets the policy-neutral cache (`spec/03` §4), or what pausing means for a device in several groups.

**Decision:**
- **Block answers per group** (`block_mode`, `block_ips`, `block_ttl`, `ede`, `ede_text`), taken from the client's highest-priority group. Default `null_ip` (A → 0.0.0.0, AAAA → ::, other types → NODATA), matching Pi-hole and Technitium (the owner's current setup); TTL 60 s; EDE 15 with the list name. NXDOMAIN and NODATA answers carry an SOA with the block TTL; block answers are authoritative except REFUSED. This changes T2.4's interim NXDOMAIN default.
- **CNAME inspection** runs wherever an answer leaves the server: cache hits, fresh upstream answers, and stale answers. The cache stays policy-neutral and the check is per client. It walks the answer section's CNAME records without allocating; the first blocked target replaces the whole answer with the client's block answer, with EDE text `CNAME target blocked by list …`.
- **Pause:** global and per group, until a deadline, keyed by group name so it survives reloads. A client is paused when its highest-priority group is (consistent with block settings coming from that group). The fast path costs one atomic load when nothing is paused. The control surface is the API (T3.4).

**Consequences:** Block behavior matches the owner's current resolvers by default and is tunable per group. CNAME cloaking (trackers behind first-party CNAMEs) is caught, for cached answers too, at the cost of a records walk on answers that have CNAMEs.

## ADR-023 — Background work under load: priorities, thread counts, and deferred frees (Proposed)
**Context:** T2.7 requires a recompile during the `realistic-home` run to raise p99 by at most 10%, with zero errors. ADR-018 ran compiles at nice 10 on half the cores (1–4) and left this measurement to T2.7. On the homelab (Ryzen 5 5500U, 6 cores / 12 threads, 2.7M names, 20k qps, `bench.py swap`), the first measurement showed large p99 spikes, and a long run crashed the server.

**Decision:**
- **Priority:** background threads (compile, index build, snapshot load, retire) use `SCHED_IDLE` on Linux instead of nice 10, through `telltale_net::background_thread()`. Nice 10 still received a share of CPU while workers were runnable.
- **Thread count:** `[filter] compile_threads = 0` (auto) now means half the cores (1–4) only while nothing is filtering yet. Once a snapshot has been published, a recompile (list refresh, reload) uses **one** thread. An explicit number applies to every compile. Even at idle priority, parallel compile threads compete with query workers for SMT siblings, memory bandwidth, and cache. On the homelab, 4 threads compiled in 2.1 s and raised p99 by 143%. One thread took 5.9 s and raised it by 7.5%, and the confirmation run with defaults measured −17.7% (within run-to-run noise). A refresh's result isn't waited for, so a slower compile costs nothing visible. ADR-018's first-compile timing, and with it T2.3's Pi gate, is unchanged.
- **Deferred frees:** swapped-out filter and routing state is dropped on a short-lived background thread after 2 s, so freeing tens of MB never lands on a worker mid-query.
- **No blocking work on runtime workers:** hashing, checking, and compressing a downloaded list runs on `spawn_blocking`. A reload with unchanged upstream config reuses the running router (health state, pooled connections, bootstrap cache).
- **`SIGUSR1`** refreshes every list now (FLT-004), and the bench uses it to trigger a list-driven recompile.

**Found while measuring:** prefetch (DNS-008) called `tokio::spawn` from the cache-hit path on UDP worker threads, which have no runtime context. The resulting panic killed the server once a hot entry reached the prefetch threshold. Prefetch now spawns on a runtime handle captured when the pipeline is built (regression test `dns_008_prefetch_from_a_non_runtime_thread`).

**Consequences:** A list refresh on a Pi 4 takes about 11.6 s for 2M names (1 thread) instead of 6.4 s, while the first compile keeps 2 threads. Users who prefer faster refreshes over latency can set `compile_threads`. The p99 measurement is noisy on a shared host: quiet-window p99 alone varied from 65 to 847 µs between rounds, so `bench.py swap` gates on the median over rounds with alternating order.

## ADR-024 — Explain: rule identity, line lookup, and surfaces (Proposed)
**Context:** FLT-013 says every decision records "list ID + rule ID" and that the API can explain "why was X blocked for client Y". `spec/05` §5 lists what explain returns: the client resolution, groups, schedule state, every matching rule across tiers with list name, line number and text, the winner, and the would-be upstream group. The snapshot (ADR-018) stores plain domain rules only as names in FSTs, with no line numbers. The API comes in M3 (T3.4).

**Decision:**
- **Rule identity.** A plain domain rule is identified by (list, listed name, scope, tier); modifier and regex rules by their index in the snapshot, which carries their line. That's what `Attribution` records on the query path (T2.4), and what the query log will store (T3.1). Line numbers aren't added to the snapshot: about 3–4 more bytes per name (+40%) for something only explain needs.
- **Line lookup on demand.** Explain re-parses the stored source of each list that matched (only those lists) and reports every line that produces the matched rule, so a name listed twice shows both lines. If the stored source's hash differs from the snapshot's (downloaded again since compiling), the lines refer to the newer copy and a note says so. A missing source gives the rule without lines, plus a note.
- **Every match, not just the winner.** `Matcher::matches` reports matches from every list, each marked whether the client's groups use it, in the exact precedence order `decide` uses. The first enabled match is, by test, `decide`'s answer for every mask. The query path's `decide` is the same code made generic over a result sink; an A/B of `matcher_bench` showed no change (p50 445 → 453 ns, p99 1085 → 1005 ns, medians of 4 alternating rounds).
- **Whole-pipeline answer.** Explain walks the pipeline's own stages on a real parsed query: allowed networks, ANY, special names, local records, identification, filter, pause, routing including RFC 6303 private PTRs. Its outcome is tested to agree with what the pipeline answers. Rate limiting depends on the moment, not the name, so it's left out. Schedules (FLT-010) are P1 and are added when they exist.
- **Surfaces.** `Pipeline::explain` returns a serializable `Explanation`, the response body for `GET /api/v1/explain` (T3.4) and the `explain_decision` MCP tool. Until then, `telltale explain` runs it offline from the config and data directory (newest snapshot, stored sources, kernel neighbor table), as text or `--json`.

**Consequences:** No snapshot growth and no query-path cost. Explaining a name that matches big lists costs a parse of those lists. Measured on the WSL laptop with 2.7M names: 0.15 s for a name in two lists totalling 6.5 MB, and 0.02 s for an unmatched name (peak RSS 54 MiB). A Pi 4 is several times slower. That's fine for an interactive "Why?" but not for bulk use. If the UI needs bulk explain (for example, annotating every row in a log view), the query log's stored attribution covers it without line text.

## ADR-025 — Compile memory peaks vs small memory limits (Proposed)
**Context:** `00` §1 targets a 128 MiB Kubernetes pod limit and small Pis (Pi Zero 2 W: 512 MiB). Steady-state RSS is well within budget: 25–35 MiB with the `09` §2 bench lists (430k names) and about 70 MiB with 2.7M names, roughly 20 B per name plus a ~17 MiB base. But compiling a snapshot is transient and much larger: peak RSS 106–109 MiB with the bench lists and **297 MiB with 2.7M names** (homelab and WSL measurements, 2026-10-03). `[filter] compile_memory` (128 MiB) bounds only the external sort; parsing, FST building, index building, and the old and new matchers coexisting (ADR-020, ADR-023) add to it. In a pod with a 128 MiB limit, a large list set gets the process OOM-killed mid-compile, taking DNS down with it, which violates "DNS never depends on anything else".

**Decision (proposed, for the owner):**
1. **Derive the compile budget from the memory limit.** When `compile_memory` is unset, read the cgroup v2 `memory.max` (or v1 `memory.limit_in_bytes`) and set the sort budget to about 25% of it, minus current RSS, with a floor of 16 MiB. Smaller budgets spill more and run slower, but stay inside the limit.
2. **Refuse rather than die.** Before compiling, estimate the peak from the number of input names (measured: about 115 B per name at 2.7M names and about 250 B at 430k, where the fixed base dominates). If it exceeds the remaining headroom under the limit, keep the current snapshot, log an error, and expose `telltale_filter_compile_skipped{reason="memory"}`, instead of risking an OOM kill.
3. **In a cluster, resolvers don't compile.** CLU-00x already ships snapshots from the controller; resolver pods only load them (steady state). So the 128 MiB target applies to resolver pods, and the controller (or a standalone node) needs the compile headroom. This goes into the Helm chart defaults (T4.4) and `docs/` sizing guidance.

**Alternatives considered:** Lowering the default `compile_memory` alone doesn't bound the other phases. mmap-loading snapshots (ADR-018) cuts steady RSS, not the compile peak. Compiling in a child process would isolate an OOM from DNS, but needs a second process in a `FROM scratch` image and complicates the single-binary model; keep it in reserve if (1)–(2) aren't enough.

**Consequences:** Until this is implemented (proposed for M4, with the Helm chart), standalone deployments need a memory limit of at least ~3× the steady-state RSS for their list set, or 256 MiB for list sets over ~1M names. `docs/` will say so with the measured numbers.

## ADR-026 — Event capture: byte rings, sizes, and precision (Proposed)
**Context:** `spec/06` §1–2 describes a fixed-size, ~128-byte `QueryEvent` with a 64-byte inline qname, per-worker rings of 65,536 slots (~8 MiB each), and HDR histograms with 3 significant digits. T3.1's AC is "drop counter 0 at 100k qps sustained on x86 with default ring sizes". The footprint priority and the M2 RSS budget (64 MiB with telemetry on) push back on several of those sizes.

**Decision:**
- **Variable-length records in a byte ring** (`rtrb::RingBuffer<u8>`, one per producing thread): a 61-byte header plus the full wire-format qname, lowercased, so ~85 bytes per typical query. A 64-byte inline name would truncate exactly the long names that DGA and anomaly detection (OBS-009/013) care about. A record is written with `push_entire_slice`: all of it or nothing, wait-free. A full ring drops the event and counts it per ring (`telltale_telemetry_dropped_total{ring}`); counters and the Prometheus histograms never drop.
- **Ring size:** `[telemetry] ring_slots` stays the knob, in events of ~128 bytes. The default drops from 65,536 to **4,096 (512 KiB per producing thread)**. With one aggregator pass every 25 ms, a fully loaded worker (~42k events/s, ~3.5 MB/s) fills it in ~170 ms, about 7× the drain period. With UDP workers plus Tokio workers each owning a ring, the spec default would have cost 8 MiB × threads (over 100 MiB on a 12-thread host).
- **Rings per producing thread, not per listener worker:** deferred answers complete on Tokio threads, so each thread that emits gets its ring on first use (one allocation and one short lock per thread lifetime), then never allocates (tested).
- **HDR precision: 2 significant digits** (1%) instead of 3. Each 1 µs–60 s histogram with `u32` counts is ~10 KiB instead of ~70 KiB. With per-client (256 + other), per-qtype, per-path, per-stage, and per-upstream histograms for the current and previous hour, that's at most ~7 MiB instead of ~45 MiB. Histograms allocate on first use.
- **Deferred to T3.2:** qname/client interning (only the segment store needs it; top-K holds names directly), and SQLite persistence of rollups (`06` §3). Until then, the minute and second windows (48 h and 15 min) and the hourly top-K and histograms (current and previous hour) are in memory only. Persistence lands with the store, its retention, and its write budget.
- **Upstream attribution:** `QueryEvent.upstream` stays 0 for now. Singleflight shares one answer between coalesced clients, so per-upstream analytics come from `UpstreamEvent`s (one per exchange, prefetches included), keyed by the upstream's stable config-order ID.

**Measured (homelab, Ryzen 5 5500U, 4 UDP workers, dnsperf on the same host, 2026-10-03):**
- **AC met:** 99,991 qps of `cache-hot` sustained for 60 s: 5,999,502 queries, 5,999,502 events, **0 dropped**, 0% loss, RSS 41 MiB.
- Hot-path cost, A/B against the previous commit, 10 rounds in alternating order: p50 at 50% load 34 → 34 µs; p99 at 50% load 751 → 751 µs (medians); saturated `cache-hot` qps 169k → 163k (median, −3.7%, with overlapping run ranges of 149–183k vs 148–183k). An earlier 6-round A/B gave −2.4%. So the event path probably costs 2–4% of saturated cache-hit throughput, within this host's run-to-run spread, and nothing measurable at realistic load.
- Locally, 4 producers at 25k events/s each with the default ring and drain period: 0 drops (optimized build).

**Consequences:** Full names in every event. About 2–8 MiB of rings depending on thread count, and bounded aggregate memory (windows ~1 MiB, top-K ~1 MiB, histograms ≤ ~7 MiB). If a host's aggregator can't keep up (a slow Pi under a flood), events drop and are counted, and DNS is unaffected.

## ADR-027 — Query-log segment format and search (Proposed)
**Context:** `spec/06` §4 defines the query log: hourly columnar segments, blocks of up to 8192 rows, per-column encodings with zstd, a block index with a 1 KiB bloom over name and client IDs, a segment dictionary, dictionary-first search, and a small search pool with "1 thread on Pi by default". T3.2's AC: a search over a 50M-row synthetic dataset in ≤ 2 s on a Pi 4, with the format fuzzed. Measuring against that AC changed several details.

**Decision:**
- **Files:** `qlog/YYYY/MM/DD/HH-<node>-<part>.seg`. A new part starts after a restart, after a dropped block (a later block must never reference dictionary entries only the dropped block introduced), or when the segment dictionary reaches 65,536 names or clients. The cap bounds the writer's memory under floods of unique names.
- **Self-describing blocks:** each block carries the dictionary entries it introduces, so a segment still being written, or cut short by a crash, is readable by walking block headers. The footer (block index, name filter, trailer) is only a faster path, written when a part is finished.
- **Encoding:** every column is a varint (or byte) stream compressed with zstd level 3; the spec's per-column delta/RLE/frame-of-reference encodings are left to zstd. Measured at 13.9–14.4 B/row (spec: 10–20). Rows are sorted by time within a block.
- **Per-section length and checksum table in the block header**, so a search reads and verifies only the sections it needs: one positional read for one column, one read for several. Checksums are xxh3-64, which only detects corruption (nothing here is content-addressed). BLAKE3 over every section was a measurable share of a 30-day search on a Pi.
- **Blooms keyed by content hashes, not dictionary IDs**, so blocks are ruled out before any dictionary is read. The spec's 1 KiB block bloom stays for clients and unfinished segments, but it can't rule out names: blocks hold thousands of distinct names, about 60% false positives. So each finished segment also gets a **name filter** in its footer (~10 bits and 7 probes per name, ~0.8% false positives). An exact-name search over 30 days skips about 99% of segments after one small read.
- **Dictionary handling:** dictionaries are decompressed in bulk into one buffer and indexed in place (no allocation per name), read only when a name or client predicate needs them. Output rows resolve their few names sparsely, from just the dictionary blocks holding those IDs. Predicates run column at a time into a selection vector; the time column is skipped when a block lies inside the range.
- **Search threads:** up to 4 (default `min(cores, 4)`), each at the lowest CPU priority via a thread-start hook (`SCHED_IDLE` in the server and CLI), so a search only uses CPU that DNS doesn't. This changes `06` §4's "1 thread on Pi by default": on one Pi core, substring and latency searches over 50M rows take ~5 s. A persistent pool claims segments newest first; results merge in order; the pool stops as soon as the page is full.
- **Write path:** the builder runs on the aggregator thread (interning, privacy, rows; no I/O). A writer thread encodes, compresses, appends, writes footers, and runs retention every 10 minutes, fed by a bounded queue of 8 blocks. A full queue drops the block and counts it (`telltale_qlog_rows_dropped_total`). DNS never waits on the disk.
- **Privacy levels** apply at write time: 1 stores names as a one-label hash, so identical names still group together; 2 also zeroes clients; 3 writes nothing. Per-group levels (`06` §4) wait for group-level config.
- **Not yet:** `node` is 0 until cluster membership (T5.x); rows from several nodes in one hour aren't merged by time. SQLite rollup persistence (ADR-026) moves to T3.3 with the Prometheus/rollup work, which uses it, so `rusqlite` arrives with its first consumer.

**Measured:**
- Synthetic 50M rows over 720 hours: 40 Zipf clients, 20k Zipf domains plus 15% one-off tracking names (pessimistic: real homes have far fewer), 15.1M dictionary entries, 686 MiB.
- **Pi 4** (Technitium in production on the same Pi, search at nice 10, 4 threads, page cache warm), second round:

| Query | Time |
|---|---|
| exact rare name | 0.21 s |
| rare substring | 1.78 s |
| client + blocked, 1000 rows | 0.43 s |
| type filter with no matches (full column scan) | 0.75 s |
| latency ≥ 1 s (1000 rows across 590 segments) | 1.92 s |
| newest rows, last 2 hours | 0.03 s |

  **AC met with 4 idle-priority threads, with thin margins on the two heaviest queries.** On 1 thread the same two take ~5 s.
- x86 (laptop, 4 threads): every query ≤ 0.9 s.
- Fuzzing: `qlog_segment` (raw, checksum-repaired, and structure-aware modes), ~670k runs across three sessions, clean.

**Consequences:** Interactive search stays within 2 s on a Pi for a month of a busy home's queries, without stealing CPU from DNS. Heavier work (a multi-month substring scan, or a much higher share of unique names) degrades linearly. If that matters, the next step is a cross-segment name index (one dictionary per day or week), not more threads.

## ADR-028 — API listener, crate boundary, and the read-only first slice (Proposed)
**Context:** `spec/07` defines the API conventions and resource map but no listener: `06` §5 says only that `/metrics` is "also on the API port". T3.4 (API-001, API-002) is the skeleton, and the owner asked for a UI next for testing, which needs an API. API-003 (auth) is T3.5.

**Decision:**
- **Listener:** a new `[api]` section (`enabled = true`, `listen = "0.0.0.0:8053"`) on its own TCP listener, also serving `/metrics` and `/livez`, `/healthz`, `/readyz` (`06` §5). Port 8053 avoids 53/80/443, Pi-hole's 80, and Technitium's 5380/53443 (the owner runs Technitium on the same Pi). The metrics listener (9153) stays for scrapers.
- **Crate boundary:** `telltale-api` owns routes, request/response types, problem+json, time parsing, and the OpenAPI document. It reaches the server only through a `Backend` trait implemented by the binary (`api_backend.rs`) over the state that already exists for `/metrics`, the pipeline, the aggregates, the query log, and list status. So the API never depends on pipeline internals, and the trait is the seam a cluster proxy (federated scope) plugs into later.
- **OpenAPI:** `utoipa` 6 generates OpenAPI 3.1 from the handlers. Doc comments become summaries and descriptions, and a test fails if any operation lacks either (AGT-001). `docs/api/openapi.json` is committed, and a test fails when it drifts (`07` §1); regenerate with `UPDATE_OPENAPI=1`.
- **Conventions:** camelCase JSON with units in field names; `{"items": [...]}` for collections; cursor pagination on the query log (other collections are small and unpaged for now); `from`/`to` as RFC 3339 or relative offsets; errors as RFC 9457 problem+json with a stable `code` enum and a `hint`; `scope` accepted on analytics calls, where `cluster` and `node:local` mean this node and anything else is a 400 `unsupported_scope` until clustering.
- **Read-only until auth:** T3.4 ships GET endpoints only (system info, stats summary/timeseries/top/latency, query log, explain, lists, groups, clients, upstreams). Mutations, with dry-run and idempotency keys (AGT-002/003), come with T3.5 so nothing can be changed without authentication. Until then the listener answers only `[access] allowed_networks`, like `/metrics`.
- **Roadmap order:** at the owner's request (2026-10-04: "we will want a UI to help with testing"), T3.5 and T3.9 come next. T3.3 (Prometheus set, Grafana, SQLite rollups) moves after T3.9; none of the UI depends on it, since the dashboard reads the in-memory windows.

**Consequences:** The UI and agents have a documented, typed surface now. Every later endpoint follows the same pattern (types and doc comments in `telltale-api`, data from `Backend`).

## ADR-029 — Local sign-in details (Proposed)
**Context:** `spec/08` §6 and API-003 define local users (Argon2id), session cookies with CSRF, opt-in HTTP Basic, scoped API tokens, TOTP, lockout, RBAC, and a first-run setup token. Several details are left open.

**Decision:**
- **Storage:** users, recovery codes, sessions, and tokens in SQLite `<data_dir>/state.db` (rusqlite, bundled). Session IDs, token secrets, and recovery codes are stored only as BLAKE3 hashes (they are 256-bit random, so a slow hash adds nothing); passwords as Argon2id PHC strings with the `08` §6 parameters. If `state.db` can't be opened, the API stays off and DNS keeps answering (rule 5).
- **Cookie `Secure` flag:** set only when the request arrived over HTTPS (`X-Forwarded-Proto: https`), because the API has no TLS listener yet and browsers drop `Secure` cookies over plain HTTP, which would make sign-in impossible on a LAN. `HttpOnly; SameSite=Strict` always. Revisit when the API gets TLS (`08` §6 asks for `Secure` unconditionally).
- **CSRF:** a per-session random token returned at sign-in and by `GET /auth/status`, required as `X-CSRF-Token` on every non-GET request authenticated by the cookie. Tokens and Basic don't need it (they are not sent automatically by browsers).
- **Tokens:** `tt_<16-char id>_<43-char secret>`. Scope caps the owner's role (`read` → viewer, `write` → operator, `admin` → admin). The optional group scope from `08` §6 is deferred to the `family` role (P1).
- **Basic:** per-user opt-in; refused over plain HTTP unless `[auth] allow_insecure_basic`; verified results cached 60 s keyed by a salted BLAKE3 hash of the credentials, invalidated on any change to the user. Users with TOTP can't use Basic (it would bypass the second factor).
- **Password policy:** 10–256 characters, no composition rules (NIST SP 800-63B).
- **Lockout:** per username and per client address, 5 free failures, then 30 s × 2^n up to 15 minutes; in memory (a restart clears it). Unknown usernames take the same time as wrong passwords (a dummy Argon2 verify).
- **Sessions:** 7 days absolute, 1 day idle (configurable in `[auth]`); `last_seen` is written at most once a minute; a password change ends the user's other sessions; disabling or deleting a user ends all of theirs; hourly purge.
- **TOTP:** RFC 6238, SHA-1, 6 digits, 30 s, ±1 step; each step is accepted once (replay protection); ten recovery codes, single-use. `[auth] totp_required_roles` refuses password-only sign-in for those roles until TOTP is enrolled (403).
- **First admin:** the setup token is kept in `<data_dir>/setup-token` (mode 0600) and logged, so it survives restarts and `telltale auth setup-token` can print it; it is deleted once an admin exists. Deployments can instead set `TELLTALE_BOOTSTRAP_ADMIN_USER` with `..._PASSWORD` or `..._PASSWORD_HASH` (Argon2id PHC only; `telltale auth hash-password` makes one), applied only while no user exists.
- **What is open:** `/api/v1/auth/{status,setup,login}`, `/api/v1/openapi.json`, and the probes. Everything else, including `/metrics` on the API port, needs a sign-in. The dedicated metrics listener (`:9153`) stays unauthenticated and limited to `allowed_networks`, so existing scrapers keep working. The API listener also stays limited to `allowed_networks` (defense in depth).
- **AGT-002/003:** the auth endpoints don't take dry-run or idempotency keys: sign-in, sign-out, and token creation aren't meaningful to preview, and replaying a token creation must not mint a second secret silently. Configuration mutations will take both when they land.

**Consequences:** The API is safe to expose on the LAN, and the UI (T3.9) can build sign-in and first-run screens on `/auth/status`. TLS on the API listener and OIDC (API-004) are later tasks; until TLS, HTTP Basic needs a TLS-terminating proxy.

## ADR-030 — Web UI MVP: serving, security, and scope (Proposed)
**Context:** T3.9 (API-005) asks for a UI MVP: login, dashboard, query log + explain, groups, lists, upstreams, local DNS, and settings, ≤ 400 KiB gzipped, with a Playwright suite. ADR-009 fixes the stack (Svelte + uPlot, embedded). The API has no configuration mutations yet, no live tail (T3.7), and no OIDC (T3.6).

**Decision:**
- **Serving:** `telltale-api` embeds `ui/dist` with `rust-embed` (`allow_missing`, so Rust builds and tests work without Node; such a binary serves a one-paragraph page saying the UI isn't built). The API router's fallback serves the UI for everything outside `/api/`. Static files need no sign-in (they hold no data); every data call does.
- **Routing:** hash routes (`#/queries?client=...`), so the server only serves `/`, `/assets/*`, and `/favicon.svg`, and filters are bookmarkable without server-side SPA fallbacks.
- **Security:** CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, plus `X-Frame-Options: DENY`, `nosniff`, and `Referrer-Policy: no-referrer` (`08` §6). The UI never uses inline scripts, `style` attributes, or `{@html}`; dynamic styles go through Svelte's `style:` directive (CSSOM, allowed by CSP). The Playwright suite fails on any console error, so CSP violations fail CI. HSTS waits for TLS on the API listener.
- **Size and caching:** `npm run build` writes a `.gz` beside each text asset (served on `Accept-Encoding: gzip`, so no compression crate on the server) and fails over 400 KiB gzipped. Hashed `assets/*` are `immutable`; `index.html` is `no-cache`. The MVP is ~60 KiB gzipped.
- **Types:** `src/lib/api-types.ts` is generated from `docs/api/openapi.json` (openapi-typescript) and committed; CI fails if it is stale, so the UI breaks at type-check time, not at runtime, when the API changes.
- **Build:** Node is build-time only: a `node:24` stage on the build platform builds `dist/` once for all image architectures. CI's `ui` job runs svelte-check, the budget, and Playwright (headless Chromium) against a real binary with an inline blocklist and a local record (no internet needed).
- **MVP scope versus `07` §3:** shipped: first-run setup and sign-in (with TOTP and recovery codes), dashboard (KPIs, stacked queries by status, upstream exchanges, where time goes, top domains/blocked/clients, upstream share and health; every chart has a table view), query log (filter chips, URL filters, cursor paging, per-row timing bar, "Why?" drawer), explain page, clients (seen and configured), groups, lists, upstreams (breaker, latency), settings (password, TOTP, tokens, users, system), light/dark themes, 360 px layout. Deferred: OIDC sign-in (T3.6); editing groups, lists, upstreams, and local records, and the allow/block quick actions (need the configuration API with AGT-002/003); live tail via SSE (T3.7; the log polls with "Auto-refresh" meanwhile); a virtualized table (100-row pages for now); the schedules editor, presets gallery, client merge and profile pages, analytics, cluster page and scope selector (M5), and the audit log (T3.8). The TOTP enrollment shows an `otpauth://` link and the key rather than a QR code, to avoid a QR dependency. The latency tile shows the upstream p90 because the API exposes p50/p90/p99, not p95.

**Consequences:** The resolver ships its own UI in one binary with no runtime dependencies. Each new API feature can add its page incrementally; the suite and the type drift check keep the UI and API in step.

## ADR-031 — Prometheus metric set and SQLite rollups (Proposed)
**Context:** T3.3 completes the `06` §5 metric set (OBS-005, OBS-011), ships a Grafana dashboard, and persists rollups (`06` §3, moved here by ADR-027). Rule 4 forbids new hot-path work without a benchmark.

**Decision:**
- **Where series come from:** the per-thread counters (T1.9) stay as they are. Series that need per-event detail (`telltale_stage_duration_seconds`, `telltale_upstream_duration_seconds{upstream,protocol}`, `telltale_blocked_total{group,list}`, opt-in `telltale_client_queries_total{client}`) are built by the aggregator thread from query/upstream events into cumulative classic histograms (the same 50 µs–5 s buckets) and counters. Nothing new runs on the query path; the cost is that these series miss events dropped by a full ring, which `telltale_telemetry_dropped_total` already reports. The only hot-path change is one increment for `telltale_cache_prefetch_total`, under a lock already held. bench-smoke after the change: 191,533 qps cache-hot, 0% loss.
- **Bounded cardinality:** blocks are keyed by (group, list) with at most 4,096 pairs; per-client series are off by default and capped at `per_client_cap` (default changed 256 → 100 to match `06` §5), the rest summed as `client="other"`; upstream series follow the configured upstreams.
- **Label deviations from `06` §5:** no `node` label on every series: Prometheus already adds `instance`, and `node` is on `telltale_build_info` for joins; cluster-wide views will add it when nodes federate (M5). `qtype` stays in its own family (`telltale_queries_by_qtype_total`) instead of a third label on `telltale_queries_total`, keeping that family at 22 series instead of 286. `telltale_upstream_requests_total` gains `outcome` (`success`, `failure`) from the router's health counters (every attempt, including health probes) and replaces `telltale_upstream_failures_total`. `telltale_ratelimited_total` mirrors `queries_total{status="rate_limited"}`. The DNSSEC, cluster, and qlog-write-time series wait for their features.
- **Grafana:** `deploy/grafana/telltale-dashboard.json` is generated by `deploy/grafana/build.py` (CI checks it is current) and uses only exported metrics, with datasource/job/instance variables.
- **Rollups:** `<data_dir>/rollups.db` (separate from `state.db` so analytics writes never contend with sign-in): `rollup_minute` (7 days), `rollup_hour` (400 days), `rollup_day` (forever), `hour_top` (top 100 per kind per hour), `hour_latency` (percentile summaries per hour; HDR histograms are not stored, since percentiles of merged hours aren't needed yet and summaries are tiny). Counts are a versioned little-endian blob with column counts in the header, so later builds read old rows. A background task flushes completed minutes once a minute, re-writing the last 3 minutes for late events but never minutes from before the process started (so a restart can't overwrite saved data with a partial view); hour and day rows are recomputed from the rows below on every write (idempotent). Retention runs hourly. All SQLite work is on a blocking thread; open or write failures are logged and the API falls back to memory (rule 5).
- **API:** `step` gains `hour` and `day` (rollups); `step=minute` merges stored minutes with memory (memory wins); `stats/summary` sums hours for ranges beyond 48 hours. The dashboard UI adds 7- and 30-day ranges.

**Consequences:** Charts and summaries reach back 400 days and survive restarts with ~1 KiB per stored minute at most. Querying a past hour's top-K through the API is not exposed yet (stored for the analytics pages).

## ADR-032 — Live tail over Server-Sent Events (Proposed)
**Context:** OBS-008 / `06` §6: `GET /api/v1/queries/stream` (SSE) "or `/ws`", server-side filters (client, group, status set, qname glob, upstream, min latency, node), and a per-subscriber rate cap (default 500 events/s) with inline drop counts. Rule 4 forbids hot-path cost; rule 5 says telemetry can't affect DNS.

**Decision:**
- **SSE only, no WebSocket:** one-way delivery is all a tail needs; SSE works through proxies, reconnects by itself in browsers (`EventSource`), and authenticates with the session cookie (GET, so no CSRF header). A WebSocket can be added later if a use appears.
- **Source:** the aggregator thread's sink (beside the query-log writer) copies query events into a `tokio::sync::broadcast` channel (4,096 deep) only while a subscriber exists; otherwise the cost is one atomic load per event. The query path is unchanged. The query-log privacy level applies (1: names hashed, 2: clients hidden too, 3: no tail).
- **Per subscriber:** a task filters raw events (no allocation: names are compared via a reused buffer), applies a token bucket (`rate`, default 500/s, 1–2000), formats matches as the same `QueryRow` as `GET /queries`, and every second reports skipped matches as `event: dropped` `{dropped, reason: "rate"|"lag"}` (lag: it fell behind the broadcast channel or its own 256-item queue). Filters: `name` + `match` (substring, exact, suffix, glob; regex is rejected to keep per-event cost bounded), `client`, `group` (primary group), `status`, `qtype`, `upstream`, `minLatencyMs`. `node` waits for clustering. At most 16 concurrent streams per node (503 beyond). A comment every 15 s keeps idle connections open.
- **Measured** (bench-smoke on the dev box, two subscribers attached for the whole run: one unfiltered at the 500/s cap, one with a name filter matching nothing; two rounds in opposite order): cache-hot 196k and 169k qps with subscribers vs 143k and 166k without, 0% loss in all runs; p99 at 50% load 3.4/3.5 ms vs 2.6/4.0 ms (within this machine's noise); p50 at 50% load 655/367 µs vs 167/215 µs, a small but consistent median cost under heavy load from formatting on the aggregator and subscriber tasks sharing CPU with the load generator. Acceptable for an operator watching a live view; zero when nobody watches.
- **UI:** the query log's "Auto-refresh" polling becomes **Live** (EventSource with the page's filters; rows flushed every 250 ms; newest 500 kept; skipped count shown). Rcode and time filters don't apply to a live view and the page says so.

**Consequences:** "Watch it happen" works in the UI, from `curl -N`, and for agents. Subscriber tasks share the async runtime with upstream I/O, which is why the cap, the subscriber limit, and allocation-free filtering matter; if a home ever needs more, move subscribers to a dedicated thread.

## ADR-033 — Audit log: what, where, and how it is chained (Proposed)
**Context:** API-006 asks for an audit log of every config change (who, when, diff), replicated cluster-wide; `08` §6 makes it append-only and hash-chained; AGT-005 asks for agent attribution and a reason. Today the only mutations are sign-in administration and config reloads (config editing through the API comes later).

**Decision:**
- **Storage:** an `audit` table in `state.db` (migration 2): `seq`, `ts`, `actor`, `actor_kind` (`session`, `token`, `basic`, `system`), `remote`, `action`, `target`, `detail` (JSON), `reason`, `prev_hash`, `hash`. `hash = BLAKE3("telltale-audit-v1" ‖ prev_hash ‖ seq ‖ ts ‖ each field with a presence byte and length)`, genesis `prev_hash` = 32 zero bytes. SQLite triggers abort UPDATE and DELETE. Verification recomputes every hash and link and also checks that `seq` has no gaps; truncation at the end is caught by comparing the head hash with a copy kept elsewhere (documented).
- **What is recorded now:** `user.create|update|delete`, `user.password`, `user.totp.enable|disable`, `token.create|revoke`, `auth.login` (successful sign-ins), `auth.lockout` (the first lock of a username or address, not every failed attempt, so a password-guessing run can't flood the log), first-admin creation by setup token or bootstrap environment, and `config.reload` (the dotted paths of changed settings, never values: configs may hold secrets). Updates record `{field: {from, to}}`; passwords and secrets appear only as `"changed"`.
- **Attribution:** sessions and Basic record the username; API tokens record `token:<name> (owner: <user>)` (AGT-005); an optional `X-Telltale-Reason` header (trimmed to 500 characters) is stored as the reason (required for agents once plan/apply exists).
- **Failure handling:** the change happens first and the entry is appended after; if the append fails, the error is logged rather than undoing the change (the audit store is the same SQLite file, so this is rare). Moving to "write the entry in the same transaction" comes with the config-edit API, where it matters most.
- **Access:** admins only (`GET /api/v1/audit` with cursor paging and action-prefix/actor filters; `GET /api/v1/audit/verify`), the UI's Settings → Audit log, and `telltale audit list|verify` offline. No retention: entries are small and the log is append-only by design.
- **Deferred:** cluster replication (M5, with the config change log), MCP client name/version in entries (with the MCP server), signed head checkpoints.

**Consequences:** Sign-in administration and reloads are accountable now, and every future mutation endpoint gets auditing by calling `Auth::record` with a diff.

## ADR-034 — OIDC sign-in: library, flow, and account rules (Proposed)
**Context:** API-004 / `08` §6: Authorization Code + PKCE, discovery, multiple providers, claim → role mapping, JIT provisioning, optional verified email, back-channel and RP-initiated logout, ID-token validation with JWKS rotation, local sessions after sign-in, a canonical `public_url`, and `disable_local_login` with a break-glass admin from `allowed_admin_networks`. AC: integration tests against Keycloak and Authentik.

**Decision:**
- **Library:** `openidconnect` 4 (the `02` §7 crate) without its bundled HTTP client. The binary supplies requests through the list fetcher's existing hyper + rustls client (system resolver, Mozilla roots, no redirects followed, 1 MiB, 15 s), so no second HTTP/TLS stack. Cost: ~0.6 MB gzip on the binary (RSA/EC/Ed25519 verification crates). `cargo deny` flags RUSTSEC-2023-0071 (`rsa`, Marvin timing attack): it concerns RSA *private-key* operations; TelltaleDNS only verifies ID-token signatures with providers' public keys and holds no RSA private key, so the advisory is ignored in `deny.toml` with that justification, to be revisited when a fixed `rsa` ships.
- **Flow:** `GET /api/v1/auth/oidc/{id}/start` (302 to the provider with PKCE S256, state, nonce) and `GET .../callback`. Flow state lives in memory for 10 minutes (max 1,000), keyed by `state` and bound to the starting browser by an HttpOnly `SameSite=Lax` cookie (Strict cookies aren't sent on the provider's redirect back), so a callback can't be replayed or completed in another browser. `returnTo` must be a UI hash route (no open redirect). Failures redirect to `/#/?loginError=...`.
- **Validation:** `openidconnect` checks signature (provider JWKS), issuer, audience, expiry, and nonce; allowed algorithms are the asymmetric ones (RS/PS 256–512, ES256/384, EdDSA), never HMAC. Discovery (with keys) is cached for an hour and refreshed once when a signature doesn't verify (key rotation). Custom claims (groups, nested `realm_access.roles`) are read from the verified token's payload; claim paths are dotted.
- **Accounts:** users are keyed by (provider, `sub`) (`state.db` migration 3) and created on first sign-in with an unusable password; the username comes from `preferred_username` (or `username_claim`, then `email`, then `sub`). A provider account is never attached to an existing local account by name (that would let a provider-side rename take over an account); a clash yields `name@provider`. The role is the highest any group maps to (`default_role` otherwise; none: refused), re-evaluated at every sign-in and audited when it changes. TOTP is the provider's job for these accounts. Disabled accounts stay disabled.
- **Sign-out:** RP-initiated with `client_id` and `post_logout_redirect_uri = <public_url>/` (from discovery's `end_session_endpoint`). No `id_token_hint`, to avoid storing ID tokens; Keycloak therefore asks for confirmation, and Authentik's default invalidation flow shows its own page. **Back-channel logout is deferred** (needs provider session IDs and a token endpoint for logout tokens; sessions are short and local).
- **Break-glass:** `disable_local_login` refuses password sign-in and HTTP Basic except for admins from `allowed_admin_networks` (default: private networks and loopback); `/auth/status` tells the UI whether to show the password form for this client.
- **Tests:** an in-process fake provider (discovery, JWKS, token endpoint, RS256 tokens) covers the flow in unit tests; `ui/tests/oidc/compose.yml` runs Keycloak 26.4 and Authentik 2025.10.1 with fixtures, and the `oidc` CI job runs the Playwright spec against both (admin, viewer, refused user, sign-out).
- **Proxies:** `[api] trusted_proxies` (default none): for requests from those addresses, the client is the rightmost `X-Forwarded-For` entry that isn't a trusted proxy (entries further left are client-controlled). Without it, everything behind an ingress shares the ingress address: one client's failed sign-ins would lock out everyone, and audit entries and break-glass checks would see the proxy. `X-Forwarded-Proto: https` keeps setting the cookie's `Secure` flag (ADR-029).
- **Resilience:** a provider that can't be set up (missing secret file) is logged and skipped; password sign-in and the API keep working.
- **Deferred:** back-channel logout, multiple redirect URIs per node (cluster nodes share `public_url` for now), OAuth for agents (AGT, P1).

**Consequences:** Homes and labs with an identity provider sign in with it; local passwords become optional. Each provider must be registered with the exact redirect URI.

## ADR-035 — Helm chart: allInOne first, client-IP proof in CI (Proposed)
**Context:** T4.1 / OPS-002/003 asks for `allInOne`, `scaled`, and `daemonSet` shapes, Services with `externalTrafficPolicy: Local`, PDB, HPA, probes, NetworkPolicy, ServiceMonitor, cert-manager, `existingSecret` everywhere; AC: `ct install` on kind and k3d arm64, DNS via the LB, and client IPs preserved in the query log in an e2e test. Clustering (M5) doesn't exist yet.

**Decision:**
- **Shapes:** only `allInOne` (one StatefulSet with a volume) until M5. `scaled` and `daemonSet` need a controller to distribute filter snapshots and share users/sessions; without it every replica would compile its own lists and keep its own sign-in state, so sign-in would break across replicas. `values.schema.json` refuses the other modes with that reason. HPA and PDB belong to `scaled` and come with it (a PDB on one replica only blocks node drains).
- **Ports:** in the pod's own network the container listens on 5353 and the Service maps 53 → 5353 (no capability needed). `hostNetwork: true` binds 53 on the node, which needs root: the container then runs as UID 0 with every capability dropped except `NET_BIND_SERVICE`, read-only root, no privilege escalation (Kubernetes doesn't grant ambient capabilities to non-root users).
- **Services:** one DNS Service with UDP and TCP 53 (mixed protocols, k8s ≥ 1.26), `externalTrafficPolicy: Local` by default, LB annotations passed through; `NOTES.txt` warns on `Cluster`. A separate API Service (ClusterIP by default; LoadBalancer or Ingress optional) and a ClusterIP metrics Service for the ServiceMonitor.
- **Probes:** startup and readiness on `/readyz` (listeners bound), liveness on `/livez`. No `preStop` sleep: the image has no shell, and the binary already drains on SIGTERM (readiness off first, OPS-007).
- **Secrets:** bootstrap admin from an existing Secret (env vars), any Secret mounted read-only under `/etc/telltale-secrets/<name>` (optional mounts let the pod start without them).
- **Monitoring:** ServiceMonitor, a PrometheusRule with five default alerts, and the Grafana dashboard ConfigMap (the same JSON as `deploy/grafana/`, kept identical by `build.py --check`).
- **cert-manager:** only through the Ingress (annotations); a DoT/DoH `Certificate` comes with those listeners (T4.5).
- **Proof:** `deploy/helm/e2e.sh` creates a kind or k3d cluster with MetalLB, installs the chart, queries through the LoadBalancer from the host (UDP and TCP), and asserts the query log recorded the host's own address on the cluster network, not a node or pod address. CI runs it on kind (amd64) and k3d (arm64), then `ct install` with `ci/*-values.yaml`. The script uses a private kubeconfig (it never changes the caller's current context) and gives k3d its own pod/service ranges so it also runs on a host that is itself a k3s node. Also verified on the owner's homelab (k3s + Cilium LB IPAM): real LAN clients appear with their own addresses.

**Consequences:** One-replica deployments are production-ready on any LoadBalancer implementation; HA within Kubernetes waits for clustering.

## ADR-036 — Guided UI: task-first names, help panels with diagrams, Simple/Advanced (Proposed)
**Context:** The owner (2026-10-04): Pi-hole is easy for non-experts; Technitium is powerful but assumes DNS expertise (zones, SOA, zone types). TelltaleDNS should offer the depth without demanding the expertise, and visual cues should help novices see what an option does. Recorded as API-011.

**Decision:**
- **Names by outcome, jargon as subtitle.** UI features are named for what they achieve; the DNS term appears underneath and in help: "Names on my network" (*local zone / records*), "Send a domain to another server" (*conditional forwarding*), "Block / allow lists" (*filter lists*), "Where answers come from" (*upstreams*). No separate "zones" concept in the UI: local names are grouped by domain, and SOA/NS are generated. Real zone features (import, secondary/transfer, serving a domain to other servers) live under Advanced on the same page.
- **One glossary, many readers.** `docs/help/topics.json` holds each topic: `id`, `title` (outcome), `term` (technical name), `summary` (one sentence), `when` (when you'd want it), `example` (home-network example), `caution` (what goes wrong if misused), `diagram` (kind, optional), `docs` (anchor). The UI imports it, the site renders it as a glossary page, and CI checks every help id used in the UI exists (and every topic is used or marked general). API descriptions stay in code (AGT-001) but use the same terms.
- **Help panels.** A "?" beside any setting opens a right-side panel with the topic in that fixed order (summary, diagram, when, example, caution, term, docs link). Keyboard and screen-reader accessible; no modal blocking the form.
- **Diagrams.** A `FlowDiagram` Svelte component draws inline SVG (no library, CSP-safe, a few KiB): a device, TelltaleDNS, and the possible destinations of a query (cache, local name, blocked, another server, upstream), with the path for this option highlighted and the user's own values filled in (`*.sororlab.dev → 192.168.5.122`). The same component illustrates help topics, previews changes before they're saved, and shows the Explain result ("this query went here, because of this rule"). Status colors and labels match the rest of the UI; every diagram has a text equivalent.
- **Simple / Advanced.** Each editing page has a Simple view (common fields, safe defaults) and an Advanced view (everything); the choice is remembered per user. Advanced never hides information that changes behavior: if an advanced field differs from its default, Simple shows a "customized in Advanced" note.
- **Previews and tests.** Every change shows a plain-language sentence plus diagram before saving (built on the API's dry-run, AGT-002), and each rule offers "Test a name" (explain).
- **Experts keep everything.** Config files, API, and CLI expose the full model; the UI never becomes the only way to do something.

**Consequences:** More UI content to write and keep current (one glossary file, checked in CI). The editing pages (T3.12 and later) are designed around this from the start; the read-only pages get help panels and diagrams in T3.11.

## ADR-037 — Masked-client-IP detector: what counts as infrastructure (Proposed)
**Context:** OPS-003 / `spec/08` §3.2: "the resolver detects when > 90% of queries come from ≤ 3 IPs inside the pod/node CIDRs and raises a UI banner". A pod doesn't know the pod or node CIDRs, and on a homelab the node network *is* the LAN, so "inside the node CIDR" would also match real devices.

**Decision:**
- **Window:** the aggregator keeps per-client counts for fixed 10-minute windows (≤ 256 clients each, off the query path). The detector reads the last complete window (or the current one before the first completes). At least 100 queries are needed to judge.
- **Infrastructure** = loopback; this host's default gateways from `/proc/net/route` and `/proc/net/ipv6_route` (inside a container that's the Docker bridge or the pod's gateway, where SNAT'd traffic appears; on a host network it's the LAN router, which matters when the router forwards everyone's DNS); node addresses in `TELLTALE_NODE_IPS` (the chart sets it from `status.hostIP`); and `[clients] infrastructure` networks for anything else (pod networks, other nodes).
- **Rule:** masked when the ≤ 3 heaviest clients that are infrastructure sent > 90% of the window's queries. A household whose traffic is dominated by a few real devices is never flagged, because they aren't infrastructure (conservative: a missed warning costs less than a false one).
- **Surfaces:** `clientIpsMasked` in `GET /api/v1/system/info` (share, sources, queries, window start), a UI banner linking to the docs (refreshed every minute), the gauge `telltale_client_ips_masked` with a chart alert after 30 minutes, and one log line per change. Evaluated only on API calls and scrapes.

**Consequences:** Multi-node clusters with `externalTrafficPolicy: Cluster` SNAT to *other* nodes' addresses, which are only recognized when listed in `[clients] infrastructure` (the chart's install notes already warn on `Cluster`).

## ADR-038 — Native installs: release assets, signing, install.sh, self-update, Compose defaults (Proposed)
**Context:** OPS-004 / `spec/08` §4 asks for a static binary with systemd unit and install script that "downloads + verifies (cosign/minisign)", `telltale self-update`, and the Compose bundle of §3.4. No release pipeline existed, and the §3.4 Compose example (`user: 65532` + `cap_add`) can't bind port 53: Docker doesn't give a non-root user ambient capabilities.

**Decision:**
- **Assets:** the image workflow's cached cross-build also exports the static musl binaries (`--target bin`) as `telltale-{x86_64,aarch64,armv7}-linux` plus `SHA256SUMS`. Every push to main replaces the `edge` prerelease; a `v*` tag creates a release and pushes image tags `X.Y.Z`, `X.Y`, `X`, `latest`.
- **Signing: minisign**, not cosign. Ed25519 over `SHA256SUMS`, verifiable offline with a 56-character public key (`deploy/release/telltale-release.pub`, also built into the binary), by `install.sh` (the `minisign` package, installed if missing) and by `self-update` (the `minisign-verify` crate: MIT, no dependencies). Cosign's keyless flow would need Sigstore's trust root and network access in both. The secret key is the repository secret `MINISIGN_SECRET_KEY`; without it releases aren't published (the job warns) rather than published unsigned.
- **install.sh:** POSIX `sh`, root, systemd required. Refuses on any signature or checksum mismatch and test-runs the binary before installing it; creates the `telltale` system user; never overwrites `/etc/telltale/telltale.toml` (the starter config is `deploy/compose/telltale.toml`, shared with Compose); swaps the binary atomically; asks (or `--disable-resolved-stub`) before turning off systemd-resolved's stub; waits for `/readyz`. Stable is the default channel; until a release is tagged it says to use `--edge`.
- **Unit:** a static `telltale` user (not `DynamicUser`, so the CLI can run as the same user against the same files), `StateDirectory=telltale`, `ProtectSystem=strict`, only `CAP_NET_BIND_SERVICE` (ambient and bounding), `@system-service` minus `@privileged`, netlink allowed (neighbor table), `MemoryMax=256M`.
- **self-update:** verifies the signature, compares this binary's SHA-256 with the release's (so "up to date" needs no version parsing and works for `edge`), downloads, checks the hash, runs `--version`, keeps `telltale.old`, renames atomically; `--restart` restarts the unit. Refused in containers. No key or URL override in production (the tests call the library with a fixture key).
- **Compose:** host network, read-only root, `cap_drop: [ALL]`, `cap_add: [NET_BIND_SERVICE]`, **as root** by default with `./data` bind-mounted (Docker creates it root-owned; a root process without `CAP_DAC_OVERRIDE` can't write the image's 65532-owned directory, which the e2e caught). Running unprivileged is documented: host sysctl `net.ipv4.ip_unprivileged_port_start=53` + `chown 65532 data`.
- **Health:** `telltale health [--url]` (an HTTP GET to `/readyz`) is the container healthcheck, since the image has no shell.
- **Tests:** CI job `native` runs the Compose bundle (host network, healthcheck, hardening) and `install.sh` against a locally served release signed with a throwaway key: DNS on 53 over UDP and TCP, runs as `telltale`, upgrade keeps the config, a swapped binary and a modified `SHA256SUMS` are both refused.

**Consequences:** The owner must add `MINISIGN_SECRET_KEY` once before the first binaries are published. The cluster-version check of `self-update` (spec §4) waits for clustering (T5.11).

## ADR-039 — DoT and DoH listeners, client IDs from certificates, PROXY v2 rules (Proposed)
**Context:** T4.5 (DNS-002/003) and T4.4 (DNS-020). The spec names SNI and DoH-path client IDs (`<clientid>.dns.example.com`) but not how the server knows which part of the name is the ID, how certificates are reloaded, or how PROXY headers are trusted.

**Decision:**
- **One connection path.** DoT is the TCP listener with a TLS acceptor (ALPN `dot`) in front; the TCP code now serves any stream, so pipelining, out-of-order answers, idle and in-flight limits are identical. DoH is hyper (HTTP/2 by ALPN `h2`, else HTTP/1.1; both already in the tree via axum) over the same TLS setup, calling the same `QueryHandler`. No new crates: rustls, tokio-rustls, hyper, hyper-util, rustls-webpki were already dependencies.
- **Client IDs come from the certificate.** If the leaf certificate has a wildcard name `*.X` and the SNI is `<label>.X`, the label is the client ID. No `server_name` setting to keep in sync with the certificate. The DoH path `/dns-query/<id>` wins over SNI. IDs are one DNS label, lowercased, carried inline in `RequestMeta` (a 64-byte `Copy` value, no allocation).
- **Certificate reload:** each TLS listener polls its two files' (mtime, length) every 10 s and swaps the `CertifiedKey` behind a `ResolvesServerCert`; new handshakes use it, open connections keep theirs; a failed read keeps the old one. Polling (not inotify) works with Kubernetes Secret symlink swaps and needs no new dependency.
- **DoH responses:** `Cache-Control: max-age` = min(answer/authority TTL, negative TTL), `max-age=0` without records. Requests the resolver never sees: wrong path or invalid client ID → 404, wrong media type → 415, other methods → 405 with `Allow`, bad base64url or shorter than a DNS header → 400, body over 64 KiB → 413. A handler `Drop` (e.g. rate limit) → 503.
- **PROXY protocol v2 only, and mandatory when enabled.** A listener with `proxy_protocol = true` reads a v2 header before TLS on every connection and closes connections without one (accepting both would let clients pick their address). v1 text headers are refused. `LOCAL` keeps the socket address. TLVs are skipped. There is no source allowlist: exposure must be limited by the network (documented).
- **Telemetry:** `Proto` gains `dot` and `doh` (metrics labels, query log, aggregates). Rollup rows carry a transport-column count (format version 2); version-1 rows still decode.
- **Helm:** `encrypted.dot` / `encrypted.doh` add ports to the same DNS LoadBalancer (so `externalTrafficPolicy: Local` keeps client IPs), with a certificate from an existing Secret or a cert-manager `Certificate`; pods listen on 8853/8443 unless on the host network.

**Consequences:** Clients must trust the certificate (a public CA, or a private one distributed to devices). DoQ and DoH3 remain skipped until their listeners (M7).

## ADR-040 — Config made through the API before clustering: managed entries in state.db (Proposed)
**Context:** API-002 (everything configurable through the API) and API-010 (name a device from the UI) need API writes now. Today the configuration is files only (on Kubernetes, the chart's values), and `spec/12` describes the end state: a change log held by the cluster primary, with GitOps mode refusing writes. Rewriting config files from the server would fight GitOps and lose comments.

**Decision:**
- **Managed entries, merged by name.** Entries written through the API are stored in `state.db` (`managed(kind, name, body JSON, updated, updated_by)`), starting with `client`. At every load (startup, `SIGHUP`, an API write) the effective config is the files plus the managed entries whose names the files don't use. The files are authoritative: file entries are read-only through the API (409), and the API can't create a name the files use.
- **Never breaks DNS.** If the merged config doesn't validate (a group a managed device names was removed from the file), the files alone are used and the reason is logged until it's fixed (rule 5). API writes are validated against the full resulting config before they're stored (422 with the field).
- **Write semantics that map onto the future change log:** one `config_version` counter in `state.db`, bumped by every write and returned as the `ETag` of `GET /clients` and in each response; `If-Match` refuses stale writes (412 `version_conflict`); `?dryRun=true` validates and reports (before/after, warnings, and an impact estimate: recent queries from the matched addresses, from the aggregator's current and previous hour) without storing; `Idempotency-Key` stores the first successful response for 24 h per user and replays it (a different request with the same key is 409). Writes need operator (or a `write` token) and are audited (`client.put`, `client.delete`) with their author.
- **Applying:** the API stores the entry, then asks the main loop to reload (the same path as `SIGHUP`, minus its own audit entry), and answers after the swap.
- **Names are resolved at read time** from the address (the query log stores addresses, not names; the old lookup by the client's index at query time mislabelled history after any client list change), so naming relabels history and live views at once.

**Consequences:** With clustering (M5), the managed table becomes change-log entries on the primary and replicates (CLU-003); GitOps mode will refuse these writes (`409 gitops_managed`). Other kinds (groups, records, routes; T3.12) reuse the same table and endpoints.

## ADR-041 — Importing zones: per-name local records, not a whole-zone authority (Proposed)
**Context:** The owner is moving the internal `sororlab.dev` zone from Technitium (split-horizon: the same domain is public in Route 53). T6.4 (Technitium importer) covers zones as "local names and routes". Technitium is authoritative for the whole zone (unknown names get NXDOMAIN); TelltaleDNS local records are per name (unknown names go upstream).

**Decision:** `telltale import zone FILE` converts RFC 1035 zone files (Technitium export, BIND, PowerDNS) into `[[record]]` TOML for the supported types (A, AAAA, CNAME, PTR, TXT, MX, SRV), skips SOA/NS at the apex, and lists everything else in a header report; the output is validated as config before it's written. Imported names behave as per-name local records, so unimported names under the zone fall through to the upstreams (the owner chose this: public-only hosts keep working from inside). A "this server owns the whole zone" mode (NXDOMAIN for unknown names) belongs to T3.12's zone-lite view.

**Consequences:** The rest of T6.4 (forwarders and conditional forwarders → upstreams and routes, block/allow lists, and a Technitium API source) remains open. Moving a zone: import, add the records while keeping the route to the old server (local records win over routes, so anything missed still resolves there), compare answers name by name, then remove the route.

## ADR-042 — Names on my network and forwarded domains through the API (Proposed)
**Context:** T3.12 (API-011, DNS-010, UPS-007) needs local names and conditional forwarding editable from the UI and the API, following ADR-040's managed entries.

**Decision:**
- **Two more managed kinds:** `record` (an owner name and the set of its records; a write replaces the set) and `forward` (a domain and its servers). A forward expands at merge time into upstreams `forward:<domain>#n` (a bare address means `udp://`), a `failover` upstream group `forward:<domain>`, and a route for the domain with a DNSSEC negative trust anchor (internal domains are usually unsigned). The names are reserved for this purpose.
- **Files win:** a name with any file `[[record]]`, or a domain any file route matches exactly, is read-only (409). Validation runs the whole merge (files + every API entry + this change) through config validation and the local-record value parser, so a bad value is a 422 with the field, before anything is stored.
- **Zone-lite, not zones:** the UI groups names by their parent domain and never asks for SOA or NS. Per-name answers fall through to upstreams for unknown names (ADR-041); a whole-zone authority mode stays deferred.
- **Endpoints:** `GET /records`, `PUT`/`DELETE /records/{name}`, `GET /forwards`, `PUT`/`DELETE /forwards/{domain}`, with the device endpoints' dry-run, `If-Match`, idempotency, operator role, and audit (`record.put`, `forward.delete`, ...). The write path is shared code.
- **Applying** reuses the reload path; a forward change rebuilds the upstream router (health state of unchanged upstreams is rebuilt too, as on any upstream change).

**Consequences:** The UI covers the common cases without the config file. Hosts files stay file-only. The MCP tools for these writes come with T6.6 / M7.

## ADR-043 — Anomaly engine v1: concrete detectors, thresholds, and persistence (Proposed)
**Context:** T3.13 implements OBS-013 under ADR-019 and `spec/06` §7.1, which fix the principles (deterministic, explainable, learn first, bounded, alert-only) but not the statistics, thresholds, or how state survives restarts.

**Decision:**
- **Statistics:** exponentially weighted mean and mean absolute deviation (MAD-style) per baseline, `f32`, plain IEEE arithmetic only (no `exp`/`ln`), FNV-1a hashing, ordered maps, event-time windows (an hour closes when an event from a later hour arrives). Findings are byte-identical across runs and architectures (a golden file checked on x86-64 and arm64 in CI).
- **Detectors and bars** (sensitivity `normal` = 6 × spread; `low` 8, `high` 4): rate spike per hour of day (≥ 300/h, ≥ 2× usual, > usual + k·spread; spread ≥ max(10, 25% of usual)); domain volume per tracked (device, eTLD+1) pair (≥ 200/h, ≥ 3× usual, pair tracked ≥ 24 h; spread ≥ max(5, 25%)); drift (≥ 20 new registrable domains a day, > usual + k·spread; day one isn't part of the baseline); beacon (≥ 10 gaps of 30 s–1 h with σ ≤ max(5% of the period, 2 s) for 4 consecutive hours, only when the pair wasn't periodic during learning, which keeps TTL-driven refreshes quiet). A rate spike that domain findings explain (≥ 50% of the excess) is reported only as those. Alerted windows don't update their baseline.
- **eTLD+1** is approximated without the Public Suffix List: the last two labels, or three under common second-level suffixes (`co.uk`, `com.au`, ...); reverse names are skipped.
- **Bounds:** 16 tracked pairs, 128 learned fingerprints, 24 hourly baselines per device (≤ 4 KiB, tested); 1024 devices by default, least recently seen evicted (counted).
- **Persistence:** the whole engine as JSON in `<data_dir>/anomaly.json`, written hourly and on shutdown (temp file + rename); `float_roundtrip` keeps reloads bit-exact. Unreadable state just restarts learning.
- **Surfaces:** `GET /api/v1/analytics/anomalies?since=`, the Anomalies page, `telltale_anomalies_total{kind}` with a chart alert (`TelltaleDNSDeviceAnomaly`, info), and later the `find_anomalies` MCP tool (T6.6). Off at privacy level 3.

**Deferred:** the TTL-violation flag (events don't carry answer TTLs yet), per-group sensitivity, mute/acknowledge, and the alert-rule engine's own destinations (OBS-010).

## ADR-044 — Cluster channel v1: identity files, reusable join tokens, and peer trust (Proposed)
**Context:** T5.1 implements CLU-001 under `spec/12` §3, which fixes the shape (Ed25519 CA, join token with CA fingerprint + URLs + secret, 90-day node certificates, mTLS over HTTP/2 with protobuf, persistent streams, replicas dial out) but not the token format, how peers name each other in TLS, where identity lives, or whether a token is single-use.

**Decision:**
- **Token:** `tt_join_` + base64url(JSON `{v, cluster_id, cluster_name, ca_fp, urls, secret, exp}`) (the spec's `vgl_join_` predates the rename). Tokens are **reusable until they expire**, because `spec/12` §3 has every Kubernetes pod join with one long-lived token from a Secret. The primary stores only SHA-256 hashes of token secrets (`tokens.json`) and compares them in constant time.
- **Join:** the joining node pins the CA by fingerprint against the chain the server sends (CA included), so the secret is never sent to a server outside the cluster. The primary picks the certificate's names itself, ignoring names in the CSR.
- **Peer names:** every node certificate carries `cluster.telltale.invalid` and `<node-id>.node.telltale.invalid` (plus its advertise hosts). Peers verify against the cluster CA and the shared name, so trust doesn't depend on the address a peer was dialed at (LAN IP, ingress, NAT). The peer's node ID comes from its certificate, and its Hello must match it. Node ID = the first 16 hex digits of SHA-256(public key).
- **Identity on disk:** `<data_dir>/cluster/{cluster.json, ca.crt, node.crt, node.key, ca.key (primary only), tokens.json}`, keys mode 0600, atomic writes. `telltale cluster init|join` write it, and the server reads it at startup (a restart joins the channel).
- **Wire:** 4-byte big-endian length + prost `Frame{Hello|Heartbeat}`, 1 MiB frame limit, `POST /cluster/v1/stream` with a streaming body in both directions, heartbeats every 5 s, peer down after 15 s, reconnect with full-jitter backoff (1 s doubling to 30 s). `POST /cluster/v1/join` is the only route served without a client certificate.
- **Port:** `[cluster] listen`, default `0.0.0.0:8443` per `spec/12`. That is the same port our docs use for DoH, so `telltale config check` warns about the clash rather than changing either default.
- **Dependencies:** `prost` is new (pure Rust; frames only, no codegen step); `rcgen` moves from dev-only to runtime for issuing certificates.

**Deferred:** certificate renewal at 2/3 of life and CA rotation (with T5.4 promotion, since only the CA holder can issue), eligible-to-eligible streams, and ephemeral Kubernetes members joining from a Secret at startup (T5.10). The cluster health page and per-peer lag (T5.9); heartbeats carry `qps`, which is still 0.

## ADR-045 — Sign-in across cluster nodes: replicated identities, per-node sessions and OIDC callbacks (Proposed)
**Context:** `spec/12` §6 says users, RBAC, and OIDC config are part of the replicated config, so sign-in works on every node even with the primary down. It doesn't say where sessions live, how one OIDC client serves several nodes reached at different URLs, or what happens to users that already exist on a node that joins (the owner's homelab node has its own users, and the Pi got its own admin before clustering).

**Decision:**
- **Replicated from the primary (with T5.2, writes forwarded by T5.7):** local users (Argon2id hashes, roles, TOTP secrets), API-token hashes and scopes, OIDC provider settings and group-to-role rules, and the session-revocation list. So a break-glass local admin works on every node, even when the identity provider is down.
- **Per node, never replicated (CLU-006 node-local keys):**
  - `auth.oidc.public_url`, because each node is reached at its own URL, and each one is registered as a redirect URI on the same OIDC client (`<public_url>/api/v1/auth/oidc/{id}/callback`);
  - the OIDC client secret file, because secrets stay in each node's own Secret or file and never cross the cluster channel.
- **Sessions are per node.** Signing in to a second node with SSO is a silent redirect (the provider already has a session). There is no shared session-signing key to protect or rotate. Sign-out and revocation replicate, so revoking a user ends their sessions everywhere within one sync.
  - If the owner later puts one hostname in front of several nodes without sticky sessions, cluster-signed session tokens (signed with the cluster key) are the follow-up; that's not needed for the hybrid Pi + k8s setup.
- **Join merges identities once:** on its first sync, a joining node offers its local users and tokens to the primary.
  - A user that doesn't exist on the primary is added.
  - A name that exists on both keeps the primary's record, and the joiner's copy is listed under Conflicts. Nothing is silently dropped.
  - After that, the primary is the only source.

**Consequences:** the owner registers one extra redirect URI in Authentik per node (for the Pi, e.g. `https://telltale-pi.sororlab.dev`, or its LAN address). The Pi's OIDC needs its own copy of the client secret.

## ADR-046 — Version management: one build identity, a signed release index, and update status everywhere (Proposed)
**Context:** owner request 2026-10-04: the user should always know which version they run, which versions exist, and whether they're on the latest, the same way on every architecture and install type. Today an edge binary reports only `telltale 0.1.0` (the Pi shows exactly that), so two different builds look identical, and nothing tells the user an update exists.

**Decision:**
- **One build identity, stamped by CI into every artifact from the same commit** (the amd64, arm64 and armv7 binaries and the multi-arch image):
  - **version:** the tag's semver for releases; `<next>-edge.<run>` for main builds, e.g. `0.1.0-edge.47`;
  - **commit:** short SHA;
  - **build date**, and **channel** (`stable` or `edge`);
  - **target:** e.g. `aarch64-unknown-linux-musl`;
  - **install type:** `native`, `container` or `helm`, from an environment variable the systemd unit, Dockerfile and chart set.
  `telltale --version` prints all of it on one line. A local dev build says `dev` and its commit, so it's never mistaken for a release.
- **Where it shows:**
  - the UI footer and an About/Updates panel under Settings;
  - `GET /api/v1/system/info` (`build {...}`);
  - the metric `telltale_build_info{version,commit,channel,target} 1`;
  - each node's Hello on the cluster channel, so the Cluster page lists every node's version and flags mixed versions (CLU-010: N/N-1 only, replicas upgrade first);
  - an MCP tool later.
- **Which versions exist:** every release publishes a signed `releases.json` next to `SHA256SUMS`, signed with the same minisign key. It lists the channel, version, date, commit, notes URL, assets per architecture with hashes, and the oldest version it can upgrade from. The `edge` index lists the latest main build. Clients trust only a verified index, never the GitHub API's unsigned listing.
- **Latest or not:** a node fetches its channel's index once a day (`[updates] check = true` by default; off for air-gapped or privacy-strict sites; through the normal HTTP client, never blocking DNS) and compares semver within its channel; edge compares by run number.
  - **Status:** `up to date`, `update available <version> (<date>)`, `newer than the index` (a dev build), or `unknown` (check off or failing; the last success time is shown).
  - The status is in the UI, in system info, and in `telltale_update_available 0|1`, with an optional info-level alert.
- **How to update, per install type:** the panel shows the right step. Native: `sudo telltale self-update --restart`. Compose: `docker compose pull && docker compose up -d`. Helm: the chart version and `helm upgrade`, or bumping it in GitOps values. A cluster gets the replicas-first order.
  - The UI never self-updates a node: replacing the binary needs root, and container installs are the orchestrator's job.
- **Architecture independence:** one index serves all architectures; a node picks its asset by target. Versions and commits are identical across architectures because CI builds them all from one commit in one workflow (already true of `image.yml`). The image tag and the binary version always match.

**Consequences:** small CI changes (stamp the version; generate and sign `releases.json`), a `[updates]` config section, and the API/UI/metric fields. `telltale self-update` switches from reading `SHA256SUMS` to reading the index (same signature check).

## ADR-047 — Config replication v1: whole-version manifests, shared vs node-local sections (Proposed)
**Context:** T5.2 implements CLU-003 under `spec/02` §5 and `spec/12` §4. Those describe a change log of semantic ops (JSON-Patch) that replicas replay, with a full snapshot as fallback. They don't say which settings are node-local before T5.5, how UI/API-made entries (ADR-040) replicate, or what a replica does with its own lists and config file.

**Decision:**
- **Whole versions, not ops (for now).** Each change produces a new manifest `(epoch, seq)` naming the complete shared configuration as one blob (canonical JSON, a few KB) and the filter snapshot's blobs. A replica converges to the newest manifest from any state, including after a long partition, with no log to replay or compact. BLAKE3 content addressing keeps transfers incremental: a config change ships one small blob, and a list change ships only the FST shards that changed.
  - **Measured:** p95 190 ms over a simulated 50 ms RTT (the AC is 5 s). On two local processes, a primary edit was answered by the replica 0.39 s later.
  - The per-change log (author, op, timestamp) with orphan detection is still needed for fencing and conflicts (T5.4); it will ride alongside, recording what each version changed.
- **Shared vs node-local:** node-local = `config_version`, `node`, `cluster`, `listen`, `api`, `auth`, `telemetry`, `cache` (a superset of CLU-006's list: sign-in stays local until ADR-045 replicates identities). Everything else is the primary's *effective* configuration: files plus UI/API entries (ADR-040), so devices named on the primary reach every node.
  - A setting the replica doesn't recognize (a newer primary) fails validation, and the replica keeps its last version rather than dropping it silently.
  - T5.5 adds the explicit `node.toml` allow-list and the startup error for overriding shared keys.
- **Signing:** manifests are signed with the cluster CA's Ed25519 key and verified against the CA certificate every node already has. `spec/12` mentions a separate signing key rotated with the CA; this reuses the CA key until CA rotation (T5.4) needs the split.
- **Replica behavior once synced:**
  - its effective configuration = its own node-local sections + the primary's shared ones;
  - its own list fetcher stops, and it installs the primary's snapshot as `snapshots/<version>`;
  - it refuses API config writes with 409 `conflict` naming the primary, until T5.7 forwards them;
  - it records the applied manifest in `cluster/applied.json` and serves it at cold start without contacting the primary (CLU-004).
  - Until its first sync, a new replica runs on its own configuration (DNS keeps filtering while it joins).
- **Primary:** checks twice a second for a changed shared configuration (by hash) or a new snapshot, and republishes with `seq + 1`, persisted in `cluster/published.json`. Peers get the current manifest when their stream connects, and every new one at once. Replicas report their applied `seq` in a heartbeat sent immediately after applying, so lag is visible without waiting for the 5 s tick.

**Consequences:** with the Pi as primary, the homelab node's GitOps values for shared sections stop applying once it syncs. The Pi's config file (or UI) becomes the place to change shared settings, until write forwarding (T5.7) and a GitOps primary option are settled with the owner.

## ADR-048 — Config authority: the cluster, not whichever node is primary, decides where configuration comes from (Proposed)
**Context:** owner question 2026-10-04: in a mixed cluster (a Kubernetes node managed by GitOps plus a Pi edited by hand), nothing stops the wrong node from becoming primary, by `cluster init` on it, a promotion during an outage (T5.4), or a quorum election. That node would then replicate its own file over the GitOps one: every node follows a config nobody committed, and the next GitOps sync fights it. Recency or availability must not decide what the source of truth is; the operator does, once.

**Decision:**
- **The cluster records its config authority** in its signed cluster state, set at `cluster init`. It is either:
  - `gitops`, which names the source (e.g. `homelab-charts:charts/argocd-apps/values.yaml#telltaledns`); or
  - `api`: the primary's file plus UI/API edits, as today.

  The authority can only be changed by an explicit, audited `telltale cluster set-authority` run on the current primary, which bumps the epoch.
- **Each node declares how its own configuration is managed** with `[cluster] config_source = "gitops" | "file"` (the Helm chart sets `gitops`), and reports it in its Hello. The Cluster page shows it next to every node.
- **Only matching nodes may be primary.**
  - Under `gitops` authority, only `gitops` nodes are eligible to publish configuration: `cluster init` on a non-GitOps node refuses `--config-authority gitops`, and elections and promotions skip ineligible nodes.
  - Under `api`, any eligible node may be primary.
- **Emergency primaries never change configuration.** If every authority-matching node is down, an operator may still promote another node (`telltale cluster promote --emergency`). It keeps nodes coordinated (leases, certificates, alerts) but publishes nothing new.
  - Every node keeps serving the last authoritative version, the API stays read-only, and the UI says so ("GitOps primary unreachable since …").
  - When an authority-matching node returns it takes over again automatically; the emergency primary had no writes, so nothing is orphaned.
- **Manifests carry their provenance:** the authority, the source, and, for GitOps, the revision (commit) the primary loaded. A replica rejects a manifest whose authority differs from the cluster's. The UI shows "configuration from homelab-charts @ <commit>" on every node.
- **GitOps write rules** (OPS-005) apply cluster-wide: under `gitops` authority, API config writes on any node return `409 gitops_managed`. Operational actions (pause blocking, flush cache, list refresh) still work. Node-local settings stay in each node's own file in both modes.
- **Mixed architectures are supported.** Every replicated blob is architecture-independent: the FSTs, list sets written as explicit little-endian, and JSON. The cluster's anomaly golden-file check already runs on amd64 and arm64. A cross-architecture snapshot test (compile on amd64, load and match on arm64 and armv7) joins CI with T5.11.

**Consequences:**
- A misconfigured or recovering node can't silently take over the configuration.
- The price is that with a GitOps authority, configuration is frozen (never lost or wrong) while no GitOps node is up. That is the right trade for a homelab where the k8s node is the one being changed.
- Implemented with T5.4 (elections and promotion) and T5.7 (writes); until then the owner's cluster uses the convention of the homelab node as primary, set up by hand.

## ADR-049 — Git as the cluster's config source: the primary fetches, the cluster distributes (Proposed)
**Context:** owner idea 2026-10-04, building on ADR-048: let nodes that aren't in Kubernetes (the Pi) also take their configuration from the Git repository, an "external control plane" every node sources from. Two shapes were weighed:
1. **Every node pulls Git.** Rejected as the default:
   - nodes poll on their own schedules, so they run different commits for a while and "which config is live?" has no single answer;
   - every node needs repository credentials, outbound internet, and a Git client;
   - a GitHub outage or rate limit hits each node separately;
   - the DNS server has to resolve the forge's name to fetch its own config.
2. **Git is the authority; the cluster distributes.** Chosen.

**Decision:**
- **A `git` config source.** On the primary, `[cluster.config] source = "git"` with `repo` (HTTPS), `ref` (branch or tag), `path` (a TelltaleDNS TOML file holding the *shared* sections), an optional `credentials_file` (read-only deploy key or token, never in the repo), and `poll` (default 60 s; a push webhook endpoint can trigger a fetch early).
- **The primary fetches; the cluster distributes.**
  - The primary fetches the file at the ref's current commit, over HTTPS through the bootstrap resolvers (as list downloads do, UPS-009).
  - It validates the file merged with each node's local sections and publishes the result as the usual signed manifest (ADR-047), recording provenance: repo, path, commit SHA, commit author, and commit time.
  - Replicas follow over the cluster channel unchanged, so every node converges to the same commit, lag is visible, and nodes keep the last good version when GitHub or the link is down (CLU-004).
- **Any Git-capable node can be primary.** Under ADR-048, a `gitops` authority now names the repository rather than a kind of node. Any eligible node that has the source configured and can reach it may publish: the Pi becomes a valid primary for a GitOps cluster, which removes most of ADR-048's frozen-config case. A node configured without the source stays ineligible.
- **Guardrails:**
  - **Pinned source:** `repo`, `ref` and `path` are pinned in the signed cluster state; changing them is a `cluster set-authority` operation.
  - **Optional commit signatures:** `require_signed = true` with an allowed-signers file (SSH or GPG keys) accepts only commits signed by those keys. Without it, anyone who can push to the repository controls DNS on every node, which is already true for Argo-managed nodes; this makes it explicit and enforceable. The UI and docs recommend it.
  - **Validate before publish:** a commit that fails validation is never published; the cluster stays on the last good commit and raises an alert naming the commit and the error.
  - **History only moves forward:** a force-pushed or rewound ref is refused unless `allow_rewind = true` (rollbacks are new commits).
  - **Bounded fetch:** size limit, timeout, TLS with system roots, no submodules, no LFS.
  - **No secrets in the repository:** config refers to secret files (as `client_secret_file` already does).
  - **Audit:** every published commit is in the audit log with its SHA and author.
- **Direct-pull fallback (off by default):** `[cluster.config] direct_fallback = true` lets a replica cut off from every primary for longer than `fallback_after` (default 1 h) fetch the same pinned source itself, with the same signature and validation rules. It applies the result locally only, and drops it when the cluster channel returns.
- **Repository layout:** the shared configuration lives in a plain file (e.g. `telltale/shared.toml`) instead of TOML embedded in Argo values. The k8s chart reads the same file (an Argo multi-source app, or the chart's `configFiles`), so one artifact feeds both the primary's Git source and Kubernetes. Each node's own settings stay in its local config or Helm values.
- **Writes:** under a Git source the API is read-only for shared configuration (`409 gitops_managed`, OPS-005). The UI offers "propose this change" as a patch or a link to the file on GitHub, never a direct commit (writing to the repository is out of scope for v1).

**Consequences:**
- Config changes for the whole cluster are Git commits, reviewed and versioned like the rest of the homelab.
- The cluster runs one fetcher, and every node shows which commit it serves.
- New: a small Git-over-HTTPS fetch (no Git binary), signature verification (SSH signatures via the existing crypto, GPG optional), and a webhook endpoint.
- Builds on T5.2 (replication) and T5.4 (authority and elections); it is T5.12.

## ADR-050 — Network groups: groups match subnets, and groups are an analytics dimension (Proposed)
**Context:** owner request 2026-10-05: categorize devices by VLAN (Management 192.168.1.0/24, IOT .2, AUX .3, LAB .5, SONOS .6, Surveillance .7, Trust .10) and see, per category, what traffic each kind of device makes.
- **Today:** a subnet can only be matched by a `[[client]]` entry (`match = ["192.168.2.0/24"]`). That entry also *names* every device in it, so the query log would show "IOT" instead of each device.
- **Groups:** they carry filtering (their lists, block mode), but they're not a first-class dimension in analytics. Per-group data exists internally (time series and blocked counters) without a UI or API around it.

**Decision:**
- **`[[group]] networks`:** a group lists the IPs and CIDRs whose devices belong to it, e.g. `networks = ["192.168.2.0/24"]`. A device gets the group of the most specific matching network.
  - An explicit `[[client]]` entry with `groups` still wins.
  - A `[[client]]` entry *without* `groups` keeps its network's group: naming a device no longer moves it to `default`.
  - Networks must not overlap at the same prefix length (validation error naming both groups).
  - Groups without `lists` keep using every list, so grouping for visibility never changes filtering unless the owner says so.
- **Groups as a dimension everywhere:**
  - the dashboard gets a "Traffic by group" chart and a group filter for every widget (top domains, top blocked, top clients, latency);
  - the query log gets a group filter and a colored group chip per row;
  - the Groups page shows each group's networks, active devices, queries, block rate, and top domains and blocked names;
  - anomaly findings name the group;
  - the API gets `group=` on stats, top, and query endpoints;
  - each group has a color, used consistently in charts and chips;
  - metrics: `telltale_group_queries_total{group,status}` (bounded: groups are capped at 64), next to the existing `telltale_blocked_total{group,list}`.
- **Replication:** groups and networks are shared configuration (ADR-047), so every cluster node attributes devices the same way.
- **Later:** importing VLANs from a router (UniFi networks, OPNsense interfaces) into groups, with the router integrations (M8). The owner's UniFi connector makes this a natural follow-up.

**Consequences:** "which kinds of devices talk to what" becomes one click (e.g. IOT: 38% of queries, 21% blocked, top: amazon devices and Roku telemetry). Per-device names keep working inside each group. The owner's setup needs seven `[[group]]` entries in homelab-charts and nothing else.

## ADR-051 — Manual failover v1: roles and epochs, key sharing with eligible nodes, fencing, orphaned versions (Proposed)
**Context:** T5.4 implements CLU-005 under `spec/12` §5 and ADR-048. The owner's topology is two eligible nodes and no witness, so the `manual` mode comes first: T5.4 is split into **T5.4a** (manual promotion, fencing, conflicts, config authority) and **T5.4b** (witness and quorum election with leases, plus the `telltale-sim` partition checker). T5.1–T5.2 tied "primary" to "holds the CA key", which makes promotion impossible.

**Decision:**
- **Role is explicit:**
  - `cluster.json` gains `role` (`primary` or `replica`) and the `epoch` the role belongs to.
  - A node publishes only while it's `primary` in the highest epoch it has seen.
  - Every Hello, heartbeat and manifest carries the sender's epoch.
- **Signed member registry:** each manifest carries the node registry (ID, site, eligible, advertise URLs), signed with everything else. The primary records nodes as they join (`nodes.json`). Every node then knows every eligible node and its URLs, so replicas can find a new primary without a new token.
- **Eligible nodes hold the signing key** (`spec/12` §4).
  - The primary sends the CA key over the mTLS stream to peers that the registry marks eligible and that are connected with a certificate for that node ID.
  - It's stored owner-only like the primary's.
  - Non-eligible nodes (Kubernetes resolver pods, CLU-009) never receive it.
  - A promoted node can then sign manifests and issue certificates. Compromising an eligible node compromises the cluster, which is the same trust the spec gives eligible nodes. Rotation comes with the CA rotation in T5.4b.
- **Who dials whom:**
  - Replicas dial the current primary: the highest-epoch node known as primary first, then the other eligible URLs.
  - Eligible nodes also keep a stream to every other eligible node, so a returning old primary learns about a newer epoch right away.
- **Manual promotion:**
  - **How:** `telltale cluster promote` on an eligible node, or the Cluster page's "Promote this node" (admin; T5.7 adds TOTP confirmation).
  - **What it does:** sets `epoch = max seen + 1` and `role = primary`, then starts publishing at once without a restart. The first manifest of the new epoch records its **base**: the `(epoch, seq)` it had applied.
  - **Refused when:**
    - the node isn't eligible;
    - it lacks the key;
    - it's not authority-matching under ADR-048: a `gitops` cluster needs `config_source = "gitops"` on the node, unless `--emergency`.
  - **Emergency primaries** coordinate but publish no new configuration: every node keeps the last authoritative version.
- **Fencing:** a node that sees a higher epoch (in a Hello, heartbeat or manifest) stops publishing and becomes a replica of that epoch's primary at once. Snapshots and manifests from a lower epoch than a replica's applied one are rejected.
- **Orphaned versions** (`spec/12` §5 rule 3):
  - When a fenced old primary had published versions in its epoch after the new primary's base, it keeps the last one under `cluster/conflicts/` (manifest, config blob, and the changed paths compared with the new primary's version).
  - It shows them on the Cluster page under **Conflicts**, and in `GET /api/v1/cluster`. They are never applied silently.
  - Re-applying a conflict on the current primary arrives with write forwarding (T5.7); until then the page shows what changed, and the owner re-makes the change on the primary.
- **Config authority (ADR-048):**
  - `cluster init --config-authority gitops|api` is recorded in the signed registry (default `api`).
  - `[cluster] config_source = "gitops" | "file"` is node-local (the Helm chart sets `gitops`), reported in Hello, and shown per node on the Cluster page.
  - Under `gitops` authority, API config writes return `409 gitops_managed` on every node.

**Consequences:**
- With the owner's homelab node as the GitOps primary, the Pi becomes an *emergency* primary candidate: if k8s is down for long, promoting the Pi keeps the cluster coordinated while configuration stays frozen. ADR-049 (Git source) later makes the Pi a full candidate.
- Existing clusters migrate in place: the CA holder becomes `role = primary` at epoch 1, and eligible replicas receive the key on their next connection.

## ADR-052 — Node-local overrides: node-only records, and warn (not refuse) on shared settings in a replica's file (Proposed)
**Context:** T5.5 (CLU-006). `spec/12` §4 says a node's own overrides allow listen addresses, cache size, query-log retention, worker count, site, and local-only records, and that overriding anything else is "rejected at startup with a clear error". ADR-047 already makes the node-local sections (`node`, `cluster`, `listen`, `api`, `auth`, `telemetry`, `cache`) stay with each node, and replaces everything else with the primary's.

**Decision:**
- **Node-only records:** `[[record]] node_only = true` keeps a record on the node whose file has it. A primary leaves it out of the shared configuration, and a replica keeps its own node-only records next to the cluster's.
- **Shared settings in a replica's file are ignored and reported, not refused.**
  - At every load the replica logs a warning naming the sections.
  - The Cluster page gains a failing `node_settings` check with the fix (remove them, or mark node-only records).
  - The spec's "reject at startup" would make a node's upgrade, or a cluster join, refuse to start over settings that have no effect. DNS would stop over a cosmetic problem, against rule 5 and CLU-004. The owner's Pi is exactly this case: its file predates joining.
- No separate `node.toml` file is needed: a node's own config file plays that role, and the node-local sections are already defined by ADR-047.

**Consequences:** the owner's Pi shows a failing `node_settings` check until its file is trimmed to node-local settings. Promoting to the spec's strict refusal stays possible later, as an opt-in `[cluster] strict_overrides = true`.

