# 11 — Architecture Decision Records

Format: Context → Decision → Consequences. New ADRs append here (`ADR-0NN`). An agent must not contradict an accepted ADR without adding a superseding ADR and flagging it to the owner.

## ADR-001 — Language: Rust (Accepted)
**Context:** Performance and footprint are paramount: a small, steady memory footprint on a Raspberry Pi and microsecond cache hits. That rules out garbage-collection pauses and runtime memory overhead, and we want memory safety at the same time.
**Decision:** Rust (stable, 2024 edition), tokio, rustls (ring or aws-lc-rs backend), quinn.
**Consequences:** No GC, static musl binaries, memory safety, and a mature DNS crate ecosystem (hickory). Compile times are slower and the contributor pool is smaller. `unsafe` is confined to `telltale-net`.

## ADR-002 — Custom hot-path wire handling; hickory for the long tail (Accepted)
**Context:** Full decode/encode per query costs allocations and µs. Cache hits only need the header, question, and TTL offsets.
**Decision:** `telltale-proto` handles the hot path zero-copy. `hickory-proto` is used for DNSSEC, zone files, and complex record handling.
**Consequences:** Two code paths, so cross-checking them against each other is part of fuzzing (differential fuzz: both parsers must agree on header, question, and EDNS).

## ADR-003 — FST + regex DFA snapshots, compiled off-path (Accepted)
**Context:** Pi-hole keeps lists in SQLite with a verdict cache, and Technitium keeps them as in-memory zones; both suit their designs. TelltaleDNS's goals (multi-million-name lists on a Pi, lookup cost independent of list size, no pause during updates) call for a compiled index.
**Decision:** Immutable, mmappable FST snapshots (reversed-label keys) + a multi-pattern lazy DFA, built in the background and swapped atomically.
**Consequences:** ~10× less memory per domain, O(|qname|) lookups, and instant reloads. Snapshots are immutable, so every edit triggers a recompile. To keep manual rule edits instant, a small **overlay** (a HashMap of manual rules) is consulted before the FST and folded into the next compile.

## ADR-004 — Container-first distribution, Kubernetes-first operations (Accepted)
**Context:** The owner prioritizes Kubernetes and also runs a Raspberry Pi. Native packaging and installers per distro are costly to build and keep working.
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
**Context:** Pi-hole keeps long-term history in SQLite, and Technitium hands per-query logs to database apps. TelltaleDNS wants 30-day searches in seconds on a Pi with no external database, and DuckDB/ClickHouse are too large for a Pi.
**Decision:** Hourly columnar segments with dictionary encoding, a block index + bloom filters, and zstd, plus SQLite rollups. Parquet export for external analysis.
**Consequences:** We own a storage format (versioned, fuzzed, with a migration tool). Search is fast via dictionary-first predicate evaluation. External SQL access goes through export or the API, not live SQL.

## ADR-007 — Plugins out-of-process (socket/exec) first, WASM later (Accepted)
**Context:** The owner needs custom upstreams. A plugin loaded into the resolver's process would share its memory and its fate: a crash or a leak there takes DNS down.
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


**Addendum (2026-10-05, T6.10, Proposed):**
- **Navigation:** the header keeps five main pages. The reference pages (Configuration, Glossary, Standards, For nerds) go in one "Reference" menu. GitHub and the theme are icon buttons. Below 860 px the nav folds into a ☰ menu. The menu is built on `<details>`, so it works without JS; `site.js` only closes the ☰ menu on narrow screens and the Reference menu on Escape or an outside click. This replaces the wrapping row of nine links.
- **For nerds page (`nerds.html`):** generated from `site/data/architecture.json`. The build checks it against the repo and fails on any disagreement, and CI runs that check (`site/build.py --check`). The checks:
  - every crate under `crates/` is described, and nothing else is;
  - the listed public types exist in their crate;
  - ADR and requirement IDs exist in `spec/11`, `spec/01` and `spec/13`;
  - `code` paths exist;
  - stack entries name real dependencies.
- **Read from the repo, not the JSON:**
  - dependency arrows ("uses" and "used by") from the crates' `Cargo.toml` files;
  - line counts;
  - the budgets, from `spec/00` §5.
- **Interaction:** the map's crates are plain links to their descriptions further down. `assets/nerds.js` adds the side panel and edge highlighting.
- **Pages deploys:** they now also run on `crates/**`, `spec/**` and `Cargo.toml` changes, so the line counts and arrows stay current.
- **Contrast:** small accent-coloured text (section eyebrows) uses `--accent-text` (5.2:1) in the light theme.
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

**Implementation (T9.1, 2026-10-06):**
- Users, recovery codes, and tokens travel as one JSON blob (`identities.json`) named by the signed manifest. Replicas take it in one transaction, keyed by user name; rows carry an `origin`: `cluster` or `local`.
- Changed from the decision above, to keep the change small: replicas **refuse** identity changes (409, naming the primary's site) instead of forwarding them.
- Changed from the decision above: users only on a replica **stay local** instead of being offered to the primary once. They keep working on that node; to share one, make it on the primary.
- A name on both nodes takes the primary's record (logged), as decided.
- The OIDC provider settings already replicate with the shared configuration. The session-revocation list isn't needed: deleting or disabling a user on the primary removes or blocks them everywhere on the next sync, and with them their sessions.

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

**Addendum (2026-10-05, T6.9 implemented):**
- **Stamping:** `crates/telltale/build.rs` reads `TELLTALE_BUILD_{VERSION,COMMIT,DATE,CHANNEL}`. CI computes them once per run and passes the same `--build-arg`s to every buildx call, so all three architectures (and the image) carry one identity, which `image.yml` checks in each binary. Edge is `<Cargo version>-edge.<run number>`, a tag is its semver, and a PR build is `-pr.<run>` on channel `dev`.
- **Install type:** the image sets `TELLTALE_INSTALL=container`, the chart `helm`, and the systemd unit `native`. Without it, the binary guesses from `/.dockerenv` or the Kubernetes environment.
- **Release index:** `deploy/release/index.py` writes `releases.json` (channel, version, commit, date, notes, and per-target asset names and hashes from `SHA256SUMS`). It's signed and verified in the release job next to `SHA256SUMS`.
- **Update check:** nodes fetch `releases/download/edge/releases.json` (edge) or `releases/latest/download/releases.json` (stable), plus `.minisig`, and verify with the built-in key. Edge builds compare by run number, and a release sorts after its edge builds. The first check is 60 s after start, then daily, retrying hourly after a failure.
- **Not yet:** `self-update` still reads `SHA256SUMS` (it works and is verified the same way). Moving it onto the index is a follow-up, as is an MCP tool for update status.


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

**Implementation notes (T5.12, 2026-10-05):**
- **Configuration:** the settings are `[cluster.git]` (`repo`, `ref`, `path`, `credentials_file`, `poll_secs`, `require_signed`, `allowed_signers_file`, `allow_rewind`, `max_bytes`, `webhook_secret_file`), node-local, rather than `[cluster.config] source = "git"`.
- **Authority:**
  - A Git source makes the published authority `gitops`, so the existing `409 gitops_managed` and promotion rules apply.
  - A node with `[cluster.git]` counts as Git-managed (`config_source` reported as `gitops`).
- **Pinning:**
  - The manifest carries `source` (repo, ref, path, commit, author, time, subject, signer), and replicas store the pin.
  - A promoted node whose `[cluster.git]` differs refuses to fetch and says so; changing the source means changing it on the primary.
- **Transport:**
  - `telltale-git` speaks protocol v2 over smart HTTP: `ls-refs`, a commits-only fetch for the history check, a blob-less fetch for the tree, then the one blob. It handles packfiles with deltas, with `miniz_oxide` the only new dependency.
  - Plain `http://` is accepted only on loopback, for tests.
  - Verified against github.com and against real `git upload-pack` in tests.
- **First start:** before the first good commit, a Git primary publishes nothing, so a fresh primary never pushes an empty configuration. It serves the last version it applied.
- **Alerts:** `TelltaleDNSGitCommitRefused` and `TelltaleDNSGitSourceFailing`. Metrics: `telltale_cluster_git_*` and `telltale_cluster_config_commit`.
- **Deferred:**
  - the direct-pull fallback;
  - GPG signatures (SSH signatures only);
  - the UI's "propose this change";
  - the Helm chart reading the same `shared.toml` (use an Argo multi-source app meanwhile).

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

## ADR-053 — Federated reads v1: what's exact, what's approximate, and which scopes exist (Proposed)
**Context:** T5.6 (CLU-002, OBS-012). `spec/12` §6 says analytics reads fan out to the peers in `scope` and merge, with HDR histograms merged exactly, query logs k-way merged with per-node cursors, a 2 s per-peer timeout, and `missing_nodes`. It names the scopes `node:<id>`, `site:<name>` and `cluster`.

**Decision:**
- **Transport:** reads are RPCs over the existing cluster streams (frame types `RpcRequest`/`RpcResponse`, kind `api.read`, JSON body). No new port, connection, or certificate. Peers are asked concurrently with a 2 s deadline. A peer without a stream is reported missing at once.
- **Merges:**
  - counters sum per bucket, across every breakdown;
  - top lists add counts and error bounds per key (the true count stays within `[count − errorBound, count]`);
  - query-log pages interleave newest first, with a cursor (`fed:` + base64url JSON) that holds each node's "before" time, or nothing once that node has run out.
- **Latency is approximate in v1.** Each node sends its percentiles, and they are weighted by query count; the maximum is exact. Shipping histograms for an exact merge needs a serialized HDR format on the wire. It's deferred until a dashboard needs exact cluster-wide tails.
- **Scopes:** `cluster` (the default) and `node:local`. `node:<id>` and `site:<name>` still answer `400 unsupported_scope`. The live tail, configuration reads, and Explain stay local.
- **Edge cases (accepted):**
  - Rows that share the exact microsecond with a page's last row from the same node may be skipped on the next page.
  - A node that joins while someone is paging appears only from the next fresh search.
  - `missingNodes` reports the latest federated read on the node; concurrent reads may each see the other's list.
- **Failure:** a peer error, timeout, or undecodable answer drops that node from the result and names it in `missingNodes`. If this node's own query log is off, but peers answered, their rows are returned and this node is listed as missing. DNS answering is never involved (CLU-004).

**Consequences:** any node's UI is a full management view for reads. Exact cluster-wide latency, named-node/site scopes and a federated live tail are follow-ups.

## ADR-054 — Write forwarding v1: the entry node vouches for the user over mTLS (Proposed)
**Context:** T5.7 (CLU-002). `spec/12` §6 says a write on any node is forwarded to the primary with the user's identity, "signed by the receiving node", so the audit log shows both the user and the entry node. Users aren't replicated yet (ADR-045 is still to come), so a user exists only on the node they signed in to.

**Decision:**
- **What's forwarded:** the configuration writes the API offers (devices, local names, forwarded domains), including dry runs. They go to the primary as the RPC `api.write` over the existing cluster stream, with a 10 s deadline.
- **Who vouches:**
  - The entry node authenticates and authorizes the user with its own users and roles, exactly as for a local write.
  - The primary trusts the entry node's claim because the stream is mutually authenticated with the cluster CA: the peer ID comes from the certificate, never from the request.
  - No extra signature is added: the mTLS channel already proves which node sent it, and a member node is trusted to replicate configuration anyway.
- **What's recorded:**
  - The primary stores the entry as made by `<user> via <site>` and audits it with actor kind `cluster` and `remote = node <id>`.
  - The entry node audits it under the user's name, with the primary's answer.
- **Versions:** a replica reports the primary's configuration version (ETag; 1 s deadline, falling back to its own), so `If-Match` works through any node. The primary's answer, including its error code (409, 404, 400), is returned unchanged.
- **Unreachable primary:** the write is refused with 503 and a hint. It is never queued: a queued write could apply long after the user saw it fail.
- **Not forwarded:** under a GitOps authority, writes are refused on every node (409 `gitops_managed`, ADR-048). Promotion and the node's own users, tokens and sessions stay local until ADR-045 replicates identities.

**Consequences:** the owner can manage the cluster from the Pi's UI as well as the homelab node's, as long as both are on the API authority. Today's cluster is GitOps-managed, so there it stays read-only, by design.

## ADR-055 — Query-log ship mode v1: closed segment files, delivered once, searched where they land (Proposed)
**Context:** T5.8 (CLU-007). `spec/12` §7 describes `ship` mode: raw events are streamed to a target in batches of columnar blocks, spilled to a 64 MiB buffer when the target is unreachable, and replayed; rollups are shipped as per-minute aggregates; `both` mode does both; receivers keep per-source-node segments.

**Decision:**
- **Unit of shipping: whole closed segment parts, not blocks.**
  - In ship mode the writer closes a part at least every `[telemetry.ship] interval_secs` (default 300 s).
  - The shipper sends each closed part (every part except the newest) to the target in 512 KiB chunks over the cluster channel (RPC `qlog.put`).
  - The receiver checks the whole file's BLAKE3, then files it unchanged under `qlog-nodes/<sender-id>/`. Nothing is re-encoded, and the sender's footer and bloom filters stay valid.
  - Only after the receiver confirms does the sender delete its copy. A lost confirmation means the file is sent again and overwritten, never duplicated.
- **Buffer:** the local log is the store-and-forward buffer, bounded by `buffer_bytes` (default 64 MiB) via the existing retention, which drops the oldest file first. No separate in-memory spill: a RAM disk under `data_dir` gives the memory variant without new code.
- **Exactly one copy:** a row is either in the sender's buffer or on the receiver. The receiver's search includes shipped logs, labelled by node, and federated reads reach the sender's unshipped rows, so a cluster-wide search sees each row once.
- **Target:** `[telemetry.ship] to` (a node ID or site), defaulting to the primary. A primary in ship mode with no other target keeps its log (logged once).
- **Deferred:**
  - **Rollup shipping.** Per-minute counts stay on each node: they're small, the dashboard already federates them, and shipping them only matters for ephemeral pods (T5.10). *Done in T9.3:* ship-mode nodes send their last 30 minutes of minutes every `interval_secs` (≤ 60 s); the target keeps them per node for 7 days (`shipped_minute`), and the cluster view adds only those of nodes that didn't answer live, so nothing counts twice.
  - **`both` mode.** It would need dedup between a live sender and its shipped copy. Not needed for the hybrid Pi + k8s setup.
- **Safety:**
  - Receivers accept only from cluster members (mTLS), only hex node IDs become paths, and segments over 256 MiB are refused.
  - Shipping is a background task, and receiving runs on blocking threads, so DNS is never involved (CLU-004).
  - The peer RPC handler is now installed whether or not the node runs the API, so a node without an API can still receive logs and answer federated reads.

**Consequences:** the owner's Pi can set `mode = "ship"` to move its query log to the homelab node's volume. Rows then appear with up to `interval_secs` of delay in the homelab node's own search; cluster-wide search shows them at once.

## ADR-056 — Automatic failover v1: one vote per epoch, voter-granted leases, pre-vote, a vote-only witness (Proposed)
**Context:** T5.4b (CLU-005). `spec/12` §5 has `witness` and `quorum` modes: a candidate needs a majority of eligible nodes plus witness for `epoch + 1`, and promotes only after the old primary's lease (15 s, renewed every 5 s) has expired; "a primary accepts writes only while it holds a valid lease". The AC is a simulator: 10k randomized partition schedules, never two writers in one epoch, orphaned writes always surfaced.

**Decision:**
- **One protocol for both modes** (`telltale_cluster::election`, pure, no I/O):
  - Voters are the eligible nodes plus witnesses, from the signed registry.
  - A voter grants each epoch once (persisted, fsync, before answering). It refuses a newer epoch while the lease it granted to another node runs (15 s on its own clock), and refuses candidates whose applied version is behind its own.
  - The primary renews with every voter every 5 s. It treats its lease as ending 15 s − 2 s after it *sent* the round a majority granted, so it stops publishing before any voter of that majority can elect someone else, for clock rates within ±1 %.
  - **Pre-vote:** a node first asks whether it *would* win. A node cut off from the cluster never inflates epochs, and never deposes a healthy primary when the partition heals.
  - `witness` and `quorum` are the same thing with different voters, so the mode is just `manual` or `auto`.
- **Mode:**
  - `telltale cluster set-failover auto|manual` on the primary. It's carried in the signed manifest, like the authority.
  - `auto` runs elections only with three or more voters, this node one of them; otherwise it behaves as `manual`, and the Cluster page's `failover` check says why.
  - Manual `promote` is refused while elections run, because it would bypass the votes.
- **Witness:**
  - `telltale cluster join <token> --witness --advertise <url>`, then `telltale cluster witness`.
  - It runs only the cluster channel and the vote handler: no DNS, lists, API or pipeline. It learns the registry and mode from verified manifests.
  - It never becomes primary and never receives the CA key.
- **Transport:**
  - Votes are the `elect.ask` RPC on cluster streams. The candidate is bound to the stream's certificate: a node can only ask for itself.
  - Voters keep a full mesh in `auto` mode: of each pair, the lower node ID dials.
- **Gating:**
  - `Cluster::may_publish()` is false for a primary without a valid lease. The publish loop waits, and API writes get 503 with a hint.
  - A primary starting in `auto` mode begins with publishing paused until its first renewal.
  - A restarted primary resumes its epoch if its own ballot is for itself; otherwise it takes part in a normal election.
  - Only nodes holding the CA key stand as candidates.
- **Under a `gitops` authority,** an elected node that isn't Git-managed becomes an emergency primary (ADR-048).

**Verification:**
- `tests/sim.rs` covers 2 + witness, 3, and 4 + witness voter sets under random asymmetric partitions, 0–15 % loss, heavy-tailed delays to 3 s, crashes with persisted ballots and histories, and ±1 % clock drift.
- It checks:
  - one primary per epoch;
  - never two writable primaries at the same real instant;
  - every write kept, or reported as orphaned;
  - a primary within 60 s of healing.
- Results at 10,000 schedules (release, in CI): 43,744 elections, 1.49 M writes, 176,933 orphaned and reported, worst recovery 24.75 s.
- It's mutation-checked: removing the lease check, or timing the lease from the reply instead of the request, is caught.
- `deploy/cluster/failover-e2e.sh` (real processes, CI): kill the primary, and the replica is elected in about 14 s with 100 % of DNS queries answered; the old primary returns and follows.

**Deferred:** CA rotation, the other part of T5.4b's title, is now T5.4c. Clocks are assumed not to jump by more than the margin; NTP slews rather than steps in normal operation.

**Consequences:** the owner's Pi + homelab cluster stays `manual` until a witness exists. A witness on any third device (for example the NAS) makes failover automatic, with the Pi as an emergency primary while the configuration authority is GitOps.

## ADR-057 — Node certificate renewal over the cluster channel, same key (Proposed)
**Context:** T5.4c (CLU-001). Node certificates last 90 days (ADR-044), and nothing renewed them, so a cluster would lose its links about 90 days after its nodes joined. The owner's cluster joined on 2026-10-04. `spec/12` §3 says certificates renew automatically; the CA rotation half of T5.4c is rarer, because the CA lasts 10 years.

**Decision:**
- **When:** each node checks every 6 hours (first one minute after start) and renews when fewer than 30 days remain, so two thirds of the lifetime has been used. It retries every 10 minutes on failure.
- **Same key:** the node sends a CSR for its existing key, so its node ID (derived from the key) never changes.
- **Who signs:**
  - A node holding the cluster key (the primary, eligible nodes) signs its own.
  - Others ask the primary with the `cert.renew` RPC on their stream.
  - The primary signs only when the CSR's key belongs to the peer the stream's certificate names. It takes the certificate's names (advertise hosts) from the signed registry, never from the request.
- **Checks before use:** the new certificate must name this node and verify against the cluster CA (Ed25519). It's written atomically.
- **Switch-over:** a certificate generation counter makes the dialer and the listener rebuild their TLS settings for the next connection. Open streams keep their session, since certificates are checked at handshake only.
- **CA rotation** (new CA, cross-signing, key re-share) stays in T5.4c, still open.

**Consequences:** clusters keep their links indefinitely while a CA holder is reachable at least once every 30 days. A witness or replica cut off from every CA holder for 90 days loses its certificate and must rejoin with a token.

## ADR-058 — Kubernetes resolver pods: a shared bootstrap secret with proof of possession, ephemeral members, sync-gated readiness (Proposed)
**Context:** T5.10 (CLU-009). `spec/12` §2 says resolver pods join with a long-lived token from a Secret, get a fresh identity per start, expire after `ephemeral_ttl` (10 min) without heartbeats, and display under their site. A join token pins the CA fingerprint, which only exists after the controller creates the cluster. So a chart can't put a token in a Secret without the controller writing to the Kubernetes API, which needs RBAC and a client library.

**Decision:**
- **Bootstrap secret instead of a pre-made token:**
  - The chart generates a random secret in a Secret (kept with `lookup` and `resource-policy: keep`, or the user's own via `existingSecret`), mounted in every pod.
  - The controller accepts it like a join token that never expires: `[cluster] bootstrap_secret_file`, re-read at every join, so rotations apply without a restart.
- **Proof of possession instead of trust on first use:**
  - A pod with `join_url` first calls `POST /cluster/v1/ca` with a fresh nonce.
  - It trusts the returned CA only if the server answers HMAC-SHA256(secret, nonce : CA fingerprint), proving it holds the same secret.
  - It then pins that CA and joins exactly as with a token.
  - A man in the middle without the secret can't pass this.
- **First start creates or joins:**
  - `[cluster.init]` (advertise URLs, authority) creates the cluster on the controller's first start, the same as `telltale cluster init`.
  - `join_url` joins on a pod's first start, retrying for 2 minutes. An ephemeral pod that can't join exits, so Kubernetes retries it (CrashLoopBackOff while the controller starts).
- **Ephemeral members:**
  - `[cluster] ephemeral = true` joins as ephemeral: never eligible, never a voter, no CA key.
  - The registry records `ephemeral`. The primary drops ephemeral members not connected and not heard from for `ephemeral_ttl_secs`, checked every minute. A pod that never connected is measured from when it joined, or from the controller's start.
  - The Cluster page groups them by site with counts (up, ready, q/s, behind).
- **Readiness:** an ephemeral node is ready only once it has applied the cluster's configuration. A new pod never serves an unfiltered answer, and the Service routes to it only after sync.
- **Helm `mode: scaled`:**
  - The allInOne StatefulSet becomes the controller and keeps its labels, so switching modes needs no reinstall.
  - Adds a resolver Deployment (`emptyDir` data, ship-mode query log, `maxUnavailable: 0`), a `-cluster` Service for the cluster port, the join Secret, and a NetworkPolicy rule for the cluster port.
  - The DNS Service selects every pod; the API and metrics Services select the controller.
  - `hostNetwork` with `scaled` is refused, since pods would compete for port 53; that's `daemonSet`, later.
- **Found on the way:** a replica's follower ignored a manifest that arrived before it subscribed, and waited for the primary's next change. It now processes the current one at start.

**Consequences:**
- `deploy/helm/scaled-e2e.sh` (CI, this build's binary on kind) proves the controller and two pods join and sync, a pod answers DNS, an outside node joins through the cluster port, and a deleted pod is replaced and expires.
- A pod restart is a new member, by design. A registry of long-gone pods is cleaned within `ttl + 1 min`.

## ADR-059 — Version compatibility v1: a protocol window, a schema stamp, and refusal over guessing (Proposed)
**Context:** T5.11 (CLU-010). `spec/12` §9 says RPC carries a protocol version and manifests a schema version; nodes accept N and N−1; the primary refuses to emit features the oldest connected node doesn't support, and warns. Until now, peers needed the exact same protocol, and manifests carried no schema. The shared configuration is parsed strictly (`deny_unknown_fields`), so an older replica would reject a newer primary's new settings.

**Decision:**
- **Protocol window:** a stream is accepted when the peers' protocols differ by at most one. Frames are protobuf, and fields are only ever added, so unknown fields are ignored. `PROTOCOL` is raised only when a message changes meaning.
- **Schema stamp:** manifests carry `schema`, the configuration schema the primary writes (now 1; 0 means from before stamping). It's raised when the shared configuration gains settings an older build would reject.
- **No down-converting:** the primary does not try to strip settings an older replica wouldn't know. It publishes what it has.
  - A replica that can't read it keeps serving its last version, so DNS is unaffected.
  - The replica records a sync error naming both schemas and saying to upgrade.
  - Per-field feature gating is deferred: the documented upgrade order (replicas first) makes it rarely matter, and guessing which settings are safe to drop could silently change filtering.
- **Visibility:** each node's protocol is on the Cluster page, and a `versions` check fails while versions or protocols are mixed, with the upgrade order as the fix. Build versions become fully distinguishable with T6.9's stamped build identity; today edge builds all say 0.1.0.

**Verification:** `deploy/cluster/upgrade-e2e.sh` (CI) runs the published `edge` binary as N−1 against this build:
- both nodes on N−1;
- the replica on N following the N−1 primary;
- the primary on N;
- the replica back on N−1 following the N primary.

An edit reaches the replica at every stage, and a client with both servers configured gets an answer to every query.

**Addendum (2026-10-05):** the shared configuration leaves out top-level sections that are at their defaults, and a replica reads a missing section as the default. Without this, adding any new section (DNSSEC, ADR-060) broke N−1 replicas even when no one used it: CI's upgrade test caught it. A new setting now reaches an older replica only once someone actually sets it. That is the case the "no down-converting" rule is for.

## ADR-060 — DNSSEC validation v1: hickory's validator over our upstream groups, off by default (Proposed)
**Context:** T6.1 (DNS-011). `spec/03` §5 asks for:
- modes `off`, `validate` (the default once stable) and `validate_permissive`;
- DO=1 upstream, validation from the root trust anchor, and CD=1 clients getting unvalidated data;
- AD only when validated and the client asked;
- bogus answers as SERVFAIL with EDE 6;
- negative trust anchors;
- `hickory-proto`'s verification primitives behind a `Validator`.

In hickory 0.26 the chain-of-trust logic (`DnssecDnsHandle`, with NSEC/NSEC3 denial proofs, wildcard checks, NSEC3 iteration limits and a validation cache) lives in `hickory-net`. The primitives in `hickory-proto` alone would mean writing that ourselves.

**Decision:**
- **Use `hickory-net`'s `DnssecDnsHandle`** (`dnssec-ring`, `tokio`; it adds no TLS or HTTP stacks). It wraps a `DnsHandle` we implement over one of our upstream groups.
  - The question, and every DNSKEY and DS lookup the proof needs, go to the same upstreams with DO=1 and CD=1 (we check, so the upstream mustn't drop what it thinks is bogus).
  - There's one handle per group, so its validation cache lasts across queries.
  - It's wrapped as `telltale_upstream::dnssec::Validator`.
- **Verdict:** the weakest proof among the answer records, or among the authority records for NXDOMAIN and NODATA. Errors from the validator other than upstream failures count as bogus.
- **Serving:**
  - Secure gets AD for clients that asked; insecure and indeterminate get no AD.
  - Bogus becomes SERVFAIL with EDE 6, never a stale answer, and is never cached; in permissive mode it's served and counted.
  - RRSIG, NSEC and NSEC3 records are stripped for clients without DO.
  - Validation runs on cache misses only, and validated answers are cached with their AD bit. The cache key already separates DO and CD.
- **Negative trust anchors:** `[dnssec] negative_trust_anchors` plus every route with `dnssec_nta`.
- **Mode names and default:** `off`, `validate`, `permissive` (spec's `validate_permissive`). The default stays `off` until it has run on the owner's nodes for a while; then a follow-up makes `validate` the default.
- **Timing:** a cold chain (root, TLD and zone keys) takes several sequential lookups. Validation gets three times the query budget, so a slow first lookup still lands in the cache even if that client gave up.
- **Found on the way (all queries):** a truncated UDP answer's TCP retry shared the adaptive per-attempt timeout calibrated on small answers (about 3× average round trip), so large answers (DNSKEY sets with signatures, long TXT) timed out. The TCP retry now gets the configured timeout of its own.

**Verification:** unit tests for verdicts, NTA coverage and stripping. `deploy/dnssec-e2e.sh` (CI, real DNS tree, forwarding to 1.1.1.1 and 9.9.9.10) checks:
- ietf.org and cloudflare.com are secure with AD;
- google.com is insecure without AD;
- dnssec-failed.org is SERVFAIL with EDE 6, and answered with CD;
- signed NXDOMAIN and NODATA validate;
- verdicts are counted.

**Deferred:**
- RFC 5011 trust-anchor updates (the built-in root keys cover KSK-2017 and KSK-2024);
- aggressive NSEC caching (RFC 8198, with recursion);
- per-reason EDE codes (7, 9, 10, 12) instead of 6;
- the `dnssec` field in query events and the Settings UI.

## ADR-061 — Pi-hole import v1: a reviewed starting configuration, faithful group semantics (Proposed)
**Context:** T6.3 (API-007; `spec/08` §8) asks for an importer of Pi-hole v5 and v6 Teleporter archives covering adlists, domain lists, groups, clients, local DNS/CNAME records, upstreams, and conditional forwarding, with a report of every unmapped setting. The spec doesn't say whether the result is applied or reviewed, how Pi-hole's per-entry group assignments map onto our per-group list sets, or what happens to Pi-hole behaviors we don't have.

**Decision:**
- **Output, not apply:** `telltale import pihole PATH` writes TOML for review (like `import zone`, ADR-041), validated to load before it's written. Applying through the API (and the UI's import page) waits for T6.7's restore path.
- **Inputs:** v6 zip (`pihole.toml` and a `gravity.db` of the group tables), v5 tar.gz (JSON per table plus `setupVars.conf`, `pihole-FTL.conf`, `custom.list`, `dnsmasq.d`), a directory, or a bare `gravity.db`. Readers are ours: zip and tar.gz in about 200 lines on `miniz_oxide`, with CRC checks and size limits. SQLite goes through `rusqlite`, already in the tree. Archived databases are read from a private temporary copy.
- **Groups stay exact:** each group gets exactly the lists Pi-hole gave it, so `default` doesn't fall back to "every list". Domain entries become inline lists, one per (type, set of groups). Disabled groups get no lists. Clients in no group go to a `pihole-no-group` group with no lists, as Pi-hole blocks nothing for them.
- **Matching:**
  - exact entries use `match = "exact"`;
  - a regex our parser would read as a plain name is wrapped as `/regex/`;
  - entries our engine can't run are reported, not dropped silently.
- **Upstreams:** they go in the `default` upstream group with strategy `fastest`, matching Pi-hole's preference for the fastest server.
- **Conditional forwarding:** each rev server becomes its own upstream group and route. The route covers the domain and the network's reverse zones: non-octet prefixes are expanded, so a /23 is two /24 zones, never widened. It gets a negative trust anchor.
- **Devices:** DHCP reservations become named devices (MAC and IP join a matching client, or a new one named by the host name). The DHCP server is not imported.
- **Report:**
  - v6: every setting Pi-hole marks `### CHANGED` that isn't mapped;
  - v5: every unmapped key in `setupVars.conf` and `pihole-FTL.conf`, except the old install's own plumbing (interface, addresses, web server);
  - names only, never values, since they include password hashes.
- **Not imported:** clients matched by host name or interface (we match by address); the `IP` blocking modes; query history; passwords and tokens.

**Verification:**
- Unit tests on hand-written inputs in both formats.
- `deploy/pihole-import-e2e.sh` (CI) configures the official `pihole/pihole` images (v6 2026.09.0 = FTL v6.7.1, v5 2024.07.0) through their own tools, exports Teleporter archives, imports them, and serves the result: local names, a CNAME's TTL, exact and regex denies (`;querytype`), the blocking mode, and group scoping.
- Pi-hole-generated files aren't committed (their comments are Pi-hole's text, NFR-006).

**Consequences:**
- Merging into an existing configuration is manual (both define `default`).
- The importer's e2e showed that the first blocking snapshot waited for every list's first fetch, including retries, so an unreachable adlist delayed all blocking at first start. Fixed: the fetcher signals the compiler at most 10 s (`settle`) after the first update in a round, so lists that arrive together still compile once.

## ADR-062 — Technitium import v1: read the API, not the backup (Proposed)
**Context:** T6.4 (API-007, P1). `spec/08` §8 says "backup zip → blocked/allowed zones, block-list URLs, forwarders + protocols, Advanced Blocking app config → groups". Technitium's backup holds `dns.config`, zone files, and the allowed/blocked lists in its own versioned binary serialization. That format is undocumented and changes between releases. Its HTTP API returns the same data as documented JSON.

**Decision:**
- **Source:** `telltale import technitium URL` reads a running server through the API with an API token, which comes from `TECHNITIUM_TOKEN` or `--token-file`, never argv.
- **Calls, all read-only:**
  - `settings/get`;
  - `zones/list`, then `zones/records/get` per zone;
  - `allowed/export`, `blocked/export`;
  - `apps/list`, and `apps/config/get` for Advanced Blocking;
  - `dhcp/scopes/list` and `dhcp/scopes/get` (optional).
- **Output:** reviewed TOML like ADR-061, validated before it's written.
- **Mapping:**
  - **Forwarders** go in the `default` group: concurrent forwarding becomes `parallel` with the same fan-out, but only with two or more usable forwarders. `name (ip:port)` pins the address, with the name as TLS name.
  - **Forwarder zones:** forwarders by priority, a route, and an NTA unless every forwarder of the zone validated.
  - **Primary zones:** records of the types we serve, with their TTLs.
  - **Blocked and allowed zones** become subtree inline lists.
  - **Advanced Blocking groups** become groups. The catch-all network's group becomes `default`, and other networks become `networks` (ADR-050). URL lists are shared across groups by URL. Regexes are wrapped as `/re/`. Server-wide lists are added to every group, since Technitium applies both. Disabled groups get no lists. The bypass list becomes a group with no lists.
  - **Blocking answer:** NXDOMAIN, or custom addresses, become the group's `block_mode`.
  - **Rate limit:** the per-/32 limit (queries per minute) becomes `[ratelimit]`.
  - **Other settings:** `dnssecValidation` and `saveCache` carry over. DHCP reservations become named devices.
- **Not imported (reported):** secondary and stub zones; QUIC forwarders; forwarders with no address; listener- and host-based group selection; per-list answers; the DHCP server; encrypted listeners; recursion ACLs, TSIG, zone transfers, the proxy, and other apps. Listeners, logging, users, and tokens are not imported either.

**Verification:**
- Unit tests on hand-written API responses.
- `deploy/technitium-import-e2e.sh` (CI) runs against `technitium/dns-server:15.6.0`. It configures everything above through Technitium's API, installs Advanced Blocking from Technitium's store, and creates an API token. It then imports, serves the result, and checks the answers.

**Consequences:**
- Importing needs the old server running, which matches the migration path (import, compare, switch).
- A backup-zip reader can follow if the format gets documented.
- The e2e found a real-data bug: concurrent forwarding with a single usable forwarder produced an invalid `parallel` group. Fixed and tested.

## ADR-063 — Backups v1: a checked archive of config and local data, without the cluster key (Proposed)
**Context:** T6.7 (API-007, P0) asks for Teleporter parity: one archive with config and local data, optionally with query history. `spec/08` §8 sketches `telltale ctl backup create [--include-qlog]` writing a `.ttbk` (tar.zst + manifest + signature) restored onto a new primary. `ctl` (the API-wrapping CLI, API-008) doesn't exist yet. The spec doesn't say what the signature is signed with or whether cluster identity is included.

**Decision:**
- **Commands:** `telltale backup create | show | restore`, local commands that work on the data directory.
  - `create` is safe while the server runs: SQLite databases are copied consistently with `VACUUM INTO`, and query-log segments only grow, so the size seen at open is copied.
- **Contents:**
  - config files under `config/`;
  - `state.db` (users, tokens, UI-made entries, audit), with sessions and idempotency keys removed;
  - `rollups.db` and `anomaly.json`;
  - the query log (`qlog/`, `qlog-nodes/`) only with `--include-qlog`;
  - lists, snapshots, the cache, and `setup-token` are left out, since they're rebuilt or transient.
- **Format:** a tar stream compressed with zstd (frame checksum on), with `manifest.json` last. It holds the format version, source node and paths, and each entry's size and BLAKE3 hash. The file is written owner-only and renamed into place when complete.
- **No signature in v1:** a signature by the source node's key proves nothing to the fresh node it's restored onto, which doesn't know that key. Integrity comes from the manifest hashes and zstd's checksum. Confidentiality is the file's permissions, as with Pi-hole's Teleporter. Encryption with a passphrase is the natural next step.
- **No cluster identity by default:** `cluster/`, with the CA key, isn't included. A portable file with the CA key could impersonate the cluster. A restored member starts standalone, and the manifest records that it was a member so restore can say what to do.
- **Restore:**
  - streams into a staging directory under the data directory;
  - checks every entry against the manifest, and anything unexpected, a path outside `config/` or `data/`, or `..`, fails before any file is moved;
  - refuses to replace existing files without `--force`;
  - chowns restored files to the data directory's owner.

**Verification:**
- Unit tests: contents, permissions, round trip, session stripping, `--force`, corruption, path containment, and the query log.
- `deploy/backup-e2e.sh` (CI) backs up a running node with an admin and an API-made name, restores it onto a second node, and checks the following on that node:
  - the name answers;
  - the admin signs in, and the old session doesn't carry over;
  - the audit log is present;
  - damaged archives are refused.

**Consequences:**
- **Download:** `GET /api/v1/backup` (admin, audited `backup.create`, without the query log) and a Settings → System button. Restore through the API is deferred: restoring under a running server is risky.
- `--include-cluster-key` (for disaster recovery of a lone primary) and passphrase encryption are follow-ups.

## ADR-064 — Agent principals v1: scoped tokens, deny by default, a reason for every change (Proposed)
**Context:** T6.5 (AGT-001..005, AGT-009). `spec/13` §2 asks for:
- agent tokens with an owner, scopes, an optional group restriction, rate limits, and expiry;
- attribution `agent:<token> (owner: <user>)` with the client and a required reason;
- dry runs with impact estimates on every mutation;
- guardrails and a cluster-wide kill switch;
- an OpenAPI document written for agents and linted.

Tokens so far had a role-like `scope` (read/write/admin), and the audit log already recorded `token:<name> (owner: <user>)` (ADR-038).

**Decision:**
- **Agent tokens:** `POST /tokens` with `kind: "agent"`.
  - The scopes are AGT-004's list: `analytics:read`, `querylog:read`, `config:read`, `config:write:{clients,records,forwards}` (`*` for all), `ops:pause`, `ops:cache`, `cluster:admin`.
  - The default is `analytics:read` + `config:read`: read-only, without the query log.
  - Optional `group` and `ratePerMinute`.
  - Each scope needs a role from the creator (`config:write:*` and `ops:*` need operator, `cluster:admin` needs admin). A token's effective role is the lower of its owner's and its scopes'.
  - Stored in three new `tokens` columns (migration 5). User tokens are unchanged.
- **Deny by default:** one table maps method and path to a scope. Anything not in it is refused for agents: users, tokens, passwords, backups, the audit log, and routes added later until they're mapped. The role checks still apply on top.
- **Group restriction:** honored where a group view exists.
  - The query log and top lists: the middleware replaces the `group` parameter.
  - Devices: listed for the group only; writes only into, and only on devices already in, the group.
  - Everything else is refused for restricted tokens rather than shown unfiltered.
- **Every change needs a reason:** agents' non-GET requests without `X-Telltale-Reason` get 400.
- **Attribution:** the actor is `agent:<token> (owner: <user>) via <X-Telltale-Client>`, with kind `agent`.
- **Rate limits:** a per-token token bucket in memory, refilled per minute, default 120 (`[agents] rate_per_minute`). Over the limit: 429 with `Retry-After`. Per node, so a cluster allows N× in total; documented.
- **Kill switch:** `[agents] enabled`, a shared section, so it replicates to every node (and, since ADR-059's addendum, doesn't trouble N−1 replicas while unset). It's applied on start and every reload.
- **Impact estimates:** device, name, and forward changes return `recentQueries` and `impact`, a sentence with the numbers. They're counted from the in-memory top lists for the current and previous hour (a lower bound, cheap, no log scan). Promotion gets `?dryRun=true`, returning a `PromotePlan` (epoch, emergency, impact) from the same checks without acting.
- **Lint:** `.spectral.yaml` (spectral:oas plus operation summary, description, tags, operationId, success response, and parameter descriptions) runs in CI. Every response now has a description.

**Verification:**
- Unit tests:
  - the scope map denies by default;
  - scope parsing and the roles scopes imply;
  - the kill switch, rate limit, required reason, and group refusal;
  - the forced group parameter.
- API tests: agent tokens over HTTP (scopes, refusals, reason, attribution, kill switch); group-restricted tokens; the promote dry run.
- `deploy/agent-e2e.sh` (CI) on a running node:
  - a dry run of every mutation reports an impact and changes nothing;
  - a real change is attributed with its reason;
  - a reload with `enabled = false` stops the agent and not the admin.

**Consequences:**
- MCP (T6.6) builds on these principals.
- `ops:pause` and `ops:cache` exist ahead of their endpoints.
- Per-group analytics views beyond top lists would let restricted agents see more.
- OAuth for agents (AGT-008) stays P1.

## ADR-065 — MCP server v1: read-only tools over the REST routes, one implementation for two transports (Proposed)
**Context:** T6.6 (AGT-006, AGT-008 bearer part, AGT-009; ADR-010). `spec/13` §3.1 lists the read-only tools, and §4 suggests a `telltale-mcp` crate with schemas generated from the Rust types (`schemars`) and a catalog snapshot test. The AC asks for:
- an MCP conformance test;
- scope and privacy authorization tests;
- a scripted agent completing the "why is the TV slow" story.

**Decision:**
- **Where:** a module of `telltale-api` (`mcp.rs`), mounted at `/mcp` on every node's API listener behind the same authentication. A separate crate would add nothing at this size. `POST /mcp` takes JSON-RPC 2.0 (single or batch) and answers JSON (Streamable HTTP without SSE; `GET /mcp` is 405). Protocol `2025-06-18`, also answering `2025-03-26` and `2024-11-05`. Methods: `initialize`, `ping`, `tools/list`, `tools/call`. Notifications get 202.
- **Tools call REST in-process:** each tool builds one or more `GET /api/v1/...` requests and sends them through the REST router with the caller's own `Authorization`/cookie. Scopes, group restriction, rate limits (one per inner call), privacy levels, and the kill switch apply exactly as for REST, with no second authorization model. The REST problem+json becomes the tool's error text.
- **Catalog (read-only):** `get_overview`, `top_items`, `search_queries`, `explain_decision`, `get_client_profile` (the device, then its queries by IP), `latency_breakdown`, `upstream_health`, `list_effectiveness`, `find_anomalies`, `cluster_status`, `get_config` (one section).
  - Each description starts "Read-only.", and each tool carries `readOnlyHint`.
  - `test_resolution` is deferred: it needs resolution without cache or log, which the pipeline doesn't offer yet.
- **Schemas:** hand-written JSON Schemas, frozen in the committed `docs/api/mcp-tools.json` and diffed by a test (`UPDATE_MCP=1` to regenerate). Generating them from the REST parameter types would tie tool arguments to query-string shapes; the snapshot still prevents drift.
- **Guardrails:** results are capped at 32 KiB (with a note) and 200 rows. Each `initialize` starts a session (`Mcp-Session-Id`), and the client name/version from it is passed on as `X-Telltale-Client`, so agent actions are attributed to the MCP client (AGT-005).
- **stdio:** `telltale mcp --stdio` relays newline-delimited JSON-RPC between stdin/stdout and a node's `/mcp` with a token, so there's one implementation of the tools. The node address comes from `--url` or the config files; nothing but protocol goes to stdout.
- **Agents and `/mcp`:** `POST /mcp` needs no scope of its own and no reason header (the tools are read-only; the inner calls are checked). Group-restricted tokens may use it, since their inner calls are narrowed.

**Verification:**
- Unit tests: the catalog snapshot; side-effect statements and caps; arguments become queries.
- An API test: initialize with a session, list, call, scope error inside a tool, unknown method, no credentials.
- `deploy/mcp-e2e.sh` (CI) runs the official `@modelcontextprotocol/sdk` client against a live node. Over Streamable HTTP, the listed tools must match the committed catalog. The test then plays the "why is the TV slow?" story (device profile with recent queries, upstream health, explain on a blocked name), repeats it over `telltale mcp --stdio`, and checks that a token without `querylog:read` gets an error from `search_queries`.

**Consequences:**
- Write tools with plan/apply and approvals (§3.2) are P1.
- OAuth for MCP clients (AGT-008) is P1.
- MCP resources and prompts are later.
- An SSE stream (`GET /mcp`) would be needed only for server-initiated messages.

## ADR-066 — CA rotation: two trusted CAs, three member-gated phases (Proposed)
**Context:** T5.4c (CLU-001, CLU-005). `spec/12` and the roadmap ask for:
- CA rotation: a new key, a cross-signed transition, node certificate renewal over the channel, and the old CA retired;
- re-sharing the key with eligible nodes.

ADR-057 already renews node certificates (same key) over the channel. A CA rotation changes the trust anchor every TLS handshake and every manifest signature depends on.

**Decision:**
- **Two trusted CAs instead of cross-signing:** during a rotation `ca.crt` is a bundle of both CAs. TLS trusts every certificate in it, so certificates from either CA verify. Manifest signatures and issued certificates are checked against any CA in the bundle. The bundle's first CA is the one that signs, and `ca.key` is always its key. Cross-signing adds nothing in a cluster whose members all receive the bundle.
- **Distribution:**
  - The primary's signed manifest carries `ca_bundle`. A node adopts a new bundle only if it keeps at least one CA the node already trusts, so trust moves step by step and a stolen CA alone can't replace it.
  - Witnesses follow manifests for this alone.
  - Eligible nodes get the next CA's key with the existing key share, now re-sent whenever it changes. A key that arrives before its CA is trusted is held (`ca-pending.key`) until a verified bundle includes it.
- **Phases, driven by the primary, each gated on every non-ephemeral registry member** (heartbeats now carry `trust_fp`, the CAs a node trusts, and `issuer_fp`, the CA of its certificate):
  1. `trust`: the bundle is old + new; the old CA signs.
  2. `switch`: once all trust both, the new key becomes `ca.key` (the old is kept as `ca-old.key`) and the bundle becomes new + old. Nodes see that their certificate isn't from the signing CA and renew within a minute (self-issued with the new key, or over `cert.renew`). A node whose `ca.key` doesn't match the signing CA asks the primary rather than sign with the old key.
  3. `finish`: once every certificate is from the new CA, the bundle is the new CA alone, and the old key and the rotation state are deleted.
- **Operator interface:** `telltale cluster rotate-ca` starts a rotation on the primary while it runs, and the running primary carries it out (it re-reads its identity every cycle). `--status` and a `ca_rotation` Cluster check show the phase and pending members. Each new CA's name carries a label, so the two trusted CAs never share a subject.
- **Fixed on the way:**
  - Configuration fetches used the TLS settings from start-up, so they'd fail after a rotation. They'd also present an old certificate after a renewal. They now read the current identity.
  - Witnesses never renewed their certificates (ADR-057 gap); they do now.
  - Cluster files were made owner-only only after being written, and two streams could collide on one temporary name. Each write now uses its own temporary name, and secrets are created owner-only.

**Verification:**
- Unit tests:
  - bundles: verify, issuer, order-independent fingerprint;
  - start: refuses a second rotation;
  - adoption: refuses unrelated trust, promotes a held key, switches, then retires.
- `deploy/cluster/rotate-e2e.sh` (CI) with a primary, an eligible replica, and a witness under DNS load:
  - all three phases complete, and every node ends trusting only the new CA, with a certificate from it;
  - the replica holds the new key, and no old, next, or pending key is left;
  - every query was answered during the rotation;
  - a configuration change replicates afterwards (signed with the new key), and a restarted replica reconnects and syncs.

**Consequences:**
- A member offline for the whole rotation must rejoin.
- Join tokens pin the CA fingerprint, so tokens from before a rotation stop working.
- A forced rotation (with members down) is a possible follow-up.

## ADR-067 — Quick rules: their own layer, the most specific scope wins, expiry on the server (Proposed)
**Context:** T6.12 (owner request 2026-10-05) wants everyday per-person rules:
- unblock a game's server for one phone for two hours;
- block a site for the kids' devices until tomorrow.

The engine can already express device-scoped rules (`$client` in the manual-rules overlay, ADR-003), but the overlay uses the lists' four tiers (important allow > important block > allow > block). Those can't say "this device's rule beats its group's rule beats the lists": a group-wide allow would override a parent's block for one child. Nothing expires on its own.

**Decision:**
- **A quick rule:**
  - allow or block a domain and its subdomains;
  - for listed devices (by name, IP, or MAC, as `[[client]]` keys), listed groups, or everyone;
  - an optional expiry (an absolute time; the UI offers durations);
  - a note, who made it (user or agent), and when.
- **Storage:** in `state.db` as a managed entry of kind `rule` (ADR-040). In a cluster, rules travel with the shared configuration the primary publishes (ADR-047), and a replica's UI forwards the write to the primary (ADR-054). Rules are capped at 1,000 per cluster.
- **Matching:** quick rules are their own layer, checked before the lists:
  1. Among rules matching the query name (any suffix of it) whose scope includes the client, a device rule beats a group rule, which beats an everyone rule.
  2. Within one scope, the longer (more specific) domain wins, then allow beats block.
  3. A match decides allow or block outright. Otherwise the lists decide as before.

  CNAME inspection (FLT-007) uses the same decision, so a block also catches a CNAME to the blocked name.
- **Hot path:** the rules sit in a read-mostly table behind `ArcSwap`, keyed by the hash of each rule's reversed domain. A lookup probes the query's suffixes, at most one probe per label, with no allocation. With no rules it costs one branch.
- **Expiry:** each node ignores a rule from the moment its expiry passes, by its own clock (T6.11 shows clock offsets). A sweep every 5 s on the primary deletes expired rules and audit-logs each expiry. A replica never needs the sweep to stop applying a rule.
- **Explanations:** an answer decided by a quick rule is attributed to it ("allowed by a quick rule for Mom's phone, expires 21:30"). The query log records it, and "Why?" and explain show it above the list matches.
- **Agents:** the scope `config:write:rules`, with the usual reason header, dry run, and impact estimate (recent queries the rule would change).

**Consequences:**
- A new rule takes effect on the next query, with no list recompile.
- Cost: about 52 ns per query with 1,000 rules, about 4 ns with none (xxh3 suffix keys, measured 2026-10-05).
- Rules are deliberately simpler than list syntax: no regex, no query types. Anything fancier belongs in a list.
- Device scoping is only as good as recognising the device; the docs say so.
- Expiry depends on node clocks being roughly right. A node whose clock is off keeps or drops a rule early or late by that offset, and the Cluster page flags offsets of 2 s or more.
- **Mixed versions (CLU-010):** the config schema rejects unknown keys, and an empty `rule` list is left out of the shared configuration. So an N−1 replica follows the cluster as long as nobody has made a quick rule. Once one exists, the replica refuses that version and keeps serving its last good one until it's upgraded. Quick rules therefore wait for a cluster-wide upgrade, as any new shared section does.

## ADR-068 — One process per data directory: an exclusive lock held for the process's life (Proposed)
**Context:** T6.14 (owner request 2026-10-05). Scaling a single-volume Deployment (or starting a second `telltale run` with the same configuration) makes two processes share one data directory: the node identity and cluster certificates, `state.db`, the query-log segments, and the cache dump. Nothing stopped it, and the damage is silent: two nodes with one identity, interleaved query-log writes, and SQLite contention.

**Decision:**
- `telltale run` takes an exclusive advisory lock (`flock`, through `std::fs::File::try_lock`) on `<data_dir>/telltale.lock` before anything else touches the directory, and holds it until the process exits.
- If another process holds it, the new one retries for 10 s (a previous process may still be shutting down), then exits non-zero with an error. The error names the directory and the holder (pid, host or pod name, and start time, which the holder writes into the file), and points to `mode: scaled`.
- If the lock file can't be opened at all (a read-only or unusual file system), the node logs a warning and starts anyway: the lock protects against a mistake and must never stop DNS (CLU-004).
- `telltale backup restore` takes the same lock without waiting, so it refuses to restore under a running server.
- Read-only commands (`qlog search`, `explain`, `backup create`) don't take it.

**Consequences:**
- The operating system releases the lock when the process exits, even after a crash or `SIGKILL`, so there is no stale-lock cleanup.
- A rolling update of a single-volume Deployment would wait for the old pod forever. The chart uses a StatefulSet and the homelab Deployment uses `Recreate`, and the docs tell people with their own manifests to do the same.
- On network file systems `flock` may be emulated or local-only. That is acceptable for a guard against mistakes.

## ADR-069 — Editing upstreams, lists, and groups from the UI: overrides in state.db, the files untouched (Proposed)
**Context:** T7.5 (owner report 2026-10-06). On a node installed with `install.sh`, the upstreams and lists come in the starter `/etc/telltale/telltale.toml`. ADR-040 makes anything the files define read-only through the API ("files win"), so none of them could be changed in the UI. Rewriting the file isn't an option either: Docker and Kubernetes mount it read-only, and on Git-managed nodes the next deploy would replace it.

**Decision:**
- Upstreams, upstream groups, lists, and client groups made or changed through the API are managed entries in `state.db` (like ADR-040's), by name. An entry can:
  - add a new name;
  - **override** a file entry of the same name (the whole entry is replaced);
  - **hide** a file entry (a tombstone: the name is left out).
- The files are never rewritten. The UI marks each entry as *file*, *UI*, or *UI override of the file*, and "Revert to the file" deletes the override or tombstone.
- Every change is validated on the merged configuration before it's stored (a group can't lose its last upstream; a list can't be removed while a group uses it; the default upstream group must keep a member), with dry run, `If-Match`, idempotency, and audit as for the other managed kinds.
- In a cluster, the merged configuration is what the primary publishes (ADR-047), so changes reach every node.
- On a node whose configuration comes from Git (`config_source = "gitops"`), each change response carries the TOML to add to the repository or the Helm values to make it permanent ("Keep it in Git"), because an override lives only in that node's `state.db`.
- Devices, local names, forwarded domains, and quick rules keep ADR-040's rule (files win), since the starter config doesn't define them.

**Consequences:**
- A standalone node can be run entirely from the UI after `install.sh`.
- Two sources of truth for the same name are possible; the UI and the `GET` endpoints show which one is in effect (`source`: `file`, `api`, or `override`).
- A file change to an overridden entry has no effect until the override is reverted; the UI says so on the entry.

## ADR-070 — Agents' plans: a dry run kept in memory on the node that made it, applied with If-Match (Proposed)
**Context:** T7.1 (AGT-007). A `plan_*` MCP tool must show what a change would do and let the agent apply it later, only if nothing changed meanwhile and, with `[agents] require_approval`, only after an operator approves. The spec doesn't say where plans live, how long they last beyond "10 minutes", or how a cluster shares them.

**Decision:**
- A plan is the REST write (method, path, body) plus its dry-run answer, the config version it saw, the reason, and who asked (the caller's token or session). Plan tools call the REST dry run in-process with the agent's own credentials, so scopes, group restrictions, rate limits, and the kill switch apply unchanged.
- `apply_plan` replays the same write with `If-Match: <version>` and the plan ID as the `Idempotency-Key`. A 412 marks the plan `stale`. Only the caller that made a plan can apply or discard it.
- Plans live in the memory of the node that made them, at most 500, open for 10 minutes and listed for a day. They aren't stored or replicated: a restart drops them, and the agent plans again.
- With `[agents] require_approval = true` a new plan is `pending` until a person with the operator role approves or rejects it (`POST /api/v1/plans/{id}/approve|reject`, the "Agent changes" page). Agent tokens can never approve or reject. Both decisions are audited.
- Approval is checked when the plan is made: turning the setting on doesn't hold plans already made, and turning it off doesn't release pending ones.
- Immediate operations (`flush_cache`, `pause_blocking`, `resume_blocking`) have no plan, as `spec/13` §3.2 says; they're audited like any agent write.
- `plan_set_schedule` waits for schedules (FLT-010). Alert destinations for pending plans wait for OBS-010.

**Consequences:**
- Nothing new is persisted, and a plan can't outlive the configuration it was checked against.
- In a cluster, an operator approves on the node the agent used. Agents should use the node whose UI people use (normally the primary). If agents and people use different nodes, plans would need to move to the replicated `state.db`.

## ADR-096 — A client group's own upstream group (Proposed)
**Context:** T9.25 (UPS-007, owner request 2026-10-06). UPS-007 already routes by client group (`[[route]] match_group`), but that lives in routing, not on the group, and the UI had no way to set it. The spec doesn't say how it ranks against domain routes, which group wins for a device in several, or what removing an upstream group a group uses does.

**Decision:**
- `[[group]] upstreams = "<upstream group>"`, validated like a route's `upstream_group`. The router turns it into a route for the group's clients that matches any name, placed after the explicit `[[route]]` entries. Precedence: a domain route (deeper suffix), then an explicit route of equal depth (a `match_group` route, which comes first), then the group's `upstreams`, then `default`.
- A device in several groups: the derived routes are ordered by group priority (highest first), then configuration order, so its highest-priority group with `upstreams` decides.
- Removing an upstream group that a client group or a route still uses is refused with a hint, rather than clearing the choice. Clearing it would quietly send, say, the kids' questions to `default` instead of a family resolver. Reverting an API override of the files' entry is allowed (the group stays).

**Consequences:**
- No hot-path cost: routes are consulted only on a cache miss, and the cache is already keyed by upstream group, so groups never share answers from different resolvers.
- `[[route]] match_group` stays for narrower cases (one group's `TXT` questions, say).

## ADR-095 — `$dnsrewrite` in lists: AdGuard's precedence, a supported subset (Proposed)
**Context:** T2.3 kept `$dnsrewrite` rules in the snapshot but didn't apply them (T7.20 put rewrites in the configuration). AdGuard-format lists and personal rule sets use them for local names, safe-search CNAMEs, and blanking names out. Without them those lists lose part of their meaning.

**Decision:**
- **Values supported:**
  - an address, either family (A/AAAA);
  - a name (CNAME);
  - `NXDOMAIN`, `REFUSED`, or `SERVFAIL`;
  - the full form for `NOERROR` with A, AAAA, or CNAME, and any rcode with an empty answer.
  Other record types (MX, TXT, SRV, HTTPS, …) make the line unsupported (counted, skipped), so a list author's intent is never half-applied.
- **Precedence, as AdGuard does it:**
  - a matching rewrite wins over blocking;
  - an exception (`@@…$dnsrewrite`, with or without a value) turns rewrites off for the names it covers;
  - `$client`, `$dnstype`, and `$denyallow` narrow a rewrite like any rule;
  - schedules and quick rules still come first.
- **Combining:** an rcode wins, then the first CNAME, then every address of the asked family. When the name is rewritten only for the other family, the answer is an empty NOERROR.
- **On the query path:** a matcher flag skips everything when no list has rewrites. Otherwise the modifier index is walked once more for the name. The answer has TTL 60, is attributed to the list in the event, and a CNAME is resolved through the normal path (cache, upstreams, filtering of the target).

**Consequences:**
- AdGuard-style lists and personal rules work as their authors meant.
- Configuration rewrites (`[[group.rewrite]]`) stay the per-group tool. List rewrites follow the lists a group uses.

## ADR-094 — Local zones answer SOA and NS at their apex; no zone transfers (Proposed)
**Context:** T7.22's zones answered their records, but not `SOA` or `NS` at the apex. Their negative answers carried a placeholder SOA owned by the question name. Tools (`dig SOA`, monitoring checks, some resolvers' zone-cut detection) expect real ones.

**Decision:**
- **From the zone file:** if it has SOA and NS at its apex, they're served as written. Relative names are completed with the origin.
- **Otherwise, made up** as Unbound does for local zones:
  - NS `localhost.`;
  - SOA `localhost. hostmaster.<zone>`;
  - serial = load time;
  - refresh 3600, retry 600, expire 86400;
  - MINIMUM = `negative_ttl`.
- **Negative answers** (NXDOMAIN and NODATA) carry that SOA owned by the apex, with TTL `negative_ttl` (RFC 2308).
- **Not done:** zone transfers (AXFR/IXFR). They need TSIG and secondary servers, which home and lab installs rarely have. The zone file, or Git, is the source to copy instead.

**Consequences:**
- `dig SOA`/`NS` and negative caching downstream behave as with any authoritative server.
- The made-up `localhost.` name server can't be queried from outside, which is the point: these zones are served by the resolver itself.

## ADR-093 — DNS stamps: enforce their certificate hashes (Proposed)
**Context:** T7.24 parsed DoH/DoT/DoQ stamps but skipped their hashes. A stamp's hashes are SHA-256 digests of the `tbsCertificate` of certificates in the server's chain: the publisher's way of saying "only these CAs (or this certificate) may vouch for it". dnscrypt-proxy enforces them.

**Decision:**
- Hashes are parsed. Each must be 32 bytes, or the stamp is malformed.
- When a stamp has hashes, the normal verification runs first, then some certificate in the presented chain must match one. With `tls_insecure_skip_verify` the match is still required, as for SPKI pins.
- No opt-out switch. Someone who doesn't want the pinning uses the plain URL instead of the stamp, which is clearer than a flag that silently weakens what the stamp says.
- Failures name the cause.

**Consequences:**
- Stamps mean what they say.
- When a provider rotates its intermediate CA before republishing the stamp, that upstream fails until the stamp is updated. A group with another member fails over meanwhile.
- No built-in preset uses stamps.

## ADR-092 — Aggressive NSEC (RFC 8198): NSEC ranges per upstream group, NSEC3 later (Proposed)
**Context:** ADR-086 deferred RFC 8198. The owner asked for the deferred features that make TelltaleDNS a more complete DNS product. Unbound and BIND both do this by default, and on a home network the root zone's NSEC records cover the steady trickle of made-up TLDs (`.lan`, `.home`, `.localdomain`).

**Decision:**
- **What's kept:** after the validator proves a negative answer secure, its NSEC records are cached, keyed by owner in canonical order, per upstream group. Each is kept only if:
  - it's proven secure;
  - it's inside the zone of the SOA that came with it;
  - it's signed by that zone.
  The SOA and all RRSIGs are kept too.
- **How long:** the NSEC's TTL, capped by the SOA's negative TTL (RFC 8198 §5.4). At most 20,000 ranges and 2,000 zones per group; past that, the ones expiring first go.
- **Answering on a miss, before going upstream:**
  - **NXDOMAIN** when one range covers the name and one covers the wildcard at the closest encloser (RFC 4035 §5.4).
  - **NODATA** when an NSEC at the name lacks the type and CNAME, and isn't a delegation (unless the question is DS).
  - **Nothing** below a delegation's or a DNAME's owner. The child zone, or the alias, decides there.
- **The answer:** NXDOMAIN or NODATA with the SOA and NSEC records, plus their signatures for DO clients, and AD as for any secure answer. TTLs are counted down to the earliest expiry. It's counted as synthesized, not as a validation.
- **Switch:** `[dnssec] aggressive_nsec`, on by default, as in Unbound.
- **Deferred — NSEC3:** synthesis needs the zone's hash parameters and a hash per lookup, and opt-out spans prove nothing for unsigned delegations. Worth doing with measurements.

**Consequences:**
- Repeated junk lookups under NSEC-signed zones (the root above all) stop reaching upstreams, and are answered in microseconds instead of a round trip.
- Answers still carry their proof, so a validating client downstream can check them.
- A config reload starts the cache empty, like the validator's own cache.

## ADR-091 — No DHCP server: routers hand out addresses (Accepted)
**Context:** T7.19 added an optional DHCPv4 server (OPS-008, ADR-078). The owner (2026-10-06): most people let their router serve DHCP, and DHCP sits outside what a DNS product should own. Keeping it means a privileged port (67), a lease state machine, and a failover question in clusters, all for few users.

**Decision:**
- The server goes: the code, `[dhcp]`, its end-to-end test, and its documentation. OPS-008 is descoped, and ADR-078 is superseded.
- Device names keep coming from outside DHCP sources:
  - routers' DHCP clients (`[[router]]`: UniFi, OPNsense);
  - mDNS announcements;
  - the importers, which still turn Pi-hole's and Technitium's DHCP reservations into named devices.
- `GET /api/v1/dhcp/leases` stays: these are the router's DHCP leases. It drops `reserved` and `source = dhcp`.
- A configuration that still has `[dhcp]` fails to load with the usual unknown-field error rather than being ignored. Neither of the owner's nodes used it.

**Consequences:**
- About 1,100 lines and a privileged port are gone. The scope stays DNS.
- Anyone who wants TelltaleDNS to serve DHCP needs their router, or dnsmasq beside it.

## ADR-090 — DoH load from h2load; restart counts in the data directory (Proposed)
**Context:** T9.13 picks up the deferrals of T0.3 (DoT/DoH load, a realistic profile) and T6.14 (restart counts, Grafana panels).

**Decision:**
- **Transports bench:** dnsperf (`-m tcp|dot`) measures TCP and DoT.
  - DoH uses h2load, a bench-only tool that isn't shipped. dnsperf's DoH client ran at about 40 ms a query against a listener that answers curl in 175 µs, so it would have measured itself.
  - DoH requests are GETs built from the same corpus, so the names match the other transports.
  - The existing `realistic-home` corpus stays with the swap test. The new mode uses cache hits, because the Python stub upstream would saturate first and hide the transports' cost.
- **Restart counts:** `<data_dir>/runs.json` holds `starts`, `unclean`, and `running`. A start increments `starts`, and adds to `unclean` if `running` is still set, then sets `running`. A clean stop clears it, even when startup fails.
  - It's written only by the process holding the data-directory lock.
  - An unreadable file starts over, rather than failing startup.
  - These are counters, so `increase()` over a range works across restarts. The heartbeat-observed `restarts` column in the cluster view stays as it is (what peers saw).
- **Grafana:** new rows for transports (queries by protocol, TLS/DoH/DoQ/PROXY problems) and the process (uptime, restarts, unclean starts, OOM kills, CPU, temperature, data-disk free). Every expression is checked with `promtool check rules` in the Prometheus image.

**Consequences:**
- What DoT and DoH cost compared with UDP is measured, and repeatable on any machine with h2load.
- A crash loop shows up as a number on the dashboard instead of a short uptime.

## ADR-089 — vqlog `or` and rollup windows; pre-save checks (Proposed)
**Context:** T9.12 picks up ADR-082's "not done" (`or`, rollup-backed long windows) and the pre-save checks deferred from T7.5.

**Decision:**
- **`or`:** `and` binds tighter. A parenthesized group is one term of the `and` list, one level deep. A bare `or` makes the whole stage one group, and mixing it with parentheses is refused as ambiguous rather than guessed. The plan keeps the plain conditions (still pushed into the index search) and adds `any_of` groups checked per row. At most 32 alternatives in all; `in (…)` covers many values of one field.
- **Rollup windows:**
  - **When:** a query whose `from` is older than `retention_days`, or any query while the query log is off, is answered from the rollups when it fits them.
  - **What fits:** `count` only, no `or`, buckets of whole hours, and at most one of status, qtype (the named ones), rcode, proto, and group, used as the key, the filter, or both. The rollups keep each breakdown on its own, so two can't be combined.
  - **Levels:** day buckets use the day rollups; everything else uses the hour rollups.
  - **Labels:** `source` says which store answered. A query that doesn't fit runs over the log as before, with a `note` saying the log only covers `retention_days`.
  - **Not chosen:** answering partly from each store. Its numbers would mix two sources, with no line between them.
- **Pre-save checks:** `POST /api/v1/checks/upstream` and `/checks/list` take the same body as the PUT.
  - The upstream check builds the upstream through the normal router (a configuration holding only it) and asks for `. NS` within 5 s. The list check downloads with `[filter]`'s limits, or takes inline rules, and parses as the compiler does.
  - `path` lists aren't checked: reading server files on request would be a new capability.
  - Both need the operator role and the entry's write scope (they reach out from the node), and both are audited. The paths sit under `/checks/` so they can't collide with an upstream or list named `test`.

**Consequences:**
- An agent can ask "blocked per day for six months" and get exact counts.
- Questions that need names or clients stay limited to what the log keeps, and the answer says so.
- A typo in an upstream URL or a dead list URL shows up before it's saved.

## ADR-088 — DNS64 exclusions and reverse names; syslog over TLS; a webhook spill (Proposed)
**Context:** T9.10 and T9.11 pick up the deferrals of T7.21 (DNS64) and T7.13 (event sinks).

**Decision:**
- **DNS64 exclusion set (RFC 6147 §5.1.4):** `dns64_exclude` on the group takes networks of either family. An excluded AAAA counts as missing. With all of a name's AAAA records excluded, AAAA records are made up for it. With some left, the excluded ones are removed, along with signatures, since the set they signed changed; DNS64 already never applies to CD clients. An excluded A record is never made into AAAA. `::ffff:0:0/96` is always excluded, as the RFC recommends.
- **DNS64 reverse names (§5.3.1):** a PTR question for an address inside the client group's /96 gets a CNAME to the embedded IPv4 address's `in-addr.arpa` name, resolved like a safe-search target. A private IPv4 address keeps RFC 6303's local NXDOMAIN, so it never goes upstream. Of the RFC's two options, the CNAME was chosen over making up a PTR record: it needs no state and shows where the answer comes from.
- **Syslog over TLS (RFC 5425):** `tls://host:port`, with octet-counted frames as on TCP, rustls with the public roots plus `tls_ca`, and the certificate checked against the host in the address. No client certificates (none asked for yet).
- **Webhook spill:** off unless `spill_max_bytes` is set (at least 1 MiB).
  - Refused batches are appended as JSON lines to `<data_dir>/sinks/<name>.spill`, with the send offset in a `.pos` file, so a restart doesn't resend what was sent. The file is compacted when it needs room and removed when it's empty.
  - Replay runs up to 20 batches after a delivered batch or on a quiet tick, and stops at the first failure. Events that arrive meanwhile wait in the sink's normal buffer.

**Consequences:**
- IPv6-only networks get working reverse names and can route around unreachable IPv6 ranges.
- A SIEM can take events over TLS.
- A collector outage no longer loses events, up to the cap. The disk writes happen only during an outage, on the sink's own thread.

## ADR-087 — Upstream follow-ups: DoH GET, UDP over SOCKS5, DNSCrypt relays, per-client ECS (Proposed)
**Context:** T9.9 picks up the deferrals of T7.8 (DoH), T7.16 (proxies), T7.23 (ECS), and T7.24 (DNSCrypt).

**Decision:**
- **DoH GET:** `doh_method = "get"` puts the query in `?dns=` (base64url, no padding) with ID 0; POST stays the default (smaller requests, no URL length concerns).
- **UDP through SOCKS5:** a `udp://` upstream with a `socks5://` proxy uses UDP ASSOCIATE (RFC 1928 §7). Up to four associations are kept for reuse; one whose control connection or relay fails is dropped. The TCP retry for a truncated answer goes through the proxy too. HTTP proxies still refuse `udp://` in the configuration check.
- **Anonymized DNSCrypt:** `relay` (a relay stamp, type 0x81, or `ip:port`) on a DNSCrypt upstream prefixes every packet with the anonymized-DNSCrypt header (8 × 0xff, 0x0000, the server's address as IPv6, its port), the certificate query included, over UDP and TCP. One relay per upstream; choosing relays at random from a list is left to configuring several upstreams in a group.
- **Per-client ECS (`ecs = "client"`):** the client's source address cut to /24 or /56 (RFC 7871 §11.1). Gaps resolved conservatively:
  - nothing is sent for non-public sources (private, loopback, link-local, CGNAT, ULA);
  - ECS options sent by clients are still never forwarded or echoed, so a downstream forwarder never caches an answer as if it were scoped;
  - the cache key gains the packed subnet (8 bytes per key, 0 when unused), but only for groups that have a `"client"` member, which is a flag checked once per miss;
  - entries are keyed by the source prefix, not the upstream's SCOPE: never shared more widely than the subnet sent, at the cost of fewer hits;
  - scoped entries aren't written to the cache file, whose format has no subnet.

**Consequences:**
- DNSCrypt users get the anonymity dnscrypt-proxy's relays give, and SOCKS5 users keep UDP's latency.
- `ecs = "client"` multiplies cache entries by the number of client subnets; it's meant for resolvers with public clients, and does nothing on a home network.

## ADR-086 — Recursion and DNSSEC follow-ups: priming, hedging, EDE reasons, an anchors file; RFC 5011 and 8198 deferred (Proposed)
**Context:** T9.8 picks up the deferrals of T6.3 (DNSSEC) and T7.15 (recursion).

**Decision:**
- **Root priming (RFC 8109):** on first use, the hints are asked for `. NS`; the answer's glue (or, without it, lookups of the names) becomes the cached root zone cut, renewed when it expires (TTL capped at a day). A failed attempt waits a minute before the next.
- **Hedged queries:** a server that hasn't answered after 1.5 × its smoothed RTT (at least 150 ms; 400 ms when unknown) is joined by the next server; the first usable answer wins. It costs at most one extra query per slow step, inside the 96-query budget.
- **EDE reasons:** a bogus answer's RRSIGs give the code: none for the records that answer → 10, all expired → 7, all not yet valid → 8 (serial-number time comparison), else 6. The library's validator doesn't expose its reason, so this reads the signatures it returns.
- **Trust anchors:** both current root KSKs (20326, 38696) ship built in (a test pins them). `[dnssec] trust_anchors_file` replaces them with a file of DNSKEY records; a bad file keeps the built-in ones.
- **Deferred — RFC 5011** automated trust-anchor updates: they need a persistent state machine with a 30-day hold-down for a root KSK change that happens every several years, which builds already carry. The anchors file covers the gap.
- **Deferred — RFC 8198** aggressive NSEC caching: it needs a cache of validated NSEC/NSEC3 ranges next to the library's validator and answer synthesis on the query path; worth doing with measurements, not as a follow-up.

**Consequences:**
- Recursive lookups ride out a slow server and a moved root server.
- SERVFAILs say why a signature failed.
- Validation survives the root key rollover with no action.

## ADR-085 — Alert email: a small built-in SMTP submission client (Proposed)
**Context:** T9.4 (OBS-010 lists email as a destination; deferred in T7.12). The owner has no relay of their own.

**Decision:**
- A minimal client in the binary (`smtp.rs`, written from RFC 5321/3207/4954/5322) over the rustls stack already shipped, instead of a mail library: one message per connection, STARTTLS (`smtp://`, 587) or implicit TLS (`smtps://`, 465), AUTH PLAIN or LOGIN, the public roots plus `tls_ca`, base64 text bodies, RFC 2047 subjects.
- A password is only sent encrypted: STARTTLS can't fall back to plain, and `smtp+insecure://` (for local catchers) refuses a username in the configuration check.
- Validation: CI runs a scripted SMTP server (STARTTLS with a private CA, implicit TLS, a wrong password reported as 535); Mailpit was checked by hand as an independent implementation; real delivery is the owner's choice of provider (a Gmail app password needs no relay).
- Not done: HTML mail, DKIM (the provider signs), a queue (a failed alert is logged like any destination).

**Consequences:** email works with any provider that offers SMTP submission, for about 30 KiB of code and no new dependency.

## ADR-084 — WASM upstream plugins: deferred, and wasmi rather than wasmtime if built (Proposed)
**Context:** M8 lists WASM upstream plugins; `04` §3 and ADR-007 name wasmtime behind a feature flag. T7.16 shipped the out-of-process plugins (`unix://` and `exec://`, DNS wire format), which already let any language implement an upstream.

**Measured (2026-10-06):** stripped, LTO, `panic = "abort"` release binaries of a program that compiles one module, against an empty program, on x86_64 Linux:

| Engine | Adds (raw) | Adds (gzip -9) |
|---|---|---|
| wasmtime 49 (Cranelift JIT, component model) | 9.4 MiB | 3.3 MiB |
| wasmi 2.0 (interpreter, pure Rust) | 1.7 MiB | 0.6 MiB |

The release binaries are 19–23 MiB raw today, and the image budget is 15 MiB compressed (OPS-001).

**Decision:**
- Don't build WASM plugins now. There's no user request; the process plugins cover the use case; and a sandboxed host networking API is a design of its own.
- If they're built, use **wasmi** behind an off-by-default `wasm` feature. It costs about a fifth of wasmtime's size, is pure Rust (no JIT, so it runs on armv7 and under seccomp profiles that forbid executable memory), and is fast enough for a per-query function that mostly waits on the network.
- Revisit on a concrete request, for example a resolver protocol that people want to ship as one file.

**Consequences:**
- M8 closes without code here.
- The plugin story stays the process boundary: crash isolation, and any language.

## ADR-083 — io_uring UDP: measured, not adopted (Proposed)
**Context:** M8 lists io_uring; `02` §3 calls it "a P2 experiment behind a feature flag". The UDP listener already batches with `recvmmsg`/`sendmmsg` on one `SO_REUSEPORT` socket per worker, so the syscall cost per query is already amortized.

**Measured (2026-10-06):** a standalone spike, not in the repo: one server thread doing the same per-datagram work both ways (64-slot `RecvMsg`/`SendMsg` io_uring ring vs 64-message `recvmmsg`/`sendmmsg`), loopback, WSL2 kernel 6.18, 8 cores, alternating 5-second rounds.
- With 4 client threads: 530.8k vs 526.3k answered per round (io_uring −0.9%).
- With 7 client threads (server about 90% CPU): 456.8k vs 471.6k (+3%).
- The spread between rounds was about ±15%, so neither difference is meaningful.

**Decision:** keep `recvmmsg`/`sendmmsg`; don't add an io_uring listener or feature. Reasons:
- No measured gain.
- More `unsafe` in the hot path (buffers that must outlive submissions).
- A second listener to test.
- io_uring is often unavailable where TelltaleDNS runs: Docker's default seccomp profile blocks it, and some distributions disable it (`kernel.io_uring_disabled`).

Revisit if a profile on real hardware shows syscalls dominating at the owner's target rates. Multishot receive with provided buffers would be the variant to try.

**Consequences:**
- One UDP code path.
- The M8 item is closed with data rather than code.

## ADR-082 — vqlog: a pipe language compiled to qlog searches, aggregated in memory (Proposed)
**Context:** T8.4, AGT-012: "a constrained, safe query DSL (`vqlog`) over the query log and rollups (filter, group by, top-K, percentiles, time bucket), with a cost estimate, exposed as one tool". The spec doesn't fix the syntax, the limits, or the scope.

**Decision:**
- Syntax: stages separated by `|` — `from`, `where` (conditions joined by `and`; `in (…)` lists instead of `or`), `bucket`, `by`, `stats`, `top`, `sort`, `limit`. A fixed grammar parsed into a plan in `telltale-api` (syntax errors are 400s with hints); no expressions, functions, or joins. The name kept from the spec (`vqlog`) although the product was renamed.
- Execution reads the query log only, not the rollups: rollups can't filter by name or client, and percentiles over them would be approximations of approximations. The conditions the qlog index can use are pushed into the search (time, one name, one client, group, statuses, qtypes, rcodes, one upstream, minimum latency); every condition is also checked on each row. Grouping is exact, in memory; percentiles are exact (nearest rank).
- Cost: a header-only estimate (segments, blocks, and rows that could match, using the same block skipping as search) before the scan, returned with every answer; `dryRun` returns only that. Above 100 million estimated rows the query is refused. The scan stops at 2 million matches, 100,000 groups, or 25 seconds and reports `truncated` with the reason; results then cover the newest queries.
- Access: `querylog:read` (it reads per-device, per-name rows); not group-aware, so group-restricted agents can't use it. Scope: this node's log plus the logs shipped to it (CLU-007), so the primary of a shipping cluster sees everything; `missingNodes` as elsewhere.
- Not done: `or` between fields, rollup-backed long windows, per-cluster fan-out with mergeable sketches, a UI editor.

**Consequences:**
- One MCP tool answers most analytics questions with exact numbers and a visible cost; the narrow tools stay for the common ones.
- Long windows on busy networks are slow (it scans), and the limits say so instead of degrading DNS (search threads run at background priority).

## ADR-081 — mDNS device naming: passive, A records of `<name>.local` (Proposed)
**Context:** T8.3 (M8 "mDNS client naming"; API-010 lists mDNS as a naming source). Many devices announce their host name over mDNS (RFC 6762) whether or not anyone asks.

**Decision:**
- `[clients] mdns` (off by default): join 224.0.0.251 on the mDNS port (5353, address and port reuse) and read A records owned by a two-label `<name>.local` in the answer and additional sections of responses others send. Never send queries or responses (no probing, no load on the network). IPv4 only, like the DHCP and router names.
- The latest name per address is kept in memory (4096 at most, the oldest tenth dropped when full) and published every 5 s; device names fall back to configured clients, DHCP leases, router leases, then mDNS.
- Service instance names (`Living Room._airplay._tcp.local`), link-local and unspecified addresses are ignored.
- Not done: asking (`QU` queries to fill the gaps), IPv6 (AAAA owners would need the neighbor table to match clients), persisting across restarts, showing the names in the leases API.

**Consequences:**
- Devices get readable names without a router integration or DHCP, on networks where TelltaleDNS can hear multicast.

## ADR-080 — Router integrations: read-only polling of UniFi and OPNsense (Proposed)
**Context:** T8.2 (M8 "router integrations"; API-010 lists DHCP leases as a naming source). Most homes run DHCP on the router, so TelltaleDNS's own DHCP (T7.19) doesn't see those leases.

**Decision:**
- `[[router]]` entries are polled read-only (`interval_secs`, 300; 15 s after a failure). UniFi: `stat/sta` (connected clients) with an API key (`X-API-KEY`), or a local user's login (UniFi OS `/api/auth/login` and `/proxy/network/...`, falling back to the classic `/api/login`); the UniFi alias wins over the host name. OPNsense: the lease search of Dnsmasq, then Kea, then ISC, with the API key and secret (basic auth).
- The result replaces that router's part of a lease view next to the DHCP server's; device names fall back to configured clients, then DHCP leases, then router leases. `GET /api/v1/dhcp/leases` lists both with a `source`.
- Self-signed consoles: `tls_ca` (the console's certificate), or `tls_insecure_skip_verify` with a configuration warning. Secrets come from files.
- Not done: OPNsense static mappings without a lease, UniFi's offline known clients (`rest/user`), pfSense, OpenWrt.

**Consequences:**
- Device names appear on networks where the router runs DHCP, with no change on the router beyond a read-only account or key.

## ADR-079 — DNSCrypt with RustCrypto's crypto_box; stamps map to existing transports (Proposed)
**Context:** T7.24 (UPS-003; `04` §2). DNSCrypt v2 needs X25519 and libsodium's box constructions; `02` §7 lists no crate for them. Stamps may name DNSCrypt, DoH, DoT, or DoQ servers.

**Decision:**
- New dependency `crypto_box` 0.9 (RustCrypto; its SalsaBox and ChaChaBox are libsodium's `crypto_box` and `crypto_box_curve25519xchacha20poly1305`, on the `curve25519-dalek` already in the tree) and `ed25519-dalek` (already in the tree) for certificates. The IETF XChaCha20-Poly1305 AEAD is a different construction and wouldn't interoperate. The detached API is used and the tag written first (libsodium's `_easy` layout); verified live against five providers' servers.
- One X25519 key per upstream for its lifetime (like dnscrypt-proxy's default); a fresh random nonce per query; ISO 7816-4 padding to 64 bytes, at least 256 over UDP; TCP when the answer is truncated.
- Certificates: TXT records of the provider name fetched in clear, each checked with the stamp's Ed25519 key (`verify_strict`) and its validity dates; the newest construction, then the highest serial, wins; refreshed after an hour or at expiry.
- DoH/DoT/DoQ stamps become those transports (host name as the TLS name, an address in the stamp pinned); the stamp's certificate hashes aren't enforced yet.
- Not supported: anonymized DNSCrypt relays, DNSCrypt stamps' `props` flags (DNSSEC, no-log, no-filter are informational).

**Consequences:**
- Users of dnscrypt-proxy's server list can paste stamps directly.
- About 100 KiB more in the binary.

## ADR-078 — DHCPv4: authoritative, broadcast replies, leases name devices (Superseded)
**Superseded by:** ADR-091. The DHCP server was removed on 2026-10-06; this record stays for history.
**Context:** T7.19 (OPS-008; `08` §7). The spec lists the options, static leases, and a lease file, but not the server's stance toward clients asking for foreign addresses, how replies reach clients without an address, or how leases "feed client naming".

**Decision:**
- A module of the binary (`crates/telltale/src/dhcp.rs`), its own task and socket (socket2: `SO_BROADCAST`, `SO_REUSEADDR`, optional `SO_BINDTODEVICE`), never on the DNS path.
- Authoritative for its subnet (like `dhcp-authoritative` in dnsmasq): REQUEST for an address this client may not have (someone else's, outside the pool, another subnet) gets NAK; INIT-REBOOT for a free pool address is granted. Offers are held 60 s; DECLINEd addresses are skipped for 10 minutes; no ping-before-offer.
- Replies (RFC 2131 §4.1): to `giaddr:67` via a relay, to `ciaddr:68` when the client has an address, else broadcast to `255.255.255.255:68` (no raw-socket unicast to an unconfigured client: broadcast is allowed and needs no extra capability).
- Options 1, 3, 6 (default: the server's address), 15, 28, 42, 51, 54, 58, 59, 119 (RFC 3397, uncompressed; split per RFC 3396 when long).
- Leases persist to `<data_dir>/dhcp-leases.json` after every change; the live view (address → lease) is published on the pipeline, so device names fall back to the lease host name (a configured client name wins), and `GET /api/v1/dhcp/leases` reads it.
- In a cluster, one node runs it (documented); other nodes don't see its leases yet.

**Consequences:**
- A Pi can replace the router's DHCP; unnamed devices get readable names immediately.
- Without failover, a second DHCP node needs split pools (not supported in config yet).

## ADR-077 — dnstap: a sampled copy of the wire messages, off by default (Proposed)
**Context:** T7.18 (OBS-007; `06` §5). dnstap needs the query and response messages, which query events don't carry (`02` §3: no allocation on the hot path).

**Decision:**
- The tap is a `OnceLock` on the pipeline set at startup: with dnstap off, the query path pays one atomic load. With it on, one query in `sample_every` (a relaxed counter) is copied, both messages, into a bounded channel with `try_send`; full means dropped and counted. Measured with bench-smoke: no change with it off (within WSL run-to-run noise).
- The writer thread speaks bidirectional Frame Streams (READY, ACCEPT, START; STOP at the end) to a Unix socket or TCP reader, reconnects with backoff (1 s to 30 s), and writes `CLIENT_QUERY` and `CLIENT_RESPONSE` (address, family, transport including DoT/DoH/DoQ, times, messages; identity = node name, version = TelltaleDNS version). Protobuf is encoded by hand: the schema is small and fixed.
- Deferred: `FORWARDER_QUERY`/`FORWARDER_RESPONSE` (they'd need a tap in the upstream exchange), and the client's port (not on the event path).

**Consequences:**
- At `sample_every = 1` every query costs two small allocations and a channel send; the docs say to sample on busy resolvers.

## ADR-076 — OTLP over HTTP with JSON, metrics converted from our exposition (Proposed)
**Context:** T7.17 (OBS-006; `06` §5). The spec asks for "the same metric set via OTLP/HTTP" and optional QueryEvent logs, without an encoding or a mapping.

**Decision:**
- OTLP/HTTP with the JSON encoding (the protobuf JSON mapping: 64-bit integers as strings). No OpenTelemetry SDK and no generated protobuf types: the binary stays small, and every OTLP/HTTP receiver accepts JSON.
- Metrics are converted from our own Prometheus exposition every `interval_secs`: counters → cumulative monotonic sums (start time = process start), gauges → gauges, histograms → explicit-bucket histograms (per-bucket counts from the cumulative ones). Names and labels are kept as in `/metrics`, so dashboards and docs apply to both.
- Query events as logs are an event-sink format (`otlp_logs`, ADR-072): batching, buffering, and retries are the sink's. Body: a one-line summary; attributes use OpenTelemetry DNS-style keys where they exist (`dns.question.name`, `client.address`), `telltale.*` otherwise.
- No OTLP/gRPC.

**Consequences:**
- Collectors that convert back to Prometheus see `_total` already in counter names (most keep it as is).
- A counter reset (restart) shows as a new start time, as OTLP expects.

## ADR-075 — Proxies, socket plugins, pins, and client certificates (Proposed)
**Context:** T7.16 (UPS-010, UPS-011; `04` §2, §6). The spec names the features but not where a proxied hostname is resolved, how an `exec://` plugin learns its socket, how plugins restart, or how pins interact with `tls_insecure_skip_verify`.

**Decision:**
- Proxies (SOCKS5 with RFC 1929 credentials, HTTP CONNECT) carry `tcp://`, `tls://`, and `https://` upstreams; others are a configuration error. A hostname URL goes to the proxy by name (SOCKS5 ATYP 3, `CONNECT host:port`), so no bootstrap is needed and no lookup leaks (Tor). Proxy addresses are IP literals (or `localhost`). UDP through SOCKS5 (UDP ASSOCIATE) stays P2.
- Socket plugins speak RFC 7766 framing over a Unix socket, on the same pipelined connection pool as TCP upstreams. `exec://` plugins get `TELLTALE_PLUGIN_SOCKET` (`<data_dir>/plugins/<upstream>.sock`) and `TELLTALE_UPSTREAM` in their environment, `args` as arguments, stdin closed, stdout and stderr logged per line; they restart with backoff (1 s doubling to 60 s, reset after a minute up) and are killed when their upstream is dropped (each reload rebuilds upstreams, so a reload restarts plugins).
- Pins are base64 SHA-256 of the leaf's `SubjectPublicKeyInfo`, checked after the normal WebPKI verification; with `tls_insecure_skip_verify` only the pin is checked. `tls_ca` adds roots for one upstream; `tls_client_cert`/`tls_client_key` (PEM) enable mTLS. Files are read at load and reload.
- Deferred: DoH GET, the WASM upstream ABI (P2).

**Consequences:**
- Tor users point an encrypted upstream at the Tor SOCKS port with a hostname URL and nothing else.
- A plugin that needs state across reloads must keep it itself (it's restarted on configuration changes).

## ADR-074 — Our own iterative resolver, conservative defaults (Proposed)
**Context:** T7.15 (DNS-012, UPS-012; `03` §6). `02` §2 allows building on `hickory-recursor`. The spec fixes the limits (16 CNAME hops, 32 referrals) and asks for QNAME minimization, 0x20 (configurable), SRTT server selection, glue in bailiwick, and RFC 8198, but not the defaults, the timeouts, or how the resolver meets the per-query budget.

**Decision:**
- `telltale-recursor` is our own iterative resolver on `telltale-proto` (no new dependencies): exact control over minimization, bailiwick rules, and limits, and nothing added to the image beyond its code.
- It's a transport of `telltale-upstream` (`recursive://`), so groups, hedging, health, the answer cache, and DNSSEC validation (which then fetches DNSKEY and DS through it) work unchanged. Its attempt timeout is at least 3 s (not the 1 s cap of forwarders); the query's overall budget (2 s) still bounds a client's wait, and zone cuts learned meanwhile stay cached, so a retry continues from there.
- Defaults: QNAME minimization on, relaxed (RFC 9156 §2.3: the full name after NXDOMAIN or failure on a minimized query; at most 10 minimized steps); 0x20 off (a few authoritative servers don't echo case; when on, such servers are remembered and asked plainly); IPv6 off (many home networks lack an IPv6 route); root hints built in, no priming query.
- Bailiwick: answers only for names under the zone being asked; glue only for server names under the referring zone; upward or sideways referrals are lame. A server name inside its own zone without glue is skipped.
- Caches: zone cuts with addresses and server-name addresses (20,000 entries each, TTLs clamped to 30 s..1 day), server SRTT (EWMA). Final answers are cached by the answer cache only.
- Limits: 16 CNAME/DNAME hops, 32 referrals per lookup, 4 nested lookups for server names, 96 queries per client question, 4 servers tried per question, 1.2 s per server at most.
- RFC 8198 (aggressive NSEC) is deferred: it needs validated NSEC records kept below the validator.

**Consequences:**
- The common "Pi-hole + unbound" setup becomes one upstream; imports from Technitium without forwarders use it directly.
- A cold resolution in a zone with slow or broken servers can exceed the 2 s budget the first time (the client gets SERVFAIL or a stale answer; the next query succeeds from the learned cuts).

## ADR-073 — DGA scoring and NXDOMAIN storms: fixed formulas, shipped bigrams, absolute storm bar (Proposed)
**Context:** T7.14 (OBS-009; `06` §7). The spec names the signals (entropy, consonant runs, bigram log-likelihood) and the storm rule shape ("> X/min and > Y%") but not the weights, thresholds, the bigram source, or how findings are grouped.

**Decision:**
- The bigram table is 27 × 27 signed bytes (`presets/bigrams.bin`, `round(4 × log2 P(next | previous))` with start and end symbols) built from the public-domain dwyl/english-words list, embedded in the binary.
- The score of a registrable domain's own label (8 to 63 characters, not `xn--`) is `0.7 × max(bigram, mix) + 0.2 × consonants + 0.1 × entropy`, each clamped to 0..1: bigram = (mean bits per letter pair − 6) / 2; mix = (letter/digit switches − 2) / 4; consonants = (longest run − 5) / 3; entropy = (normalized entropy − 0.85) / 0.15. Calibrated on ~200 real service domains (none reach 0.2) and random-letter and hex labels (0.8 to 1.0). Logs come from tables, so the score is identical on every architecture.
- Only first-seen domains of devices past their learning period are scored for findings; a `dga` finding needs at least 2 at or above the sensitivity's threshold (0.75, 0.6, 0.5) in one hour, and is one finding per device-hour with samples.
- An NXDOMAIN storm is absolute (no baseline): at least `nxdomain_per_minute` (30) NXDOMAIN answers and `nxdomain_percent` (50 %) of the device's queries in a calendar minute; once per device per hour.
- The first-seen feed starts after a device's first day (its initial learning would flood it) and keeps the last 2000 entries, persisted with the engine.
- List overlap is counted at compile time (pairs of lists per shared name); `hits` are this node's counts since start, not 24 h / 7 d windows from the query log.

**Consequences:**
- Dictionary-word DGAs and short generated labels aren't caught; some vendor IDs may score high (the UI shows the score, not a verdict).
- A restart resets list hits; overlap is exact for the active snapshot.

## ADR-072 — Event sinks: one bounded buffer per sink, API-shaped JSON, no disk spill (Proposed)
**Context:** T7.13 (OBS-010; `06` §5). The spec asks for JSON-lines, syslog, and webhook sinks "with retry and a disk spill cap", but not the event format, how a slow sink is kept off the query path, or how retries are bounded.

**Decision:**
- An event is the API's query row (`QueryRow`: the same fields and names as `GET /api/v1/queries`, names resolved when the event is written, the query log's privacy level applied), so a sink's output and the API's agree.
- The aggregator thread formats each event once and offers it to every sink with `try_send` on a bounded channel (`max_buffer`); each sink writes from its own thread. A full buffer drops the event, counted and logged once a minute. DNS and the query log never wait for a sink.
- The webhook posts batches (`batch` events or `flush_secs`), retries a failed batch twice (1 s, 2 s), then drops it. Events buffer in memory only; the "disk spill cap" isn't implemented: the query log already keeps every event on disk.
- Syslog is RFC 5424 over UDP or TCP (RFC 6587 octet counting); TLS isn't implemented yet. Severity is *notice* for blocks and *informational* otherwise.
- Sinks are started once at startup (like the query log's writer); a reload doesn't change them.

**Consequences:**
- A collector outage loses events beyond the buffer; the query log, which sinks don't replace, still has them.
- Syslog over TLS needs a forwarder (rsyslog, Vector) until it's added.

## ADR-071 — MCP over OAuth: JWT access tokens from the OIDC provider, for existing users only (Proposed)
**Context:** T7.4 (AGT-008, P1). MCP clients sign in with OAuth 2.1: the server publishes RFC 9728 metadata naming an authorization server, and accepts that server's access tokens. The spec says to use the configured OIDC provider but not how tokens become principals, or which tokens are accepted.

**Decision:**
- One provider is the authorization server for MCP (`[auth.oidc] mcp_provider`). TelltaleDNS is only a resource server: client registration, consent screens, and refresh are the provider's.
- Accepted tokens are JWTs signed with the provider's published keys (asymmetric algorithms only), with its issuer, the audience `mcp_audience` (default `<public_url>/mcp`), and a current expiry (60 s leeway). There's no introspection, so opaque tokens are refused.
- The token's `sub` must match a user who has signed in to the web UI with that provider (ADR-034). An unknown subject is refused rather than creating an account, because access tokens rarely carry the group claims that decide roles.
- The principal is an agent of that user: the TelltaleDNS scopes in `scope` or `scp` (or the read-only default when there are none), never above the user's stored role; audited as `agent:oauth:<azp> (owner: <user>)`. Rate limits, the kill switch, plans, and approvals apply as for agent tokens.
- An unauthenticated or refused `/mcp` request gets `WWW-Authenticate: Bearer resource_metadata="…"` (and `error="invalid_token"` when a token was sent).

**Consequences:**
- Assistants connect with SSO and the user's consent, and no long-lived token is stored in the assistant.
- Each request verifies a signature (keys cached with discovery, refreshed on rotation); no per-token cache is kept.
- Providers that only issue opaque access tokens need a token per agent instead, until introspection is added.
