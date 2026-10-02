# 02 — Architecture

## 1. Process model: one binary, three roles
```
telltale run --role=all          # default: Pi / single node / small k8s install
telltale run --role=resolver     # data plane only (scale horizontally)
telltale run --role=controller   # control plane only (API, UI, compiler, analytics store, cluster primary candidate)
```
- Every cluster **node** runs a resolver. A node with role `all` or `controller` is *eligible* to be the cluster **primary** (see `12`).
- The reference homelab topology:
  ```
   ┌─────────────── Site "home-pi" ───────────────┐    ┌──────────── Site "k8s" ─────────────────────────┐
   │ Raspberry Pi 4  (container or systemd)       │    │ controller StatefulSet (1 pod, PVC)  role=controller│
   │ telltale role=all  ── replica OR primary ───────┼─mTLS┼─ resolver Deployment (N pods)        role=resolver  │
   │ local snapshot + local query store           │    │ LoadBalancer :53 (MetalLB, ETP=Local)              │
   └──────────────────────────────────────────────┘    └────────────────────────────────────────────────────┘
          ▲ clients get both IPs via DHCP option 6 (Pi IP, k8s LB IP) ▲
  ```

## 2. Crate layout (Cargo workspace)
| Crate | Responsibility | Notes |
|---|---|---|
| `telltale-proto` | Zero-copy DNS wire parser/writer for the hot path (header, question, EDNS, answer walk for CNAME/IP inspection, TTL patching) | `forbid(unsafe)`. Uses `hickory-proto` only for full decode/encode off the hot path (DNSSEC, zone files). |
| `telltale-net` | Listeners: UDP (SO_REUSEPORT, recvmmsg/sendmmsg), TCP, TLS (rustls), DoH (hyper/h2 + h3 via quinn), DoQ (quinn), PROXY protocol | The only crate allowed `unsafe` (syscalls). |
| `telltale-cache` | Sharded S3-FIFO cache of wire responses; serve-stale; prefetch queue; persistence | |
| `telltale-filter` | List parsers, rule compiler, snapshot format (FST + regex DFA), matcher | Compiler runs in the controller (or locally in `all`). |
| `telltale-policy` | Client identification, group resolution, schedules, rate limiting, rewrites, safe search | |
| `telltale-upstream` | Upstream transports, pools, strategies, health, breakers, bootstrap, proxies, plugin upstreams | |
| `telltale-recursor` | Iterative resolver + DNSSEC validator | P1; may build on `hickory-resolver`/`hickory-recursor` components where mature. |
| `telltale-telemetry` | QueryEvent, ring buffers, aggregator, rollups, histograms, top-K, Prometheus/OTLP/dnstap exporters | |
| `telltale-store` | Query-log segment store (columnar, zstd) + SQLite for config/rollups/audit | |
| `telltale-cluster` | Membership, CA/join tokens, snapshot replication, fencing, federation RPC | |
| `telltale-api` | axum REST API, auth, OpenAPI, WebSocket/SSE tail, embedded UI assets | |
| `telltale-config` | Config schema (serde), validation, env overrides, GitOps mode, migrations | |
| `telltale` (bin) | CLI, role wiring, signal handling, `ctl` subcommands | |
| `ui/` | SPA (Svelte 5 + Vite + uPlot); built output embedded with `rust-embed` | Target ≤ 400 KiB gzipped. |

## 3. Threading and I/O model
- **Runtime:** tokio multi-thread runtime for control, upstream, TLS, and HTTP work. The UDP fast path runs on **N dedicated worker threads** (N = available cores, configurable). Each worker owns its own SO_REUSEPORT UDP socket per listen address and loops `recvmmsg → process batch → sendmmsg`. That gives no cross-thread contention for the common case.
- **Fast path inside a worker (synchronous, allocation-free):**
  `parse header+question → identify client → policy/filter decision → cache lookup → write response into the per-worker send buffer`.
  Only a **cache miss** (or prefetch) crosses into async land: the worker sends a request to the upstream manager through a bounded MPSC channel, and the answer is sent from the async task with `send_to` on the worker's socket (`Arc<UdpSocket>`).
- **TCP/DoT/DoH/DoQ** run as tokio tasks and call the same synchronous `Pipeline::handle()` first, so behavior is identical across transports.
- **Shared read-mostly state** (filter snapshot, policy tables, config) sits behind `arc_swap::ArcSwap`, so readers never lock. A swap is a pointer store, and old snapshots are freed when the last reader drops.
- **Allocator:** `mimalloc`. **Per-worker scratch arenas** for response building.
- **Platform notes:** Linux is the first-class target. On macOS and other non-Linux platforms, fall back to plain `recv_from`/`send_to` loops. `io_uring` is a P2 experiment behind a feature flag.

## 4. Data flow (single query)
```
packet ──► listener ──► Pipeline::handle(ctx)
                         │ 1 parse (telltale-proto)                 [t_parse]
                         │ 2 client id + group (telltale-policy)    [t_policy]
                         │ 3 rate limit
                         │ 4 local records / rewrites / safe-search
                         │ 5 filter decision (telltale-filter)      [t_filter]
                         │ 6 cache lookup (telltale-cache)          [t_cache]
                         │   hit → patch ID/TTL → respond
                         │   miss → upstream router ───────────► telltale-upstream (async)   [t_upstream]
                         │                                         │ DNSSEC validate         [t_dnssec]
                         │ 7 response policy: CNAME inspection, IP filter   ◄───┘
                         │ 8 cache insert
                         │ 9 respond                              [t_send]
                         └► QueryEvent → per-worker ring ─► aggregator thread ─► rollups / store / exporters / live tail / cluster shipper
```
Stage timings use a monotonic TSC-based clock (`quanta`), recorded as u32 microseconds (u16 granularity is not enough for upstream times).

## 5. Control plane flow
```
config edit (UI/API/GitOps) ─► primary: validate ─► append to change log (epoch, seq) ─► audit
                                     │
                                     ├─► list fetcher (ETag) ─► compiler ─► snapshot vN (content-addressed blobs)
                                     ▼
                       replication stream (mTLS, HTTP/2) ─► replicas fetch missing blobs ─► verify signature ─► ArcSwap
```
- A **snapshot** = a manifest (version, epoch, config hash, blob hashes, signature) + blobs: `config.cbor`, `filter-<group>.fst`, `regex-<set>.dfa`, `rules.idx`, `local-zones.cbor`.
- Blobs are **content-addressed** (BLAKE3), so a list change ships only the changed FST. Large FST blobs are zstd-compressed on the wire.
- The resolver writes the applied snapshot to `data/snapshots/` and **mmaps** the FSTs. Cold start loads them directly (DNS works before cluster contact: CLU-004, cold start ≤ 500 ms).

## 6. Storage layout (per node)
```
/var/lib/telltale/
  snapshots/<version>/manifest.json, *.fst, *.dfa, ...   # last 3 kept
  state.db              # SQLite (WAL): local node identity, cluster state, rollups, audit (replica copy), users (primary authoritative)
  qlog/<yyyy>/<mm>/<dd>/<hh>.seg                          # query-log segments (06)
  cache.bin             # optional cache persistence
  pki/                  # node key, node cert, cluster CA cert
```
In Kubernetes: the controller uses a PVC. Resolver pods use `emptyDir` (snapshot re-fetched on start, local qlog optional because they ship to the controller by default).

## 7. Key dependencies (pin in Cargo.toml; justify any additions in an ADR)
`tokio`, `socket2`, `quanta`, `arc-swap`, `crossbeam` (or `rtrb`), `mimalloc`, `rustls` + `tokio-rustls` + `rustls-platform-verifier`, `quinn`, `h3`/`h3-quinn`, `hyper` + `h2`, `axum`, `fst`, `regex-automata`, `aho-corasick`, `hickory-proto` (+ `dnssec-ring`), `rusqlite` (bundled), `zstd`, `blake3`, `ed25519-dalek`, `rcgen`, `serde` + `toml` + `ciborium`, `prost` (cluster RPC messages), `hdrhistogram`, `argon2`, `totp-rs`, `openidconnect`, `tracing`, `rust-embed`, `clap`.

## 8. Error-handling and resilience rules
1. The DNS path never panics on input. Every parse failure produces FORMERR or a drop, and increments a counter.
2. No `.unwrap()` outside tests and startup config validation.
3. Every external I/O has a timeout. Upstream budgets are derived from the client's remaining time budget (default 2 s total, 400 ms per attempt).
4. Back-pressure: bounded queues everywhere. When the upstream queue is full, serve stale, else return SERVFAIL with EDE 23 (Network Error) and count it.
5. A failure in a telemetry sink, store, or cluster link must never degrade DNS answering.
