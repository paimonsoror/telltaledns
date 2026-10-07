# Pass 01: query path and performance

**Output:** `docs/review/v0.2.0/01-query-path.md` (+ `patches/01-*`)

## Scope
How a question becomes an answer, and how fast: the listeners, parsing, the pipeline, and the
answer cache. Performance is the owner's first priority, so this pass sets the tone.

- `crates/telltale-proto/` (wire parsing and building, names, EDNS)
- `crates/telltale-net/` (UDP with `recvmmsg`/`sendmmsg`, TCP, DoT, DoH, DoH3, DoQ listeners;
  `sys.rs` holds all of the project's `unsafe`)
- `crates/telltale/src/pipeline.rs` (the pipeline: identification, access checks, local data,
  filtering, cache, deferral to upstreams), `server.rs` (wiring), `warm.rs`
- `crates/telltale-cache/` (sharded S3-FIFO, stored answers patched on a hit, singleflight,
  persistence)

## Read first
1. `spec/02-architecture.md` §3 (hot path budget) and `spec/03-resolution-pipeline.md`.
2. ADR-002, ADR-013, ADR-020, ADR-023 in `spec/11-decisions.md`.
3. `crates/telltale-net/src/udp.rs` → `handler.rs` → `crates/telltale/src/pipeline.rs`
   (`Handler::handle`, `handle_sync`, `resolve_or_defer`, `resolve_for_client`) →
   `crates/telltale-cache/src/lib.rs` (`get`, `insert`) and `entry.rs`.

## Look for
- **Allocations, locks, syscalls on the cache-hit and blocked paths.** The zero-allocation
  tests are `crates/telltale-cache/tests/alloc.rs` and those in `telltale-proto`; is anything
  on the hot path not covered by them?
- **Correctness under hostile input:** truncated or malformed queries, compression loops,
  EDNS options, oversized messages, 0x20 case, ID handling, TC and the UDP size limit,
  TCP framing and pipelining limits, slow-loris clients on TCP/DoT/DoH.
- **Every `unsafe` block in `sys.rs`:** is the `SAFETY:` justification true? Lifetimes of
  buffers handed to the kernel, `MappedFile` (mmap of filter snapshots, added in 0.2.0).
- **Cache semantics:** TTL decrement, negative caching (RFC 2308), serve-stale (RFC 8767),
  prefetch, the byte budget (`Entry::weight`), eviction fairness, persistence on restart.
- **Concurrency:** contention on cache shards, the singleflight map, `ArcSwap` reloads,
  shutdown draining.
- **Measured, not guessed:** use the criterion benches and `make bench-smoke`; if you claim a
  cost, show the numbers (and repeat them).

## Threat surface
Every byte from the network. A panic, hang, or unbounded allocation reachable from a query
is critical. Amplification (ANY is minimal-responded, RFC 8482) and the open-resolver guard
(`allowed_networks`).

## Useful
```sh
cargo bench -p telltale-proto; cargo bench -p telltale-cache --bench cache_hit
cargo test -p telltale-cache --test alloc --release
cargo test -p telltale-cache --test footprint --release -- --nocapture
ls fuzz/ 2>/dev/null; cat .github/workflows/fuzz.yml   # what's fuzzed, and how often
```
