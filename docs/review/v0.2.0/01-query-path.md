# Pass 01: query path and performance (v0.2.0)

Reviewed at tag `v0.2.0` (commit 338db09) in `~/telltale-review`. `main` has not changed any
in-scope file since the tag (only the crate version bumps in `Cargo.toml`), so every patch
applies to `main` as is.

## Summary

The query path is in good shape and does what the spec promises. The UDP fast path is a real
per-worker, batch-syscall, zero-allocation loop; the parser is bounds-checked everywhere and
is fuzzed nightly; the cache stores wire bytes and answers a hit with a copy and a few patches
under one shard lock. The strongest new evidence from this pass: a whole-pipeline allocation
test (identification, access checks, local data, quick rules, the filter, routing, metrics
and the event ring included) measures **zero allocations** for cache hits and blocked
answers. That test did not exist; it should (01-04).

Top three points:

1. **TCP and DoT connections can be held forever by a client that stops reading** (01-01,
   high). The idle timeout covers reads only; the writer blocks without limit, the reader
   then blocks on the full channel, and the connection slot stays taken. A thousand such
   connections from one host exhaust TCP/DoT until a restart, and graceful shutdown waits
   on them forever. Verified with a test; the fix is a write timeout (patch, verified).
2. **Resource caps are uneven across transports** (01-02, 01-03, medium). DoQ and DoH3
   accept connections without any cap, and every TCP connection may make the server buffer
   64 KiB on a two-byte length prefix. Both are cheap to fix (patches, verified).
3. **Two small correctness bugs at the edges** (01-05, 01-07, low), both verified: an OPT
   record outside the additional section corrupts the rendered answer (an unchecked
   subtraction), and IPv4 replies to broadcast-addressed queries never leave the box.

Nothing in this pass restates the known v1.0-gate items.

## Strengths

- **The UDP worker loop is exactly what `spec/02` §3 describes.** One `SO_REUSEPORT` socket
  and one thread per worker, `recvmmsg → handle batch → sendmmsg`, every buffer allocated
  once at startup and the pointer tables rebuilt before each call
  (`crates/telltale-net/src/sys.rs:172-224`, `:228-256`, `:302-352`;
  `crates/telltale-net/src/udp.rs:207-261`). A 200 ms socket read timeout
  (`udp.rs:96`, `:171`) keeps shutdown bounded without signals or self-pipes.
- **`unsafe` is contained and every justification holds.** All of it lives in `sys.rs`;
  the lint `undocumented_unsafe_blocks` enforces the `SAFETY:` comments
  (`crates/telltale-net/src/lib.rs:120-121`). I checked each block: buffers handed to the
  kernel are owned by `Batch` and live across the call; `sockaddr_storage` reads are
  family- and length-checked (`sys.rs:387-411`); `MappedFile` is a read-only private
  mapping whose `MADV_DONTNEED` semantics, SIGBUS exposure, and `Send`/`Sync` arguments
  are written down and correct (`sys.rs:533-626`).
- **Hostile input is handled by construction.** Every read in `telltale-proto` goes through
  `get`/`be16`/`be32`; compression pointers must point strictly backwards, which rules out
  loops without a visited set, with a hop bound on top
  (`crates/telltale-proto/src/name.rs:735-750`); extended label types are rejected; the
  question may not use compression; the OPT rules of RFC 6891 §6.1.1 are checked for
  queries (`crates/telltale-proto/src/query.rs:387-393`); EDNS version > 0 gets BADVERS with
  an OPT (`crates/telltale-proto/src/writer.rs:494-503`). Proptest round trips, differential
  tests against hickory, and five nightly fuzz targets with corpus caching back this up
  (`crates/telltale-proto/tests/proto.rs`, `fuzz/`, `.github/workflows/fuzz.yml`).
- **The cache hit is a copy plus patches, and nothing else.** An entry is one allocation
  holding packed TTL offsets, the normalized name, and the answer with ID 0 and no OPT
  (`crates/telltale-cache/src/entry.rs:616-637`); a hit copies it, sets the ID and flags,
  writes the client's question bytes back (0x20 case preserved), decrements the TTLs in
  place, and appends a per-client OPT (`entry.rs:906-937`). The name is compared byte for
  byte on every hit, so a hash collision is a miss, not a wrong answer
  (`crates/telltale-cache/src/lib.rs:369`, tested in `tests/cache.rs:150`). The byte budget
  uses a measured per-entry overhead (`entry.rs:734-737`); the footprint test reports
  260 B per entry against a budget of 272 B.
- **Eviction is S3-FIFO done carefully.** Generation-tagged queue entries make removal lazy
  and cheap, stale queue entries are compacted when they dominate, the ghost set is bounded
  by the live count, and the scan-resistance property has a test
  (`crates/telltale-cache/src/s3fifo.rs:183-268`, `:293-313`).
- **Policy before cache, cache entries policy-neutral.** Filtering, local data, rewrites,
  and quick rules all run before the lookup, and CNAME targets are re-checked on hits
  (`crates/telltale/src/pipeline.rs:1538-1627`), so a cached answer can never leak one
  group's policy to another.
- **Back-pressure and coalescing are right.** A bounded in-flight semaphore turns overload
  into stale answers or SERVFAIL with EDE 23 (`pipeline.rs:1784-1795`, `spec/02` §8.4);
  identical misses share one upstream request and a leader that gives up releases its
  followers to resolve on their own (`crates/telltale-cache/src/singleflight.rs:385-392`,
  `:444-450`); the stale-answer timer runs the resolution as its own task so the cache
  still refreshes after the client was answered stale (`pipeline.rs:1796-1807`,
  RFC 8767 §5).
- **The whole synchronous pipeline is allocation-free.** Measured in this pass: 2,000
  `Handler::handle` calls (1,000 cache hits with a filter installed and CNAME inspection
  running, 1,000 blocked answers, both for a configured client, events emitted) allocate
  nothing. See 01-04 for the test.
- **Prefetch learned from a real crash.** It spawns on a runtime handle captured at
  construction instead of `tokio::spawn`, with a regression test
  (`pipeline.rs:2016-2030`, `:3495-3527`; ADR-023).
- **Shutdown has the right order.** Not ready first, a drain delay for load balancers,
  stream listeners, a bounded wait for in-flight upstream work, then UDP
  (`crates/telltale/src/server.rs:974-1005`). The cache dump is serialized to memory before
  touching disk, written to a temp file with mode 0600, and renamed into place
  (`server.rs:1081-1096`), and a dump taken under different routing is refused on load
  (`crates/telltale-cache/src/persist.rs:504-558`).
- **Observability does not cost the hot path.** Per-thread metric slots with relaxed atomics
  (`crates/telltale-telemetry/src/lib.rs:242-280`) and a per-thread event ring that never
  allocates after its first event (`crates/telltale-telemetry/src/ring.rs:88-118`).
- **TCP pipelining is done properly.** Reader and writer are split, answers go out of order
  through a bounded channel, in-flight queries are capped by a semaphore, and the response
  scratch buffer is per runtime thread rather than per connection
  (`crates/telltale-net/src/tcp.rs:95-99`, `:257-361`).

## Measurements

All on the review laptop (WSL2, Ryzen 5 5500U, shared cores), so single-run numbers are
hints, not gates. How each was taken is in the finding or the command.

| What | Result |
|---|---|
| `cargo test -p telltale-proto -p telltale-net -p telltale-cache` (debug) | all pass |
| `cargo test -p telltale-cache --test alloc --release` | pass (0 allocations) |
| `cargo test -p telltale-cache --test footprint --release` | 260 B per entry live, budget counts 272 B |
| Whole-pipeline allocation test (new, debug; 01-04) | 0 allocations over 2,000 handle() calls, twice |
| `cargo bench -p telltale-proto` | parse_query+hash 54 ns; blocked_answer_synthesis 62 ns; cache_hit_patch (copy, ID, 3 TTLs) 5.4 ns |
| `cargo bench -p telltale-cache --bench cache_hit` | full hit (parse, hash, key, shard lock, copy, patch, OPT) 154 ns single thread (6.5 M/s); 4 threads × 10k hits on shared shards 3.98 ms, about 100 ns per hit per thread under contention |
| `make bench-smoke` (one run, unpinned) | cache-hot 135k qps, 0 % loss (p50 815 µs saturated; at 50 % load p50 159 µs, p99 5.2 ms, the WSL tail `docs/v1-gate.md` already discounts); miss-heavy 2,000 qps fixed, 0 % loss, p50 463 µs, p99 719 µs |

## Findings

### 01-01 TCP and DoT connections stay open forever when the client stops reading

| Field | Content |
|---|---|
| Severity | **high** |
| Category | reliability, security |
| Where | `crates/telltale-net/src/tcp.rs:280-291` (the writer task has no timeout), `:294-307` (the idle timeout wraps reads only), `:336` (the reader then blocks on the full channel), `:218` (`accept_loop` joins every connection on shutdown); `crates/telltale/src/server.rs:997-999` (shutdown awaits each stream listener) and `:416-423` (a reload that changes a TCP/DoT listener awaits the old one) |
| Evidence | **verified.** New test `dns_001_tcp_slow_reader_is_closed` on v0.2.0: a client sends 2,000 queries to a handler returning 60 KB answers and never reads. After 1.5 s the next client (cap 1) is reset by the server: `Ok(Err(Os { code: 104, kind: ConnectionReset }))`. The stalled connection's reader sits in `tx.send` because the writer sits in `write_all` against a zero window, and TCP keeps a zero-window connection alive as long as the peer answers probes. With the patch the slot is freed once a write stalls for the idle timeout, the next client is answered, and `stalled_closed` reads 1. |
| Impact | One misbehaving client (or one deliberate one; it needs no privilege, just a LAN address) pins a connection slot for as long as it likes; 1,024 of them from a single host exhaust TCP and DoT for everyone until a restart, which also kills TC-bit fallbacks from UDP. Graceful shutdown (OPS-007) waits on such a connection forever at `server.rs:998`, and so does a reload that replaces the listener. DoT shares the code, so the encrypted path is affected the same way. |
| Recommendation | Bound every write (and the final flush and shutdown) by the idle timeout; when it expires, close the connection and count it (`telltale_tcp_stalled_closed_total`). The reader notices the closed channel on its next send and stops. Alternative or addition: a per-IP connection cap (question 2). |
| Patch | `patches/01-01-tcp-write-timeout.patch`: verified, `cargo test -p telltale-net --test tcp` passes (6 tests), clippy clean for `telltale-net` and `telltale`. It adds the `stalled_closed` counter but not its `/metrics` line: one more tuple next to `telltale_tcp_idle_closed_total` at `crates/telltale/src/http.rs:1167` takes that function past clippy's `too_many_lines` (100), so the implementer should split the function when adding it. |
| Effort | S |
| References | DNS-001, DNS-002, OPS-007, RFC 7766 §6.2.3, `spec/03` §1 |

### 01-02 The QUIC listeners (DoQ, DoH3) accept connections without any cap

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | reliability, footprint |
| Where | `crates/telltale-net/src/doq.rs:128-161` and `crates/telltale-net/src/doh3.rs:109-157` (one task per accepted connection, no limit), against `tcp.rs:175`, `:196-200` and `doh.rs:135`, `:146-149` where TCP and HTTP/2 DoH cap at 1,024. Also `doq.rs:86-87` (100 streams per connection) and `:201` (`read_to_end` with no timeout). |
| Evidence | **verified** by reading; the patch's test refuses a second connection with the cap set to 1. quinn bounds only handshakes in progress, not accepted connections. A DoQ stream that is opened and never finished keeps its task and up to 64 KiB until the 30 s idle timeout, and any traffic on the connection resets that timeout. |
| Impact | Each accepted QUIC connection costs a connection state machine, a task, and buffers (tens of KiB). A client on the network can open them until the process passes a 128 MiB pod limit and is OOM-killed, taking UDP with it: the "DNS never depends on anything else" rule broken from inside the DNS listeners. These listeners are opt-in (P1), which keeps this at medium. |
| Recommendation | A semaphore like the TCP listener's, refusing (QUIC `CONNECTION_REFUSED`) beyond `max_connections` (1,024 by default) and counting refusals (patch). Follow-up, not patched: bound each DoQ stream read with the idle timeout. |
| Patch | `patches/01-02-quic-connection-cap.patch`: verified, `cargo test -p telltale-net --test doq --test doh3` passes (4 tests), clippy clean |
| Effort | S |
| References | DNS-004, RFC 9250 §5.5, `spec/03` §1 |

### 01-03 A two-byte length prefix makes the TCP reader buffer up to 64 KiB per connection

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | footprint, reliability |
| Where | `crates/telltale-net/src/tcp.rs:308-318` (`req.resize(n, 0)` for any `n ≥ 12`, then a read under the idle timeout; the `Vec` keeps its capacity for the connection's life) |
| Evidence | **verified.** New test `dns_001_tcp_oversized_query_closes_connection` on v0.2.0: a connection claiming an 8,192-byte query is kept open waiting for the body (the client's 2 s read times out) while the server holds the buffer. With the patch the connection is closed at once. |
| Impact | 1,024 connections (the cap) × 64 KiB = 64 MiB, renewable every 10 s with two bytes per connection. The whole v1.0 memory budget for a loaded resolver is 64 MiB, and a pod limit is 128 MiB (`docs/v1-gate.md`). |
| Recommendation | Cap the query length at 4,096, the same bound the UDP receive buffer already imposes (`sys.rs:21`), and close the connection on anything larger (patch). RFC 7766 permits 65,535, but nothing TelltaleDNS answers needs a query above 4 KiB: no UPDATE, no zone transfers (ADR-094). The same bound would suit DoQ (`doq.rs:28`) and the DoH POST body (`doh.rs:291`). |
| Patch | `patches/01-03-tcp-query-length-cap.patch`: verified, 6 TCP tests pass, clippy clean |
| Effort | S |
| References | DNS-001, NFR-002, RFC 7766 §8 |

### 01-04 NFR-002 is verified for the cache, not for the pipeline a worker actually runs

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | test gap |
| Where | `crates/telltale-cache/tests/alloc.rs:48-68` covers parse → key → `Cache::get` and block synthesis only. Everything `Handler::handle` adds (`crates/telltale/src/pipeline.rs:584-707`, `:1208-1281`, `:1285-1370`, `:1538-1627`, `:2240-2296`: identification, the allowed-networks check, the rate limiter, special names, local data, quick rules, schedules, list rewrites, the filter, routing, CNAME inspection, metrics, the event ring) has no allocation test. `crates/telltale/src/main.rs:62-65` sets mimalloc as the global allocator unconditionally, which is why none could be added in that crate. |
| Evidence | **verified.** The new test passes: 0 allocations over 2,000 `handle()` calls (debug build, run twice). That is good news and a strength, but it was unverified, and a single `to_vec()` or `format!` added to any of those stages would have gone unnoticed by CI. |
| Impact | A silent regression of the project's first priority. |
| Recommendation | Add the test (patch): the global allocator is gated with `cfg(not(test))` so `allocation-counter` can count in the binary crate's tests. Keep extending it when stages are added. |
| Patch | `patches/01-04-pipeline-alloc-test.patch`: verified, test passes, `cargo clippy -p telltale --all-targets -- -D warnings` clean. It adds `allocation-counter` as a dev-dependency of `telltale` (already in the tree for three other crates) and touches `Cargo.lock`. |
| Effort | S |
| References | NFR-002, `spec/02` §3 |

### 01-05 An OPT record outside the additional section corrupts the rendered answer

| Field | Content |
|---|---|
| Severity | **low** |
| Category | correctness |
| Where | `crates/telltale-proto/src/record.rs:706-716` (`summarize` accepts an OPT in any section); `crates/telltale-cache/src/entry.rs:848-852` (`finish` cuts the message at the OPT and does `arcount -= 1`) |
| Evidence | **verified.** New test on v0.2.0: `Cache::render` on an upstream answer with ANCOUNT = 1, ARCOUNT = 0 whose only record is an OPT panics with "attempt to subtract with overflow" in a debug build. In release, overflow checks are off (`Cargo.toml` `[profile.release]`), so ARCOUNT wraps to 65,535 and the client receives a message announcing one answer and 65,535 additional records with none present. The path is reachable for any upstream answer through `Cache::render` (`pipeline.rs:1828`), where no TTL rule can reject it first, and through `insert` when `min_ttl > 0`. |
| Impact | A misbehaving or spoofed upstream answer becomes a malformed reply to the client (release) or a dropped query (debug). The upstream is semi-trusted and only that query suffers, so low; but it is precisely the class the "never panics on input" rule guards (`spec/02` §8.1), and with `panic = "abort"` an unchecked subtraction anywhere on this path would be fatal. |
| Recommendation | Reject an OPT outside the additional section in `summarize` (RFC 6891 §6.1.1: "in the additional data section"), which makes the answer `Malformed` for both `render` and `insert`; and use `saturating_sub` in `finish` so no future caller can underflow it (patch). |
| Patch | `patches/01-05-opt-section.patch`: verified, proto (14) and cache (16) tests pass, clippy clean |
| Effort | S |
| References | DNS-005, DNS-006, RFC 6891 §6.1.1, `spec/02` §8.1 |

### 01-06 A cached answer larger than the UDP worker's buffer is reported as a miss

| Field | Content |
|---|---|
| Severity | **low** |
| Category | performance, observability |
| Where | `crates/telltale-cache/src/entry.rs:919` (`out.get_mut(..len)?` fails when the answer is longer than `out`), `crates/telltale-cache/src/lib.rs:382-385` (`None` becomes `Lookup::Miss` and counts as one); the UDP worker's buffer is 4,096 bytes (`sys.rs:23`) |
| Evidence | **verified.** New test on v0.2.0: a 5.4 KB TXT answer is inserted; `get` with a 4,096-byte buffer returns `Miss`. The pipeline then defers to the upstream (`pipeline.rs:1368`), renders the fresh answer into a 64 KiB buffer, and truncates it for UDP anyway (`:1828-1832`, `:572-581`). |
| Impact | Every UDP query for such a name costs an upstream round trip and a cache insert, and `telltale_cache_*` counts it as a miss. Answers over 4 KiB are rare (big TXT or DNSKEY sets), hence low. |
| Recommendation | Serve the truncated form from the cache: header and question, TC = 1, the client's OPT, counted as a hit; the client retries over TCP, where the 64 KiB scratch buffer holds it (patch). The patch also keeps DNS64 from synthesizing on a TC answer. |
| Patch | `patches/01-06-cache-oversized-tc.patch`: verified, all cache tests pass (including the new one), the DNS64 pipeline tests pass, clippy clean for `telltale-cache` and `telltale` |
| Effort | S |
| References | DNS-005, DNS-006, `spec/03` §3 step 10 |

### 01-07 IPv4 replies to queries sent to a broadcast address never leave the box

| Field | Content |
|---|---|
| Severity | **low** |
| Category | correctness |
| Where | `crates/telltale-net/src/sys.rs:452-461` (the reply source is taken from `ipi_addr`, the packet's destination); `:493-499` (it is sent as `ipi_spec_dst`) |
| Evidence | **verified** on a local debug server bound to `0.0.0.0:5300` (so `IP_PKTINFO` is on). A `localhost A` query to the interface address was answered; the same query to the subnet broadcast address was received but its reply failed: `telltale_udp_received_total 2`, `telltale_udp_replied_total 1`, `telltale_udp_send_errors_total 1`. With the patch: received 2, replied 2, send errors 0, and the broadcast query was answered from the interface address. |
| Impact | Clients that find a resolver by broadcast (uncommon; some embedded devices do) get nothing, and each attempt shows up as a send error. |
| Recommendation | Read `ipi_spec_dst` on receive: it is the local address the kernel would answer from, which equals `ipi_addr` for unicast and the interface's own address for broadcast and multicast (patch; one field, and the round-trip unit test now checks IPv4 too). |
| Patch | `patches/01-07-ipv4-reply-source.patch`: verified, `telltale-net` unit tests pass, the experiment above passes with the patched binary |
| Effort | S |
| References | DNS-001, `spec/03` §1 ("replies come from the address the query arrived on") |

### 01-08 The rate limiter takes a mutex on every query, and the benchmarks never see it

| Field | Content |
|---|---|
| Severity | **low** |
| Category | performance |
| Where | `crates/telltale/src/pipeline.rs:1230-1232`; `crates/telltale-policy/src/ratelimit.rs:76-86` (a `parking_lot::Mutex` on one of 32 shards chosen by the client key); `crates/telltale-config/src/schema.rs:1227-1238` (on by default, `127.0.0.0/8` and `::1` exempt); `bench/bench.py:323-336` (the server and dnsperf both on `127.0.0.1`) |
| Evidence | **suspected** (by reading). `spec/02` §3 says the fast path takes no lock beyond the cache shard; this is a second one, per query, for every non-exempt client. `SO_REUSEPORT` spreads one client's queries over every worker by 4-tuple hash, so all workers contend on that client's shard. The critical section is a `HashMap<u128>` probe and a few float operations, roughly 50–100 ns, so at the gate's 170k qps the lock is a few percent busy; the cost is probably small but it has never been measured, because the bench client is exempt. |
| Impact | The published cache-hit numbers exclude work that every real client pays. |
| Recommendation | Confirm: run `bench/run.sh smoke --target <eth0 address>:5300` against a server bound to the interface address with dnsperf's `-a <eth0 address>` (and `[ratelimit] queries` raised so nothing is refused), and compare with the loopback run. If it shows, keep the buckets per worker thread (the limiter only needs approximate fairness) or use an atomic token bucket. |
| Patch | none (a measurement first) |
| Effort | S to measure, M to change |
| References | DNS-014, NFR-001, `spec/02` §3 |

### 01-09 DoH has no request-body or write timeout

| Field | Content |
|---|---|
| Severity | **low** |
| Category | reliability |
| Where | `crates/telltale-net/src/doh.rs:229-232` (HTTP/1.1: `header_read_timeout` only), `:291` (a POST body is collected with a size limit but no time limit), `:216-219` (HTTP/2 keep-alive pings detect a dead peer, not one that stops reading) |
| Evidence | **suspected**: the same shape as 01-01, in hyper's connection rather than TelltaleDNS's writer. Confirm with the 01-01 test shape against `DohServer`: a client that sends POST bodies one byte at a time, or sends requests and never reads responses, should be closed within the handshake timeout. |
| Impact | As 01-01 for the DoH listener (1,024 slots). |
| Recommendation | Wrap each request's handling (`Ctx::answer`) in `timeout(cfg.handshake_timeout)`, and drive `serve_connection` with a deadline that calls `graceful_shutdown` when a connection has been busy without completing a request for that long. |
| Patch | none (hyper has no per-request write timeout; the design needs a look) |
| Effort | M |
| References | DNS-003, DNS-001 |

### 01-10 Deferred UDP replies use a blocking `sendmsg` on runtime threads

| Field | Content |
|---|---|
| Severity | **low** |
| Category | performance |
| Where | `crates/telltale-net/src/udp.rs:191-204` (`defer` sends from a tokio task through the worker's socket), `crates/telltale-net/src/sys.rs:356-385` (`sendmsg` with flags 0), `udp.rs:161-178` (the socket is blocking; only a read timeout is set) |
| Evidence | **suspected.** When the socket's send buffer is full (a backed-up qdisc or a slow interface), a blocking `sendmsg` parks the tokio worker that called it until the buffer drains, stalling every other deferred answer and upstream exchange on that worker. The worker threads' `sendmmsg` has the same property but owns its thread. Confirm with a small `limit` on a loopback `tc netem` and the miss-heavy corpus, watching tokio worker latency. |
| Impact | Tail latency for cache misses under an unusual send-side backlog; no correctness issue. |
| Recommendation | `MSG_DONTWAIT` for the deferred send and count `EAGAIN` as a dropped reply (it would have been dropped by the kernel anyway). |
| Patch | none |
| Effort | S |
| References | DNS-001, `spec/02` §3 |

### 01-11 Hostile upstream answers are not fuzzed through the cache

| Field | Content |
|---|---|
| Severity | **low** |
| Category | test gap |
| Where | `fuzz/fuzz_targets/parse_response.rs` walks records, patches TTLs, and truncates; it never reaches `entry::prepare`, `Cache::render`, or `Cache::insert`, which is where 01-05 lived. The `parse_query` target checks the server's own output; nothing checks the output built from an upstream's input. |
| Evidence | **verified** by reading the targets. |
| Impact | The next unchecked assumption about an upstream's framing is found by a client, not by CI. |
| Recommendation | A target that pairs a fixed, valid query with arbitrary response bytes and runs `Cache::render`, `Cache::insert` then `Cache::get`, and `truncate_for_udp` on the result, asserting that whatever comes out re-parses with `summarize`. Fifteen lines in `fuzz/`. |
| Patch | none (the fuzz crate builds on nightly and was not run here) |
| Effort | S |
| References | NFR-004, ADR-002 |

### 01-12 The advertised EDNS payload size is not configurable

| Field | Content |
|---|---|
| Severity | **low** |
| Category | docs |
| Where | `crates/telltale/src/pipeline.rs:36-37`, `:51` (`Settings.edns_payload` defaults to 1232), `crates/telltale/src/server.rs:635-642` (built with `..Settings::default()`; no configuration key reaches it; `crates/telltale-config/src/schema.rs` has no such field) |
| Evidence | **verified** by reading. DNS-005 says "a configurable advertised UDP payload size (default 1232)". |
| Impact | Nobody is hurt by 1232 (the Flag Day value); the requirement text and the code disagree, and a deployment on a jumbo-frame or IPv6-only network cannot raise it. |
| Recommendation | Either add `[dns] edns_payload` (bounded to 512..=4096, since the worker's send buffer is 4,096 bytes) or amend DNS-005 to say "fixed at 1232". A note for the T10.6 requirement-by-requirement check. |
| Patch | none (the owner decides which way) |
| Effort | S |
| References | DNS-005 |

## Questions for the owner

1. **Rate limiting defaults.** DNS-014 fixes the default at 1,000 queries per 60 s per
   address with REFUSED. In the owner's own topologies the client address is real (the
   Pi serves devices directly; the homelab Service keeps source IPs), so each device gets
   its own budget. A router that forwards for a whole LAN, or anything that proxies many
   devices behind one address, would be refused above about 17 queries per second
   sustained. Is that the intended default? (01-08 is about the lock, not the policy.)
2. **Per-address connection limits.** All stream listeners cap connections globally at
   1,024 and nothing per client address, so one host can take every slot. Is a per-address
   cap (say 32) wanted, and should the caps become configuration (`[listen]`)?
3. **Query size cap of 4,096 bytes on TCP** (01-03): agreed? If some future feature needs
   larger queries (UPDATE is the only common one), the constant is in one place.
4. **EDNS payload size** (01-12): configuration key, or amend the requirement?

## Not reviewed

- `telltale-policy` internals (client identification tables, local data, the rate limiter's
  fairness, special-name classification) beyond their cost on the hot path: pass 02.
- `telltale-upstream` (routing rules, hedging, the DoT/DoH/DoQ clients, DNSSEC):
  pass 03. `Router::select` was read only for its hot-path cost (a route scan, no
  allocation).
- The netlink neighbor-table parser (`crates/telltale-net/src/neigh.rs`), certificate
  reloading (`tls.rs`), and the DoH `route`/`get_message` helpers were read for bounds only;
  the PROXY v2 parser (`proxy.rs`) is bounded at 1,024 bytes and looks right.
- The non-Linux UDP fallback (`udp.rs:264-295`) was not exercised.
- `warm.rs` was read; it is paced, off the DNS path, and has nothing to report.
- The fuzz targets were read, not run (nightly toolchain).
- Latency under load and the Pi numbers remain as `docs/v1-gate.md` states them; nothing
  here changes that picture.
