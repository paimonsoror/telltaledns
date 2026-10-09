# 03 — Resolution Pipeline

## 1. Listeners (DNS-001..004, DNS-020)
```toml
[[listen]]
proto = "udp"          # udp | tcp | dot | doh | doh3 | doq
addr  = "0.0.0.0:53"
[[listen]]
proto = "doh"
addr  = "0.0.0.0:443"
path  = "/dns-query"   # also matches /dns-query/{client_id}
tls   = { cert = "/certs/tls.crt", key = "/certs/tls.key" }   # reloaded on file change (cert-manager rotation)
proxy_protocol = false
```
- UDP: one socket per worker per address (SO_REUSEPORT); `IP_PKTINFO`/`IPV6_RECVPKTINFO` so that, on a wildcard bind, replies come from the address the query arrived on.
- TCP: RFC 7766 pipelining and out-of-order responses; idle timeout 10 s; max 64 in-flight per connection; global connection cap.
- DoT: ALPN `dot`. SNI is captured for client ID (`<clientid>.dns.example.com`).
- DoH: GET `?dns=` (base64url) and POST `application/dns-message`; `Cache-Control: max-age` = min TTL. A JSON API (`application/dns-json`) is P2.
- DoQ: ALPN `doq`; one stream per query.
- Privileged ports: the container runs non-root with `CAP_NET_BIND_SERVICE` (or binds 5353 with Service port mapping in k8s).

## 2. Parsing (telltale-proto)
- Parse in place from the receive buffer: header, the **single** question (QDCOUNT ≠ 1 → FORMERR), and the OPT RR (payload size, DO bit, ECS, EDNS MAC option code 65001, cookies).
- Normalize the qname to lowercase into a per-worker stack buffer (max 255 bytes) and compute a 64-bit hash (`ahash` or `xxh3`) once. The cache, the filter (for its exact-hash prefilter), and telemetry interning all reuse that hash.
- Reject: QR=1, opcode ≠ QUERY (→ NOTIMP), labels > 63 bytes, names > 255 bytes, compression loops.

## 3. Pipeline order (authoritative)
1. **Parse** (§2).
2. **Client identification** (FLT-006). Precedence: client ID (DoH path / SNI) → EDNS MAC → MAC from the neighbor table (IP → MAC, cached and refreshed every 60 s from netlink, Linux only) → IP/CIDR match → default. Resolve to `ClientRef { id, group_ids: SmallVec<[u16; 4]> }`. Lookups use a prefix trie for CIDRs and hash maps for exact keys. They are precompiled in the snapshot.
3. **Rate limit** (DNS-014). A sharded token bucket per client IP (/24 for v4 and /56 for v6 aggregation is optional).
4. **Special names:** `use-application-dns.net` → NXDOMAIN (disables Firefox canary DoH, configurable); `*.resolver.arpa` DDR (RFC 9462) answers advertising our DoH/DoT/DoQ when configured (P1); `localhost`, RFC 6761 names; `version.bind`/`id.server` → REFUSED by default.
5. **Local data:** local records → local zones (DNS-010/018) → per-group rewrites (FLT-014) → safe search (FLT-011). Local data is answered authoritatively (AA=1) and never filtered unless `filter_local=true`.
6. **Filter decision** (05). `Allow(rule) | Block(rule) | None`. On Block, synthesize the response per the group's block mode (FLT-008) and go to step 10.
7. **Cache lookup** (§4). Hit → patch → step 10. A stale hit with serve-stale enabled → respond stale (EDE 3) and trigger a background refresh.
8. **Upstream resolution** (04). Route by (qname suffix, group, qtype) → upstream group → strategy.
9. **Response policy:** DNSSEC validation (if enabled) → CNAME deep inspection (FLT-007: run every CNAME target through the filter for this client; on block, replace the response with the block response and attribute the rule plus the chain) → response IP filtering (FLT-015) → ECS scrubbing → cache insert (only after policy, keyed so per-group policy can't leak; see §4).
10. **Respond.** Set the RA bit, copy RD, add EDE options when applicable, truncate for UDP if > advertised size (TC=1), and send. Emit a QueryEvent.

## 4. Cache (DNS-006..009)
- **Key:** `(qname_hash, qtype, qclass, DO-bit, cd-bit, upstream_view_id)`. `upstream_view_id` separates answers obtained from different upstream groups (e.g., a kids' group routed to a family-filter upstream must not share a cache with adults). Filtering is applied *before* the cache, so cached entries are policy-neutral.
- **Value:** the response wire bytes (header with ID=0) + an offset list of TTL fields + insertion `Instant` + original min TTL. On a hit, `memcpy` into the send buffer, write the ID, and subtract elapsed seconds from each TTL offset. No re-encode.
- **Structure:** 64 shards (power of two ≥ 4 × workers), each `parking_lot::Mutex<S3Fifo>`. Shard selection = hash bits. Capacity is configured in **bytes** (default 32 MiB) as well as entries.
- **TTL policy:** `min_ttl` (default 0), `max_ttl` (default 86400), `negative_ttl_max` (default 3600, honoring SOA MINIMUM), SERVFAIL cached for 5 s (RFC 9520).
- **Serve-stale** (DNS-007): keep expired entries for up to `stale_max_age` (default 1 day). Use them when upstreams fail or exceed `stale_answer_client_timeout` (default 1800 ms). Answer TTL = 30 s. Add EDE 3.
- **Prefetch** (DNS-008): if an entry is hit while remaining TTL < `prefetch_threshold` (10%) and it has had ≥ `prefetch_min_hits` (3) hits, enqueue a refresh (deduplicated).
- **In-flight dedup:** identical concurrent misses coalesce on one upstream request (a singleflight map keyed like the cache).
- **Persistence** (DNS-009): on graceful shutdown write `cache.bin` (zstd), restore on start, and drop expired entries beyond the stale window.
- **Flush APIs:** all, by name (with subtree), by upstream view.

### 4.1 Sizing advice (OBS-021, ADR-106)
Each shard follows a 1-in-16 sample of keys (fingerprint bits 32–35 clear) after eviction: fingerprint → (evictions so far, expiry). When a sampled key is inserted again while its old answer would still be fresh, `evictions now − evictions then` is how many more entries the shard needed to still hold it; counted at the smallest of +25%, +50%, +100% of its live entries that covers it. Ghosts further back than +100% are forgotten, and the list is capped at 2 × live/16 + 16 per shard. It runs only in `insert` (after an upstream answer) and eviction, never on a lookup. `stats()` scales the counts by 16 and makes them cumulative (`ghost_hits`); shards also keep their peak weight (`peak_bytes`, the sum of shard peaks). The advice (`grow` at ≥ 1 point of extra hits, the smallest such step; `shrink` with no evictions after 100,000 lookups and a peak under half the budget, to peak × 1.5 ≥ 4 MiB; `ok`; `learning` under 10,000 lookups) is in `GET /api/v1/cache/stats` (`sizing`), MCP `cache_advice`, and `telltale_cache_ghost_hits_total{size}` / `telltale_cache_peak_bytes`.

## 5. DNSSEC (DNS-011)
- Modes: `off`, `validate` (default once stable), `validate_permissive` (log bogus, don't fail).
- Set DO=1 upstream when validating. Validate the chain of trust from the configured trust anchor (root KSK; RFC 5011 auto-update P1). Cache DNSKEY/DS through the same cache.
- Client CD=1 → return unvalidated data. Set AD=1 only when validated and the client set DO or AD.
- Bogus → SERVFAIL + EDE (6 DNSSEC Bogus, 7 Signature Expired, 9 DNSKEY Missing, …). Negative trust anchors per domain (e.g., for local AD domains forwarded conditionally).
- Implementation: use `hickory-proto` DNSSEC verification primitives. Wrap them behind a `Validator` trait so they can be replaced.

## 6. Recursive resolution (DNS-012, UPS-012) — P1
- Iterative from root hints, with QNAME minimization (relaxed mode), 0x20 case randomization (configurable), NS selection by smoothed RTT, glue validation within bailiwick, a CNAME/DNAME chase limit of 16, and a max 32 referrals per query.
- Aggressive NSEC caching (RFC 8198) when DNSSEC is validated (T9.16, ADR-092: NSEC; NSEC3 not yet).
- Exposed as an upstream of type `recursive`, so the default homelab setup ("Pi-hole + unbound") becomes one upstream group with a single entry.

## 7. Response synthesis rules
- Blocked A/AAAA in `null` mode: A `0.0.0.0` / AAAA `::`, TTL `block_ttl` (default 10 s; short so unblocking is fast).
- Blocked other qtypes in `null` mode: NODATA (NOERROR, empty answer, SOA in authority with negative TTL = `block_ttl`).
- For HTTPS/SVCB (type 65/64) of a blocked name: NODATA, so browsers don't learn ECH/alt endpoints.
- EDE text format: `"blocked by <list-name>#<rule-id>"`. Configurable to `"blocked"` only for privacy.
