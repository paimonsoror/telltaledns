# Pass 03: upstreams, recursion, DNSSEC

**Output:** `docs/review/v0.2.0/03-upstreams-dnssec.md` (+ `patches/03-*`)

## Scope
Everything that asks other servers: forwarding over UDP, TCP, DoT, DoH (HTTP/2 and 3), DoQ,
DNSCrypt; upstream groups, health, hedging, routes; the built-in recursive resolver; DNSSEC
validation.

- `crates/telltale-upstream/` (`upstream.rs`, `conn.rs` pooled stream connections, `doh*.rs`,
  `doq.rs`, `dnscrypt.rs`, `tls.rs` pins and client certificates, `proxy.rs`, `plugin.rs`,
  `group.rs`, `health.rs`, `router.rs`, `bootstrap.rs`, `dnssec.rs`, `nsec.rs`)
- `crates/telltale-recursor/`
- the upstream parts of `crates/telltale/src/pipeline.rs` (`resolve_shared`,
  `resolve_validated`, `fallback`)

## Read first
1. `spec/04-upstreams.md`; ADR-013, ADR-060, ADR-074, ADR-075, ADR-079, ADR-086, ADR-087,
   ADR-092, ADR-093, **ADR-098** (DNSSEC findings from the 2026-10-07 live trial).
2. `group.rs` (`resolve`: hedging, attempt order) → `upstream.rs` (`exchange`) → `conn.rs`.
3. `dnssec.rs` (`Validator::resolve`, `proven_insecure`, `verdict`).

## Look for
- **DNSSEC correctness and safety.** 0.2.0 added an unsigned-zone proof that corrects the
  library's bogus verdicts (ADR-098). Can it be abused to mark a signed zone insecure? Is
  "an apex has its own SOA (unvalidated)" plus "a validated DS denial" sound for NSEC and
  NSEC3 opt-out? Cache poisoning of the insecure-zone map? Interactions with negative trust
  anchors and RFC 8198 synthesis.
- **Transport robustness:** connection reuse and retry (a retry on a connection the server
  closes before answering was added in 0.2.0), TLS verification and pinning, DoH/DoQ stream
  handling, timeouts and budgets, what counts as a failure in health tracking and the
  circuit breaker.
- **Hedging and groups:** does hedging ever multiply load badly, starve a slow upstream's
  health signal, or return a worse answer? Routes by suffix, qtype, client group (ADR-096).
- **Recursion:** referral handling, glue, loops, 0x20, limits (ADR-074).
- **The "failure" counter** (`telltale_upstream_requests_total{outcome="failure"}`) lumps
  timeouts, connection errors, and SERVFAIL/REFUSED together: the live Pi showed 4-6 %
  failures against Quad9 that couldn't be attributed. Propose how to make it diagnosable.

## Threat surface
Spoofed or malicious upstream answers (bailiwick, cache poisoning, oversized or malformed
replies), downgrade of encrypted transports, DNSSEC bypass, resource exhaustion from slow
or looping upstreams.

## Useful
```sh
cargo test -p telltale-upstream                                  # includes dnssec_offline, pool_retry
TELLTALE_LOG=debug TELLTALE_LOG_DNSSEC_LIBRARY=1 target/debug/telltale run -c it.toml
dig @127.0.0.1 -p <port> www.netflix.com +dnssec                 # unsigned CNAME chain
dig @127.0.0.1 -p <port> dnssec-failed.org                       # deliberately broken
bash deploy/dnssec-e2e.sh                                        # if its prerequisites are present
```
