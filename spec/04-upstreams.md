# 04 — Upstreams

## 1. Model
```toml
[[upstream]]
name = "cf-dot"
url  = "tls://1.1.1.1:853"            # scheme picks the protocol
tls_server_name = "cloudflare-dns.com"
weight = 1

[[upstream]]
name = "quad9-doh"
url  = "https://dns.quad9.net/dns-query"
bootstrap = ["9.9.9.9", "149.112.112.112"]   # UPS-009
http_version = "auto"                         # 2 | 3 | auto (try h3 via Alt-Svc, fall back to h2)

[[upstream]]
name = "home-ad"
url  = "udp://192.168.1.10:53"

[[upstream]]
name = "root"
url  = "recursive://"                         # UPS-012

[[upstream_group]]
name = "default"
members = ["cf-dot", "quad9-doh"]
strategy = "fastest"                          # failover | round_robin | weighted | fastest | parallel
parallel_fanout = 2                           # only for strategy=parallel

[[route]]                                     # UPS-007 / DNS-017
match_suffix = ["corp.example.com", "168.192.in-addr.arpa"]
upstream_group = "ad-only"
dnssec_nta = true                             # local zones are usually unsigned
```

## 2. URL schemes (UPS-001..003, UPS-010, UPS-011)
| Scheme | Protocol | Notes |
|---|---|---|
| `udp://host[:53]` | UDP, TCP fallback on TC | Random source port and ID; 0x20 optional |
| `tcp://host[:53]` | TCP, pipelined | Connection pool |
| `tls://host[:853]` | DoT | Pooled, pipelined; session resumption; optional SPKI pin |
| `https://host/path` | DoH (h2; h3 with `http_version`) | POST by default; GET for cacheability via an option; custom headers |
| `h3://host/path` | DoH over HTTP/3 only | |
| `quic://host[:853]` | DoQ | 0-RTT disabled by default (replay risk) |
| `sdns://...` | DNSCrypt v2 / DoH stamp | Stamp parsing covers DNSCrypt, DoH, and DoT stamps (P1) |
| `recursive://` | Built-in recursor | |
| `unix:///run/x.sock`, `exec://...` | Custom plugin upstream | §6 |
| any + `proxy = "socks5://127.0.0.1:9050"` | Via proxy | TCP-based protocols only; UDP via SOCKS5 UDP ASSOCIATE (P2) |

Common options per upstream: `timeout_ms`, `tls_server_name`, `tls_ca`, `tls_client_cert`/`tls_client_key` (mTLS), `tls_insecure_skip_verify` (with a loud warning), `spki_pins`, `headers` (DoH), `ecs = "strip"|"pass"|"<cidr>"`, `edns_payload`, `pool_size`, `idle_timeout`, `weight`, `labels`.

## 3. Preset catalog (UPS-004)
- Ship `presets/upstreams.toml` as data. It must include **all Pi-hole UI presets**: Google, OpenDNS, Level3, Comodo, Quad9 (filtered, unfiltered, filtered+ECS), Cloudflare (incl. DNSSEC), each with v4 and v6 addresses. It must also include the major encrypted resolvers Technitium users commonly pick: Cloudflare (+family/security), Google, Quad9, AdGuard (default/family/unfiltered), NextDNS (templated with profile ID), Mullvad, and ControlD (templated), with DoT, DoH, and DoQ URLs where offered.
- In the UI, a preset is one click and expands into explicit upstream entries (so config stays explicit).

## 4. Strategies (UPS-005)
| Strategy | Behavior |
|---|---|
| `failover` | Ordered; use the first healthy upstream; on error/timeout within a query, try the next one. |
| `round_robin` | Rotate over healthy members. |
| `weighted` | Smooth weighted round robin. |
| `fastest` | Pick the lowest EWMA latency (α=0.2) among healthy members; with probability ε=5%, probe another member to keep stats fresh. |
| `parallel` | Send to the best `parallel_fanout` members at once; the first valid (NOERROR/NXDOMAIN, passes DNSSEC if enabled) response wins; cancel the others. This is Technitium's "concurrency". |

Retry budget: total query budget 2 s; per-attempt timeout = min(upstream.timeout_ms, adaptive 3 × EWMA + 50 ms, 1000 ms). A SERVFAIL/REFUSED from an upstream counts as a failure and triggers the next attempt (configurable).

## 5. Health and circuit breaking (UPS-006)
- **Passive:** a rolling window of the last 50 outcomes. If the error rate exceeds 50% with ≥ 10 samples, the breaker goes **open** for 10 s (exponential backoff up to 5 min), then **half-open** (1 probe query). Three failures in a row open it too.
- **SERVFAIL and REFUSED are answers, not outages:** they are errors in the window and trigger the next attempt (§4), but they don't count toward the three in a row (an answer ends the streak), and their latency is the measured one, not the attempt's timeout. A client retrying one broken domain can't bench a healthy upstream, but an upstream that SERVFAILs more than half of everything still opens (review 03-04).
- **Active:** every 30 s, query `health_check_name` (default `.` NS or a configured name) for upstreams not used in the last 30 s.
- If all members are unhealthy, still try the least-recently-failed member (never return SERVFAIL without at least one attempt), then serve stale.
- Exported per upstream: state, EWMA, p50/p95/p99 (HDR), request/err/timeout counters, pool size, TLS handshake count, and h2/h3 stream counts.

## 6. Custom upstream plugins (UPS-011)
Three levels, from simplest to most powerful:
1. **Parameterized endpoints** (§2 options): covers custom DoH paths, headers (e.g., an auth token), mTLS, SNI override, and pinning.
2. **Socket plugin (P1):** `unix:///path.sock` or `exec://...`. TelltaleDNS speaks **plain DNS wire format over a stream** (2-byte length prefix, RFC 7766 framing) on a Unix socket. With `exec://`, TelltaleDNS spawns and supervises the plugin process (restart with backoff, stdout/stderr to logs). Any language can implement an upstream (e.g., Tailscale MagicDNS bridge, Consul, a custom DoH-with-OAuth provider) without linking into TelltaleDNS. Plugins can't crash the resolver.
3. **WASM upstream (P2):** a component-model WASM module (`wasmtime`, feature-gated) implementing `resolve(query: list<u8>) -> result<list<u8>, error>` with host-provided, capability-scoped networking. Opt-in feature so the default binary stays small.

The `Upstream` trait in code:
```rust
#[async_trait]
pub trait Upstream: Send + Sync {
    fn id(&self) -> UpstreamId;
    fn protocol(&self) -> Protocol;
    async fn exchange(&self, query: &[u8], budget: Duration) -> Result<Bytes, UpstreamError>;
    fn health(&self) -> HealthSnapshot;
}
```

## 7. Bootstrap and loops (UPS-009)
- Hostname upstreams resolve through `bootstrap` IPs (per upstream or global; default: the system resolver from `/etc/resolv.conf`, **excluding** our own listen addresses). Results are cached and re-resolved at TTL.
- Loop detection: tag outbound queries with an EDNS option (local-use code 65429) carrying the node ID. Drop and alert on receipt of our own tag.
