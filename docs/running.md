# Running TelltaleDNS

> **Status:** early development. TelltaleDNS resolves queries over UDP and TCP through plain or encrypted upstreams (`udp://`, `tcp://`, `tls://` DoT, `https://` DoH over HTTP/2), with caching, failover, and serve-stale. Filtering and the web UI arrive in the next milestones (`spec/10-roadmap-and-tasks.md`).

## Start
```sh
telltale run                         # uses $TELLTALE_CONFIG, else /etc/telltale/telltale.toml, else defaults
telltale run -c telltale.toml        # explicit config file(s); later files override earlier ones
```
A minimal working config:
```toml
[[listen]]
proto = "udp"
addr = "127.0.0.1:5300"

[[listen]]
proto = "tcp"
addr = "127.0.0.1:5300"

[[upstream]]
name = "cloudflare"
url = "udp://1.1.1.1"

[[upstream]]
name = "quad9"
url = "udp://9.9.9.9"

[[upstream_group]]
name = "default"          # queries that match no route use this group
members = ["cloudflare", "quad9"]
strategy = "fastest"      # failover | round_robin | weighted | fastest | parallel
```
```sh
telltale run -c dev.toml
dig @127.0.0.1 -p 5300 example.com
```
Defaults without `[[listen]]`: UDP and TCP port 53 on `0.0.0.0` and `[::]`, with one worker thread per available CPU (container CPU limits are respected). Ports below 1024 need root or `CAP_NET_BIND_SERVICE`. DoT, DoH, and DoQ *listeners* are accepted in config but skipped with a warning.

## Upstream presets
Instead of looking up addresses, start from a preset:
```sh
telltale presets list                                   # Cloudflare, Google, Quad9, AdGuard, Mullvad, Control D, NextDNS, ...
telltale presets show quad9 --proto tls,https --group default >> telltale.toml
telltale presets show nextdns --param profile=abc123    # templated presets need your account ID
```
`show` prints explicit `[[upstream]]` entries plus a `fastest` group. Your config always lists exactly what's used and never depends on the catalog, which only helps you write it. The catalog covers every Pi-hole preset plus the common encrypted resolvers; a nightly job checks that every entry still answers. DoQ (`quic://`) endpoints are listed but skipped until DoQ support lands.

## Encrypted upstreams
```toml
[[upstream]]
name = "cloudflare-dot"
url = "tls://1.1.1.1"                       # DNS over TLS, port 853
tls_server_name = "cloudflare-dns.com"      # name on the certificate

[[upstream]]
name = "quad9-doh"
url = "https://dns.quad9.net/dns-query"     # DNS over HTTPS (HTTP/2)
bootstrap = ["9.9.9.9", "149.112.112.112"]  # how to look up dns.quad9.net itself
```
- Certificates are verified against the built-in Mozilla root set, so no CA files are needed, even in a minimal container. `tls_insecure_skip_verify = true` turns verification off (a warning is logged; don't use it on untrusted networks).
- **Hostname upstreams** are looked up through `bootstrap` servers, or the system resolvers from `/etc/resolv.conf` when `bootstrap` is empty (never through TelltaleDNS itself), and the result is cached for its TTL. To skip the lookup, put the IP in the URL and set `tls_server_name`.
- Connections are kept open and reused: many queries share one DoT connection (`pool_size`, default 4; closed after `idle_timeout_ms`, default 30 s), and DoH multiplexes every query over a single HTTP/2 connection.
- Not yet supported (startup error if set): `spki_pins`, `proxy`, `ecs` other than `"strip"`, `http_version = "3"`.

## How a query is answered
```mermaid
flowchart LR
  Q[query] --> P{parse}
  P -- malformed --> E[FORMERR / NOTIMP / BADVERS]
  P --> C{cache}
  C -- fresh hit --> A[answer, TTLs counted down]
  C -- miss / expired --> U[upstream group]
  U -- answer --> S[cache + answer]
  U -- slow or failing, have stale data --> ST[stale answer + EDE 3]
  U -- all failed --> SF[SERVFAIL + EDE 22]
```
- **Cache:** answers are cached for their TTL (clamped by `[cache] min_ttl`/`max_ttl`). Negative answers are cached when the upstream includes an SOA. SERVFAIL is cached for 5 seconds. Hot entries are refreshed in the background just before they expire.
- **Upstreams:** if an upstream is slow, the next one is tried *in parallel* rather than after a timeout, and the first good answer wins. An upstream that fails 3 times in a row (or more than half the time) is benched for 10 seconds, doubling up to 5 minutes, then probed again. Identical concurrent questions share one upstream request.
- **Serve-stale:** if upstreams don't answer within 1.8 s (`[cache] stale_answer_client_timeout_ms`) and an expired answer is still in the cache (up to a day old by default), it's served with TTL 30 and Extended DNS Error 3 ("Stale Answer"), while the refresh continues in the background.
- **Privacy:** queries to upstreams carry a fresh random ID and source port, and none of the client's EDNS options (no client subnet, cookies, or MAC addresses are forwarded).
- **Loop protection:** outbound queries carry a random per-process tag. If one comes back to us (an upstream that forwards to TelltaleDNS), it's dropped and an error is logged instead of looping forever.

## Routing (conditional forwarding)
```toml
[[upstream]]
name = "home-router"
url = "udp://192.168.1.1"

[[upstream_group]]
name = "lan"
members = ["home-router"]

[[route]]
match_suffix = ["home.arpa", "168.192.in-addr.arpa"]   # local names and reverse lookups
upstream_group = "lan"
```
The longest matching suffix wins; routes can also match `match_qtype = ["PTR"]`.

## Stop
`SIGTERM` or `SIGINT` (Ctrl-C) stops the listeners and exits. Full connection draining and hot reload come later (OPS-007, OPS-009).

## Logging
Logs go to stderr. Set the level with `TELLTALE_LOG` (`error`, `warn`, `info` (default), `debug`, `trace`).

## Error responses
| Query | Response |
|---|---|
| Opcode other than QUERY | NOTIMP |
| Malformed (bad name, QDCOUNT ≠ 1, bad OPT, …) | FORMERR |
| EDNS version > 0 | BADVERS with an OPT record of version 0 (RFC 6891) |
| No upstream group applies (none configured) | REFUSED + EDE 14 "no upstreams configured" |
| Shorter than a DNS header, or a response (QR=1) | Silently dropped |

Responses larger than the client's UDP limit are truncated (TC=1) so the client retries over TCP. TCP follows RFC 7766: pipelined queries, answers in completion order, a 10-second idle timeout, at most 64 outstanding queries per connection, and at most 1024 connections.
