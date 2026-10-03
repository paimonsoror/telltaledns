# Running TelltaleDNS

> **Status:** early development. TelltaleDNS listens on UDP and TCP and parses queries, but it doesn't resolve them yet. Every well-formed query gets **REFUSED** with Extended DNS Error 14 ("Not Ready"), so clients immediately fail over to their next resolver. Caching, upstreams, and filtering arrive in the next milestones (`spec/10-roadmap-and-tasks.md`).

## Start
```sh
telltale run                         # uses $TELLTALE_CONFIG, else /etc/telltale/telltale.toml, else defaults
telltale run -c telltale.toml        # explicit config file(s); later files override earlier ones
```
Defaults: UDP and TCP port 53 on `0.0.0.0` and `[::]`, with one worker thread per available CPU (CPU limits in containers are respected). Ports below 1024 need root or `CAP_NET_BIND_SERVICE`. For local testing, listen on a high port:

```toml
# dev.toml
[[listen]]
proto = "udp"
addr = "127.0.0.1:5300"
```
```sh
telltale run -c dev.toml
dig @127.0.0.1 -p 5300 example.com
```

TCP follows RFC 7766: pipelined queries on one connection, a 10-second idle timeout, at most 64 queued responses per connection, and at most 1024 concurrent connections. DoT, DoH, and DoQ listeners are accepted in config but skipped with a warning until they're implemented.

## Stop
`SIGTERM` or `SIGINT` (Ctrl-C) stops the listeners and exits. Full connection draining and hot reload come later (OPS-007, OPS-009).

## Logging
Logs go to stderr. Set the level with `TELLTALE_LOG` (`error`, `warn`, `info` (default), `debug`, `trace`).

## How queries are handled today
| Query | Response |
|---|---|
| Well-formed query | REFUSED + EDE 14 "resolver starting" (EDE only if the client used EDNS) |
| Opcode other than QUERY | NOTIMP |
| Malformed (bad name, QDCOUNT ≠ 1, bad OPT, …) | FORMERR |
| EDNS version > 0 | BADVERS with an OPT record of version 0 (RFC 6891) |
| Shorter than a DNS header, or a response (QR=1) | Silently dropped |

Responses larger than the client's UDP limit are truncated (TC=1) so the client retries over TCP.
