# Configuration

TelltaleDNS reads one TOML file, `telltale.toml`, plus optional overrides. Every key is optional: anything you leave out uses a built-in default. A fully commented example lives in [`examples/telltale.toml`](examples/telltale.toml).

## Validate before you deploy
```sh
telltale config check telltale.toml               # "config OK" or a list of errors
telltale config check telltale.toml node.toml     # later files override earlier ones
telltale config check telltale.toml --print       # show the effective config (defaults + files + env)
telltale config check telltale.toml --no-env      # ignore TELLTALE_* variables
```
Every problem is reported with the exact key path, and all problems are reported at once:
```
error: cache.bogus: unknown field `bogus`, expected one of `max_bytes`, `max_entries`, ...
error: upstream[1].url: unsupported scheme `ftp://` (expected one of: udp, tcp, tls, https, ...)
error: upstream_group[0].members[1]: unknown upstream `ghost`
```
Unknown keys are always errors, so typos never get silently ignored. Values containing control characters (newlines, tabs, ...) are rejected.

## Editor completion
```sh
telltale config schema > telltale.schema.json
```
Point your editor's TOML language server at the schema (e.g. with Taplo/Even Better TOML: `#:schema ./telltale.schema.json` as the first line of the file).

## Precedence
From lowest to highest:
1. Built-in defaults
2. Config files, in the order given (tables merge key by key; **arrays such as `[[listen]]` replace** the earlier value entirely)
3. Environment variables `TELLTALE_<SECTION>_<KEY>`
4. Command-line flags

## Environment variables
Any scalar key can be set from the environment. Upper-case the path and join it with `_`:

| Variable | Sets |
|---|---|
| `TELLTALE_ROLE=resolver` | `node.role` (keys in `[node]` may skip the `NODE_` part) |
| `TELLTALE_CLUSTER_SITE=home-pi` | `cluster.site` |
| `TELLTALE_CACHE_MAX_TTL=3600` | `cache.max_ttl` |
| `TELLTALE_CACHE_MAX_BYTES=64MiB` | `cache.max_bytes` |
| `TELLTALE_TELEMETRY_MODE=ship` | `telemetry.mode` |
| `TELLTALE_TELEMETRY_QLOG_RETENTION_DAYS=7` | `telemetry.qlog.retention_days` |

- Values are converted to the key's type. Booleans accept `true/false/1/0/yes/no/on/off`. Lists accept a TOML array (`["a","b"]`) or comma-separated text (`a,b`).
- Arrays of tables (`[[listen]]`, `[[upstream]]`, ...) can't be set from the environment. Use a file.
- An invalid value is an error that names the variable: `cache.max_ttl (from TELLTALE_CACHE_MAX_TTL): expected an integer, got "soon"`.
- Unknown `TELLTALE_*` variables are logged as warnings and ignored. This is deliberate: Kubernetes injects `TELLTALE_PORT`, `TELLTALE_SERVICE_HOST`, and similar variables for any Service named `telltale`.
- `TELLTALE_CONFIG`, `TELLTALE_NODE_CONFIG`, `TELLTALE_LOG`, and `TELLTALE_LOG_FORMAT` are reserved for the binary itself, as are `TELLTALE_BOOTSTRAP_ADMIN_USER`, `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD`, and `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH` (the first admin from a secret; see `docs/running.md`).

## Sizes
Byte sizes accept an integer number of bytes or a string with a unit: `"32MiB"`, `"2 GiB"`, `"500MB"`. Binary units (KiB, MiB, GiB, TiB) are powers of 1024; decimal units (KB, MB, GB, TB) are powers of 1000.

## Sections
| Section | Purpose | Reference |
|---|---|---|
| `[node]` | role (`all`/`resolver`/`controller`), name, worker threads, data directory | `spec/02` |
| `[cluster]` | cluster name, site label, primary eligibility | `spec/12` |
| `[[listen]]` | `udp`, `tcp`, `dot`, `doh` listeners (`doh3`, `doq` are accepted and skipped for now); `tls` cert/key for DoT and DoH (reloaded on change), DoH `path`, `proxy_protocol` (v2) on TCP-based listeners. Default: UDP + TCP on port 53, IPv4 and IPv6 | `spec/03` §1, DNS-002/003/020 |
| `[[upstream]]` | upstream resolvers; the URL scheme picks the protocol | `spec/04` |
| `[[upstream_group]]` | named sets of upstreams with a strategy (`failover`, `round_robin`, `weighted`, `fastest`, `parallel`). Queries that match no route use the group named `default` | `spec/04` §4 |
| `[[route]]` | conditional forwarding by domain suffix, client group, or query type | `spec/04` §1 |
| `[[record]]` | local records (A, AAAA, CNAME, PTR, TXT, MX, SRV; `*.` wildcards) | `docs/running.md` |
| `[local]` | hosts files to import, automatic PTRs, default TTL for local records | `docs/running.md` |
| `[[list]]` | filter lists: a `url`, a local `path`, or inline `rules`; `kind` (`block`/`allow`), `match` (`subtree`/`exact`), per-list refresh and size limit | `docs/running.md` |
| `[[group]]` | client groups: which lists apply, priority | `docs/running.md` |
| `[[client]]` | known devices: name, how to recognize them (IP, CIDR, MAC, `id:`), groups | `docs/running.md` |
| `[clients]` | neighbor table on/off and refresh interval; which forwarders' EDNS MAC to trust; `infrastructure` networks for the masked-client-IP check | FLT-006, OPS-003 |
| `[filter]` | list refresh interval, download concurrency, timeout, retries, size limit; compile threads and memory | `spec/05` §3.4 |
| `[access]` | networks allowed to query (everyone else is refused) | `spec/08` §6 |
| `[ratelimit]` | per-client query budget, action, exemptions, IPv4/IPv6 grouping | DNS-014 |
| `[special]` | localhost, Firefox canary, CHAOS, private reverse lookups | ADR-014 |
| `[cache]` | memory budget, TTL clamps, serve-stale, prefetch | `spec/03` §4 |
| `[telemetry]` | telemetry mode, query-log retention and privacy, Prometheus endpoint, device anomaly detection (`[telemetry.anomaly]`) | `spec/06`, OBS-013 |
| `[api]` | REST API listener (also serves `/metrics` and health probes) | `spec/07`, ADR-028 |
| `[auth]` | session lifetimes, HTTP Basic over plain HTTP, roles that must use two-factor sign-in; `[auth.oidc]` sign-in providers (Keycloak, Authentik, ...) with group-to-role rules and break-glass | `docs/running.md`, ADR-029 |
