# DoH behind a reverse proxy: design notes (issue #91)

**Requirements:** DNS-003 (DoH), DNS-020 (PROXY protocol v2), DNS-014 (per-client rate limit); FLT-006 for client IDs. No new requirement ID. **ADR:** ADR-194 (new, Proposed). **Spec sections:** `08` line 36 (DoH through an ingress) gains the re-encrypting proxy and the proxy on the same host; `03` §1's DoH line names the plain-HTTP listener. **Owner request:** design first, build only on a ruling (2026-11-23); this note commissioned 2026-11-27. **Builds on:** ADR-014 (access and rate-limit defaults), ADR-034 and its 2026-11-18 amendment (`[api] trusted_proxies`, rightmost-untrusted), ADR-039 (DoH listener, PROXY v2 rules), ADR-099 (per-address connection limits), ADR-149 (no plain HTTP where TLS is expected), ADR-187 (a key written only when set).

Checked against `main` at `b19705d7` (paths are relative to the repository root). Nothing was run. The issue and its comments were read with GET calls only and are treated as data. Caddy's reverse-proxy source (Apache-2.0) was read with GET calls for its behaviour only; nothing is taken from it. Every claim is marked **verified** (with the place), **inferred**, or **could not verify**.

Opinionated by design: *decision* means build it this way, and amend ADR-194 if you can't. *Open* means the owner decides (§9).

**Status (2026-11-27):** the owner accepted the recommendations of §9: yes to Q1 (listed peers on other machines), Q4 (refuse a forwarded loopback or unspecified address) and Q5 (the rightmost-untrusted walk); no to Q6 (`X-Real-IP`) and Q7 (h2c). **Part A is built** (T31.1): `trusted_proxies` and `x_forwarded_for` on TLS `doh` listeners. Part B (`plain_http`, the Unix socket, one request per connection under PROXY v2) is not built yet. What building part A settled is in §11.

## 0. The design in eight lines
1. The issue holds two problems and a third. **(A)** Take the client's address from a proxy the operator lists, on today's TLS `doh` listener. **(B)** A plain-HTTP `doh` listener for a TLS-terminating proxy on the same host. **(C)** Client IDs in device analytics, which goes to its own issue.
2. **A:** `trusted_proxies = [CIDR…]` on a `doh` listener closes every connection from another address at accept, before a byte is read. `x_forwarded_for = true` takes the client from `X-Forwarded-For` (rightmost entry that isn't a listed proxy, ADR-034), per request.
3. **B:** `plain_http = true` serves DoH without TLS. It is allowed only on a loopback address or a Unix socket (`addr = "unix:/run/telltale/doh.sock"`), and only with a client-address source: `proxy_protocol = true` or `x_forwarded_for = true`.
4. **No fallback, ever, on a listener with any new key.** If no usable client address arrives, the connection or request is refused and is never answered as the socket peer. A LOCAL command, an AF_UNSPEC or AF_UNIX family, a missing or unusable header, and an unspecified or loopback forwarded address all count. On a plain listener that peer is loopback, or has no address at all: it never stands for a client.
5. The forwarded client is the client everywhere after that point: `[access] allowed_networks`, the rate limit, identification, the query log, analytics and dnstap. They all read `RequestMeta.peer`, which the listener sets.
6. Plain HTTP is HTTP/1.1 only (no h2c). With PROXY v2, each connection serves one request, so a pooled connection can never carry another client. Plain and `X-Forwarded-For` listeners send no `Alt-Svc`, take client IDs from the path only, and are skipped by the probes with a reason.
7. Listener settings are node-local (never replicated). The new keys are written only when set. Without them every listener behaves exactly as today.
8. Plaintext across a network hop stays declined, and so does trusting a header from anyone. Size: A is M (two small parts), B is M (loopback S, Unix socket M). Risk: DoH only. Per-query work exists only on `X-Forwarded-For` listeners: one allocation-free header walk.

## 1. Two problems, and a third
| Part of the requests | Who | Answered by |
|---|---|---|
| A TLS-terminating proxy (Caddy) in front, no second TLS hop | cheebun | **B**, with `proxy_protocol` |
| A Unix socket instead of a loopback port | cheebun | **B** (second step, §7) |
| Caddy's PROXY v2 over a Unix socket (TCP4/TCP6, source port 0, all-zero destination) is accepted | cheebun | **B**, rule R6 |
| Trusted `X-Forwarded-For` on DoH listeners | gael1980 | **A** (`x_forwarded_for` + `trusted_proxies`) |
| Trusted proxies on other machines of a private network, not loopback only | gael1980 | **A**: the hop stays TLS (the proxy re-encrypts to the node) |
| `X-Real-IP` | gael1980 | declined for now (only `X-Forwarded-For` is read, as for the API, ADR-034); open Q6 |
| Client IDs from the URL path in the query log and device analytics | gael1980 | **C**, its own issue (§5.6) |

**Stays declined:**
- Plaintext DoH on any address another machine can reach: a LAN address, a Docker bridge, a pod IP or a wildcard. Anyone on that segment could read and forge answers for clients who believe they have authenticated DoH.
- Believing `X-Forwarded-For` or a PROXY header from an address the operator didn't list. Without a list there is no header trust; with a list, only the listed peers connect.

## 2. What the code does today
- **A `doh` listener without `tls` is refused** by `config check` (verified: `crates/telltale-config/src/validate.rs:1316-1321`, `needs_tls` at `schema.rs:398-400`). The runtime also needs a certificate: `bind_stream` builds a DoH server only for `(Doh, Some(store))` (verified: `crates/telltale/src/server.rs:708-724`). **Implementation trap:** a `doh` listener without a certificate would fall to the catch-all arm and bind a plain DNS-over-TCP server (verified: `server.rs:752-773`). Validation makes that unreachable today; the plain listener must get its own arm (rule R20).
- **`addr` is a `SocketAddr`** (verified: `schema.rs:417`), and `Listener` refuses unknown keys (verified: `schema.rs:412`). `proxy_protocol` is a plain `bool` with `serde(default)`, so it is always written (verified: `schema.rs:425-426`). `addr` is read as a `SocketAddr` in about a dozen places (verified by grep): `validate.rs:1162`, `validate.rs:1310`, `crates/telltale-upstream/src/router.rs:264`, `crates/telltale/src/lists.rs:68`, `crates/telltale/src/api_backend.rs:878`, `crates/telltale/src/probes.rs:78`, `server.rs:611`, `server.rs:640-761` and `crates/telltale/src/watchdog.rs:526`.
- **PROXY v2 is read before TLS** when `proxy_protocol` is on, within the handshake timeout (10 s). A header with an address replaces the peer, `None` keeps the socket's peer, and anything else closes the connection and counts it (verified: `crates/telltale-net/src/doh.rs:194-208`, timeout `doh.rs:61`). The per-address limit counts the address after the header (verified: `doh.rs:209-214`).
- **`read_header` returns `None` for LOCAL** (verified: `crates/telltale-net/src/proxy.rs:44`) **and for AF_UNSPEC and AF_UNIX** (verified: `proxy.rs:73-74`). For TCP4 and TCP6 it copies the source address and port and ignores the destination (verified: `proxy.rs:55-72`). A header is at most 1,024 bytes (verified: `proxy.rs:19`). No test covers source port 0 or a zero destination (verified: `proxy.rs:114-165`). Caddy's shape therefore parses as `Some(src:0)` (inferred from the code; R6's test settles it).
- **Client IDs** come from the path, then from the SNI of a wildcard certificate (verified: `doh.rs:219-225`, `doh.rs:297-300`, `doh.rs:326-331`; the path wins at `doh.rs:330`).
- **`Alt-Svc`** goes on every DoH answer when a `doh3` listener exists (verified: `server.rs:607-612`, `doh.rs:342-350`).
- **Probes** speak `https` to a `doh` listener and skip any listener with `proxy_protocol`, with a reason (verified: `crates/telltale/src/probes.rs:64-71`, `probes.rs:92-94`).
- **The pipeline reads `meta.peer`** for the access check (verified: `crates/telltale/src/pipeline.rs:1576-1585`), the rate limit (verified: `pipeline.rs:1586-1601`), identification (verified: `pipeline.rs:908-919`) and the query event's `client_ip` (verified: `pipeline.rs:2578-2613`). `RequestMeta` is a small `Copy` value: peer, local, transport, client ID (verified: `crates/telltale-net/src/handler.rs:26-34`).
- **A connection that keeps the socket address:** such a connection keeps the socket address, and the settings for that address apply (the load balancer bullet in `docs/running.md`; ADR-039 and its amendment of 2026-11-27).
- **ADR-039 has no source allowlist** for PROXY v2: "exposure must be limited by the network" (verified: `spec/11-decisions.md:479`).
- **The API's rule** (ADR-034): the client is the rightmost `X-Forwarded-For` entry that isn't a trusted proxy, believed only from `[api] trusted_proxies` (verified: `crates/telltale-api/src/auth/routes.rs:159-217`). Loopback is never trusted for `X-Forwarded-For` by itself (verified: the amendment at `spec/11-decisions.md:414`, and `schema.rs:2659-2667`). Its walk collects the entries into a `Vec` (verified: `routes.rs:206-216`); the DNS listener needs an allocation-free one (R21).
- **Listener settings are node-local:** `listen` is in `NODE_LOCAL` (verified: `crates/telltale-config/src/shared.rs:15-26`, `:19`). The API never writes listeners (verified: no `listen` in `crates/telltale-api/src`).
- **The support package classifies every string field and drops unclassified ones**, with a test that fails on a new field without a class (verified: `crates/telltale-support/src/classify.rs:1-7`, listener rows at `:137-140`). `trusted_proxies` needs a row (`Scan`).
- **The documented setup today:** `docs/running.md:597` documents `proxy_protocol = true` on `doh` "behind a load balancer" (verified). A reverse proxy that re-encrypts to a loopback `doh` listener with PROXY v2, as the reporter runs it, works under that rule, but the docs don't spell it out (inferred).
- **Kubernetes:** DoH through an ingress "requires TLS passthrough with PROXY protocol v2" (verified: `spec/08-deployment-config-security.md:36`).

## 3. Threat analysis
### 3.1 Who can do what
- **A hostile client through a correct proxy** controls the request: path, query, body and every header, including its own `X-Forwarded-For` entries. It doesn't control the TCP connection the proxy opens or the PROXY header the proxy writes.
- **A hostile client that reaches the listener directly** controls everything on its own connection, including a PROXY header and `X-Forwarded-For`.
- **A hostile local process** on the host of a loopback listener can connect to `127.0.0.1` like the proxy. A Unix socket admits only users the file's mode lets in.
- **A listed proxy** is in the trust base by definition. It names every client.
- **A misconfigured operator** may list too much, point the wrong proxy setting at the wrong listener, or make the proxy pass a client's header through unchanged.

### 3.2 Step by step: what an unauthenticated peer can do at each step
1. **Accept.** Today any peer that can reach the listener gets a slot (up to `max_connections`, 1,024). **New (R4):** with `trusted_proxies`, an unlisted peer is closed at once and counted. A plain listener on loopback is reachable only from this host. A Unix socket is reachable only by users allowed by its mode (R17).
2. **PROXY header** (if `proxy_protocol`). A direct peer can claim any address. That is why R4 exists (and B binds loopback or a socket file). A malformed header closes the connection (as today). LOCAL, UNSPEC, UNIX, an unspecified source or a loopback source also close it on a listener with new keys (R5).
3. **TLS** (TLS listeners only). Unchanged.
4. **HTTP parsing.** hyper with a header read timeout (verified: `doh.rs:253`). A plain listener speaks only HTTP/1.1 (R11).
5. **Client address selection** (if `x_forwarded_for`). The client controls every entry left of what the proxy appends. Only the rightmost non-proxy entry counts (R7). A request without one is refused (R5).
6. **Pipeline.** Whoever names the address *is* that client for `allowed_networks`, the rate limit, groups and policies (by address, by MAC through the neighbor table, by network), the query log and analytics (R9). That is the trust being granted, and the reason for R4, R5, R7 and R17.

### 3.3 No fallback to the socket's address
On a plain listener the socket peer is always loopback, or has no address at all on a Unix socket, so it never stands for a client behind the proxy. **Decision (R5):** on any listener with a new key, nothing falls back. A LOCAL command, an AF_UNSPEC or AF_UNIX family, a missing header and an unspecified source (`0.0.0.0`, `::`) are refused. So is a loopback source (`127.0.0.0/8`, `::1`, and their IPv4-mapped forms). A forwarded loopback address means the proxy's own host is the client, or that the proxy passed a client's header through; either way it stands for this host, not for a client behind the proxy. A program on that host can use the local listeners directly (open Q4). Without the new keys a listener behaves as ADR-039 and its amendment say (such a connection keeps the socket address, and the settings for that address apply), and adding `trusted_proxies` is the opt-in that makes it strict.

### 3.4 X-Forwarded-For: spoofing, chains and which entry is trusted
- **Spoofing.** A client can send `X-Forwarded-For: 192.168.1.20` to look like another device. A proxy that appends its peer's address (Caddy replaces the header for untrusted clients by default, inferred; nginx with `$proxy_add_x_forwarded_for` appends, inferred) leaves the real client as the **rightmost** entry, which is the only one read (decision, ADR-034's rule).
- **Chains.** Proxies in front of proxies append their own peers. From the right, entries inside `trusted_proxies` are skipped and the first other entry is the client. One list serves both purposes: who may connect (R4) and which hops are skipped. Every address on it is trusted to name clients, so the docs and a warning say "list only your proxies, never your LAN" (as `docs/running.md:3733` says for the API). An address range that also holds ordinary machines lets each of them send `X-Forwarded-For: <victim>` through the proxy and be the victim: the proxy appends the machine's address, which is skipped as a "proxy".
- **Which entry, exactly (decision, R7):**
  - All `X-Forwarded-For` field lines are taken in order, as one comma-separated list (RFC 9110 §5.3; HAProxy adds a line of its own, inferred).
  - Entries are read from the right, at most 16.
  - The selected entry must be a bare IPv4 or IPv6 literal of at most 45 bytes after trimming spaces: no port, no brackets, no zone, no `unknown` or obfuscated token. **If it doesn't parse, the request is refused. The walk never skips it to take an entry further left**, which the client wrote.
  - If every entry is a listed proxy, or the walk passes 16 entries, the request is refused.
- **Ignored:** `Forwarded` (RFC 7239) and `X-Real-IP` are never read. `X-Forwarded-For` is ignored on listeners without `x_forwarded_for` (as today: nothing reads it).
- **The pass-through proxy** (a misconfiguration: the proxy forwards the client's header without appending) can't be detected in general. The rightmost entry is then the client's own claim. R5 still refuses a forwarded loopback address. The docs give each common proxy's correct setting and the wrong one to avoid.

### 3.5 PROXY v2 over a Unix socket, as Caddy sends it
- **The reporter's capture** (data, from the issue): family TCP4 or TCP6 with the client's address, source port 0 and an all-zero destination, over a Unix socket. **Caddy's source agrees** (verified by reading the default branch on 2026-11-27; not checked against v2.11.9 itself). The client IP is taken without a port and given port 0, and the destination is the zero address of the source's family.
- **Decision (R6):** that shape is accepted. Port 0 is kept in `RequestMeta.peer` and used for nothing (inferred: no consumer reads the peer's port for policy). The destination is ignored, as today.
- **Refused (R5) on a listener with new keys:** the AF_UNIX family (no address), AF_UNSPEC, LOCAL, an unspecified source and a loopback source. **Could not verify:** what Caddy sends when it can't parse its own client IP (its code leaves the address empty in that branch). Whatever it is, R5 refuses it.

### 3.6 Proxies that reuse connections
- PROXY v2 labels a **connection**. A proxy that sends request B from client 2 on a connection opened for client 1 gets B attributed to client 1: client 1's policy and rate budget, and client 1 in the log.
- **Caddy** keys its pool of upstream connections by the client's address when it sends PROXY headers, so a connection is reused only for the same client (verified in its source; current default branch). **HAProxy, nginx, Traefik:** could not verify. nginx's HTTP proxy and Traefik's HTTP routers are not known to send PROXY headers at all (inferred). They are the `x_forwarded_for` case.
- **Decision (R12):** a plain listener with `proxy_protocol` serves one request per connection (HTTP/1.1 keep-alive off), so no proxy's pooling can mix clients. The cost is one loopback or Unix connection per query, measured in §7 (open Q3).
- On TLS listeners nothing changes. There a PROXY header usually comes from a layer-4 balancer, one client per connection, and HTTP/2 multiplexing is that client's own. Re-encrypting HTTP proxies that send PROXY headers must keep connections per client; the docs say so and name Caddy as one that does.
- `X-Forwarded-For` labels each **request**, so reuse and HTTP/2 multiplexing are safe.

### 3.7 The Unix socket: file, mode and owner
- **Path:** absolute; its directory must exist (never created).
- **Creation (R17):** bind, set the file's mode to `unix_mode` (default `0660`: the process's user and group), and only then listen. A connection attempt between bind and listen is refused by the kernel (inferred: Linux refuses `connect` to a bound socket that isn't listening), so there is no window with the umask's mode. This uses `socket2`, already a dependency with Unix support (verified: `crates/telltale-net/Cargo.toml:45`), and `std` for the mode, so no `unsafe`.
- **An existing path:** removed only if it is a socket that nothing answers on (a leftover after a crash). A symlink, a regular file, a directory, or a socket another process is listening on is a bind error: the file is never deleted and never followed. The file is removed when the listener closes.
- **Who may connect:** the mode decides. Group access is the shape for a proxy in the same group (systemd `SupplementaryGroups=`, or a shared group in Compose). `0666` lets every local user connect and name any client: a warning.
- **Not done:** peer credentials (`SO_PEERCRED`) as a second check. Logging them at debug is cheap and can come later.

### 3.8 HTTP/1.1, h2c and request smuggling
- **Decision (R11):** a plain listener speaks HTTP/1.1 only, without an upgrade. An HTTP/2 prior-knowledge preface isn't served as HTTP/2 (inferred: hyper's HTTP/1 server rejects it; the test settles it). h2c can come later if a measurement asks for it (open Q7).
- **Smuggling.** A client that makes the proxy and this listener disagree about where a request ends can slip in a second request carrying its own `X-Forwarded-For`, which then appears to come from the listed proxy. This matters for `x_forwarded_for` over HTTP/1.1, plain or TLS.
- **Defences (R13):**
  - on an `x_forwarded_for` listener, a request carrying both `Content-Length` and `Transfer-Encoding` is answered 400 and its connection closed;
  - after any refusal for a missing address the connection is closed, so the rest of a desynchronised stream is never read;
  - PROXY v2 (one request per connection on a plain listener) is the recommended source on the same host;
  - an HTTP/2 hop (TLS listener, ALPN `h2`) has no such ambiguity.
- **Could not verify:** hyper's own handling of conflicting framing (needs a test). The rule above doesn't depend on it.

### 3.9 Malformed input
| Input | Result |
|---|---|
| PROXY: no signature, version 1, unknown command or family, short block, over 1,024 bytes, truncated, timeout | connection closed, counted (as today: `proxy.rs:30-75`, `doh.rs:203-206`) |
| PROXY on a listener with new keys: LOCAL, UNSPEC, UNIX, unspecified or loopback source | connection closed before HTTP, counted `no_client_address` |
| `X-Forwarded-For` missing, empty, unparsable at the selected entry, all entries listed proxies, more than 16 entries walked | 403, `Connection: close`, the pipeline never called, counted `no_client_address` |
| Conflicting framing on an `x_forwarded_for` listener | 400, connection closed |
| Bad HTTP | hyper's 4xx or close (as today) |

**Log lines** for refusals: at most one per listener and reason per minute, never with a header's value (the sender wrote it), as the API's proxy hint does (verified: `routes.rs:177-187`).

### 3.10 Probes and Alt-Svc
- **Probes (R16):** a plain listener, and a TLS listener with `x_forwarded_for`, are skipped with a reason, as `proxy_protocol` listeners already are. A probe would send no client address and be refused, and the probe client speaks only `https://` to a `doh` listener (verified: `probes.rs:68`). The reason text points to `[probe] targets` with the proxy's public URL, which tests the whole path.
- **Alt-Svc (R14):** never sent on a plain listener or an `x_forwarded_for` listener. The client reaches the proxy, not this node, so an advertised `h3` port would point at the proxy's host. On other listeners nothing changes.

### 3.11 Resource limits
- **Connections:** `max_connections` (1,024) as today. `max_connections_per_address` (default 32, verified: `crates/telltale-net/src/peer_limit.rs:11`) counts the PROXY client after the header (as today, ADR-099). With `x_forwarded_for` it counts the socket peer, the proxy: every connection is the proxy's, and the client is known only per request. `config check` warns if it is left at the default with `x_forwarded_for`.
- **Headers:** PROXY at most 1,024 bytes within 10 s (verified, §2). HTTP headers within the header read timeout (verified: `doh.rs:253`), under hyper's default size limits (exact figures could not verify; unchanged, since a DoH GET can carry about 87 KB of base64url). The `X-Forwarded-For` walk reads at most 16 entries of at most 45 bytes each and allocates nothing (R21).
- **Residual:** a local process can hold a loopback listener's slots, as it can today's loopback TLS listener. A Unix socket with mode `0660` limits that to the proxy's group.

### 3.12 Kubernetes and clusters
- **Unchanged recommendation:** TLS passthrough with PROXY v2 and `externalTrafficPolicy: Local` (`spec/08:36`). `trusted_proxies` can now also restrict that listener to the balancer's addresses.
- **An HTTP ingress that re-encrypts** (A, `x_forwarded_for`) needs the ingress controller's addresses in `trusted_proxies`. Those are pod addresses that change, and listing the pod network makes every pod a trusted proxy. The docs say: only with a NetworkPolicy that lets only the ingress reach the listener, or prefer passthrough.
- **A proxy sidecar in the pod:** a pod's loopback is the pod's own, so B on `127.0.0.1` is reachable only from that pod's containers (inferred: containers in a pod share one network namespace). A Unix socket on an `emptyDir` works too.
- **Clusters:** each node's `[[listen]]` lives in its own file (node-local), so a three-node cluster sets `trusted_proxies` on each node. Nothing is replicated and nothing changes on the cluster wire.

### 3.13 The rules (each one testable)
| Rule | Statement | Test (§6) |
|---|---|---|
| R1 | Opt-in: a `doh` listener without `tls` and without `plain_http` is refused, with today's message. | `dns_003_plain_doh_needs_opt_in` |
| R2 | `plain_http` only on `127.0.0.0/8`, `::1`, or a `unix:` path. | `dns_003_plain_doh_loopback_or_unix_only` |
| R3 | `plain_http` needs `proxy_protocol` or `x_forwarded_for`, not both. | `dns_003_plain_doh_requires_a_client_address_source` |
| R4 | With `trusted_proxies`, an unlisted peer is closed at accept, before any byte is read. It is required with `x_forwarded_for` on an address listener. | `dns_003_xff_only_from_listed_peers`, `dns_020_proxy_v2_only_from_listed_peers` |
| R5 | On a listener with any new key, no fallback to the socket peer. LOCAL, UNSPEC, UNIX, an unspecified or a loopback source closes the connection. A request without a usable `X-Forwarded-For` client gets 403 and its connection is closed. | `dns_020_plain_doh_local_or_unix_family_refused`, `dns_020_local_refused_once_trusted_proxies_is_set`, `dns_020_forwarded_unspecified_or_loopback_refused`, `dns_003_xff_missing_or_unusable_refused` |
| R6 | TCP4 or TCP6 with source port 0 and a zero destination is accepted. | `dns_020_proxy_v2_port_zero_and_empty_destination_accepted` |
| R7 | `X-Forwarded-For`: lines joined in order; walk from the right skipping listed proxies; the first other entry must be a bare IP literal, else refuse (never skip left); at most 16 entries. | `dns_003_xff_rightmost_untrusted_entry`, `dns_003_xff_unparsable_entry_is_not_skipped`, `dns_003_xff_walk_is_bounded` |
| R8 | Only `X-Forwarded-For`, only where enabled. `Forwarded` and `X-Real-IP` are never read. | `dns_003_xff_ignored_without_the_key` |
| R9 | The forwarded client is the client for access, rate limit, identification, log, analytics and dnstap. | `dns_014_rate_limit_counts_the_forwarded_client`, `dns_014_access_list_applies_to_the_forwarded_client`, `obs_001_query_log_records_the_forwarded_client` |
| R10 | The per-address limit counts the PROXY client, or the proxy with `x_forwarded_for`. | `dns_003_per_address_limit_counts_the_proxy_with_xff` |
| R11 | Plain listener: HTTP/1.1 only, no h2c, no upgrade. | `dns_003_plain_doh_http1_only` |
| R12 | Plain listener with PROXY v2: one request per connection. | `dns_020_plain_doh_proxy_v2_one_request_per_connection` |
| R13 | `x_forwarded_for`: conflicting framing gives 400 and a close; any address refusal closes. | `dns_003_xff_listener_refuses_conflicting_framing`, `dns_003_forwarded_listener_closes_after_a_refused_request` |
| R14 | No `Alt-Svc` on plain or `x_forwarded_for` listeners. | `dns_003_plain_and_xff_listeners_send_no_alt_svc` |
| R15 | Client IDs from the path only on plain and `x_forwarded_for` listeners: the SNI there is the proxy's, and a wildcard certificate would give every client the proxy's label. | `dns_003_xff_listener_ignores_sni_client_ids`, `dns_003_client_id_from_path_survives_forwarding` |
| R16 | Probes skip plain and `x_forwarded_for` listeners with a reason. | `obs_020_probes_skip_listeners_that_need_a_forwarded_address` |
| R17 | Unix socket: mode set before listen; never replaces a file, a symlink or a live socket; removed on close. | `dns_003_unix_socket_mode_set_before_listen`, `dns_003_unix_socket_never_replaces_a_file_or_a_live_socket`, `dns_003_unix_socket_removed_on_close` |
| R18 | Without new keys nothing changes (ADR-039 LOCAL rule, `Alt-Svc`, SNI IDs, probes). | `dns_020_local_keeps_socket_address_without_new_keys` + existing tests |
| R19 | New keys not written at their defaults, and never shared. | `dns_003_new_listener_keys_not_written_at_default`, `clu_003_listener_keys_never_shared` |
| R20 | A plain listener speaks HTTP, never DNS over TCP. | `dns_003_plain_doh_listener_speaks_http` |
| R21 | The address selector is bounded and allocation-free; the PROXY and `X-Forwarded-For` parsers are fuzzed. | `dns_003_xff_selector_allocates_nothing`, fuzz targets `proxy_header`, `forwarded_for` |

## 4. Configuration and schema
### 4.1 Keys (on `[[listen]]`, `proto = "doh"` only; decision)
| Key | Type | Default | Written | Meaning |
|---|---|---|---|---|
| `plain_http` | bool | `false` | only when `true` | No TLS: a TLS-terminating proxy on this host is in front (B). |
| `x_forwarded_for` | bool | `false` | only when `true` | The client's address is the rightmost `X-Forwarded-For` entry that isn't a listed proxy (A). |
| `trusted_proxies` | list of networks (`Cidr`, as `[api] trusted_proxies`) | `[]` | only when non-empty | The only peers this listener accepts, and the hops skipped in `X-Forwarded-For`. Its presence also makes a `proxy_protocol` listener strict (R5). |
| `unix_mode` | string, octal (`"0660"`) | `"0660"` | only when set | The socket file's mode (B, Unix socket only). |
| `addr` (changed type, second step of B) | string: `ip:port` or `unix:/absolute/path` | (required) | as written | An address, or a Unix socket path. An `ip:port` string serializes exactly as today. |

`proxy_protocol` is unchanged (and stays always written, as today).

### 4.2 Validation (`validate.rs::listeners`, the project's message style)
Errors:
- `listen[i].plain_http`: "only valid for doh listeners"
- `listen[i].plain_http`: "set `tls` or `plain_http`, not both"
- `listen[i].tls`: "required for dot, doh, doh3, and doq listeners" (unchanged; skipped only when `plain_http = true`)
- `listen[i].addr`: "a plain_http listener must listen on loopback (127.0.0.0/8 or ::1) or a unix socket, e.g. 127.0.0.1:8053: plain HTTP must not cross a network"
- `listen[i].plain_http`: "needs the client's address from the proxy: set `proxy_protocol = true` or `x_forwarded_for = true`"
- `listen[i].x_forwarded_for`: "only valid for doh listeners"
- `listen[i].x_forwarded_for`: "set `proxy_protocol` or `x_forwarded_for`, not both"
- `listen[i].trusted_proxies`: "required with `x_forwarded_for`: list your proxies' addresses, e.g. [\"10.0.5.20/32\"]" (address listeners; optional on a Unix socket, where it only skips hops)
- `listen[i].trusted_proxies`: "only valid on a doh listener with `proxy_protocol` or `x_forwarded_for`"
- `listen[i].trusted_proxies`: "`0.0.0.0/0` trusts every address: list only your proxies" (any prefix length 0)
- `listen[i].addr`: "a unix socket needs an absolute path, e.g. unix:/run/telltale/doh.sock"
- `listen[i].addr`: "a unix socket is only valid for a doh listener with `plain_http`"
- `listen[i].unix_mode`: "only valid for a unix socket"
- `listen[i].unix_mode`: "must be an octal mode such as 0660"

A host name in `trusted_proxies` is already refused by the type ("`x` is not an IP network", verified: `crates/telltale-config/src/types.rs:233-235`).

Warnings:
- "listen[i].trusted_proxies: `10.0.0.0/24` is a network, not one proxy: every machine in it can name any client; list only your proxies" (any entry wider than one host)
- "listen[i].trusted_proxies: a loopback listener only sees this host; `10.0.5.20/32` never connects"
- "listen[i].max_connections_per_address: with `x_forwarded_for` every connection is the proxy's; the default 32 may refuse it: raise it or set 0"
- "listen[i].unix_mode: `0666` lets every local user connect and name any client"

### 4.3 Examples
Caddy on the same host, PROXY v2 (B, loopback):
```toml
[[listen]]
proto = "doh"
addr = "127.0.0.1:8053"
plain_http = true
proxy_protocol = true
```
```
dns.example.com {
	reverse_proxy /dns-query* 127.0.0.1:8053 {
		transport http {
			proxy_protocol v2
		}
	}
}
```
The same over a Unix socket (B, second step): `addr = "unix:/run/telltale/doh.sock"`, with Caddy's `reverse_proxy /dns-query* unix//run/telltale/doh.sock` and the same transport block.

nginx on the same host (B, `X-Forwarded-For`):
```toml
[[listen]]
proto = "doh"
addr = "127.0.0.1:8053"
plain_http = true
x_forwarded_for = true
trusted_proxies = ["127.0.0.1/32"]
max_connections_per_address = 0
```
with `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (appends the client). Never `$http_x_forwarded_for`, which passes the client's own claim through.

A proxy on other machines that re-encrypts to each node (A; for example a Traefik-based proxy with connectors at 10.0.5.20 and 10.0.5.21):
```toml
[[listen]]
proto = "doh"
addr = "0.0.0.0:443"
tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }
x_forwarded_for = true
trusted_proxies = ["10.0.5.20/32", "10.0.5.21/32"]
max_connections_per_address = 0
```
A layer-4 balancer that passes TLS through with PROXY v2 (today's `proxy_protocol = true`) can add `trusted_proxies = ["10.0.5.20/32"]` to accept only the balancer and to refuse LOCAL.

### 4.4 Node-local, old nodes, written only when set
- **Node-local (verified: `shared.rs:15-26`).** Nothing new reaches the cluster's shared configuration, the snapshot log or the peer protocol. A replica on an older version is unaffected by another node's listener settings.
- **An older binary given the new keys in its own file refuses it** (`deny_unknown_fields`, verified: `schema.rs:412`). That only happens on a downgrade. At start it would not run with that file; on a reload it would keep the running configuration (both inferred: needs a check by an implementer). The docs say: remove the keys before installing an older version, including through the cluster's upgrade path.
- **Written only when set (the ADR-187 pattern):**
  - `skip_serializing_if` on each new key;
  - `addr` serializes as today for addresses.

  A default listener's serialized form, the schema output and backups therefore stay byte-identical for existing users, and a backup restored on an older version still loads.
- **Regenerated:** `docs/config-schema.json`. OpenAPI only if `system/info`'s listener strings change (§9 Q9; recommended: no change).
- **No API operation, MCP tool or UI change:** listeners aren't edited through the API (§2).
- **Support package:** add `("listen[].trusted_proxies[]", Scan)` and `("listen[].unix_mode", Plain)`. The table's own test fails without them (verified: `classify.rs:1-7`).

### 4.5 Docs
- **`docs/running.md`, "Encrypted DNS for your devices":** a short pointer after the "Behind a load balancer" bullet (`:597`), and a new subsection "Behind a reverse proxy" covering:
  - which setup takes which keys (the table of §1, in plain words);
  - the four examples above;
  - the rules users notice:
    - requests without a client address are refused;
    - a client on the proxy's own host is refused through the proxy;
    - `[access] allowed_networks` and the rate limit apply to the real client, so clients outside the allowed networks are refused;
    - list only your proxies;
    - point the proxy's health check at a TCP connect, or at the web UI's `/livez`;
  - the metrics;
  - the downgrade note.
- **The matching section in `site/guide-encrypted.html`** (DOC-006).
- **Schema comments** on each key.
- **`spec/08` line 36** gains the re-encrypting proxy (A) and the proxy on the same host (B).

## 5. Behaviour rules
1. **Explicit opt-in.** Nothing changes until a new key is written. `plain_http` exists so that forgetting `tls` is still an error (R1).
2. **No usable address, no answer.** The forwarded source is mandatory on plain listeners and on any listener with a new key, and there is no fallback (R5). This is ADR-039's "mandatory when enabled", carried to the address itself.
3. **Limits and access lists count the forwarded client** (ADR-099, DNS-014, ADR-014):
   - the access list and the token bucket key on `meta.peer` (verified, §2), so setting `meta.peer` to the forwarded client is the whole change;
   - the per-address connection limit is the one place that counts connections, so with `x_forwarded_for` it counts the proxy (R10);
   - a forwarded address is counted and checked like any client's address.
4. **The query log and analytics see the client address.** `emit` takes `meta.peer` (verified: `pipeline.rs:2578-2596`), so the log, top clients, anomalies and the masked-client-address banner (ADR-037) all see real clients. No change in telemetry.
5. **Client IDs.** Path IDs work through any proxy that keeps the path (the reporter's rewrite does). SNI IDs are not taken on plain or `x_forwarded_for` listeners (R15). Client IDs are self-asserted, as today (FLT-006): identification, not authentication.
6. **Client IDs in device analytics (part C): what the code does today, and a proposal.**
   - The query event carries the client's address and `client_ref`, the index of the configured `[[client]]` that matched (by ID, MAC or address), but **no client ID** (verified: `crates/telltale-telemetry/src/event.rs:77-104`).
   - The query log stores a dictionary of client **addresses** (`ClientId` column, keyed by `client_ip`), `ClientRef` and the group (verified: `crates/telltale-store/src/qlog/format.rs:37-64`, `crates/telltale-store/src/qlog/writer.rs:208`).
   - Every per-device structure in the aggregator is keyed by the 16-byte address (verified by grep: `crates/telltale-telemetry/src/agg.rs`, `anomaly.rs`, `seen.rs`, `last_hour.rs`; also `docs/design/kubernetes-workloads.md` §3).
   - So **matching by ID works** (the pipeline identifies with the ID, `pipeline.rs:908-919`), while **device statistics group by address**. That matches gael1980's observation (inferred for that exact setup). An ID that matches no `[[client]]` leaves no trace of itself in the log (inferred).
   - A forwarded address (A or B) fixes the proxy-address collapse. A roaming device seen only by its ID would still be split by address.
   - **Proposal:** its own issue: device analytics keyed by a configured client matched by ID. ADR-150's synthetic address in `100::/64` for Kubernetes workloads is a ready pattern. Priority P2 or P3; it is observability work with no new trust.

## 6. Tests
All are deterministic: in-process servers on loopback, no wall-clock races. Clients bind a chosen loopback source (`127.0.0.2:0`) to test peer lists. The harness follows `crates/telltale-net/tests/tls.rs:169-175` (`doh_server`, the `Seen` handler). The regressions that fail before the change are marked **(fails before)**.

**Configuration (`crates/telltale-config`):**
- `dns_003_plain_doh_needs_opt_in`: `doh` without `tls` or `plain_http` still gives today's message (guard).
- `dns_003_plain_doh_loopback_or_unix_only`:
  - refused: `0.0.0.0`, `[::]`, `192.168.1.5`, `203.0.113.9`, `[fe80::1]`;
  - accepted: `127.0.0.1`, `127.0.0.2`, `[::1]` and, in the second step, `unix:/run/x.sock`;
  - refused: a relative `unix:` path.
- `dns_003_plain_doh_requires_a_client_address_source`; `dns_003_plain_doh_not_with_tls`; `dns_003_proxy_protocol_and_x_forwarded_for_are_exclusive`.
- `dns_003_x_forwarded_for_needs_trusted_proxies`; `dns_003_trusted_proxies_refuses_everyone_and_warns_on_networks`; `dns_003_trusted_proxies_only_with_a_forwarded_source`.
- `dns_003_new_listener_keys_not_written_at_default`: a listener without them serializes as before. `clu_003_listener_keys_never_shared`: `shared_part` has no `listen`.
- `ops_011_support_package_classifies_the_new_listener_fields` (the existing schema walk, extended).

**Listener (`crates/telltale-net`):**
- `dns_020_proxy_v2_port_zero_and_empty_destination_accepted` (fails before on the plain listener, since the key doesn't exist; the `proxy.rs` unit part passes on today's parser and pins it): TCP4 `127.0.0.1:0 → 0.0.0.0:0` and TCP6 `[2001:db8::7]:0 → [::]:0` give the source with port 0, and the request is answered.
- `dns_020_plain_doh_local_or_unix_family_refused`: LOCAL, AF_UNSPEC and AF_UNIX each close the connection; the handler is never called; the counter rises.
- `dns_020_local_refused_once_trusted_proxies_is_set` **(fails before)**: on a TLS listener with `proxy_protocol` and `trusted_proxies`, a LOCAL header no longer serves the socket's peer.
- `dns_020_local_keeps_socket_address_without_new_keys`: ADR-039 unchanged (guard).
- `dns_020_forwarded_unspecified_or_loopback_refused`: `0.0.0.0`, `::`, `127.0.0.5`, `::1`, `::ffff:127.0.0.1` refused by PROXY and by `X-Forwarded-For`.
- `dns_020_proxy_v2_only_from_listed_peers` and `dns_003_xff_only_from_listed_peers` **(fails before)**: a client from `127.0.0.1` is closed at accept when only `127.0.0.2/32` is listed; from `127.0.0.2` with `X-Forwarded-For: 192.0.2.7` the handler sees `192.0.2.7`.
- `dns_003_xff_rightmost_untrusted_entry`:
  - `198.51.100.1, 192.0.2.7` gives `192.0.2.7`;
  - `192.0.2.7, 127.0.0.2`, with `127.0.0.2` listed, gives `192.0.2.7`;
  - two field lines give the last line's entry.
- `dns_003_xff_unparsable_entry_is_not_skipped`: `10.0.0.1, 203.0.113.9:4711`, `[2001:db8::1]`, `unknown`, an empty value and a 46-byte entry are all refused, and never resolved to `10.0.0.1`.
- `dns_003_xff_missing_or_unusable_refused`; `dns_003_xff_walk_is_bounded` (17 listed entries refused); `dns_003_xff_ignored_without_the_key`.
- `dns_003_forwarded_listener_closes_after_a_refused_request`; `dns_003_xff_listener_refuses_conflicting_framing`.
- `dns_003_plain_doh_http1_only`: an HTTP/2 preface is not served as HTTP/2, and the handler is not called.
- `dns_020_plain_doh_proxy_v2_one_request_per_connection`: two pipelined requests get one answer and then EOF.
- `dns_003_plain_and_xff_listeners_send_no_alt_svc` (with `alt_svc` set in the config).
- `dns_003_xff_listener_ignores_sni_client_ids`; `dns_003_client_id_from_path_survives_forwarding` (`/dns-query/kids-tablet` with a forwarded address).
- `dns_003_per_address_limit_counts_the_proxy_with_xff`.
- `dns_003_xff_selector_allocates_nothing`: the counting allocator, as for the hot path.
- Second step: `dns_003_unix_socket_mode_set_before_listen`, `dns_003_unix_socket_never_replaces_a_file_or_a_live_socket`, `dns_003_unix_socket_removed_on_close`, `dns_020_proxy_v2_over_unix_socket_tcp4_family_accepted`.
- Kept unchanged: `dns_003_doh_get_post_client_ids_and_errors`, `dns_003_doh_http1_and_proxy_protocol`, `dns_004_doh_advertises_http3` (verified: `tests/tls.rs:217`, `:299`, `:325`), `dns_020_parses_v4_v6_and_local`, `dns_020_rejects_bad_headers` (verified: `proxy.rs:115`, `:136`).

**Server and pipeline (`crates/telltale`):**
- `dns_014_rate_limit_counts_the_forwarded_client` **(fails before for `x_forwarded_for`)**: a DoH server with the real pipeline, a limit of 2 per window and three forwarded clients behind one loopback proxy. Client A's third query is refused and B and C are answered, whatever the connection's own address.
- `dns_014_access_list_applies_to_the_forwarded_client`: a forwarded `203.0.113.9` gets REFUSED with EDE 18, although the socket's peer is loopback.
- `obs_001_query_log_records_the_forwarded_client`: the event's `client_ip` is the forwarded address.
- `obs_020_probes_skip_listeners_that_need_a_forwarded_address`.
- `dns_003_plain_doh_listener_speaks_http`: `bind_stream` with `plain_http` answers an HTTP GET (the catch-all arm is never taken).

**Fuzz** (NFR-004): `proxy_header` (`read_header`) and `forwarded_for` (the selector), added to the nightly set.

## 7. Size, order, risk and benchmarks
- **Order: A, then B.**
  - **A1** (S): `trusted_proxies` and the strict rule on TLS `doh` listeners. It hardens today's re-encrypting setup and gives layer-4 PROXY setups an allowlist.
  - **A2** (S): `x_forwarded_for` on TLS `doh` listeners. This answers the other-machines case without plaintext.
  - **B1** (S, after A): `plain_http` on loopback: a `(Doh, plain)` arm in `bind_stream`, HTTP/1.1 only, one request per connection with PROXY, the probe skip.
  - **B2** (M): Unix sockets. `addr` becomes an address-or-path type, which touches the dozen readers listed in §2, plus the socket's lifecycle.
  - A is M in all; B is M in all.
  - **Recommendation (Q2):** ship B1 and B2 together. A Unix socket is the safer shape (file permissions instead of "every local process"), and the first reporter prefers it.
- **Risk to the DNS path:**
  - DoH only. UDP, TCP, DoT, DoQ, DoH3 and the pipeline are unchanged.
  - Existing DoH listeners gain one predictable branch at accept (an empty `trusted_proxies`) and one per request (`x_forwarded_for` off).
  - Mixed-version clusters: none (node-local; no wire, snapshot or shared-schema change).
  - Downgrade: the older binary refuses a file with the new keys (§4.4).
- **Per-query work, and where:**
  - **A2:** in `Ctx::answer_inner` (`doh.rs:296-331`), before `RequestMeta` is built. The walk reads at most 16 short entries from the right, with a CIDR check against a few networks: tens to a few hundred nanoseconds (inferred), no allocation. Only on `x_forwarded_for` listeners.
  - **A1:** one CIDR scan per connection at accept, off the per-query path.
  - **B1:** removes the TLS work, but with PROXY v2 adds one loopback or Unix connection (accept, header, task) per query (R12).
- **Benchmarks** (AGENTS rule 4, `telltale-net` changes):
  - `make bench-smoke` against a same-binary control (paths not touched; within noise);
  - `make bench-transports` (verified: `Makefile:28-30`), DoH row, for:
    - a TLS listener without new keys (within noise);
    - with `x_forwarded_for` (`h2load -H "X-Forwarded-For: …"`);
    - a plain loopback listener with PROXY v2, one request per connection; this number decides Q3;
  - the allocation test for the selector.
- **Release fit:** a later minor, not 0.9.0. It is a new listener mode and a new trust.

## 8. Trying to break it
**A hostile client:**
- It forges `X-Forwarded-For` through a correct proxy: only the rightmost entry counts, which the proxy wrote (R7).
- It puts a port or junk in its header so that the proxy's entry is the only clean one: the proxy's entry is the rightmost and selected. If the proxy itself writes a port, the request is refused rather than skipped to the client's entry (R7).
- It connects straight to an `x_forwarded_for` or listed TLS listener: closed at accept (R4). A plain listener is reachable only from the host (R2).
- It sends a PROXY header with no address, or claims loopback: refused (R5).
- It smuggles a second request on a shared HTTP/1.1 connection: framing conflicts close the connection (R13). With PROXY on a plain listener there is only one request per connection (R12).
- It floods: its own address is now rate-limited, where before it shared the proxy's (an improvement, R9).
- It picks another device's client ID in the path: possible, as today (FLT-006). Unchanged and documented.

**A hostile listed proxy:**
- It can be any client: any group or policy, another device's rate budget (the bucket is shared across transports, so it can make a LAN device's UDP queries refused for a window), and any address in the log. It can rotate addresses to evade the limit.
- It can't name loopback (R5). It can't reach the API, configuration or other nodes through this. It is bounded by `max_connections` and, with `x_forwarded_for`, by the per-address limit on itself.
- This is the trust the operator grants, and the docs say so.

**A hostile local process (B on loopback):** it can connect like the proxy and name any client, with the same reach as a listed proxy. It can also hold connection slots. The Unix socket with mode `0660` closes this (B2). The docs say plainly: on loopback, every process on the host is trusted.

**A misconfigured operator:**
- Forgets `tls`: an error (R1).
- Binds plain HTTP on `0.0.0.0`: an error (R2).
- No address source: an error (R3).
- `proxy_protocol` on, but the proxy doesn't send it: every connection is closed and counted (loud).
- A pass-through `X-Forwarded-For` (the proxy doesn't append): the client's claim is believed. R5 removes the loopback case; the per-proxy docs and examples are the defence (§3.4).
- Lists the LAN or the pod network in `trusted_proxies`: a warning (`/0` is an error).
- Forgets that `allowed_networks` now applies to real clients: they get REFUSED with EDE 18. It fails closed, and the query log shows why.
- Points the proxy's health check at the DoH path: 403, the backend shows as down (loud; the docs say what to check instead).
- Leaves the per-address limit at 32 with `x_forwarded_for`: a warning.
- Sets `unix_mode = "0666"`: a warning.
- Downgrades with the keys set: the older binary refuses the file (documented).

**What this design can't prevent:** a proxy that is listed and lies, a pass-through proxy configuration, and a client choosing a client ID. All three are stated in the docs.

## 9. Open questions for the owner (each with a recommendation)
1. **Trust a forwarded address from listed peers, including private-network peers on other machines?** Recommend yes. Per listener, an allowlist enforced at accept, no fallback, TLS on the hop (A). That is ADR-034's model for the API, applied to DNS listeners.
2. **Unix sockets: in the same change as plain HTTP, or later?** Recommend the same slice as loopback (B1 + B2 together, after A). It is the safer shape and the one the first reporter prefers. If B must be smaller, loopback first, with the docs naming the local-process risk.
3. **One request per connection on a plain listener with PROXY v2?** Recommend yes at first (safe whatever the proxy's pooling). Measure with `bench-transports`, and relax to keep-alive in a later ADR only if the cost is real; Caddy's per-client pool (verified) would allow it.
4. **Refuse a forwarded loopback or unspecified address?** Recommend yes. A forwarded loopback address stands for the proxy's host, not for a client, also under a misconfigured proxy. The cost: a client on the proxy's own host can't use DoH through the proxy, and uses the local listeners instead.
5. **Rightmost-untrusted with one list (ADR-034), or exactly one hop?** Recommend rightmost-untrusted with one list, a bounded walk, warnings on networks and `/0` refused. It is consistent with the API and supports proxy chains. One hop would be stricter, but it collapses clients behind chained proxies to an intermediate's address.
6. **`X-Real-IP` (and `Forwarded`)?** Recommend not now. `X-Forwarded-For` only, as for the API. The common proxies can send it (inferred). One header means one rule to audit.
7. **h2c on plain listeners?** Recommend not now (HTTP/1.1 only). Revisit with a measurement.
8. **`trusted_proxies` on `tcp` and `dot` listeners with PROXY v2 too?** Recommend later, with the same rules. Their accept loop is separate (`crates/telltale-net/src/tcp.rs`).
9. **Label plain listeners in `system/info`** (today `doh://127.0.0.1:8053`, verified: `api_backend.rs:875-879`)? Recommend no change now, to avoid an API string change. The docs explain it.
10. **A public DoH endpoint behind a proxy needs `allowed_networks` widened for every listener.** Should a listener have its own access list? Recommend not in this ADR. It is a separate decision about who may use the resolver. Open an issue if a user asks.
11. **Client-ID device analytics (C):** recommend its own issue, opened by the reporter.

## 10. Verified, inferred, could not verify
**Verified (cited above):** the TLS requirement and the runtime arm (`validate.rs:1316-1321`, `schema.rs:398-400`, `server.rs:708-724`); the catch-all arm (`server.rs:752-773`); `addr`'s type and its readers (`schema.rs:417`, the grep list in §2); unknown keys refused (`schema.rs:412`); PROXY before TLS and its outcomes (`doh.rs:194-214`); `read_header`'s `None` cases and the copy of the source (`proxy.rs:44`, `:55-75`); no port-0 test (`proxy.rs:114-165`); client IDs (`doh.rs:219-225`, `:297-331`); `Alt-Svc` (`server.rs:607-612`, `doh.rs:342-350`); probes (`probes.rs:64-71`, `:92-94`); the pipeline's uses of `meta.peer` (`pipeline.rs:908-919`, `:1576-1601`, `:2578-2613`); the defaults (`schema.rs:1799-1809`, `:1873`); ADR-014, ADR-034 and its amendment, ADR-039, ADR-099, ADR-149, ADR-187 (`spec/11-decisions.md:111-124`, `:397-414`, `:471-483`, `:3027-3038`, `:2513-2523`, `:1958-1985`); node-local `listen` (`shared.rs:15-26`); support-package classification (`classify.rs:1-7`, `:137-140`); the query event, the log columns and the address-keyed analytics (`event.rs:77-104`, `format.rs:37-64`, `writer.rs:208`); `socket2` with Unix support (`telltale-net/Cargo.toml:45`); `Cidr` parsing (`types.rs:227-246`); `bench-transports` (`Makefile:28-30`); DNS-003, DNS-014, DNS-020 (`spec/01-requirements.md:12`, `:23`, `:29`); `spec/08:36`. Caddy's per-client connection key, port 0 and zero destination (its source, default branch, read 2026-11-27).

**Inferred:** that Caddy's header shape parses as `Some(src:0)` on today's parser (the R6 test pins it); that nothing reads the peer's port for policy; that the kernel refuses connections between bind and listen; that a pod's containers share loopback; that hyper rejects an HTTP/2 preface on its HTTP/1 server; the selector's cost; how Caddy, nginx and HAProxy write `X-Forwarded-For`; that nginx's HTTP proxy and Traefik's HTTP routers don't send PROXY headers; an older binary's start and reload behaviour with unknown keys; that an ID matching no `[[client]]` leaves no trace in the log.

**Could not verify:** Caddy v2.11.9 itself, as opposed to its current source; what Caddy sends when it can't parse a client address; HAProxy's and Traefik's connection reuse with PROXY headers; Pangolin's and Newt's exact header behaviour; hyper's handling of conflicting framing and its default header limits; what the UI shows for a log row with a `ClientRef` but a proxy's address. All of these need execution or the other projects' own documentation.

## 11. Building part A: what it settled (T31.1, 2026-11-27)
- **Where the rules live.** `crates/telltale-net/src/forwarded.rs` holds the networks, the walk (`client`), what counts as a client (`is_client`) and the once-a-minute log gate; `doh.rs` applies them: the peer check at accept, the PROXY header's strict outcomes, and the per-request walk on `x_forwarded_for` listeners (before the path, so the pipeline is never asked for a refused request). `DohConfig::behind_listed_proxies()` is true with either key; with `x_forwarded_for` and an empty list (which validation refuses) nobody connects.
- **Conflicting framing (R13).** hyper 1.11's HTTP/1 server already does what R13 asks for in effect: a request with both `Content-Length` and `Transfer-Encoding` is framed by `Transfer-Encoding` (the `Content-Length` header is removed before the service sees it) and its connection is closed after the answer (RFC 9112 §6.3). A listener check for both headers could never fire, so there is none: the request is answered, and nothing behind it on the connection is read. `dns_003_xff_listener_closes_after_conflicting_framing` pins this with a request counted inside the body behind it, in both header orders. HTTP/2 has no such framing.
- **A refused request ends its connection.** HTTP/1.1: the 403 carries `Connection: close` and hyper closes after it, so a request pipelined behind it is never read. HTTP/2: the connection is shut down gracefully after the answer (GOAWAY), so streams already open finish.
- **IPv4-mapped entries.** An `X-Forwarded-For` entry such as `::ffff:192.0.2.7` (a dual-stack proxy may write one) is the IPv4 client `192.0.2.7`, so the query log and the rate limit see one client whichever form the proxy writes. The PROXY header's source is kept as it comes, as before.
- **R6 and R5 together.** The R6 test's loopback example (`127.0.0.1:0 → 0.0.0.0:0`) parses as planned, but a listener with `trusted_proxies` refuses a loopback source (R5), so the listener part of the test uses `192.0.2.7:0` and `[2001:db8::7]:0`.
- **Metric.** `telltale_doh_forwarded_refused_total{reason="unlisted_peer"|"no_client_address"}`; a 403 also counts in `telltale_doh_bad_requests_total` (every 4xx does). The log lines name the listener and, for an unlisted peer, its address; never a header's value.
- **Fuzzing.** The walk has the nightly target `forwarded_for`. A `proxy_header` target for `read_header` (existing code) is left for later.
- **Not measured here.** `make bench-smoke` and the DoH row of `make bench-transports` need the benchmark machine; the build machine used for part A has a generic CPU. Existing listeners gain one branch at accept and one per request; the walk allocates nothing (`dns_003_xff_selector_allocates_nothing`).
