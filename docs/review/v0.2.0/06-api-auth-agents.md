# Pass 06: API, authentication, agents and MCP (v0.2.0)

Reviewed at tag `v0.2.0` (commit 338db09) in `~/telltale-review`. Since the tag, `main` has
changed `crates/telltale-api/src/config_api.rs` (+78), `mcp.rs` (+58), `model.rs` (+25),
`lib.rs` (5 lines), `crates/telltale/src/api_backend.rs` (+243) and `managed.rs` (+11), mostly
for the rate-limit UI/API/agent tool (45f85a0). Patches 06-02 (`config_api.rs`), 06-03
(`api_backend.rs`), 06-04 and 06-07 (`mcp.rs`, `lib.rs`) will need small offsets there; the
`auth/` patches (06-01, 06-08) apply as is. Nothing here touched the Pi, the homelab, or
`~/homelab-charts`; every test ran in-process in the worktree.

## Summary

The sign-in and agent layers are built the way the spec asked and, mostly, the way the ADRs
describe: secrets are stored hashed and compared in constant time, lockouts are per username
and per address and audited once, TOTP codes can't be replayed, sessions carry a CSRF token on
a `SameSite=Strict` cookie, tokens never exceed their owner's role and are re-checked against
the owner on every request, agents are denied by default with a route map that has its own
tests, group-restricted agents can't pivot to another group's devices by IP, plans are
owner-bound and applied with `If-Match` and the plan ID as the idempotency key, and the audit
chain is tamper-evident with tests that break it on purpose. What's missing is mostly about
**bounds and attribution**, not about who may do what.

Top three points:

1. **Password checks have no concurrency bound** (06-01, medium, patched). Every sign-in,
   HTTP Basic cache miss, and unknown-user dummy check runs Argon2id at 19 MiB on Tokio's
   blocking pool, which allows 512 threads; the lockout gives every username and every
   address five free attempts, so many sources can have many checks in flight at once. The
   chart limits a pod to 256–512 MiB, so a burst of sign-in attempts can take the node, and
   DNS with it (`02 §8`). The patch caps checks at four in flight and answers 503 with
   `Retry-After` beyond that; a refusal isn't a failed sign-in.
2. **A pre-save list check echoes fetched content to agents** (06-02, medium, patched).
   `POST /api/v1/checks/list` downloads any `http(s)` URL the node can reach and returns up to
   ten lines it couldn't parse, text included, to anyone with `config:write:lists`. For an
   operator in the UI that's the point; for an agent token it makes the node a reader of
   whatever the pod network or LAN serves. The patch keeps the counts and reasons for agents
   and the text for people.
3. **Configuration writes aren't serialized** (06-03, medium, suspected, patched). A write is
   planned against a snapshot in one blocking task and stored in another; `If-Match` is
   optional. Two writes planned on the same snapshot can each be valid and together not, and
   `effective()` then falls back to the config files alone, so every entry made through the
   API or UI stops applying until `state.db` is fixed. The patch holds one lock across
   plan, store, and reload.

The rest is low: MCP-made changes are audited with `0.0.0.0` as the client address (06-04,
patched), `X-Forwarded-Proto` is believed from any peer (06-05), an admin can't revoke another
user's token without disabling the user (06-06), JSON-RPC batches are unbounded (06-07,
patched), HTTP Basic lockouts don't count the address (06-08, patched), and viewers see every
pending plan (06-09).

## Strengths

- **Sign-in is careful about the basics.** Argon2id with the spec's parameters
  (`crates/telltale-api/src/auth/crypto.rs:15-32`), the same cost for unknown users
  (`auth/mod.rs:605-611`), lockouts keyed by lower-cased username and by address with the
  first lock audited (`:540-573`, `:596-603`), TOTP steps that only move forward
  (`crates/telltale-store/src/state.rs:425-434`, `auth/mod.rs:676-680`), single-use recovery
  codes (`state.rs:460-469`), and constant-time compares for the setup token, token secrets,
  and CSRF tokens (`auth/mod.rs:517`, `:784`, `auth/routes.rs:186`).
- **Tokens never outrank their owner.** The owner's role and status are re-read per request:
  a token of a disabled user is refused, and an agent token's scopes are capped by the owner's
  role (`auth/mod.rs:741-747`, `:789-813`); creating a token above one's role is refused
  (`auth/routes.rs:1346-1358`, `:1407-1450`).
- **Agents are denied by default, and the map is tested.** `required()` lists every route an
  agent may use and refuses the rest, with people-only routes named (`auth/agent.rs:122-226`,
  tests `:393-510`); every change needs a reason (`:365-373`); the kill switch and rate limit
  apply before the route is looked at (`:325-337`).
- **Group restriction holds on reads.** A restricted agent's `group` is forced into
  `/queries` and `/stats/top` (`auth/routes.rs:224-229`, `:259-277`), `/clients` is filtered
  (`lib.rs:1067-1076`), and `stats/top` refuses `client` together with `group`
  (`lib.rs:932-941`), so the forced group can't be sidestepped by naming an IP.
- **Plans and idempotency are done right.** Transitions check the owner (`plans.rs`), the
  apply replays the exact write with `If-Match` on the plan's version and the plan ID as
  `Idempotency-Key` (`mcp.rs:1576-1610`); a replay compares the request bytes, lives 24 h, and
  is stored only for successes (`config_api.rs:1254-1276`, `:1320-1331`,
  `crates/telltale-store/src/state/managed.rs:160-193`).
- **The audit chain is tamper-evident and says so under test.** Hashes cover a domain
  string, the sequence, and every field with a presence byte and a length prefix
  (`crates/telltale-store/src/state/audit.rs:59-87`); triggers refuse `UPDATE`/`DELETE`
  (`state.rs:68-71`); the tests drop the triggers and edit, delete, and truncate
  (`audit.rs:257-294`). Passwords never reach `detail` (`auth/routes.rs:1595-1614`, checked
  by `tests.rs:1274-1275`).
- **Identity replication is one transaction and keeps a node usable** (`state/identity.rs:
  190-359`): local users stay, the primary wins a name, the TOTP step never moves backwards,
  and a bad document changes nothing (`:447-456`).
- **OIDC does the hard parts**: flow state bound to a browser cookie, PKCE, a cap on open
  flows, asymmetric algorithms only, issuer/audience/expiry/not-before checks on MCP access
  tokens, and return paths kept inside the UI (`auth/oidc.rs`, `oidc/flow_tests.rs`).
- **The UI is served safely**: a CSP without `unsafe-inline`, `X-Frame-Options: DENY`,
  traversal and `.gz` checks (`ui.rs`, tested at `tests.rs:1121-1151`); the setup token is a
  0600 file, reused across restarts and deleted after setup (`crates/telltale/src/auth_setup.rs:
  142-153`, `:165-184`).

## Measurements

| What | Result |
|---|---|
| `cargo test -p telltale-api` at v0.2.0 (debug) | 55 pass (unit, HTTP, OIDC flow, MCP) |
| `cargo test -p telltale-store` at v0.2.0 | 22 pass |
| `cargo test -p telltale --bin telltale api_ agt_` at v0.2.0 | 32 pass |
| Each patch applied alone to v0.2.0: the new test (fails unpatched for 06-02, 06-04, 06-07, 06-08), the crate's tests, `cargo clippy … -D warnings` | see each finding's Patch row |

No load test was run and no live provider was used; 06-01 is argued from the allocation per
verification, the blocking pool's size, and the chart's limits, not measured.

## Findings

### 06-01 Password checks have no concurrency bound: a burst of sign-ins can take the node

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | reliability (`02 §8`: DNS must not depend on the API), resource bound |
| Where | `crates/telltale-api/src/auth/mod.rs:604-611` (`login` verifies, or dummy-verifies, on every attempt); `:859-866` (`by_basic` does the same on a cache miss); `auth/crypto.rs:15-32` (Argon2id m=19 MiB, t=2, p=1, allocated per call); `auth/routes.rs:45-51`, `:154-168` (every request's authentication runs on `spawn_blocking`); `crates/telltale/src/main.rs:1206-1209` (the runtime's blocking pool is the default, 512 threads); `auth/mod.rs:218`, `:596-603` (five free attempts per username *and* per address before any wait); `deploy/helm/telltale/values.yaml:37-43`, `:162-169` (memory limits 256 Mi and 512 Mi) |
| Evidence | **verified by reading, not measured.** Each verification allocates its 19 MiB; nothing bounds how many run at once but the blocking pool. The lockout counts failures per username and per address, so distinct usernames from distinct addresses (an IPv6 prefix supplies plenty) each get five attempts before a wait, and attempts that are merely in flight aren't counted. Unknown usernames cost the same by design (`dummy_verify`). Thirteen concurrent checks exceed the 256 Mi limit; the API is on the same LoadBalancer IP as DNS (pass 05, `service.dns.alsoServe`), so reachable from the whole LAN, and from the internet wherever the UI is published for OIDC. |
| Impact | Memory pressure or an OOM kill of the resolver process from the sign-in form, the opposite of `02 §8`. On a Pi the same burst means swapping. The spec's lockout (ADR-029) limits guessing, not concurrency. |
| Recommendation | Bound the checks: at most four in flight (a Pi verifies one in ~0.3 s, so four is plenty for people), and answer 503 `unavailable` with `Retry-After: 1` beyond that, without counting the refusal as a failure. Patched. A follow-up could set `max_blocking_threads` lower than 512 for the whole runtime, but the DB and query-log work share that pool, so the targeted bound is safer. |
| Patch | `patches/06-01-bounded-password-checks.patch` (`auth/mod.rs`: `MAX_PASSWORD_CHECKS`, a counter and a drop guard, used by `login` and `by_basic`; test `api_003_password_checks_are_bounded` in `auth/tests.rs`). **Verified:** with the fix `cargo test -p telltale-api` (56, with the new test) passes and `cargo clippy -p telltale-api --all-targets -- -D warnings` is clean; the test can't run unpatched (it names the slot API). A first version used `AtomicU32::fetch_update`, which the current toolchain deprecates in favour of `try_update`; the patch uses `fetch_add`/`fetch_sub`, which builds on both. |
| Effort | S |
| References | API-003, ADR-029, `02 §8`, `spec/08` §6 |

### 06-02 A pre-save list check reads any reachable URL and shows agents what it found

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | security (server-side request on an agent's behalf; information disclosure) |
| Where | `crates/telltale-api/src/config_api.rs:801-819` (`check_list`: the result goes back as is); `crates/telltale/src/checks.rs:100-188` (downloads the URL with `[filter]`'s size and timeout, then returns up to 10 unparseable lines with 120 characters of their text, and the fetch error text); `crates/telltale-filter/src/fetch/http.rs:173-216` (`http` and `https` to any host, 5 redirects; no address policy); `auth/agent.rs:206-208` (an agent needs `config:write:lists`, the same scope that saves a list); `checks.rs:32-98` (`check_upstream` sends a DNS probe to any `udp/tcp/tls/https/quic` address and returns the rcode, record count, or error) |
| Evidence | **verified by reading** (the new test shows the shape with a fake backend). The list parser reports lines it can't use with their text; for a page that isn't a list, that's the page's first ten lines. The node reaches its pod network, the cluster's services, the LAN, and on a Pi whatever the Pi can see. Lists hosted on a LAN are a legitimate use (`http://192.168.1.5/hosts.txt`), so refusing private addresses outright would break real setups. |
| Impact | An agent token with `config:write:lists` (an operator-level grant, but one meant to be handed to software) can use the node to read the first lines of internal HTTP resources, and to tell open from closed ports by the error text; `check_upstream` gives the same reachability oracle for DNS ports. The check is audited (`check.list` with the URL), so it isn't silent. |
| Recommendation | Keep the text for people and give agents the counts and reasons (patched: `N line(s) couldn't be used (reasons); an operator can see them in the UI`). Then decide (question 6) whether agents' checks should be plans like their writes, and whether link-local and the cloud metadata range (`169.254.0.0/16`, `fd00::/8`'s metadata equivalents) should be refused by default for list URLs with an opt-in, which is the usual answer for a fetcher that takes URLs from an API. |
| Patch | `patches/06-02-list-check-samples-for-operators.patch` (`config_api.rs`; `tests.rs` gives the fake backend a `check_list` and adds `agt_009_list_check_samples_are_for_operators`). **Verified:** the test alone fails on v0.2.0 (the agent's answer contains the sample text); with the fix `cargo test -p telltale-api` (56) passes and clippy is clean. |
| Effort | S (patch); M for an address policy with configuration and docs |
| References | API-002 (T9.12), AGT-004, AGT-009, ADR-064 |

### 06-03 Configuration writes aren't serialized: two valid plans can leave `state.db` invalid, and then nothing made through the API applies

| Field | Content |
|---|---|
| Severity | **medium** (suspected) |
| Category | correctness (concurrency), availability of API-made configuration |
| Where | `crates/telltale/src/api_backend.rs:1890-1973` (`write_client`: the plan runs in one `spawn_blocking`, the store in a second, nothing held between them); `:3148-3237` (`do_write_managed`: the same, with the cascade's extra writes each in their own transaction, `:3204-3218`); `:2141-2225` and `:2545-2685` (plans validate the merged configuration against the snapshot they read); `crates/telltale-store/src/state/managed.rs:87-124` (the version is checked only when the caller sent `If-Match`); `config_api.rs:41-57` (`If-Match` is optional, `*` means none); `crates/telltale/src/managed.rs:343-369` (`effective()`: if the stored entries don't merge, the config files alone are used and the reason is logged) |
| Evidence | **suspected; not reproduced** (a race, so no deterministic test). Each write validates `files + stored entries + this change` and then stores this change alone. Two concurrent writes without `If-Match` (the UI sends it; `telltale ctl` and scripts may not; the MCP `apply_plan` does) are each valid against the same snapshot: say one removes a list and the other adds a group that uses it, or one hides an upstream the other's new group names. Both are stored, each bumping the version; the reload after the second finds the merge invalid and answers "saved but couldn't be applied"; from then on every start and reload logs `ignoring config made in the UI until this is fixed` and runs the files alone. The window is the few milliseconds between the plan's `spawn_blocking` and the store's, plus the reload, per write. |
| Impact | Devices, local names, quick rules, forwards, and every override made through the UI or API stop applying at once, silently for DNS (which keeps answering from the files, as designed) and loudly in the log. Recovery is a hand edit of `state.db` or deleting the offending entry through an API that now refuses, because every plan merges the same broken set. Rare in a home, likelier with two agents planning at once. |
| Recommendation | One configuration write at a time: a `tokio::sync::Mutex<()>` in `Sources`, held from the plan through the store and the reload. Writes are rare and a reload takes milliseconds, so the cost is nil; dry runs take it too for simplicity. Patched. The thorough fix is to re-validate inside the store's transaction (the store would need the merge), or to require `If-Match` on every write, which breaks scripts. |
| Patch | `patches/06-03-config-writes-one-at-a-time.patch` (`http.rs`: the lock in `Sources` and its test constructor; `server.rs`; `api_backend.rs`: taken at the top of `write_client` and `do_write_managed`). No new test (the race isn't deterministic). **Verified:** builds; `cargo test -p telltale --bin telltale api_` (29) passes; `cargo clippy -p telltale --all-targets -- -D warnings` is clean. |
| Effort | S (patch); M for validation inside the transaction |
| References | API-002, API-010, ADR-040, ADR-069, AGT-003 |

### 06-04 Changes made through MCP are audited from `0.0.0.0`, and each tool call pays the agent's rate limit several times

| Field | Content |
|---|---|
| Severity | **low** |
| Category | audit correctness (AGT-005 attribution), rate limit accounting |
| Where | `crates/telltale-api/src/mcp.rs:1317-1375` (`send`: a fresh in-process `Request` that copies five headers and has no peer address); `auth/routes.rs:63-87` (`remote()`: without `ConnectInfo` the peer is `0.0.0.0`, and `X-Forwarded-For` is read only from a trusted peer); `:129-168` (the inner request is authenticated again, with `touch_token` and the agent policy, `agent.rs:331`); `tests.rs:1337` (the test suite already notes that peerless requests read as `0.0.0.0`) |
| Evidence | **verified.** The new test `agt_005_mcp_changes_keep_the_client_address` fails on v0.2.0: a `flush_cache` tool call from `192.168.1.77` is audited as `cache.flush` with `remote: 0.0.0.0`. It works on the homelab only because `0.0.0.0/32` would have to be in `trusted_proxies` (it isn't; the chart sets the pod network), so every MCP-made rule, pause, flush, and plan apply in the audit log carries `0.0.0.0`, while the plan's own `requestedBy` carries the right name. For the rate limit, one `get_client_profile` is three to five bucket takes (the `/mcp` POST and each REST read), so an agent's 120/min is really 30–60 tool calls. |
| Impact | The audit log (API-006) answers "from where" wrong for every agent change made over MCP, which is the main way agents are expected to make them; lockouts aren't affected (tokens don't lock). The rate accounting is merely stricter than documented. |
| Recommendation | Carry the outer request's client address on the in-process requests (an extension `remote()` honours first), set once per `/mcp` request. Patched. For the rate limit, either document that each REST call behind a tool counts, or skip the bucket for in-process calls (the `/mcp` POST already took one); that's a one-line follow-up once the extension exists. |
| Patch | `patches/06-04-mcp-keeps-the-client-address.patch` (`auth/routes.rs`: `OnBehalfOf`; `mcp.rs`: set in `post`, attached in `send`; `lib.rs`; test in `tests.rs`). **Verified:** the test alone fails on v0.2.0 (`left: Some("0.0.0.0")`, `right: Some("192.168.1.77")`); with the fix `cargo test -p telltale-api` (56) passes and clippy is clean. |
| Effort | S |
| References | AGT-005, AGT-006, API-006, ADR-065 |

### 06-05 `X-Forwarded-Proto` is believed from any peer

| Field | Content |
|---|---|
| Severity | **low** |
| Category | security (transport assumptions) |
| Where | `crates/telltale-api/src/auth/routes.rs:102-107` (`is_https`: the header alone); `:135` (used for every request); `:311-318` (`Secure` on the session cookie follows it); `auth/mod.rs:830-835` (HTTP Basic is refused over plain HTTP unless the header says `https`); `crates/telltale-config/src/schema.rs:1768-1770` (documented as "a proxy that sends `X-Forwarded-Proto: https`", any proxy) |
| Evidence | **verified by reading.** `remote()` trusts `X-Forwarded-For` only from `trusted_proxies`; `is_https` has no such check. A client talking plain HTTP straight to port 8053 can add the header and send Basic credentials in the clear, which is what the gate exists to prevent (`spec/08` §6: "refused over plain HTTP"). The `Secure` flag matters less: a cookie set over plain HTTP wasn't protected anyway. |
| Impact | The Basic-over-HTTPS promise holds against mistakes, not against a script that sets one header; credentials in the clear on a LAN where the API port is reachable. Small, because the client has to opt in, but ADR-029's wording suggests the header was meant to come from the ingress. |
| Recommendation | Honour `X-Forwarded-Proto` only from a trusted peer, like `X-Forwarded-For`, and say so in `schema.rs` and `docs/`. People who terminate TLS on the same host (Caddy on `127.0.0.1`) would then need `trusted_proxies = ["127.0.0.1/32"]`, which is why this is a question (3) rather than a patch: it changes a documented setting. |
| Patch | none (a documented behaviour change) |
| Effort | S |
| References | API-003, ADR-029, `spec/08` §6 |

### 06-06 An admin can't revoke another user's token without disabling the user

| Field | Content |
|---|---|
| Severity | **low** |
| Category | operability (incident response) |
| Where | `crates/telltale-api/src/auth/routes.rs:1452-1484` (`DELETE /tokens/{id}` deletes only the caller's own); `:1486-1506` (`GET /users` shows no tokens); `:1543-1626` (`PATCH /users/{id}` with `disabled` ends sessions, not tokens, which `active_user` then refuses, `auth/mod.rs:741-747`, `:789`); `crates/telltale-store/src/state.rs:674-682` (`delete_token` is keyed by owner) |
| Evidence | **verified by reading.** A leaked agent token owned by an operator can be revoked only by that operator, or by an admin disabling or deleting the operator (which ends everything they have) or changing their password (which ends sessions, not tokens, `auth/routes.rs:1575-1580`). There is no listing of tokens across users, so an admin can't even see that a token exists. |
| Impact | Slower, blunter response to a leaked token; the audit log shows `token:<name> (owner: <user>)` so the owner is known, but the admin's only tool is the user. |
| Recommendation | `GET /api/v1/users/{id}/tokens` and `DELETE /api/v1/users/{id}/tokens/{tokenId}` for admins, audited as `token.revoke` with the owner; the UI's user page lists them. Agent-ready by the usual rules; no MCP tool (people-only). Not patched: it adds operations, so OpenAPI and docs move with it. |
| Patch | none |
| Effort | S–M |
| References | API-003, API-006, AGT-004, ADR-029 |

### 06-07 JSON-RPC batches are unbounded, and a truncated resource doesn't say so

| Field | Content |
|---|---|
| Severity | **low** |
| Category | resource bound (AGT-009), MCP correctness |
| Where | `crates/telltale-api/src/mcp.rs:1876-1885` (every message of a batch runs in turn, no cap); `:25-27` (the server announces `2025-06-18`, the revision that dropped batching, while still accepting batches for older clients); `:1761-1765` (`resources/read` caps the text at 32 KiB silently; tools add a "(truncated …)" note, `:1723-1725`); the request body is axum's default 2 MiB (no `DefaultBodyLimit` in `lib.rs`) |
| Evidence | **verified.** The new test shows 17 pings in one batch are answered on v0.2.0; a 2 MiB body fits tens of thousands of `tools/call` messages, each running its REST reads (a `vqlog` scan among them) one after another. For an agent token the rate limit catches it after 120 inner calls; for a user token (no bucket) it doesn't. One request can keep a worker busy for a long time; DNS isn't affected. |
| Impact | A slow API from one request, and an agent that reads a resource silently gets a document cut mid-JSON. |
| Recommendation | Cap a batch at 16 messages (patched, `-32600`), and append the same truncation note to resources (one line, not in the patch to keep it to the bound). |
| Patch | `patches/06-07-mcp-batches-are-bounded.patch` (`mcp.rs`: `MAX_BATCH`; test `agt_009_mcp_batches_are_bounded` in `tests.rs`). **Verified:** the test alone fails on v0.2.0 (17 messages are answered `200`); with the fix `cargo test -p telltale-api` (56) passes and clippy is clean. |
| Effort | S |
| References | AGT-006, AGT-009, ADR-065 |

### 06-08 HTTP Basic failures don't count against the address, and a success doesn't clear the count

| Field | Content |
|---|---|
| Severity | **low** |
| Category | security (lockout coverage), consistency with ADR-029 |
| Where | `crates/telltale-api/src/auth/mod.rs:852-873` (`by_basic`: the username key only; no `succeed` after a correct password); `:596-603`, `:634-635` (`login`: username and address, cleared on success); `:302-303` (`Presented.remote` is already there, for break-glass checks) |
| Evidence | **verified.** The new test `api_003_http_basic_lockout_counts_the_address` fails on v0.2.0: six wrong Basic attempts under different usernames from one address, then the right password for a real user from the same address, is accepted. On the sign-in form the same address is locked for 30 s. Without `succeed`, a user's own earlier typos keep counting for 15 minutes. |
| Impact | Spraying usernames over Basic isn't slowed per address (each username still is); the audit sees no `auth.lockout` for the address. Basic is off by default and per user, so the surface is users who opted in. |
| Recommendation | Mirror `login`: key by username and address, clear both on success. Patched. |
| Patch | `patches/06-08-basic-lockout-counts-the-address.patch` (`auth/mod.rs`; test in `auth/tests.rs`). Overlaps 06-01 in `by_basic` (both apply to v0.2.0 on their own; apply 06-01 first and resolve the two-line overlap). **Verified:** the test alone fails on v0.2.0 (the seventh attempt from the locked address is accepted); with the fix `cargo test -p telltale-api` (56, including the existing lockout tests) passes and clippy is clean. |
| Effort | S |
| References | API-003, ADR-029 |

### 06-09 Viewers see every pending plan

| Field | Content |
|---|---|
| Severity | **low** |
| Category | authorization (least privilege) |
| Where | `crates/telltale-api/src/lib.rs:491-492` (`plans::read_routes` under `require_viewer`); `plans.rs` (`list`: agents see their own plans, people see all) |
| Evidence | **verified by reading.** A plan carries the write's method, path, body, preview, reason, and who asked. A viewer, who can't change configuration, can read every proposed change and its reason; approving and rejecting are operator routes, so nothing can be done with it. |
| Impact | Mild: viewers already see the configuration itself; plans add intent and the requester's name. |
| Recommendation | Either list plans for operators only, or show viewers only their own (`owner_key` matches), which is what agents get. One condition in `plans::list`. |
| Patch | none |
| Effort | S |
| References | AGT-007, ADR-070 |

## Questions for the owner

1. **The setup token in the log** (`crates/telltale/src/auth_setup.rs:180-183`): it's printed
   at `warn` with the token, which on Kubernetes lands in whatever collects pod logs. It only
   works until the first admin exists, and `telltale auth setup-token` prints it from the
   file. Keep the log line, or print the file path and the command instead?
2. **Unauditable changes** (`auth/mod.rs:941-961`): when the audit append fails (disk full,
   a locked database), the change stands and the failure is logged. ADR-033 doesn't say;
   API-006 reads as "every change is audited". Refuse the change instead? And there's still
   no retention for the audit log (pass 04 noted it).
3. **`X-Forwarded-Proto` from trusted proxies only** (06-05): worth the documented change
   (people terminating TLS locally list `127.0.0.1/32`)?
4. **Admin token management** (06-06): add the two routes and the UI list?
5. **Agents' pre-save checks** (06-02): should `check_list` and `check_upstream` be plans for
   agents (they reach out from the node), and should list URLs to link-local and metadata
   ranges be refused by default with an opt-in?
6. **A second factor for promotion through the API** (05-09, carried): still wanted? It's a
   UX and spec decision (`spec/12` §5, ADR-051), not something to patch quietly.

## Not reviewed

- `telltale ctl` (`crates/telltale/src/ctl.rs`) beyond how it takes the token
  (`TELLTALE_TOKEN` or `--token-file`, never an argument); the Svelte UI's own code; the
  contents of `docs/api/openapi.json` beyond the security schemes (its drift test ran).
- The vqlog engine's semantics: its limits were checked (`MAX_LIMIT` 200, `MAX_QUERY_LEN`
  2000, at most 3 keys, 32 alternatives, 64 values in a list; the 100M-row refusal is in the
  backend), not the query planner or its cost model.
- OIDC against a live provider; the in-process flow tests (`oidc/flow_tests.rs`, 4 tests)
  ran. The importers (Pi-hole, Technitium, AdGuard Home) and backup/restore (`.ttbk`) were
  not read.
- `deploy/agent-e2e.sh` and `deploy/mcp-e2e.sh` were not run (CI runs them); the MCP tests
  here go through the same router in-process.
- No load test; 06-01 is reasoned, not measured.
- The cluster-facing API operations (promote, set-failover, set-authority) were covered in
  pass 05; the Helm chart and what the LoadBalancer exposes are pass 07's.
