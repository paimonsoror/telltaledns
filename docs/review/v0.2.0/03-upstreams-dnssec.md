# Pass 03: upstreams, recursion, DNSSEC (v0.2.0)

Reviewed at tag `v0.2.0` (commit 338db09) in `~/telltale-review`. `main` has not changed any
in-scope file since the tag (only the crate version bumps in `Cargo.toml`), so every patch
applies to `main` as is. Nothing here touched the Pi or the homelab; every experiment ran
against in-process fake servers.

## Summary

The forwarding side is careful where it matters: every transport validates the reply
against the query before anything else sees it, stray and spoofed datagrams are ignored
rather than fatal, pooled connections are retried once on a fresh one, hedging is bounded by
the member count and losers finish so health stays honest, and the recursor applies
bailiwick, in-zone glue, lame detection, and hard work limits. The DNSSEC path is the
weak spot, and it is one logic error, not a design problem.

Top three points:

1. **The unsigned-zone proof added in 0.2.0 (ADR-098) can be made to accept a spoofed
   answer inside a signed zone** (03-01, high, verified). A validated DS denial proves "no
   DS at this name", not "this name is a zone cut": every ordinary name in a signed zone
   has one. The code takes "has an SOA" from an unvalidated answer and "DS denied" from a
   validated one, so an attacker who can forge upstream answers (the DNSSEC threat model)
   forges an SOA too, and the bogus answer is served as insecure and remembered as an
   unsigned zone for 15 minutes. The offline signed-root harness reproduces it; the fix
   requires the denying NSEC/NSEC3 to show NS without SOA or DS, the same test hickory
   applies in its own insecure-delegation check. Patch, verified.
2. **The failure counter can't be read** (03-02, medium). Timeouts, connection errors,
   mismatched replies, unresolved hostnames, SERVFAIL, and REFUSED are one number. The
   patch counts them by kind (`telltale_upstream_failures_total{kind}`), which is what the
   Pi's 4–6 % against Quad9 needs. 03-04 is the likely explanation of part of that number:
   a SERVFAIL from a healthy upstream counts as a failure *with the timeout as its latency*
   and three in a row open the breaker, so a client looping on one broken domain moves
   every query off the primary for ten seconds and inflates its EWMA.
3. **The recursor's 0x20 is defeated by the first wrong-case reply** (03-03, medium,
   verified). A reply with the case changed makes it stop waiting, mark the server as
   "doesn't echo case" for good, and ask again plainly, so a spoofer who guessed ID and
   port wins on the retry. Off by default and only with `recursive://`; patch keeps
   waiting for the intact reply.

The rest: a validation can run for far longer than the client's budget while holding an
in-flight permit (03-05), and three low items (a string-matched transport error, a
bootstrap reply accepted without a parse check, a SOCKS relay reply matched by ID only).

Not reported, as the README asks: ADR-098's open item (Quad9 closing DoT connections at a
cold start), which the pool retry addresses; RFC 5011 (ADR-086); the v1.0 gate.

## Strengths

- **Every reply is checked against its query before it counts.** `matches_query` compares
  ID, QR, opcode, and the question (`crates/telltale-upstream/src/upstream.rs:249-269`),
  `summarize` parses the whole message, and the UDP loop ignores what doesn't match and
  keeps waiting rather than failing (`upstream.rs:907-926`), which is the right answer to
  a spoof flood. The recursor does the same with case-exact comparison when 0x20 is on
  (`crates/telltale-recursor/src/net.rs:59-84`, `:109-130`). DoH and DoQ use ID 0 and let
  the stream identify the reply (`upstream.rs:758-767`); DoQ, DoH, and DoH3 cap bodies at
  64 KiB (`doq.rs:18`, `:128`; `doh.rs:135`).
- **Encrypted transports don't fall back to plain.** The TC retry is UDP → TCP only
  (`upstream.rs:826-832`); DoT, DoH, DoQ, and DoH3 have no downgrade path. Certificates are
  verified against the compiled-in Mozilla roots, pins are checked on top of normal
  verification (`tls.rs:156-180`), and `tls_insecure_skip_verify` is the one explicit
  exception, warned at startup (`tls.rs:44-60`). DNSCrypt fetches its certificate in the
  clear by design and verifies it with the stamp's Ed25519 key using `verify_strict`,
  picking the newest construction and highest serial (`dnscrypt.rs:7-9`, `:255-270`).
- **Pooled connections survive the server closing them mid-query.** One task owns each
  stream, waiters are matched by ID, timed-out waiters are dropped so a stalled server
  can't pin the connection, and a reply that never comes is retried once on a fresh
  connection because queries are idempotent (`conn.rs:82-112`, `:163-235`;
  `tests/pool_retry.rs`). DoH and DoQ do the same one-retry on a broken connection
  (`doh.rs:80-92`, `doq.rs:100-120`).
- **Hedging is bounded and honest.** The attempt order puts admitted members first, hedges
  immediately only behind probes, exploratory picks, and members whose last attempt
  failed, and tries the least-recently-failed closed-breaker member as a last resort
  (`group.rs:92-136`). A query launches at most one attempt per member; a failure starts
  the next at once; losers are detached rather than aborted so their real outcome reaches
  the health tracker (`group.rs:236-241`). SERVFAIL/REFUSED is kept as a fallback while
  better members are tried (`group.rs:243`). The chaos test (one member blackholed, p99
  within 1.5× of baseline, zero client-visible failures for every strategy) is a real
  acceptance test (`tests/upstream.rs:345-394`).
- **Routing precedence is written down and tested.** Deepest suffix, then an explicit route of
  equal depth, then the client group's own upstream group, then `default` (ADR-096;
  `router.rs:1-4`; `tests/router.rs:144-224`, `:292-330`). The cache key carries the view, so
  two groups routed to different resolvers never share an answer (pass 01).
- **The recursor is defensive by construction.** QNAME minimization with a label cap,
  bailiwick on every record (`msg.rs:156-162`), glue accepted only for server names under
  the referring zone (`msg.rs:280-284`), referrals that must be strictly below the current
  zone and above the question (`msg.rs:266-273`), lame answers rejected rather than
  followed, and hard limits on queries, referrals, CNAME hops, depth, and tries
  (`lib.rs:77-84`, `:152-160`). The test tree covers poisoning, lame servers, root
  priming, hedging, and 0x20 (`tests/recursor.rs`).
- **The DNSSEC path asks upstreams with CD=1 and validates itself** (`dnssec.rs:122-128`), so
  an upstream's own verdict is never trusted. Negative trust anchors are checked before
  validation (`pipeline.rs:1892-1895`); RFC 8198 synthesis uses only ranges learned from
  secure answers signed by the zone's own key, refuses below delegations and DNAMEs, and
  proves the wildcard for NXDOMAIN (`nsec.rs:116-179`, `:191-234`); the depth-limit error
  is kept apart from bogus (`dnssec.rs:631-636`); and the EDE code says why a bogus answer
  failed (`dnssec.rs:383-416`). The offline signed-root test (`tests/dnssec_offline.rs`)
  is the right harness, and it made 03-01 cheap to prove.

## Measurements

| What | Result |
|---|---|
| `cargo test -p telltale-upstream -p telltale-recursor` (debug) at v0.2.0 | all pass (32 unit + 37 integration; `presets_online` ignored) |
| `dns_011_offline_forged_apex_inside_signed_zone_stays_bogus` on v0.2.0 (03-01) | fails: verdict `Insecure` for a forged, unsigned answer; passes with the patch |
| `dns_012_case_mismatch_does_not_drop_0x20` on v0.2.0 (03-03) | fails: the resolver returns the spoofed `6.6.6.6`; passes with the patch |

No load or latency measurements in this pass: the brief's performance questions (hedging
load) were answered by reading, and the README forbids load tests against the live hosts.

## Findings

### 03-01 The unsigned-zone proof accepts any secure DS denial, so a spoofed SOA turns a signed zone "insecure"

| Field | Content |
|---|---|
| Severity | **high** |
| Category | security (DNSSEC bypass) |
| Where | `crates/telltale-upstream/src/dnssec.rs:586-623` (`ds_signed`: a validated NODATA for DS with `Verdict::Secure` returns "unsigned" without looking at what the NSEC/NSEC3 says the name is), `:567-582` (`is_apex`: "has an SOA" from an unvalidated query), `:519-558` (`proven_insecure`: the walk continues past signed ancestors, so the first candidate whose forged SOA and genuine DS denial line up wins, and is cached for 15 min), `:504-511` and `:280-286` (`known_insecure`: later questions under it skip validation entirely), `:324-331` and `:300-315` (every bogus verdict, including hickory's "no RRSIGs" and "no NSEC" errors, goes through the proof) |
| Evidence | **verified.** The offline signed root gains an ordinary name `b.a.` (A record, NSEC with types A/RRSIG/NSEC, no NS). With the fake server forging `b.a. A` (unsigned, 192.0.2.66) and `b.a. SOA` (unsigned), v0.2.0 returns `Verdict::Insecure` (`tests/dnssec_offline.rs:529`), that is, it would fetch and serve the forged answer without AD; the second question hits the `known_insecure` cache. With the patch both questions are `Bogus` and `stats.insecure` stays 0. The existing tests (secure, NODATA, NXDOMAIN, forged signature, wrong anchor, RFC 8198, the genuinely unsigned `u.` zone through a CNAME) still pass. |
| Impact | In `mode = "validate"` an attacker who can inject upstream answers (a plain-UDP upstream on a hostile network, a compromised or malicious upstream, or the position DNSSEC exists to defend against) defeats validation for any name in any signed zone with one extra forged packet: the forged answer is served, and everything under that name is served unvalidated for 15 minutes. The SOA check adds nothing because it is unvalidated, and the DS denial is genuine. In `permissive` mode (the recommended one today) bogus answers are served anyway, so the practical exposure is the `validate` mode the owner is working toward. RFC 4035 §5.2 and hickory's own check (`hickory-net` `dnssec/mod.rs`, "Case 1": NSEC at the zone with NS, without DS and SOA) both require the delegation bits. |
| Recommendation | Accept a secure DS denial as proof of an unsigned delegation only when the NSEC that denies it is owned by the apex and has NS without SOA or DS, or the NSEC3 whose owner is the apex's hash has the same bits (opt-out stays as it is: hickory already returns it as `Proof::Insecure` after its own check). Keep the SOA query as a cheap pre-filter, but never as evidence. Add the forged-apex case to `dnssec_offline.rs` so the proof can't regress. ADR-098's "only the DS denial is trusted" paragraph should be amended to say what the denial must show. |
| Patch | `patches/03-01-dnssec-unsigned-proof-needs-a-cut.patch`: verified, `cargo test -p telltale-upstream --test dnssec_offline` (5 tests) and `--lib dns_011` (11 tests, including base32hex vectors and NSEC/NSEC3 cut checks) pass, clippy clean. It adds a 20-line base32hex encoder rather than a dependency (`data-encoding` is already in the tree through hickory if the implementer prefers it). |
| Effort | S |
| References | DNS-011, ADR-098, RFC 4035 §5.2, RFC 5155 §8.9, RFC 6840 §4.4 |

### 03-02 The failure counter lumps six different things together

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | observability |
| Where | `crates/telltale-upstream/src/upstream.rs:727-748` (`exchange` reduces the outcome to a bool before recording it; `ExchangeError` at `:124-133` already distinguishes timeout, I/O, bad response, unresolved), `crates/telltale-upstream/src/health.rs:113-162` (`record(ok, …)`), `crates/telltale/src/http.rs:905-928` (`outcome="failure"`), `docs/running.md:1582` |
| Evidence | **verified** by reading; the Pi's unexplained 4–6 % is the brief's own observation. |
| Impact | The one upstream signal an operator has can't say whether Quad9 is slow (timeouts), the DoT connections are being closed (I/O; the ADR-098 open item), the answers don't match (bad response), or the resolver is simply being told SERVFAIL for broken domains (which is not an upstream problem at all, see 03-04). Each of those has a different fix, and today they are indistinguishable without a packet capture. |
| Recommendation | Record an `Outcome` (ok, timeout, network, bad_response, unresolved, servfail, refused, other_rcode) instead of a bool, keep per-kind counters in `Health`, and export them as `telltale_upstream_failures_total{upstream,kind}` next to the existing family (which stays, so the dashboard's failure-rate panel keeps working). Expose the same breakdown in the API's upstream info when the OpenAPI is next regenerated (not in the patch). Then read the Pi: if `servfail` dominates, it is 03-04; if `network`, it is the ADR-098 connection issue; if `timeout`, it is the path. |
| Patch | `patches/03-02-upstream-failure-kinds.patch`: verified, `cargo test -p telltale-upstream --lib health::` (5 tests), `--test upstream failure_kinds` (ServFail and Blackhole fakes land in the right buckets), and `cargo test -p telltale obs_005_render` (the family is rendered) pass; clippy clean for `telltale-upstream` and `telltale`. Adds one row to the metrics table in `docs/running.md`. |
| Effort | S |
| References | UPS-006, OBS-011, `spec/04` §5 |

### 03-03 The recursor drops 0x20 for a server on the first reply with the case changed

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | security (spoofing resistance) |
| Where | `crates/telltale-recursor/src/net.rs:118-129` (`udp` returns `CaseMismatch` as soon as one such reply arrives, instead of waiting for the intact one), `crates/telltale-recursor/src/lib.rs:624-629` (`try_server` then marks the server `no_case` for the life of the process and asks again plainly), `crates/telltale-recursor/src/cache.rs:178-187` |
| Evidence | **verified.** New test `dns_012_case_mismatch_does_not_drop_0x20`: the `example.com` server sends a lowercase reply with `6.6.6.6` before its real one. On v0.2.0 the resolver returns `6.6.6.6` (`tests/recursor.rs:448`): the first reply triggered the plain retry, and the second spoof matched it exactly. With the patch the real `10.0.0.1` is returned and the server was asked once. |
| Impact | 0x20 exists to add about one bit of entropy per letter to the 32 bits of ID and port an off-path spoofer has to guess. Here a spoofer who guesses those 32 bits doesn't need the case at all: any wrong-case reply makes the resolver abandon the case check for that server permanently and re-ask plainly, and the same flood wins the retry. The feature is off by default and only matters for `recursive://` upstreams, which bounds the exposure, but when it is on it provides no protection. |
| Recommendation | Treat a wrong-case reply like any other stray: note it and keep waiting for one with the case intact. Only when the timeout expires with nothing but wrong-case replies seen, conclude that the server doesn't echo the case and retry plainly (which costs legitimate case-mangling servers one timeout, once, since the flag is cached). Consider a note in the config docs that 0x20 is worth turning on with the recursor. |
| Patch | `patches/03-03-recursor-0x20-waits-for-the-real-reply.patch`: verified, `cargo test -p telltale-recursor` passes (8 integration tests, including the existing case-mangling server test), clippy clean. |
| Effort | S |
| References | DNS-012, ADR-074, RFC 5452 §9.2, draft-vixie-dnsext-dns0x20 |

### 03-04 A SERVFAIL from a healthy upstream is recorded as a timeout-length failure and three open the breaker

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | correctness (health, routing) |
| Where | `crates/telltale-upstream/src/upstream.rs:734-746` (`ok` is false for SERVFAIL/REFUSED, and the latency recorded for any failure is `max(elapsed, timeout)`), `crates/telltale-upstream/src/health.rs:129-158` (every failure counts toward `consecutive_failures`; 3 open the breaker), `crates/telltale-upstream/src/group.rs:98` (a member whose last attempt failed is hedged immediately on every query), `spec/04-upstreams.md:66` ("A SERVFAIL/REFUSED from an upstream counts as a failure and triggers the next attempt") |
| Evidence | **verified** by reading. The spec sentence says a SERVFAIL should trigger the next *attempt*, which `Group::resolve` does; it doesn't say it should count as the upstream being *down*, which is what the breaker and the EWMA treat it as. |
| Impact | One client asking a DNSSEC-broken or lame domain three times in a row (browsers retry) opens the breaker on a healthy primary for 10 s, doubling to 5 min on repeats; every query goes to the other members meanwhile, and after it closes the primary is hedged on every query until a success. Under `fastest`, the primary's EWMA jumps to the attempt timeout (up to 1 s) per SERVFAIL, so it sorts behind slower members for a while. These are also "failures" in 03-02's old counter, and plausibly a share of the Pi's 4–6 %. |
| Recommendation | On top of 03-02's `Outcome`: count SERVFAIL/REFUSED in the rolling window (so a resolver that answers SERVFAIL to half of everything still opens) but not toward `consecutive_failures`, and record their real latency rather than the timeout. Keep "triggers the next attempt" as is. Add a test: three SERVFAILs in a row leave the breaker closed; three timeouts open it. |
| Patch | none (it changes `Health::record`'s contract, which 03-02 also touches; apply 03-02 first, then this is a ten-line change) |
| Effort | S |
| References | UPS-006, ADR-013, `spec/04` §5 |

### 03-05 A validation can run for 30 s past the client's 2 s budget, holding an in-flight permit

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | reliability (resource exhaustion) |
| Where | `crates/telltale-upstream/src/dnssec.rs:293-295` (the validating lookup gets `budget * 3`), `:534-556` (`proven_insecure` then walks up to 6 zone levels, each an SOA and a DS lookup with `budget` each, and the DS lookup is itself a validated chain), `:304`, `:317`, `:326` (the proof runs after a bogus verdict, after an error, and after the 3× timeout), `crates/telltale/src/pipeline.rs:1784-1798` (the in-flight permit is held by the spawned task for the whole resolution), `:1799-1807` (the client is answered after `budget + 100 ms` or the stale timeout) |
| Evidence | **suspected.** Derived from the code: worst case per name is 3 × 2 s + 6 × 2 × 2 s = 30 s with the default budget, and ADR-098 itself notes 1.5 s for the first question under a looping name. I did not build the slow-upstream harness to time it. |
| Impact | Each such task holds one of the in-flight permits (`spec/02` §8.4) for its lifetime. A client (or a crawler, or a misbehaving IoT device) asking a few hundred distinct names in a zone whose upstream is slow or whose chain is broken can hold every permit for tens of seconds, at which point every other miss is answered stale or SERVFAIL with EDE 23. DNS stops depending only on DNS; it depends on how long validation takes. The named cost ("a few DS and SOA queries the first time a zone is seen") is per zone, but the *failure* cost is per name, since names that can't be proven unsigned aren't cached. |
| Recommendation | Bound the whole validation (lookup plus proof) by one deadline derived from the budget, say 2× it, and pass the remaining time into `proven_insecure` instead of a fresh `budget` per query. Cap concurrent proofs with a small semaphore (8) so a burst can't take every permit; a proof that can't get a slot returns "not proven" (bogus stays bogus, which is the conservative outcome). Remember negative proof results briefly (a name that could not be proven unsigned in the last minute isn't re-walked). |
| Patch | none |
| Effort | M |
| References | DNS-011, ADR-098, NFR-004, `spec/02` §8.4 |

### 03-06 Transport errors are told from validation errors by a string prefix

| Field | Content |
|---|---|
| Severity | **low** |
| Category | maintainability |
| Where | `crates/telltale-upstream/src/dnssec.rs:638-641` (`is_transport` matches `e.to_string().starts_with("upstream:")`), `:133` (`GroupHandle::send` builds that string), `:300` (a transport error becomes `ResolveError::Empty`, anything else goes to the bogus path) |
| Evidence | **verified** by reading. |
| Impact | An upstream failure that hickory wraps or rewords (it wraps I/O errors from the handle in its own variants in places) would be judged bogus instead of "no answer", served as SERVFAIL with EDE 6, and counted against validation. The 15-minute `known_insecure` entry can't be created from this path (03-01 aside), so it is a wrong EDE and a wrong counter, not a wrong answer. |
| Recommendation | Carry a typed marker: wrap the group's error in a `NetError::Io` with a custom `io::Error` whose payload is a crate-local type, and downcast in `is_transport`; or keep a per-handle "last send failed" flag the way `last` already carries the upstream ID. |
| Patch | none |
| Effort | S |
| References | DNS-011, DNS-013 |

### 03-07 Bootstrap replies are accepted on an ID and question match without a parse check

| Field | Content |
|---|---|
| Severity | **low** |
| Category | robustness |
| Where | `crates/telltale-upstream/src/bootstrap.rs:120-137` (`udp_query` returns the first datagram that `matches_query`; the other UDP path at `upstream.rs:920` also requires `summarize`), `:94-112` (the records are then walked with `records()`, which is bounds-checked) |
| Evidence | **verified** by reading; the parser is safe on malformed input (pass 01), so this is about accepting a truncated or garbled reply as "no addresses" instead of waiting for the real one. |
| Impact | A spoofed or damaged reply that matches ID and question but doesn't parse ends the wait, and the bootstrap resolves to nothing (then `Unresolved`), until the next attempt. Low: it needs a matching ID and the window is one query. |
| Recommendation | Mirror `udp_exchange`: `matches_query(..) && summarize(..).is_ok()`. |
| Patch | none (one line) |
| Effort | S |
| References | UPS-009 |

### 03-08 The SOCKS5 UDP relay matches replies by message ID only

| Field | Content |
|---|---|
| Severity | **low** |
| Category | robustness |
| Where | `crates/telltale-upstream/src/proxy.rs:203-222` (`UdpRelay::exchange` accepts the first payload whose first two bytes equal the ID) |
| Evidence | **verified** by reading. The relay socket is connected to the proxy's relay address, so only the proxy can deliver to it; the question check at `upstream.rs:802` still runs on the result. |
| Impact | A proxy that mixes up or replays datagrams gets its reply rejected at the outer check (a `BadResponse` failure) rather than the relay waiting for the right one. No spoofing exposure beyond what the proxy itself can do. |
| Recommendation | Use `matches_query(payload, query, id)` in the relay loop, as the plain UDP path does, and extend `ups_010_socks5_udp_associate` to send real queries (its fake answers without the QR bit today). |
| Patch | none |
| Effort | S |
| References | UPS-010 |

## Questions for the owner

1. **ADR-098 wording (03-01).** The ADR says "only the DS denial is trusted: … a signed
   zone's DS can't be validly denied". That is true of the zone's apex and false of every
   other name in it. With the patch, should the ADR be amended in place or superseded by a
   short new one that states the rule (NSEC/NSEC3 at the cut with NS, without SOA and DS)?
2. **Breaker semantics (03-04).** Should SERVFAIL/REFUSED keep counting toward the error-rate
   window (an upstream that SERVFAILs half of everything is unhealthy) but not toward the
   three-in-a-row rule? That is what the patch-less recommendation assumes.
3. **Validation deadline (03-05).** Is "give up on the proof after 2× the query budget and
   serve the conservative verdict" acceptable, or should a slow proof be allowed to finish
   in the background and only its *result* be bounded?
4. **0x20 default (03-03).** With the fix in, is it worth turning `case_randomization` on
   by default for `recursive://`? The cost is one timeout per case-mangling server, once.
5. **API exposure of 03-02.** Should the per-kind failures appear in the upstream info
   endpoint and the Upstreams page (OpenAPI change), or is `/metrics` enough?

## Not reviewed

- The DoH3 and DoQ client internals beyond connection lifecycle and the body cap (quinn's
  own handling of stream limits was taken on trust).
- `presets.rs` and `presets/upstreams.toml` were read for the expansion logic only; the
  catalog's correctness (which provider supports what) was not checked.
- Plugin upstreams (`plugin.rs`): the supervisor was read (backoff, kill-on-drop, log
  forwarding); the socket protocol is the pooled stream path already covered.
- The TLS client-certificate path (`UpstreamTls`) and the certificate-file watcher: read
  for shape, not exercised.
- hickory's validator itself (`hickory-net` 0.26.3): read only where TelltaleDNS's logic
  depends on its return values (`find_ds_records`, `verify_nsec`, the `Nsec` error).
- The live `deploy/dnssec-e2e.sh` and the `dig` checks in the brief: they need a running
  server against real upstreams, which the README's rules rule out from this machine
  beyond what the offline harness proves.
