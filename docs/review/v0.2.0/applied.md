# Applying the v0.2.0 review: what was done (2026-10-07)

Branch `review/v0.2.0-fixes` in `~/dnsproject`, off `main` (0.3.0). One commit per finding, not pushed, not merged. This file is uncommitted, like the reports.

## Gate status (read this first)

- **Passed, per finding:** the tests the report named plus `cargo clippy -p <crates> --all-targets -- -D warnings` and `cargo fmt`, before each commit. The whole Playwright suite (35 tests, including the new rate-limit flow and the changed Lists/Upstreams pages) passed after the last UI change.
- **Final gate, run at 45f85a0 (the branch head) with one build job:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (574 passed, 0 failed, 5 ignored network tests), and `cargo deny check` (advisories, bans, licenses, sources ok) all pass. The first attempt was killed by Claude Code for low memory on the laptop (not a test failure) and was rerun. A second machine (a Linux Mint 22.3 VM on the NAS, Rust 1.99.0) gave the same result: 574 passed, 0 failed. One test there, `ops_007_drain_delay_keeps_answering_after_sigterm`, failed repeatedly in the VM's first ~20 minutes after boot (load average 8 to 36), also on `main`, and passed 3 of 3 once the VM was quiet: timing-sensitive under load, not caused by this branch.
- **`make bench-smoke` (AGENTS.md rule 4), same laptop, single unpinned runs, so about ±25 % noise:**

  | | cache-hot qps | cache-hot @50 % p50 / p99 | miss-heavy p50 / p99 |
  |---|---|---|---|
  | branch, 3 runs | 105k, 158k, 150k | 167–211 µs / 4.2–4.9 ms | 487–543 µs / 927–1215 µs |
  | `main`, 2 runs | 128k, 127k | 143 µs (and 879 µs) / 4.5–4.9 ms | 479 µs / 863–1055 µs |
  | review (v0.2.0) | 135k | 159 µs / 5.2 ms | 463 µs / 719 µs |

  No regression beyond noise: the branch's median is at or above `main`'s, and the miss-heavy tail on the branch is slightly higher but inside the same spread. A pinned, repeated run (for example on the VM) would be firmer if wanted.

## Findings

| Finding | Commit | Status |
|---|---|---|
| 03-01 DNSSEC unsigned-zone proof | 130676e (+775ff56 rustfmt) | done; ADR-098 corrected in place |
| 01-01 TCP/DoT stalled reader | 990c170 | done; `/metrics` line, render function split, docs |
| 01-02 QUIC connection cap | 97e722e | done, plus the follow-up (DoQ stream read bounded by the idle timeout) |
| 01-03 TCP query cap 4,096 | b75cd23 | done; DoQ and DoH POST not capped (see Deferred) |
| 01-04 pipeline allocation test | df156ff | done (`--3way`: `Cargo.lock` context) |
| 01-05 OPT outside additional | 34c7626 | done |
| 01-06 oversized cached answer | a79be87 | done (`--3way`; conflict with 01-05 in `tests/cache.rs`, both tests kept) |
| 01-07 IPv4 broadcast reply source | cce7a0b | done |
| 01-08 rate limiter lock | none | deferred: a measurement against a non-exempt client address, not done |
| 01-09 DoH body and write timeouts | none | deferred: needs a design on hyper (effort M) |
| 01-10 deferred UDP send blocks | none | deferred: only suspected; confirm with netem first |
| 01-11 fuzz hostile answers via the cache | fd8a7ad | done: new `cache_response` target; type-checks, **not run** (needs nightly) |
| 01-12 EDNS payload | b190c31 | done as `[dns] edns_payload` (ADR-100) |
| 02-01 non-list 200 | 8b89471 | done, threshold configurable |
| 02-02 regex set trim | 3650575 | done |
| 02-03 cold-start fallback, fsync | 427b928 | done, fsync is an option (default on) |
| 02-04 explain gaps | 5df6fe8 | done: schedules, zones, list `$dnsrewrite`, group rewrites, safe search, via shared functions |
| 02-05 disabled lists keep files | ea20036 | done; also skipped in manual refreshes |
| 02-06 safe-search allocation | afc6b9c | done; the allocation test failed before (2,000 allocations) and passes |
| 02-07 overlay | 0901251 | done: removed; ADR-003 amended |
| 02-08 regex cost | 64c79b9 | done as a cap with reporting (ADR-101) |
| 02-09 silent index fallback | 56d5bfd | done: warning plus `telltale_filter_lookup_mode` |
| 03-02 failure kinds | b5c0f2f | done (`--3way`), in `/metrics`, API, and Upstreams page |
| 03-03 0x20 | 0c61e5c | done; stays off by default |
| 03-04 SERVFAIL and the breaker | 636f5f1 | done; `spec/04` §5 states the rule |
| 03-05 validation deadline | 30e7962 | done (ADR-098 note) |
| 03-06 typed transport marker | 1844f6e | done |
| 03-07 bootstrap parse check | 4a8c45e | done |
| 03-08 SOCKS relay matching | e6c14ac | done |

Owner-answer work beyond the findings: per-address connection cap and `[[listen]]` limits (b6a5288, ADR-099); rate limit adjustable in the UI, API, and as an MCP tool (45f85a0).

## ADRs

Added, all `Proposed`: **ADR-099** per-listener and per-address connection limits; **ADR-100** `[dns] edns_payload`; **ADR-101** `max_regexes` and its measurements. Amended in place with dated notes (history kept): **ADR-098** (the correction for 03-01, and the deadline and limits for 03-05) and **ADR-003** (overlay removed). `spec/04` §5 gained the SERVFAIL/REFUSED rule.

## Where I disagreed with, or went beyond, the review

- **02-08 is worse than "low".** Reproduced with `matcher_bench`: 1,000 prefix-sharing regexes cost 1.1 µs per query and 33 MiB, 1,500 cost 1.6 µs and 41 MiB, **2,000 grew to 5.9 GiB in two minutes** (the review only saw it not finish). That is an out-of-memory risk on a Pi, so the cap defaults to 1,000. The cause inside the regex engine is not understood. `bench-smoke` still lacks the 1,000/2,000-pattern points.
- **03-05:** the lookup's allowance drops from 3 budgets to 1.5, so a rescue proof still fits inside the 2-budget total. That is my reading of "one deadline"; the alternative (lookup gets all 2) would kill the rescue of looping names.
- **03-04:** a failed half-open probe is unchanged (a SERVFAIL probe still reopens the breaker), FORMERR/NOTIMP still count as a down upstream, and SERVFAIL/REFUSED no longer set `last_failure`.
- **02-01:** the usable-list check also applies to file and inline lists, not only downloads.
- **02-04:** DNS64 reverse names (`ip6.arpa` inside the NAT64 prefix) are still not explained; it was not in the report.
- **02-07:** `telltale explain --json` loses the always-false `manual` field.
- **Order effects:** 01-04, 01-06, and 03-02 needed `--3way`, only because earlier commits on this branch moved the context (`Cargo.lock`, `tests/cache.rs`, `http.rs`).
- **Defaults to check in your environment:** the per-address cap of 32 will starve clients behind a balancer that hides client addresses (no PROXY protocol, SNAT); documented next to the key and in ADR-099.

## Deferred

01-08 (measure the limiter's lock against a non-exempt client), 01-09 (DoH write timeouts), 01-10 (`MSG_DONTWAIT` for deferred sends; confirm first), the DoQ/DoH POST 4,096 bound from 01-03, the 1,000/2,000-regex points for `bench-smoke`, and the 90 % shrink guard for lists (you chose a configurable threshold instead).

## Bench numbers

See Gate status. The criterion `cache_hit` bench (154 ns single thread in the review) was not rerun.


---

# Passes 04–06: what was done (2026-10-08)

Branch `review/v0.2.0-fixes-2` in `~/dnsproject`, off `main` at 7aa39c3. One commit per finding (27 commits), not pushed, not merged. This section is uncommitted, like the reports. No owner answers were given for these passes, so every open question below was left as it is, with the conservative reading recorded as `Proposed` (AGENTS.md rule 3).

## Gate status (read this first)

- **Per finding:** the tests the report named, plus `cargo clippy -p <crates> --all-targets -- -D warnings` and `cargo fmt`, before each commit. OpenAPI and `ui/src/lib/api-types.ts` regenerated for 06-01, 04-07, and 06-09; `svelte-check`, the UI build, and the help check pass.
- **Final gate at a015deb (laptop, two build jobs):** `cargo fmt --all --check`, `python3 site/build.py` (no tree changes), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (**597 passed, 0 failed**, 5 ignored network tests), and `cargo deny check` (advisories, bans, licenses, sources ok) all pass.
- **Simulator:** 2,000 schedules (debug) pass with the 05-05 change; the mutant that forgets a restarted voter's lease fails within them ("two writers"). The 10,000-schedule release run is left to CI: the build VM's repository copy is behind `main` (it lacks 7aa39c3), so it wasn't used.
- **Not run:** the Playwright suite (no e2e test covers promotion; the Cluster page change is type-checked only) and the `deploy/cluster/*.sh` e2e scripts (CI runs them).

## Findings

| Finding | Commit | Status |
|---|---|---|
| 04-01 event clock and clock steps (high) | f238921 | done as patched; `telltale_clock_steps_total` and `telltale_clock_last_step_seconds` |
| 04-02 duplicate ring series | 7bc7f2e | done as patched |
| 04-03 `blocked_total{list}` keyed by decider | 8363dcf | done (`--3way`, docs context) |
| 04-04 privacy levels and analytics | f7d0365 | **partial**: `rollups.db` top lists now follow the level (they were stored in plain text for 400 days at every level, which the review didn't mention); docs say what each level covers. Live analytics and anomaly baselines unchanged: owner question 04 q1, ADR-102 |
| 04-05 unsalted level-1 hash | f7d0365 | **docs only**: the docs say what level 1 does and doesn't protect against. The key is owner question 04 q2 |
| 04-06 part-number scan | 707a0b5 | done: the next part starts after the one just closed. Rotation policy for short bursts not changed |
| 04-07 `upstream` filter never matches | 7796400 | **docs only**: OpenAPI and docs say it matches nothing yet. Recording the upstream is owner question 04 q3 (ADR-026) |
| 04-08 dnstap timeouts | d065065 | done, plus a logged, backed-off reconnect after a failed write and `telltale_dnstap_dropped_total` (04 q4), which now also counts copies dropped while disconnected |
| 04-09 sink formatting on the aggregator | eaf0841 | partial: the per-event schedule-name clone is gone. Moving formatting off the thread waits for a measurement, as the review says |
| 04-10 one-off alerts re-sent | ad3a3cd | done: oldest subjects forgotten first, with a test |
| 04-11 hour extras lost on restart | 8c5398e | done: backfilled after the startup replay (new "replay done" flag). No new test: it needs the writer task, a database, and a replay |
| 05-01 joiner decides eligibility (high) | 5932b84 | done as patched. Eligibility in the join token is owner question 05 q1 |
| 05-02 any member fences the primary (high) | 8711ae5 | done (`--3way`, test file); the test also checks a Hello claiming eligibility can't make a pod a voter first |
| 05-03 ephemeral members write | ed949aa | done; docs say what resolver pods can't do. Checked: the homelab's API and cluster ports reach only the controller |
| 05-04 no takeover from an emergency primary | e5aa507 | done by hand, plus the Cluster page (it disabled Promote whenever a primary was up). Automatic takeover is owner question 05 q2 |
| 05-05 leases on the wall clock | 43cc6a1 | done: `CLOCK_BOOTTIME` election clock, ballots record their clock and are adopted conservatively, simulator restarts on unrelated clocks, mutation-checked. ADR-056 amended. New dependency, see below |
| 05-06 bootstrap secret HMAC oracle | 722a3d0 | done as a warning under 32 characters, not a refusal (see disagreements) |
| 05-07 join tokens can't be revoked | c762e14 | done: `telltale cluster token list` and `revoke <id or token>` |
| 05-08 shallow history called a rewind | c56cd4d | done: the message says "more than N commits since" when the fetch was cut at its depth |
| 05-09 promotion without a second factor | none | deferred: owner question 05 q4 / 06 q6 (needs a UI flow) |
| 05-10 ADR-066 wording | a015deb | done: ADR corrected with a dated note; docs say rotation helps only against an unused leak |
| 05-11 shipped `.part` leftovers | 22ee28c | done: swept hourly, older than a day, every sender. Per-sender retention rate limit not changed |
| 06-01 unbounded password checks | 7f79a5b | done as patched; 503 documented in OpenAPI and docs |
| 06-02 list check echoes fetched lines | 9e3ab73 | done as patched. Agent checks as plans and an address policy are owner question 06 q5 |
| 06-03 config writes not serialized | eda78ca | done as patched; checked that the rate-limit write (new on `main`) goes through the locked path and nothing nests |
| 06-04 MCP audited from 0.0.0.0 | cf9167a | done (`--3way`), plus the follow-up: in-process calls don't take from the bucket, so the rate counts tool calls (test added) |
| 06-05 `X-Forwarded-Proto` from any peer | none | deferred: owner question 06 q3 (a documented behaviour change) |
| 06-06 admin can't revoke others' tokens | none | deferred: owner question 06 q4 (new API operations and UI) |
| 06-07 unbounded batches | f14654f | done (`--3way`), plus a truncation note on resources and per-message rate charging for batches (needed once 06-04 made a tool call cost one request) |
| 06-08 Basic lockout ignores the address | faca787 | done (`--3way`; the overlap with 06-01 merged cleanly) |
| 06-09 viewers see every plan | 4b079b4 | done: viewers see their own, operators and admins all |

## ADRs

Added: **ADR-102** (Proposed): privacy levels cover what is kept and sent out; the live analytics wait for a decision. Amended in place with dated notes (history kept, each marked Proposed): ADR-026, 029, 031, 048, 051, 054, 056 (the clock change), 058, 064, 065. ADR-066 corrected (05-10).

## Where I disagreed with, or went beyond, the review

- **04-04 is wider than reported.** Besides the in-memory analytics, `rollups.db` kept each hour's top domains, blocked names, and clients in plain text for 400 days at every level. That is stored data, which every reading of the spec says the level governs, so it is fixed regardless of the owner's answer to q1.
- **05-05 uses `CLOCK_BOOTTIME`, not plain `Instant`.** `Instant` is `CLOCK_MONOTONIC`, which stops during suspend: a suspended primary would resume believing its lease still runs. `CLOCK_BOOTTIME` neither steps nor stops. Reading it without `unsafe` outside `telltale-net` needs `rustix` (`time` feature, Linux only). It was already in `Cargo.lock` but only as a test dependency, so this is a new runtime dependency for the binary; with LTO only the clock call is linked.
- **05-05 restart rule.** A voter that restarts takes any lease it granted as running a full 15 s from the restart. That costs at most 15 s of failover after a voter restart, and is what the review proposed.
- **05-06 warns instead of refusing.** The homelab's join Secret was created outside Git and I didn't read its length (the live cluster is off limits). Refusing a short secret could stop the resolver pods from joining on the next rollout; a warning can't.
- **06-04 and 06-07 together.** Skipping the bucket for a tool's REST calls would have let a 16-message batch run 16 tool calls for one request, so batches now charge one per message for agent tokens.
- **06-02** keeps the fetch error text for agents (connection refused vs timeout still tells open from closed ports). That's part of owner question 06 q5.

## Open owner questions (nothing was changed for these)

1. 04 q1: should privacy levels 1 and 2 govern the live analytics too (removing per-device analytics, the masked-IP detector, and device anomaly alerts at level 2)?
2. 04 q2: a per-installation or per-cluster key for level 1's hash, or store nothing for names at level 1?
3. 04 q3: record the answering upstream on query events, or keep the filter documented as unused?
4. 05 q1: should a join token say whether it may bring an eligible node (`token create --eligible`)?
5. 05 q2: automatic takeover from an emergency primary when the Git-managed node is back?
6. 05 q4 / 06 q6: a password or TOTP confirmation for promotion through the API (`spec/12` §5 asks for it)?
7. 06 q1: keep printing the setup token in the log, or print the file path and command?
8. 06 q2: refuse a change whose audit entry can't be written? And audit-log retention.
9. 06 q3: honour `X-Forwarded-Proto` only from `trusted_proxies` (local TLS terminators would need `127.0.0.1/32`)?
10. 06 q4: admin routes and UI to list and revoke other users' tokens?
11. 06 q5: should agents' pre-save checks be plans, and should list URLs to link-local and metadata ranges be refused by default?

## Live deployment notes

Nothing was rolled out. Before rolling: 05-01 and 05-02 don't change existing registry records (the Pi joined with a token as an eligible node and stays one); 05-03 refuses writes only from ephemeral members, and the homelab's API and cluster ports reach only the controller; 05-05 makes each voter's first 15 s after the upgrade a full lease, which matters only under automatic failover (it needs three voters; the live cluster has two).

## Bench numbers

`make bench-smoke`, same laptop, single unpinned runs (about ±25 % noise). `main` (7aa39c3) and the branch were built with the `bench-fast` profile and alternated in one session:

| | cache-hot qps | cache-hot @50 % p50 / p99 | miss-heavy p50 / p99 |
|---|---|---|---|
| branch, 5 runs | 178k–194k | 113–159 µs (one 1.7 ms outlier) / 1.6–3.7 ms | 447–495 µs / 751–1279 µs |
| `main`, 2 runs | 173k, 209k | 107–121 µs / 1.3–4.2 ms | 471–479 µs / 847–1247 µs |
| pass 01–03 record (yesterday) | 105k–158k | 143–211 µs / 4.2–4.9 ms | 463–543 µs / 719–1215 µs |

No regression beyond noise. The query path changed only by 04-01 (one relaxed atomic load in place of a plain one).


## Owner's decisions on the open questions (2026-10-08, same branch)

The owner accepted the recommendations for all eleven questions. One commit each, gated like the rest (tests named per crate, clippy `-D warnings`, fmt; OpenAPI, UI types, and the config schema regenerated where they changed; `svelte-check` for UI changes). `deploy/cluster/e2e.sh` and `failover-e2e.sh` pass locally with the new token flags.

| Question | Commit | What was done |
|---|---|---|
| 06 q1 setup token in the log | dd61a8f | the log names the file, not the token; cluster members other than the primary make no setup token |
| 05 q1 eligibility in join tokens | 7d64643 | `token create --eligible` / `--witness`; a plain token brings a plain member; e2e scripts updated |
| 05-09 / 06 q6 promotion confirmation | b655393 | sessions send `password` (+ `totp`); wrong ones count toward the lockout and answer 403; tokens unchanged; Cluster page asks for them. Agents with `cluster:admin` keep `spec/13`'s behaviour (my recommendation wrongly assumed agents were already refused) |
| 06-05 `X-Forwarded-Proto` | 0b75613 | believed only from `trusted_proxies` or loopback; MCP's in-process calls carry it only when the outer request qualified |
| 04 q1 privacy levels everywhere | 3186d97 | the aggregator applies the level before the analytics; anomaly engine (and new-device alerts) off at 1+, masked-client detector off at 2+; ADR-102 rewritten |
| 04 q3 upstream attribution | 95f8957 | the answering upstream travels through validation and singleflight to the query event |
| 06-06 admin token revocation | 173742f | `GET /users/{id}/tokens`, `DELETE /users/{id}/tokens/{tokenId}`, Settings → Users → Tokens |
| 05 q2 automatic takeover | 00b3ba8 | a Git-managed, eligible replica takes over from an emergency primary after the conditions hold for 60 s; never from a primary that's simply gone |
| 06 q2 unauditable changes, retention | 1dca44d | after a failed audit write, the next change records `audit.gap` first or is refused (503); `[auth] audit_retention_days` (365) with a checkpoint so the chain still verifies (state.db migration 7) |
| 04 q2 keyed level-1 hash | e396ea6 | `blake3::keyed_hash` with a per-node key; the primary publishes it (`privacy_key` in the manifest) and every node adopts it |
| 06 q5 agents' checks | f830ca1 | link-local and cloud-metadata addresses refused for every fetch (opt-in `[filter] allow_link_local_urls` for lists); agents get "unreachable" for failed checks; checks stay reads, not plans |

Also done on the owner's go, outside this branch: DNSSEC set to `off` in homelab-charts (0f8f1e9, pushed). On the Pi, uncached lookups went from a ~128 ms mean with ~9 upstream exchanges each to 26.5 ms and ~1.2 exchanges; validation stays off until the validator caches the key chain.

Not done here, queued by the owner for after this reaches edge: the dashboard's per-node view, and group chips on the top-clients table.
