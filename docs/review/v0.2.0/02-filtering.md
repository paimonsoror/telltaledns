# Pass 02: filtering and policy (v0.2.0)

Reviewed at tag `v0.2.0` (commit 338db09) in `~/telltale-review`. `main` has not changed any
in-scope file since the tag (only the crate version bumps in `Cargo.toml`), so every patch
applies to `main` as is.

## Summary

The filtering core is sound. Parsing, compiling, and matching are built the way `spec/05`
describes: lists parse in parallel into a bounded-memory external sort, the merge interns
list sets and writes sharded FSTs that are published by one directory rename, the matcher
reads them through a hash index with a random seed and a worked-out false-positive bound,
and precedence is a table with tests that make the index and the FST walk agree. Policy
decisions (identification, quick rules, schedules, local data) run before the cache and
never allocate. I found no way for a list or a client to change what another group sees.

Top three points:

1. **A list source that starts serving something other than a list replaces the good copy
   with nothing** (02-01, medium, verified). The fetcher refuses HTML pages by their first
   bytes and bodies over the size cap, but a JSON error page, a compressed body (the
   server ignoring `Accept-Encoding: identity`), or any other 200 with garbage parses to
   zero rules and wins. Every name that list blocked is unblocked until the source
   recovers. Patch: parse the body before accepting it, and refuse `Content-Encoding`.
2. **Two ways to lose the filter at a compile or a restart** (02-02 and 02-03, medium,
   both verified). A set of regexes that each build but don't build together makes the
   whole compile fail, forever, for every list (02-02). A snapshot that was published but
   can't be opened (a truncated shard after a power cut; the FSTs are never fsynced) makes
   a cold start serve without a filter instead of falling back to the previous snapshot
   (02-03). Patches for both.
3. **Explain disagrees with the pipeline for schedules and zones** (02-04, medium,
   verified). A `block_all` schedule that is in force and an authoritative local zone are
   invisible to `telltale explain` and the API's "Why?", which then say "resolved normally".
   Patch. Three smaller explain gaps remain (list `$dnsrewrite`, group rewrites, safe
   search) and are listed under the finding for the implementer.

The rest is low: disabled lists lose their downloaded files (02-05, patch), a per-query
allocation for safe-search groups, the regex cost curve, a silent index fallback, and an
overlay path that production never uses.

Nothing in this pass restates the known v1.0-gate items (the Pi recompile time, T10.3, is
measured there; this pass looked at memory, not time).

## Strengths

- **Parsing is a classifier, not a guesser** (ADR-017). One ordered decision per line
  (`crates/telltale-filter/src/parse/mod.rs:9-30`), with cosmetic and unsupported rules
  counted rather than rejected, invalid lines kept per kind with samples
  (`parse/mod.rs:102-130`), name validation that rejects what the wire format can't carry
  (`parse/name.rs`), and `$badfilter` applied at compile time so a list can retract its own
  rule (`compile/mod.rs:5`). The golden tests in `tests/golden.rs` pin the output for the
  fixtures in `tests/fixtures`.
- **Compiling is bounded and atomic.** Records go into an arena with a memory budget and spill
  to sorted runs when it is exceeded (`compile/sort.rs:34-60`, `compile/mod.rs:66`); the merge
  interns list sets so a snapshot holds one bitset per distinct combination
  (`compile/listset.rs:47-60`); shards are written to a `.partial` directory and published by
  a single rename (`compile/mod.rs:418-432`); the reader verifies every blob against the
  BLAKE3 in the manifest before mapping it (`snapshot.rs:259-275`); and the FST pages are
  released once the hash index answers, so a 2 M-name snapshot costs its index, not its
  files, at steady state (`snapshot.rs:325`, `crates/telltale/src/lists.rs:415-434`).
- **The matcher's index is argued, not assumed.** A random per-index seed, a 47-bit
  fingerprint per entry, and a written false-positive bound (`matcher.rs:555-569`); a
  precedence table (`matcher.rs:942`) with tests that run the same questions through the
  index and the FST walk and demand identical answers; and `tests/matcher_alloc.rs`
  proving the decision path allocates nothing. Explain shares the matcher's code: the
  `Sink` trait (`matcher.rs:182-226`) lets `decide` and `explain` walk the same tables, so
  "why" and "what" can't drift for list rules.
- **Identification is a fixed chain with the right trust boundary.** Client ID (DoT SNI, DoH
  path) → EDNS MAC, accepted only from `trust_edns_mac_from` networks → neighbor-table MAC
  → exact IP → most specific CIDR (`crates/telltale-policy/src/clients.rs:4`, `:538-575`).
  Groups are resolved by priority and the primary group is one lookup
  (`clients.rs:599-626`). Quick rules are a seeded hash table with a byte comparison on hit
  and no allocation (`quick.rs:9`, `:191`).
- **Fetching is defensive.** Conditional GETs, a bounded number of redirects that never go
  from https to http (`fetch/http.rs:173-199`), `Accept-Encoding: identity` to keep the
  size cap meaningful (`http.rs:231-232`), a byte cap enforced while reading, bounded
  concurrency, backoff, and a settle window so one dead source doesn't delay the others
  (`fetch/mod.rs:196-225`). Lists are rejected when they're HTML (`fetch/mod.rs:520-533`),
  and a failed fetch keeps the last good copy (the gap is in what counts as "failed":
  02-01).
- **Policy stays ahead of the cache.** Quick rules, schedules, local data, rewrites, and the
  filter all run before the lookup (pass 01 checked the ordering at
  `crates/telltale/src/pipeline.rs:1538-1627`); the explain path has its own tests that
  compare it with the pipeline's decision (`crates/telltale/src/explain/tests.rs`,
  `flt_013_explain_agrees_with_the_pipeline`).

## Measurements

All on the review laptop (WSL2, Ryzen 5 5500U, shared cores), so single-run numbers are
hints, not gates. How each was taken is in the finding or the command.

| What | Result |
|---|---|
| `cargo test -p telltale-filter -p telltale-policy` (debug) | all pass (37 + policy) |
| `matcher_bench` (bench-fast), 200k synthetic names, 0 regexes | p50 181 ns, p90 239 ns, p99 337 ns, p99.9 1.1 µs |
| same, 1,000 regexes (`^ads[0-9]+\.`-style anchored patterns) | p50 1.19 µs, p90 1.41 µs, p99 1.98 µs, p99.9 35 µs; load + index + regex build 71 ms |
| same, 2,000 regexes | the bench did not finish in 19 min and reached 5.0 GiB RSS before I stopped it (02-08) |
| regex set probe (02-02) | 8 distinct `(?:[a-z]{200}){200}`-style patterns: each builds alone, the set of 8 fails; `(?:[a-z]{500}){500}` fails alone |

## Findings

### 02-01 A 200 response that isn't a list replaces the good copy

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | reliability |
| Where | `crates/telltale-filter/src/fetch/mod.rs:472-476` (`accept_body` runs `sanity_check` only), `:520-533` (`sanity_check`: empty, or HTML by its first 15 bytes), `crates/telltale-filter/src/fetch/http.rs:278-292` (status checked, `Content-Encoding` ignored) |
| Evidence | **verified.** New test `flt_004_non_list_bodies_keep_the_last_good_copy` on v0.2.0: a list fetched once from `/good` (3 rules), then from the same path serving `{"error":"rate limited"}`, a `<head>`-only page, and a gzip body with `Content-Encoding: gzip`. On v0.2.0 the JSON body is accepted as a new version with 0 rules (`tests/fetch.rs:762`). With the patch all three are errors, the stored copy stays at 3 rules, and the list is retried with backoff. |
| Impact | A CDN error page, a captive portal, a list host that starts compressing, or a mirror that moves to a JSON API empties a list at the next refresh. Every name that list blocked is resolved until the source recovers, and the only sign is a line in the log and a drop in `telltale_list_entries`. For the largest lists this is most of the filter. |
| Recommendation | Treat "parses to no rules" as a failed fetch: parse the body once in `accept_body` and reject it when it has no rules but invalid lines, or more invalid lines than rules (a JSON blob, a compressed body, an HTML page without the doctype prefix all fail this). Refuse any `Content-Encoding` other than `identity` in the client, since the body would be a binary blob the parser can't read and the size cap would be measuring compressed bytes. Keep the existing size cap and HTML check. |
| Patch | `patches/02-01-fetch-non-list-bodies.patch`: verified, `cargo test -p telltale-filter --test fetch` passes (15 tests), clippy clean. The parse adds one pass over the body per successful download (not on the query path). |
| Effort | S |
| References | FLT-004, `spec/05` §6 |

### 02-02 A regex set that only fails as a whole stops every compile

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | reliability |
| Where | `crates/telltale-filter/src/compile/mod.rs:814-836` (`check_regexes`: if `build_many` fails, each pattern is rebuilt alone and only the ones that fail alone are dropped), `:811` (`regex_builder` sets the engine's size limits) |
| Evidence | **verified.** Probe (`tests/rv02_regex_probe.rs`, not kept): 8 distinct `(?:[a-z]{200}){200}` patterns each build alone and the set of 8 fails. New test `flt_003_regex_set_that_only_fails_as_a_whole_is_trimmed`: 16 such patterns plus `^ads[0-9]+\.` fail to compile on v0.2.0 (`compile/tests.rs:283`); with the patch the compile succeeds, the small pattern is kept, and the dropped ones are reported with "too large together with the other regexes". |
| Impact | `regex-automata` builds one combined automaton for the set, so its size limit is a property of the set, not of any member. One list with a handful of large patterns (or two lists whose patterns are fine apart) makes `build_many` fail, `check_regexes` keeps every pattern, and the compile fails. The compile loop retries the same inputs and fails the same way, so the filter never updates again until someone edits a list. The log names no pattern. |
| Recommendation | When `build_many` fails and every pattern builds alone, drop patterns by cost until the set builds: build each alone, take its `memory_usage()`, remove the largest, retry, and report the removed ones. Bound the loop by the number of patterns. |
| Patch | `patches/02-02-regex-set-compile-check.patch`: verified, `cargo test -p telltale-filter --lib compile::` passes (9 tests, 26 s because the test builds large automata), clippy clean. |
| Effort | S |
| References | FLT-003, `spec/05` §3.3 |

### 02-03 An unopenable newest snapshot leaves a cold start without a filter; shards are never fsynced

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | reliability |
| Where | `crates/telltale/src/lists.rs:375-383` (`Publisher::load`: an open error logs and returns, the current filter stays, which at startup is none), `:591` (`check` opens the newest only), `crates/telltale-filter/src/compile/shard.rs:57`, `:138` (FST files created and finished, never `sync_all`), `crates/telltale-filter/src/compile/mod.rs:418-432` (rename without syncing the files or the directory) |
| Evidence | **verified.** New test `flt_004_cold_start_falls_back_to_the_previous_snapshot`: compile v1 and v2, truncate v2's `subtree-0.fst`, publish v2 as generation 1. On v0.2.0 no filter is active (`lists.rs:756`, `left: None`). With the patch v2 is renamed `2.broken`, v1 is loaded, and the active version is 1. |
| Impact | A power cut or an OOM kill between the rename and the data reaching disk leaves a snapshot directory whose manifest is complete and whose shards are short or zero-filled (ext4 and most filesystems order the rename before the data unless the files are fsynced). The next start finds it, fails the BLAKE3 check, logs "keeping the current filter" (there is none), and serves unfiltered. The previous snapshot is still on disk next to it and is never tried. The Pi is the install most likely to lose power. |
| Recommendation | Sync each shard, the modifier FST, and the list-set table before the rename, and the parent directory after it. At generation 1 (startup), when the newest snapshot can't be opened or activated, rename it `<version>.broken` and try the next newest; remove `.broken` directories after the next successful compile. |
| Patch | `patches/02-03-snapshot-cold-start-fallback.patch`: verified, `cargo test -p telltale-filter --lib compile::` (8 tests) and `cargo test -p telltale lists::` (2 tests) pass, clippy clean for both crates. The fsyncs add a few hundred ms to a large compile on SD cards and nothing to the query path. |
| Effort | S |
| References | FLT-003, FLT-004, NFR-004, ADR-023 |

### 02-04 Explain misses `block_all` schedules and local zones

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | correctness |
| Where | `crates/telltale/src/explain.rs:128-260` (`explain` walks quick rules, lists, pause, routes; no schedules), `:309-340` (`answered_early` checks local records but not zones), `crates/telltale/src/pipeline.rs:1484` (the pipeline applies `schedules.load()` in `decide_for`) and `:546` (`Pipeline::explain` doesn't pass it) |
| Evidence | **verified.** New tests `flt_013_schedules_are_explained` (a group with a daily 00:00–23:59 `block_all` schedule) and `flt_013_zones_are_explained` (a local zone `corp.example` for one group): on v0.2.0 both report "no rule applies; resolved normally" (`explain/tests.rs:433`, `left: Resolved`); with the patch the first is `Blocked` with the schedule named and the second is `Local`. |
| Impact | The one tool that is supposed to say why a name was blocked gives the wrong answer for two features the UI offers (schedules, zones). A parent checking "why is this blocked for the kids right now" is told it isn't. The API's "Why?" and `telltale explain` share this code. |
| Recommendation | Give `explain::State` the schedule snapshot and the zones; report a `block_all` schedule in force as `Blocked` with the schedule's name, and a question inside a zone the group serves as `Local`. Not in the patch, for the implementer: list `$dnsrewrite` answers (`pipeline.rs:673`), group rewrites (`:1078`), and safe search (`:703`) are also invisible to explain. The pipeline's own code for them is in `Pipeline`, so the clean fix is the one the quick rules already use: a function that both paths call. |
| Patch | `patches/02-04-explain-schedules-zones.patch`: verified, `cargo test -p telltale explain::` passes (8 tests), clippy clean. |
| Effort | S (the patch), M (the three remaining gaps) |
| References | FLT-013, FLT-010, `spec/05` §7 |

### 02-05 Disabling a list deletes its downloaded copy

| Field | Content |
|---|---|
| Severity | **low** |
| Category | usability |
| Where | `crates/telltale-filter/src/fetch/mod.rs:60-64` (`ListSpec::from_config` filters `enabled`), `:452` (`prune` removes the store entries of lists not in the specs) |
| Evidence | **verified** by reading and by the new unit test `flt_004_disabled_lists_stay_known_but_never_due` (a disabled list is kept by `prune` and never due). |
| Impact | Toggling a large list off and on in the UI (the common "is it this list?" check) downloads it again, and in the meantime the list is gone from the store, so `telltale explain` can't show its lines. On a Pi behind a slow link, the re-download is minutes. |
| Recommendation | Keep disabled lists in the specs with an `enabled` flag; skip them when scheduling fetches and when compiling; prune only lists that left the configuration. |
| Patch | `patches/02-05-disabled-lists-keep-files.patch`: verified, `cargo test -p telltale-filter` passes (37 tests), clippy clean for `telltale-filter` and `telltale`. |
| Effort | S |
| References | FLT-004 |

### 02-06 Safe-search groups allocate a `String` per query

| Field | Content |
|---|---|
| Severity | **low** |
| Category | performance |
| Where | `crates/telltale/src/pipeline.rs:1108-1114` (`safe_search_target` builds `q.qname.display().to_string()` for every query from a group with safe search on, then looks the name up) |
| Evidence | **verified** by reading; the comment above it says "no allocation for other groups", which is true, and the allocation test from pass 01 (01-04) runs without a safe-search group. |
| Impact | One heap allocation and a lowercase copy per query for the groups that use the feature (typically the kids' group, the one with the most devices). It is the only allocation left on the cache-hit path, and it is per group, so it is easy to miss in a benchmark. |
| Recommendation | Match the engine suffixes against `q.qname` directly (the wire form is already lowercase-comparable with `eq_ignore_ascii_case`, and `telltale_config::safesearch::target` could take the name's labels), or keep a per-group precompiled suffix table. Add a safe-search group to the 01-04 allocation test so it stays at zero. |
| Patch | none |
| Effort | S |
| References | FLT-011, NFR-002 |

### 02-07 The overlay is dead code in production

| Field | Content |
|---|---|
| Severity | **low** |
| Category | maintainability |
| Where | `crates/telltale/src/lists.rs:394`, `:416`, `:592` (every `Matcher` is built with `Overlay::default()`), `crates/telltale-filter/src/matcher.rs` (the overlay's lookup runs on every decision) |
| Evidence | **verified** by reading: nothing outside tests constructs a non-empty overlay. |
| Impact | ADR-003's "quick rules take effect without a recompile" is served by `telltale-policy`'s quick rules, not by the overlay, so the overlay check on the decision path is a branch that never fires, plus a test surface (`flt_003_overlay_applies_without_recompiling`) for a feature nobody runs. Harmless today; a trap for the next person who assumes it is live. |
| Recommendation | Either remove the overlay and amend ADR-003, or wire it to the quick rules and drop one of the two. A one-line note in ADR-003 pointing at `telltale-policy::quick` is the minimum. |
| Patch | none |
| Effort | S |
| References | ADR-003, FLT-005 |

### 02-08 Regex rules cost about 1 µs per query per thousand, and the bench stops working at 2,000

| Field | Content |
|---|---|
| Severity | **low** |
| Category | performance |
| Where | `crates/telltale-filter/src/matcher.rs` (the regex set is consulted on every miss of the exact and suffix tables), `crates/telltale-filter/examples/matcher_bench.rs` |
| Evidence | **verified** for 1,000 (table in Measurements: p50 181 ns → 1.19 µs, p99.9 1.1 µs → 35 µs). **suspected** for the cliff: with 2,000 patterns the bench did not print a result in 19 minutes and reached 5.0 GiB RSS; with 5,000 it got through "load + index + regex build" in 176 ms and then produced no lookup line in the first run either. I did not find out whether the time goes into the lookups (a lazy-DFA cache that thrashes and falls back to a slower engine) or into the bench's own bookkeeping. |
| Impact | At 1,000 patterns the filter still answers in about a microsecond, well inside budget. The cliff matters because the regex count isn't bounded anywhere: one list with a few thousand regex lines (some community lists have them) could make every miss slow and the process large. The compile-time check (02-02) only tests that the set builds. |
| Recommendation | Measure where the 2,000-pattern time goes (`perf` on the bench, or the engine's `which_overlapping_matches` statistics), then either cap the regex count per snapshot with a reported overflow, or raise the engine's DFA cache capacity in `regex_builder` in proportion to the pattern count. Add the 1,000- and 2,000-pattern points to `bench-smoke`. |
| Patch | none |
| Effort | M |
| References | FLT-003, NFR-001, `spec/05` §3.3 |

### 02-09 The index silently falls back to the FST walk above 65,536 list sets

| Field | Content |
|---|---|
| Severity | **low** |
| Category | observability |
| Where | `crates/telltale-filter/src/matcher.rs:569`, `:587` (`MAX_INDEXED_LISTSETS`; the index build gives up on the first value past it), `crates/telltale/src/lists.rs:415-434` (the log line says `lookup=Walk` and nothing else) |
| Evidence | **verified** by reading. Reaching the limit needs many lists with many distinct overlaps; I did not build such a snapshot. |
| Impact | Lookups go from about 180 ns to the FST walk, and the FST pages stay resident (the release at `lists.rs:424` is skipped), on an install that did nothing but add lists. The only sign is a `?lookup` field in one info line. |
| Recommendation | Log at warn with the count and the limit when the index can't be built, and expose the lookup mode as a gauge (`telltale_filter_lookup_mode`). The limit itself is a reasonable design choice; it just needs to be visible. |
| Patch | none |
| Effort | S |
| References | FLT-003, OBS-011, ADR-020 |

## Questions for the owner

1. **Usable-list threshold (02-01).** The patch rejects a body with no rules but invalid
   lines, or more invalid lines than rules. A legitimate list that is mostly cosmetic
   rules still passes (cosmetic lines count as unsupported, not invalid). Is "more invalid
   than valid" the right line, or should it be stricter (any list that lost more than,
   say, 90 % of its previous rule count is suspect)?
2. **Fsync cost on the Pi (02-03).** The patch syncs each shard and the directory. On an SD
   card a 2 M-name compile gains a few hundred milliseconds. Acceptable, or should it be an
   option that defaults to on?
3. **Overlay (02-07).** Remove, or keep for a planned use?
4. **Regex budget (02-08).** Is a per-snapshot cap on regex rules (with the overflow
   reported in the UI) acceptable behaviour, or must every regex a list ships be honoured?

## Not reviewed

- The rate limiter's fairness and the lock on its path: pass 01 (01-08).
- `crates/telltale-policy/src/special.rs` and `local.rs` were read for correctness of the
  classification and the zone answers (SOA/NS synthesis, ADR-094) but not fuzzed.
- The UI side of lists and groups (`ui/`): out of this pass's scope.
- The Pi-hole and AdGuard importers (`crates/telltale/src/import*`): not in the brief.
- The DNS64 and rebinding checks in `pipeline.rs` were read in pass 01; nothing new here.
- List `$dnsrewrite` precedence (ADR-095) was checked against the ADR by reading
  `rewrite.rs` and its tests; not exercised with real lists.
