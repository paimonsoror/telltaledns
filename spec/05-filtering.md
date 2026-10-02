# 05 — Filtering Engine

## 1. Concepts
- **List:** a source of rules: a URL (with update interval), a local file, or inline rules (the UI's "manual allow/deny"). Each list has a `kind`: `block` or `allow` (Pi-hole parity: allow lists exist). AdBlock syntax can mix the two inside one list via `@@`.
- **Group:** `{ id, name, lists: [list_id], upstream_group, block_mode, schedules, safe_search, blocked_services, rewrites, dns64, rate_limit }`. Clients map to ≥ 1 group. With multiple groups, the enabled lists are the union, and settings come from the highest `priority` group.
- **Rule precedence (deterministic, documented in the UI):**
  1. `important` allow (`@@...$important`)
  2. `important` block (`...$important`)
  3. allow (any source: domain, wildcard, regex, AdBlock `@@`)
  4. block (any source)
  5. no match → resolve normally

  Within a tier, the first match wins in this order: exact > most-specific suffix > regex. For attribution only, ties go to the lowest list ID.

## 2. Supported syntax (FLT-001)
| Input | Example | Compiled as |
|---|---|---|
| hosts | `0.0.0.0 ads.example.com` (any IP; `localhost` lines ignored) | subtree block |
| plain domain | `ads.example.com` | subtree block (or exact if the list has `match = "exact"`) |
| wildcard | `*.example.com` | subtree block of `example.com` *excluding the apex* |
| AdBlock | `||ads.example.com^` | subtree block |
| AdBlock exception | `@@||good.example.com^` | subtree allow |
| AdBlock exact | `|ads.example.com^` | exact |
| modifiers | `$important`, `$badfilter`, `$client=…`, `$dnstype=AAAA\|A`, `$denyallow=a.com\|b.com`, `$dnsrewrite=…` (P1) | modifier-rule table (§3.3) |
| Pi-hole regex | `(^\|\.)doubleclick\.net$;querytype=A` / `;invert` | regex set with metadata |
| AdBlock regex | `/^ad[0-9]+\./` | regex set |
| comments | `#`, `!`, `[Adblock Plus 2.0]` | ignored |

Unsupported AdBlock cosmetic/URL-path rules are counted as `unsupported` in list stats (not errors).

## 3. Compiled snapshot (FLT-003)
### 3.1 Domain sets as FSTs
- Normalize each domain: lowercase, IDNA → punycode, strip the trailing dot, validate labels.
- **Key = reversed labels joined by `.` with a trailing `.`**, e.g. `ads.example.com` → `com.example.ads.`. The trailing separator lets a walk detect label boundaries.
- Two FSTs per snapshot: `subtree.fst` and `exact.fst`. **Value (u64)** = an index into the `ListSetTable`. That is an interned, deduplicated table of list-ID bitsets (most domains appear in the same few list combinations, so the table stays small).
- **Lookup algorithm:** walk the FST byte-by-byte along the reversed qname. At each label boundary (`.`), if the node is final, collect `(depth, listset_id)`. A single pass is O(|qname|), returns all matching suffixes, and does no allocation (fixed-size SmallVec of ≤ 8 hits; deeper matches are rare and truncate safely to the most specific 8).
- **Group check:** `listset_bitset & group.enabled_lists_bitset != 0`, evaluated separately for allow and block lists. Bitsets are fixed-width `[u64; N]` with N = ceil(max_lists/64); the default max is 1024 lists, so N = 16.
- **Memory target:** ≤ 12 bytes per unique domain on average for typical lists (HaGeZi, OISD, StevenBlack). Measured and gated in CI (`09`). The FSTs are mmapped from the snapshot dir, so pages are shared and cold pages can be evicted on low-RAM Pis.

### 3.2 Regex
- All regex rules compile into one `regex_automata::meta::Regex` multi-pattern set (lazy DFA; linear time; **no backtracking constructs allowed**; patterns that fail to compile are rejected and reported). The result is the set of matching pattern IDs. Each pattern ID maps to metadata: `{ list_id, kind, qtypes, invert, important }`.
- Prefilter: skip regex evaluation entirely if the client's groups have no regex rules (common case).
- `;invert` rules are kept in a separate small set and evaluated as "does NOT match".
- Budget: ≤ 2 µs p99 for 5,000 regexes on x86 for typical qnames (benchmarked).

### 3.3 Modifier rules
- Rules with `$client`, `$dnstype`, `$denyallow`, or `$dnsrewrite` go into `modrules.fst` (same reversed key). The value indexes a `ModRuleTable` with predicates evaluated only on a hit.
- `$badfilter` is resolved at compile time (it removes the matching rule) and never reaches the snapshot.
- `$client` values resolve at compile time to client IDs/CIDRs where possible.

### 3.4 Compilation pipeline (FLT-004)
1. The **fetcher** downloads lists concurrently (max 4), with ETag/Last-Modified conditional GETs, size caps (default 64 MiB/list), timeouts, and per-list retries. Raw sources are stored as `lists/<id>.src.zst` (needed for "explain" line lookups and offline recompiles).
2. The **parser** streams lines into `(normalized_key, list_id, flags)` tuples. Parallelize per list (rayon).
3. **Merge:** an external sort when the total exceeds a memory budget (default 128 MiB on the controller); the k-way merge emits keys in sorted order with combined list bitsets.
4. **FST build:** streaming `fst::MapBuilder`, written directly to disk.
5. **Regex compile:** in parallel with the FST build.
6. Write the manifest, sign it (05 + 12), and publish → resolvers `ArcSwap` it. The old snapshot stays mapped until its last reader drops.
- **Hard rule:** the compile runs in a background thread pool with `nice`/low priority (configurable cores, default 1 on Pi), and **never** holds any lock the query path takes.
- Failure handling: a list that fails to download keeps its last good version. A compile failure keeps the previous snapshot and raises an alert.

## 4. Policy features
- **Pause (FLT-009):** a global or per-group atomic `paused_until: u64`. While paused, the decision returns None (the event status records `paused`).
- **Schedules (FLT-010):** `[[schedule]] { name, tz, windows = [{days=["mon".."fri"], start="21:00", end="07:00"}], action = "block_all" | "enable_lists:[..]" }`. A 15-second ticker recomputes an atomic `active_schedule_mask` per group, so there is no time math per query.
- **Safe search (FLT-011):** a data file `presets/safesearch.toml` of `domain → CNAME target` (e.g., `www.google.* → forcesafesearch.google.com`, YouTube → `restrict.youtube.com` / `restrictmoderate.youtube.com`). Implemented as an internal rewrite evaluated in pipeline step 5.
- **Blocked services (FLT-012):** `presets/services/*.toml`, with each service a named list of AdBlock rules, compiled like a list.
- **Response IP filter (FLT-015):** per-group CIDR deny list applied to answers. The default rebinding protection blocks RFC 1918/ULA answers for non-local names (opt-in, because some homelab names legitimately do this; local-domain exceptions are configurable).

## 5. Explain API (FLT-013)
`GET /api/v1/explain?name=ads.example.com&client=192.168.1.20&qtype=A` returns the client resolution, groups, schedule state, every matching rule across tiers (list name, rule line number + text retrieved from the stored source), the winning decision, and the would-be upstream group. The UI exposes this as a "Why?" link on every query-log row.

## 6. List statistics
Per list: entries, unique contribution (domains not present in any other enabled list), invalid lines, unsupported lines, last fetch status, size, compile time, and **hit count over 24h/7d** (from telemetry). The UI flags dead lists (0 hits in 30 days) and highly redundant lists (> 95% overlap).
