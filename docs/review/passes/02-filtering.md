# Pass 02: filtering and policy

**Output:** `docs/review/v0.2.0/02-filtering.md` (+ `patches/02-*`)

## Scope
Which questions are blocked, rewritten, or answered locally, and for whom: block lists,
groups and devices, schedules, quick rules, rewrites, safe search, explain.

- `crates/telltale-filter/` (list fetching `fetch/`, parsing `parse/`, compiling `compile/`
  into FST snapshots, `snapshot.rs`, the matcher and its hash index `matcher.rs` +
  `matcher/`, `$dnsrewrite` in `rewrite.rs`, `explain/`)
- `crates/telltale-policy/` (client identification `clients.rs`, local records and zones
  `local.rs`, quick rules `quick*`, rate limiting, special names)
- `crates/telltale/src/lists.rs` (compile loop, snapshot swaps), `explain/`, the filter and
  group parts of `pipeline.rs` (`decide_for`, `block_answer`, schedules, `safe_search`, rebinding,
  `dns64_*`)

## Read first
1. `spec/05-filtering.md`; ADR-003, ADR-016 to ADR-024, ADR-050, ADR-067, ADR-095.
2. `crates/telltale-filter/src/compile/` → `snapshot.rs` → `matcher.rs` (`decide`).
3. `crates/telltale-policy/src/clients.rs` (`identify`, `group_ids`, `primary_group`).

## Look for
- **Matching correctness:** precedence (`$important`, allow vs block, exact vs suffix vs
  regex), wildcards, IDNs and case, CNAME inspection, list syntax edge cases (hosts,
  AdBlock, regex; malformed lines), `$client`/`$dnsrewrite` semantics.
- **Swaps under load:** compile in the background, atomic publish, freeing old snapshots
  (ADR-023), memory peaks while compiling (T10.3 is about the Pi's recompile time).
- **Identification:** IP vs CIDR vs MAC (neighbor table, EDNS MAC trusted only from
  configured routers) vs client ID (DoT SNI, DoH path); group priority with several groups;
  0.1.0 fixed logging the wrong group for early answers: are other paths still exposed?
- **Explain:** does `telltale explain` / the API's Why? always agree with what the pipeline
  actually decided?
- **Fetching lists:** size limits, redirects, TLS verification, failure behaviour (keep the
  last good snapshot), ETag/If-Modified-Since.

## Threat surface
Downloaded lists are untrusted input (huge lines, pathological regexes, decompression
bombs, millions of entries). EDNS client MAC spoofing. Rewrites that point at private
addresses (rebinding protection).

## Useful
```sh
cargo bench -p telltale-filter
cargo test -p telltale-filter; cargo test -p telltale-policy
ls bench/lists/            # the fixed list snapshot used by the benches (not in git)
```
