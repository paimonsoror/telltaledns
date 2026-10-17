# Prompt: apply the v0.2.0 review findings

You are working in `~/dnsproject` (TelltaleDNS, `main`, currently version 0.3.0). Read
`AGENTS.md` first and follow its ground rules throughout: requirement IDs at the
implementation site and in test names and commit messages, no `unwrap()`/`expect()` on
runtime paths, `unsafe` only in `telltale-net`, no new runtime dependency without a one-line
justification, docs updated for user-visible behaviour, OpenAPI regenerated if the API
changes, and `make bench-smoke` before finishing any task that touches `telltale-proto`,
`telltale-net`, `telltale-cache`, `telltale-filter`, `telltale-policy`, or
`telltale-telemetry`.

## What you are applying

A three-pass code review of tag v0.2.0 lives in `docs/review/v0.2.0/`:

- `01-query-path.md`, `02-filtering.md`, `03-upstreams-dnssec.md`: one report per pass.
  Each has a findings section (tables with Severity, Where, Evidence, Recommendation,
  Patch, Effort), a "Questions for the owner" section, and a "Not reviewed" section.
- `patches/NN-MM-<name>.patch`: one `git diff` per finding that has a patch, produced
  against v0.2.0 and verified there (tests and clippy). `main` has changed only crate
  versions since the tag, so they should apply as is; check with `git apply --check`.

Read all three reports before changing anything, so you know how the findings relate
(for example 03-04 builds on 03-02, and 02-04 lists work the patch doesn't cover).

## Order

Work by severity, then by whether a patch exists:

1. **03-01** (high, DNSSEC bypass in the ADR-098 unsigned-zone proof) and **01-01** (high,
   TCP/DoT connections held open by a client that stops reading).
2. Every other finding with a patch: 01-02 to 01-07, 02-01 to 02-05, 03-02, 03-03.
3. Mediums without a patch, in this order: 03-04 (apply on top of 03-02), 03-05, then the
   medium items from pass 01 that have no patch (take the severities from the tables, not
   from memory).
4. Lows without a patch, only if small (effort S) and clearly correct. Leave the rest as
   deferred with a reason.

## For each finding

1. Restate the finding's ID, requirement IDs, and what "done" means (the Recommendation
   field; for patched findings the patch is the baseline, not the whole job).
2. If there is a patch: `git apply --check`, then apply it (`--3way` if needed). If it no
   longer applies or a test it adds fails on `main` for a reason the report didn't foresee,
   stop on that finding, write down what you saw, and move on; do not force it.
3. Do the follow-up work the report names in the Patch or Recommendation fields, e.g.:
   - 01-01: add the `telltale_tcp_stalled_closed_total` line to `/metrics` (split the
     render function so clippy's `too_many_lines` passes) and document it in `docs/running.md`.
   - 02-04: the three remaining explain gaps (list `$dnsrewrite`, group rewrites, safe
     search) by sharing one function between the pipeline and explain, as the quick rules do.
   - 03-01: amend ADR-098 in `spec/11-decisions.md` so the "only the DS denial is trusted"
     paragraph states what the denial must show (NSEC/NSEC3 at the cut with NS, without
     SOA and DS). Keep the ADR's history; add the correction, don't rewrite it.
   - 03-02: expose the per-kind failures in the upstream info API and the Upstreams page
     if the owner's answer (below) says so; regenerate the OpenAPI if you do.
   - 03-04: SERVFAIL/REFUSED count in the rolling window but not toward the three-in-a-row
     rule, and are recorded with their real latency; add the test the report describes.
4. Run the tests the finding's Patch field names, plus
   `cargo clippy -p <crates touched> --all-targets -- -D warnings`.
5. Update `docs/` (and the matching `site/` page) for anything user-visible, and tick
   nothing in `spec/10-roadmap-and-tasks.md` unless the finding completes a roadmap task.
6. Commit on a branch `review/v0.2.0-fixes`, one commit per finding:
   `fix(<crate>): <what> [<REQ IDs>] (review 03-01)`. Do not push, tag, or release; the
   owner does that (`docs/releasing.md`).

## Owner's answers to the reports' questions

Each report ends with "Questions for the owner". Use these answers; where one is blank,
take the most conservative option consistent with the ADRs, record it as a new ADR with
status `Proposed` in `spec/11-decisions.md`, and list it in your end-of-task report.

- Pass 01: rate-limit default (q1): ___ ; per-address connection cap (q2): ___ ;
  4,096-byte TCP query cap (q3): ___ ; EDNS payload size config (q4): ___
- Pass 02: usable-list threshold (q1): ___ ; fsync on by default (q2): ___ ;
  overlay remove or keep (q3): ___ ; regex cap per snapshot (q4): ___
- Pass 03: ADR-098 amend vs supersede (q1): ___ ; breaker semantics for SERVFAIL (q2): ___ ;
  validation deadline (q3): ___ ; 0x20 default for `recursive://` (q4): ___ ;
  per-kind failures in the API (q5): ___

## Rules that still apply

- Read-only toward the outside world: do not touch the live cluster (the Pi at
  192.168.3.2, the homelab at 192.168.5.x), `~/homelab-charts`, or GitHub settings, and run
  no load tests against them. Local builds, tests, and benchmarks are fine.
- Do not edit anything under `docs/review/`; it is the record of what was found.
- This machine: WSL2, 8 threads, 7.6 GiB. Build with `CARGO_BUILD_JOBS=2`; run anything
  longer than about ten minutes in the background; never run two cargo builds at once.
- Clean room (AGENTS.md rule 6). No code from Pi-hole, Technitium, or AdGuard Home.

## When everything is applied

1. `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo fmt --check`, and `make bench-smoke` (compare with the numbers in the reports'
   Measurements sections; a regression beyond noise is a finding, not something to absorb).
2. Write `docs/review/v0.2.0/applied.md`, the one exception to the "don't edit
   `docs/review/`" rule, with: a table of finding → commit → status (done / partial /
   deferred, with the reason), the ADRs you added or amended, every place you disagreed
   with the review and why, and the bench numbers. Keep it uncommitted like the reports.
3. Stop. Do not merge the branch.
