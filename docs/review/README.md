# Code review handoff: TelltaleDNS v0.2.0

You are reviewing **TelltaleDNS at the `v0.2.0` tag**: about 96,000 lines of Rust in 15 crates,
a 15,600-line Svelte UI, a Helm chart, install scripts, and docs. The review is split into
focused **passes**, one capability area at a time (`passes/`). Do one pass per session, in
order unless the owner says otherwise. This page is the brief every pass shares: read it
first, every time.

**Starting a session** (the owner pastes this):

> Read `docs/review/README.md` in `~/dnsproject`, then do pass NN from
> `docs/review/passes/NN-*.md` against the `v0.2.0` worktree. Write the report and patches
> where the README says, and stop when that pass is done.

What the owner wants from you: **an honest, evidence-backed assessment**. Say clearly what
is excellent and why (so it's kept), and what should improve, with concrete fixes. Another
agent will review your proposed patches before anything is implemented, so make each one
self-contained and easy to judge.

## The project in one minute

TelltaleDNS is a filtering, encrypted, observable DNS resolver that runs on a Raspberry Pi,
in Kubernetes, or on both as one cluster. Read `EXECUTIVE-SUMMARY.md` (10 minutes) before
your first pass. The specification is in `spec/` (`01-requirements.md` has every REQ ID;
`11-decisions.md` has the ADRs). Code comments cite requirement IDs (`// REQ: FLT-003`).

**The owner's priorities, in order** (use them to rank findings):
performance > lightweight footprint > observability > Kubernetes and Pi deployability >
clustering/HA with one management plane > protocol breadth > UI polish.

**Rules the code follows on purpose** (don't report these as problems; do report breaking
them):
- **DNS never depends on anything else.** Telemetry, storage, the API, and the cluster must
  not affect answering queries (`spec/02` §8, CLU-004).
- **The hot path** (receive → parse → cache/filter → answer) allocates nothing and takes no
  locks beyond the cache shard (NFR-002; `spec/02` §3). Changes there need a benchmark.
- **`unsafe` lives only in `crates/telltale-net/src/sys.rs`**, each block with a
  `// SAFETY:` comment. Everywhere else `unsafe_code = "forbid"`.
- **No `unwrap()`/`expect()` on runtime paths** (tests may).
- **Clean room:** no code from Pi-hole, Technitium, AdGuard Home, or other copyleft
  projects. Their public formats and docs are fine. Don't suggest copying their code.
- **Tone:** public text credits Pi-hole and Technitium as inspirations and never compares
  against them.

## Ground rules for you

- **Review a fixed copy.** Create a worktree at the tag and review there, so `main` can move
  on: `git -C ~/dnsproject worktree add ~/telltale-review v0.2.0` (once; later passes reuse
  it). Line numbers in findings refer to that copy.
- **Read-only toward the outside world.** Don't commit, push, open issues or PRs, or change
  anything on the live cluster (the Pi at 192.168.3.2, the homelab at 192.168.5.x), in
  `~/homelab-charts`, or in GitHub settings. Don't run load tests against the Pi or the
  homelab. Local builds, tests, and benchmarks on this machine are fine.
- **This machine:** WSL2 (Ubuntu 24.04), 8 threads, 7.6 GiB. Build with
  `CARGO_BUILD_JOBS=2` (more has run the machine out of memory). Commands longer than about
  10 minutes should run in the background.
- **Write only under `docs/review/v0.2.0/`** in the main checkout (`~/dnsproject`), and leave
  it uncommitted: the owner decides what to keep.

## Building, testing, measuring

```sh
cd ~/telltale-review
CARGO_BUILD_JOBS=2 cargo build -p telltale                      # debug binary: target/debug/telltale
CARGO_BUILD_JOBS=2 cargo test --workspace -- --skip flt_004_a_slow_list
CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets -- -D warnings
make bench-smoke                                                # cache-hit and miss throughput, ~1 minute
python3 bench/gate.py                                           # the v1.0 gate measurements (docs/v1-gate.md)
python3 bench/memprobe.py                                       # memory by mapping
cargo bench -p telltale-cache --bench cache_hit                 # criterion micro-benchmarks (also telltale-proto, -filter)
```
- Per-crate tests: `cargo test -p <crate>`. End-to-end scripts are in `deploy/` (cluster,
  DNSSEC, imports, sinks) and `ui/tests/e2e` (Playwright; see `bench/README.md` and
  `docs/running.md` for setup). Prefer focused tests over the full suite.
- Benchmarks on this machine are noisy (WSL, shared cores): treat a single run as a hint,
  repeat before claiming a regression, and say how you measured.
- A local resolver for experiments: write a small `telltale.toml` (see `bench/bench.py`
  `server_config()` for a minimal one) and run `target/debug/telltale run -c it.toml`
  on a high port. Upstreams: Quad9 over DoT (`tls://9.9.9.9`, `tls_server_name =
  "dns.quad9.net"`) works from here.

## What not to report (already known)

Read these before each pass; findings that only restate them waste the next agent's time.
New evidence, a better fix, or a cause nobody found is welcome; say so explicitly.
- **The v1.0 gate** (`docs/v1-gate.md`, roadmap M10 in `spec/10-roadmap-and-tasks.md`):
  memory with 1M names above 64 MiB (T10.2, in progress), Pi recompile over 8 s (T10.3),
  cold start 565 ms (T10.4), latency and Pi throughput not measured on separate hardware
  (T10.5), no requirement-by-requirement check yet (T10.6), the security review itself
  (T10.7), the comparative report (T10.8).
- **DNSSEC** (ADR-098): `validate` mode isn't recommended yet because at a cold start the
  upstream can close fresh DoT connections and fail the first validations; the first
  validation of a deep chain can exceed the client's wait (SERVFAIL, then cached);
  `_dns.resolver.arpa` is forwarded instead of answered locally.
- **Deliberately out of scope** (see the ADRs): DHCP (ADR-091), RFC 5011 trust-anchor
  tracking (ADR-086), zone transfers (ADR-094), WASM plugins (ADR-084), io_uring (ADR-083).
- **Accepted decisions** (every ADR through ADR-096 is Accepted). You may challenge one, but
  name it, and say what changed or what it missed.

## How to report

Write `docs/review/v0.2.0/NN-<area>.md` for pass NN, and patches as
`docs/review/v0.2.0/patches/NN-<finding-number>-<short-name>.patch`.

**The report:**
1. **Summary** (5-10 lines): the area's overall health and your top three points.
2. **Strengths:** what's done well, each with where it is (`path:line`) and why it matters.
   Be specific; "clean code" isn't a strength, "the cache-hit path copies the stored answer
   and patches only the ID and TTLs (`write` in `crates/telltale-cache/src/entry.rs`)" is.
3. **Findings**, most important first, at most about 15 per pass. Each one:

   | Field | Content |
   |---|---|
   | ID | `NN-01`, `NN-02`, ... |
   | Title | one line |
   | Severity | **critical** (data loss, security hole, DNS outage), **high** (wrong answers, a broken requirement, a real risk), **medium** (a clear improvement with real impact), **low** (worth doing when nearby) |
   | Category | correctness, security, performance, footprint, reliability, observability, maintainability, test gap, docs |
   | Where | `path:line` in the v0.2.0 worktree (several if needed) |
   | Evidence | what you saw; **verified** (say how: a test you ran, a command, a measurement) or **suspected** (say what would confirm it) |
   | Impact | who notices, when, and how badly |
   | Recommendation | the fix, and alternatives if there's a real trade-off |
   | Patch | file name in `patches/`, or "none" (with why: design discussion needed, too large) |
   | Effort | S (under an hour), M (a day), L (more) |
   | References | REQ IDs, ADRs, RFC sections |
4. **Questions for the owner:** decisions only the owner can make.
5. **Not reviewed:** what you skipped or couldn't check, so the next pass or the owner knows.

**Patches:**
- `git diff` format against `v0.2.0`, from the worktree root (`git -C ~/telltale-review diff`
  after editing, then reset the worktree: `git -C ~/telltale-review checkout -- .`).
- One finding per patch, as small as it can be, following the code's conventions: REQ IDs
  in comments, a test for behaviour changes, no `unwrap` at runtime.
- Say in the finding whether the patch builds and its tests pass (`verified`) or not.
- If `main` has moved and the area changed since v0.2.0, note it; the implementing agent
  rebases.

**Calibration:**
- Prefer fewer, well-evidenced findings to many guesses. A suspected finding is fine when
  it's labelled so and says how to confirm it.
- No style preferences (formatting, naming taste) unless they hide a bug or mislead.
- Read the code around a finding before reporting it: much of what looks wrong in isolation
  is handled a few lines away or explained in an ADR.
- When something is excellent, say so plainly. The owner asked for both.

## The passes

| # | Area | File |
|---|---|---|
| 01 | Query path and performance | `passes/01-query-path.md` |
| 02 | Filtering and policy | `passes/02-filtering.md` |
| 03 | Upstreams, recursion, DNSSEC | `passes/03-upstreams-dnssec.md` |
| 04 | Telemetry, storage, observability | `passes/04-observability.md` |
| 05 | Cluster and HA | `passes/05-cluster.md` |
| 06 | API, authentication, agents (MCP) | `passes/06-api-auth-agents.md` |
| 07 | Configuration, deployment, release | `passes/07-config-deploy.md` |
| 08 | Web UI | `passes/08-ui.md` |
| 09 | Docs and site accuracy | `passes/09-docs.md` |
| 10 | Synthesis | `passes/10-synthesis.md` |

Security is part of every pass (each lists its threat surface); pass 06 and pass 05 carry
the most.
