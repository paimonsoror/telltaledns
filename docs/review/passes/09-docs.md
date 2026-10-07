# Pass 09: docs and site accuracy

**Output:** `docs/review/v0.2.0/09-docs.md` (+ `patches/09-*`)

## Scope
Whether what the project says is true and usable: the README and executive summary, the user
docs, the project site, the specification against the code, release notes.

- `README.md`, `EXECUTIVE-SUMMARY.md`, `docs/running.md`, `docs/configuration.md`,
  `docs/releasing.md`, `docs/v1-gate.md`, `deploy/release/notes/`
- `site/` (static pages built by `site/build.py`; `python3 site/build.py` checks links,
  coverage, and page sizes)
- `spec/` (requirements, ADRs, roadmap) as a description of the code

## Read first
1. `README.md` → `docs/running.md` (skim the table of contents, then read the sections the
   earlier passes found interesting).
2. AGENTS.md (the project's documentation rules, DOC-006) and ADR-012.

## Look for
- **Claims vs reality:** every number (memory, throughput, latency, image size) should come
  from a measurement this repository can reproduce (`bench/`, `docs/v1-gate.md`). Two
  footprint claims were wrong until 2026-10-07; look for others. Feature claims the code
  doesn't back up, or features the docs don't mention.
- **Usability:** can a new user go from nothing to a working Pi or Kubernetes install with
  only these docs? Try the steps you can try locally (config snippets through
  `telltale config check`, commands' flags against `--help`).
- **Examples that don't validate:** run each TOML snippet in `docs/` through
  `target/debug/telltale config check` (with stub upstreams where needed).
- **Spec drift:** requirements marked done whose behaviour differs from the code; ADRs whose
  "Decision" no longer matches what was built (and wasn't amended).
- **Tone rule:** public text credits Pi-hole and Technitium and never compares against them.

## Useful
```sh
python3 site/build.py
target/debug/telltale config check snippet.toml
grep -rn "MiB\|qps\|µs\| ms\b" README.md EXECUTIVE-SUMMARY.md site/*.html docs/*.md   # numeric claims to check
```
