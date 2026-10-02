# AGENTS.md — Instructions for the implementing agent

You are building **TelltaleDNS**, a filtering, encrypted, observable, clustered DNS resolver, from the specification in this repository. The spec is the source of truth. Read in this order before writing code:
1. `EXECUTIVE-SUMMARY.md` (why), `docs/analysis.md` (what we learned from Pi-hole/Technitium)
2. `spec/00-overview.md` → `spec/01-requirements.md` (the contract) → `spec/11-decisions.md` (ADRs)
3. The section spec for your current task, then `spec/10-roadmap-and-tasks.md`.

## Ground rules
1. **Spec-driven.** Work task by task in the order in `spec/10`. Before starting a task, restate its requirement IDs and acceptance criteria. When done, tick its box and note anything deferred.
2. **Traceability.** Reference requirement IDs in code comments at the implementation site (`// REQ: FLT-003`), in test names (`flt_003_...`), and in commit messages (`feat(filter): FST snapshot compiler [FLT-003]`).
3. **Spec gaps or conflicts:** do not silently invent behavior. Choose the most conservative option consistent with the ADRs, record it as a new ADR in `spec/11-decisions.md` with status `Proposed`, and list it in your end-of-task report for the owner.
4. **Performance is a feature.** Never add allocation, locking, or I/O to the hot path (`02 §3`) without a benchmark proving it's within budget. Run `make bench-smoke` before finishing any task that touches `telltale-proto`, `telltale-net`, `telltale-cache`, `telltale-filter`, `telltale-policy`, or `telltale-telemetry`.
5. **DNS never depends on anything else.** Telemetry, storage, API, and cluster failures must not affect query answering (`02 §8`, CLU-004).
6. **Clean room.** Do not copy code from Pi-hole (EUPL-1.2), Technitium (GPL-3.0), AdGuard Home (GPL-3.0), or any copyleft source. Using their *public docs/RFCs/data formats* (e.g., reading Pi-hole's `gravity.db` schema for the importer) is fine. Permissively licensed crates are fine after a `cargo-deny` check.
7. **Safety.** `unsafe` is only allowed in `telltale-net`, and each use needs a `// SAFETY:` justification. No `unwrap()`/`expect()` on runtime paths.
8. **Dependencies.** Prefer the crates listed in `02 §7`. Adding a new runtime dependency requires a one-line justification in the PR and must not push the image past 15 MiB.
9. **Done means:** the acceptance criteria pass in CI; clippy is clean; docs updated (`docs/` user docs for any user-visible behavior); OpenAPI regenerated if the API changed; the roadmap checkbox is ticked.

## Repository layout (target)
```
crates/telltale-*/        # see spec/02 §2
crates/telltale/          # binary
ui/                    # Svelte app
deploy/helm/telltale/     # Helm chart
deploy/compose/        # Pi / Docker Compose bundles
deploy/systemd/        # native unit + install.sh
deploy/grafana/        # dashboards
presets/               # upstreams.toml, safesearch.toml, services/*.toml, oui.txt, bigrams.bin
bench/                 # harness, corpora, compare/
docs/                  # user docs + analysis
spec/                  # this specification
```

## Owner priorities (for tie-breaking)
Performance > lightweight footprint > observability > Kubernetes + Pi deployability > clustering/HA with a single management plane > protocol breadth > UI polish. Auth = local users (basic) + OIDC; **no LDAP**. Every new API operation must be agent-ready (AGT-001..005) and, where it fits the catalog, exposed as an MCP tool (`spec/13`).
