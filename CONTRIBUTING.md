# Contributing to TelltaleDNS

Thank you for helping. TelltaleDNS answers the DNS lookups on your network in microseconds, filters
them by your rules per device, and shows you exactly who asked, what they asked, and why it answered
the way it did. It runs on a Raspberry Pi, in Kubernetes, or on both as one cluster.

There are many ways to help:

- **Report a problem** you found running it, or suggest an idea.
- **Fix a bug** or **build a feature**.
- **Improve the docs**: the user docs in [`docs/`](docs/) and the [project site](https://paimonsoror.github.io/telltaledns/) in [`site/`](site/).
- **Translate** the web UI (see [Translations](#translations)).
- **Test it** on your own network and report what you find. The `edge` build is made from every commit on `main`.

## Before you start

- Search the [issues](https://github.com/paimonsoror/telltaledns/issues) and
  [pull requests](https://github.com/paimonsoror/telltaledns/pulls) first: someone may already be on it.
- For anything large, or anything that changes how TelltaleDNS behaves, open an issue first, so the
  direction is agreed before you write the code.
- Small fixes (a typo, a broken link, a bug with an obvious fix) can go straight to a pull request.

## Reporting a problem

Open an issue with the **Bug report** form. It asks for:

- what you did, what you expected, and what you saw instead;
- the version (`telltale --version`, or **Settings → System**) and how you run it (native, container, Helm);
- a **support package**, if you can make one.

A support package is one `.tar.gz` that you make on your own machine; nothing is uploaded. Make it in
**Settings → System → Support package**, or with `telltale support-package` (add `--offline` if the
node won't start). At the default level, `strict`, addresses and names (of hosts, devices, clients,
groups and nodes, among others) become pseudonyms, query names and secrets are left out, and the log
keeps only warnings and errors. Log lines are redacted by pattern, which is best effort, so look the
package over before you attach it, and don't attach the pseudonym map (`--keep-map`): it holds your
real names. [Support package](docs/running.md#support-package) in `docs/running.md` lists what it
holds at each level.

**Security problems are not reported in public.** Report them privately, as [`SECURITY.md`](SECURITY.md) describes.

## Making a change

### How the project is organised

- **The specification in [`spec/`](spec/00-overview.md) is the source of truth.**
  [`spec/01-requirements.md`](spec/01-requirements.md) lists the requirements, each with an ID such
  as `FLT-003`. New user-visible behaviour gets a requirement there if none covers it yet.
- **Requirement IDs are traced.** They appear in code comments where a requirement is implemented
  (`// REQ: FLT-003`), in test names (`flt_003_compile_and_look_up`), and in commit subjects
  (`feat(filter): safe search per group [FLT-011]`). The requirement check in CI
  (`python3 spec/trace.py --check`) finds the tests by their names.
- **Decisions are ADRs** in [`spec/11-decisions.md`](spec/11-decisions.md). Where the spec is
  silent, choose the most conservative option and propose it as a new ADR with the status
  `Proposed`; the maintainer decides whether to accept it.
- [`AGENTS.md`](AGENTS.md) describes how the maintainer's own tooling, a coding agent, works on the
  project. The rules below come from it and from CI.

### The checks

CI runs on every pull request ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Run the
quick checks yourself first; [How we work: the gates](https://paimonsoror.github.io/telltaledns/dev-gates.html) explains every job.

```sh
# Rust, from the repository root (make check runs all four)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                  # needs cargo-deny

# The web UI, from ui/, if you changed it
npm ci
npm run check                     # svelte-check; warnings fail
npm run check:help                # every "?" in the UI has a help topic
npm run build                     # fails over the 400 KiB gzipped budget
npm run test:e2e                  # the Playwright suite against the real binary (see ui/README.md)

# The site and the requirement trace, from the repository root
python3 site/build.py --check
python3 spec/trace.py --check
```

The project turns on clippy's pedantic lints, and CI fails on any warning. A few more rules:

- **Performance comes first.** Don't add allocation, locking, or I/O to the query path
  ([`spec/02-architecture.md` §3](spec/02-architecture.md#3-threading-and-io-model)) without a
  benchmark that shows it stays within budget. If you change `telltale-proto`, `telltale-net`,
  `telltale-cache`, `telltale-filter`, `telltale-policy`, or `telltale-telemetry`, run
  `make bench-smoke` (it needs `dnsperf` and Python 3.10 or later) on `main` and on your branch, on
  the same machine. Each run writes a file under `bench/results/`; compare the two with
  `python3 bench/bench.py compare base.json new.json` and put the result in the pull request. CI
  runs the benchmark too, but hosted runners are too noisy to judge speed. See
  [Size and performance budgets](https://paimonsoror.github.io/telltaledns/dev-budgets.html#speed).
- **No `unwrap()` or `expect()` on runtime paths.** Clippy denies them; tests may use them.
- **A new runtime dependency** needs a one-line justification in the pull request, and it must not
  push the container image past 15 MiB.
- **Generated files are never edited by hand**: the OpenAPI document, the UI's API types, the
  configuration schema, and the requirements trace. Change the source and regenerate;
  [the gates page](https://paimonsoror.github.io/telltaledns/dev-gates.html#generated) lists the
  commands.

### Write it yourself

TelltaleDNS learned from Pi-hole and Technitium by reading their public documentation and data
formats, never their code (see [`EXECUTIVE-SUMMARY.md`](EXECUTIVE-SUMMARY.md)). Contributions follow
the same rule: don't copy code from them, or from any other project under a copyleft licence (GPL,
EUPL and the like). Public documentation, RFCs, and data formats are fine. Depending on
permissively licensed crates is fine too; `cargo deny check` checks their licences.

### Docs

A change people can see (a setting, a page, a command) updates the user docs in [`docs/`](docs/)
and the matching page of the project site in [`site/`](site/), in the same pull request.
`python3 site/build.py --check` checks that the site builds and that its links resolve.

## Pull requests

- **One change per pull request.** Say what it changes and why, and link the issue it closes
  (`Fixes #123`).
- `main` takes changes only through pull requests, and each one needs a review from a code owner
  ([`.github/CODEOWNERS`](.github/CODEOWNERS)) before it is merged. A maintainer will review yours.
- CI runs on your pull request. If a job fails, read its log, push a fix to the same branch, and say
  what you changed. Please don't force-push over review comments.
- A test that fails and then passes on a re-run is treated as a bug, not noise: see
  [A flaky test](https://paimonsoror.github.io/telltaledns/dev-gates.html#flaky).

## Translations

The web UI's languages are data files: `ui/src/locales/<tag>.json` holds pairs of English and
translation, and `npm run check:i18n` (in `ui/`, and in CI) checks that every translation keeps the
placeholders, tags, web addresses, and numbers of its English. The Languages section of
[`ui/README.md`](ui/README.md) explains the format and the tools.

- **A new language** has an entry in `ui/src/locales/manifest.json`, with its owners: the GitHub
  accounts of the people who answer for its content, and `offered: false`. The translator adds the
  entry or asks a maintainer to add it to the branch. Ask in an issue first.
- **A translation pull request** changes only that language's file and, for a new language, its
  manifest entry (the check fails either one alone). An update to a language already in the manifest
  changes its pack only. `node scripts/i18n.mjs sync <tag>`, run in `ui/`, writes the file with the
  empty translations to fill in.
- **Each language has an owner.** The checks and the review look at a translation's structure; the
  language's owner reads the translation itself and approves it.

## License

TelltaleDNS is licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT),
at your option.

## Credit

The [Contributors](README.md#contributors) table in the README thanks people for code, tests, docs,
bug reports, and ideas. It follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification and is updated by hand.
