# Releasing TelltaleDNS

How stable releases are cut. Written for maintainers and for agents: follow it as is. The
**release** workflow does the steps the same way every time; this page explains what it
does, what to check, and what to do when a step fails. Decision record: ADR-097.

## Versions and channels

| | Built from | Binaries (`telltale --version`) | Container image | Helm chart | GitHub |
|---|---|---|---|---|---|
| **edge** | every push to `main` | `X.Y.Z-edge.N`, channel `edge` | `:edge`, `:sha-<7 chars>` | `X.Y.Z-edge.N` (appVersion `edge`) | the `edge` prerelease, replaced each time |
| **stable** | a `vX.Y.Z` tag | `X.Y.Z`, channel `stable` | `:X.Y.Z`, `:X.Y`, `:X`, `:latest` | `X.Y.Z` (appVersion `X.Y.Z`) | release `vX.Y.Z`, marked latest |

- `X.Y.Z` on `main` is the version being worked toward: `[workspace.package] version` in
  `Cargo.toml` and `version` in `deploy/helm/telltale/Chart.yaml` (always equal). `N` is the
  image workflow's run number.
- Semver sorts `X.Y.Z-edge.N` **below** `X.Y.Z`. So the moment `X.Y.Z` is released, `main`
  moves to the next version (`X.Y+1.0` by default), through a pull request the release workflow
  opens (`main` allows changes only through pull requests). Otherwise edge builds would look
  older than the release, and `helm --devel` and update checks would never offer them.
- `install.sh` and `telltale self-update` take the **latest release** for `stable` (GitHub's
  `releases/latest`, which skips prereleases) and the `edge` prerelease for `--edge` /
  `--channel edge`. Both verify `SHA256SUMS` against the release key; an unsigned release
  isn't installable.
- `:sha-<7 chars>` images are immutable. Pin one (with chart `X.Y.Z-edge.N`) to deploy a
  specific edge build through GitOps.

## Cutting a release

1. **Write the notes** on `main`: `deploy/release/notes/vX.Y.Z.md`, a short Markdown summary
   for people upgrading (highlights, anything to do when upgrading, known issues). GitHub
   appends its generated changelog below it. Commit and push; wait for CI to pass on that
   commit.
2. **Run the workflow:** GitHub → Actions → **release** → Run workflow, version `X.Y.Z`
   (`next` is optional; the default is `X.Y+1.0`).
3. **Watch two runs:**
   - **release** (about a minute): preflight, tag, start the tag's build, then open a pull
     request (branch `release/start-<next>`) that moves `main` on, with CI running on the
     branch.
   - **image** on ref `vX.Y.Z` (about 30 minutes): build and test every architecture, push
     the image tags, publish the chart, sign and publish the GitHub release, then
     **verify**. The release is done when `verify` is green.
4. **Merge the pull request** the workflow opened ("chore: start `<next>` development (after
   vX.Y.Z)"). It can be merged while the tag's build is still running (that build is of the
   tag, not of `main`). It needs a code owner's approval or an administrator's bypass, like
   any change to `main`. Once it is merged, CI and the edge build start by themselves and
   edge builds are named `<next>-edge.N`.
5. **After:** the README's release badge updates itself. Deployments that follow edge pin
   the next edge chart as usual.

The workflow opens the pull request with its own token, which needs **Settings → Actions →
General → Allow GitHub Actions to create and approve pull requests**. Without it the branch is
still pushed and the job fails with a link to open the pull request by hand.

### What preflight checks

`deploy/release/preflight.sh X.Y.Z` stops before anything is published unless:
the version is `X.Y.Z` (no suffix); `Cargo.toml` and `Chart.yaml` say `X.Y.Z`; the tag
`vX.Y.Z` doesn't exist; `deploy/release/notes/vX.Y.Z.md` exists; and the newest CI run on
`main`'s head passed.

### What verify checks

`deploy/release/verify.sh X.Y.Z` (run by the tag build, or by hand with `curl`, `minisign`,
`helm`, and `docker`):
`SHA256SUMS` and `releases.json` are signed with `deploy/release/telltale-release.pub`; the
x86_64 binary matches its sum and reports `X.Y.Z … channel stable`; all three architectures
are listed with their SBOM and their debug file (`telltale-<arch>-linux.debug.zst`, the symbols
that make a stack from the stripped binary readable); `releases/latest` points at `vX.Y.Z`; `:X.Y.Z`, `:X.Y`, `:X`, and `:latest` are
the same multi-arch image (amd64, arm64, arm/v7); chart `X.Y.Z` has appVersion `X.Y.Z`.

## When something fails

- **Preflight fails:** nothing was published. Fix what it names (often: CI hasn't finished,
  or the notes file is missing) and run the workflow again.
- **The tag's image run fails** (a flaky test, a registry hiccup): re-run the failed jobs on
  that run. Nothing is re-tagged.
- **The tag needs a code fix:** never move or reuse a published tag. Fix on `main`, set the
  version to the patch release (`deploy/release/bump.sh X.Y.Z+1`, commit, push, wait for CI),
  write `notes/vX.Y.Z+1.md`, and release `X.Y.Z+1`. The workflow moves `main` on again.
- **The pull request that moves `main` on isn't opened** (the job's last step fails: usually
  the setting above is off): the release itself is fine, and the branch `release/start-<next>`
  is already pushed. Open the pull request from the link in the job's error (or enable the
  setting and re-run the job). If that isn't possible either, run
  `deploy/release/bump.sh <next>` locally, commit
  (`chore: start <next> development (after vX.Y.Z) [OPS-004]`), and push it the way you push
  to `main` (branch protection's bypass) or through a pull request of your own.
- **Verify fails:** it prints each check as `ok` or `FAIL`. Registry or "latest" lag gets
  three tries; anything else is a real problem: fix it, then re-run the `verify` job.

## Without the workflow

From a machine with push access: `git tag -a vX.Y.Z -m "TelltaleDNS X.Y.Z"` on a commit
whose CI passed, then `git push origin vX.Y.Z`. A tag pushed by a person starts the image
workflow by itself. Then run `deploy/release/bump.sh <next>` on a branch, commit, and open a
pull request into `main` (or push to `main` as an administrator), and check with
`deploy/release/verify.sh X.Y.Z` once the tag's build is green.

## Things that aren't obvious

- **A tag or commit pushed with a workflow's own token starts no workflows.** That's why the
  release workflow starts the tag's build, and CI and edge for its version commit, explicitly
  (`gh workflow run`). `ci.yml` and `image.yml` accept `workflow_dispatch` for this. The
  image workflow's publish steps run for pushes *and* dispatches on `main` or `v*` tags.
- **Workspace crates name each other's version** (`telltale-proto = { version = "X.Y.Z",
  path = … }`). A version change has to update them and `Cargo.lock` too: use
  `deploy/release/bump.sh`, never a hand edit. The committed OpenAPI document
  (`docs/api/openapi.json`, `info.version`) carries the version too; CI fails if it's stale,
  and `bump.sh` updates it (learned from v0.1.0: the first bump missed it).
- **`Chart.yaml` says `appVersion: "edge"`** on `main`. The tag's build packages the chart
  with appVersion `X.Y.Z`, so a stable chart installs the matching stable image.
- **Signing needs the `MINISIGN_SECRET_KEY` secret.** Without it the build warns and
  publishes nothing. The public half lives in `deploy/release/telltale-release.pub`,
  `crates/telltale/src/selfupdate.rs`, and `deploy/systemd/install.sh`. A new key means
  updating all three.
- **The `edge` prerelease is deleted and re-created** by each push to `main`. A superseded
  run steps aside instead of racing the newer one. It never affects "latest".
